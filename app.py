import os
import threading
import traceback
from flask import Flask, render_template, redirect, url_for, jsonify, send_file, request
from scrape import scrape_all_parallel
from parse import parse_vulnerabilities_with_ai, generate_ai_insights, find_mitigation
from report import generate_report
import json
from datetime import datetime, timedelta
import pickle
from search_vulnerabilities import search_vulnerabilities_with_ai, search_vulnerability_details

# Near the top with other imports:
from enhanced_verification import CVEVerifier, VulnerabilityValidator
from verification_config import (
    get_source_reliability, 
    is_authoritative_source,
    format_verification_report,
    VERIFICATION_RULES
)

from exploit_scraper import scrape_all_exploits_parallel
from exploit_parser import enrich_exploit_with_ai

app = Flask(__name__)

# File paths
REPORT_FILE = "vulnerability_report.txt"
JSON_FILE = "vulnerability_report.json"
EXPLOITS_JSON_FILE = "exploits_report.json"
VULN_CACHE_FILE = "vuln_cache.pkl"
EXPLOIT_CACHE_FILE = "exploit_cache.pkl"
STIX_FILE_PATH = "vulnerabilities_stix.json"

# Cache settings
CACHE_DURATION = timedelta(hours=24)  # 24 hour cache validity


# ===================================================================
# CACHE UTILITY FUNCTIONS
# ===================================================================

def get_cached_vulnerabilities():
    """Return cached vulnerability data if it's still valid (< 24 hours old)"""
    if os.path.exists(VULN_CACHE_FILE):
        try:
            with open(VULN_CACHE_FILE, "rb") as f:
                cache = pickle.load(f)
            
            cache_age = datetime.now() - cache["timestamp"]
            
            if cache_age < CACHE_DURATION:
                hours_old = cache_age.total_seconds() / 3600
                print(f"✅ Using cached vulnerability report ({hours_old:.1f} hours old)")
                return cache["data"]
            else:
                print(f"⚠️  Vulnerability cache expired ({cache_age.total_seconds() / 3600:.1f} hours old)")
        except Exception as e:
            print(f"⚠️  Error reading vulnerability cache: {e}")
    
    return None


def save_cached_vulnerabilities(data):
    """Save vulnerability report to cache with timestamp"""
    try:
        with open(VULN_CACHE_FILE, "wb") as f:
            pickle.dump({"timestamp": datetime.now(), "data": data}, f)
        print(f"💾 Vulnerability cache saved at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        print(f"⚠️  Error saving vulnerability cache: {e}")


def get_cached_exploits():
    """Return cached exploit data if it's still valid (< 24 hours old)"""
    if os.path.exists(EXPLOIT_CACHE_FILE):
        try:
            with open(EXPLOIT_CACHE_FILE, "rb") as f:
                cache = pickle.load(f)
            
            cache_age = datetime.now() - cache["timestamp"]
            
            if cache_age < CACHE_DURATION:
                hours_old = cache_age.total_seconds() / 3600
                print(f"✅ Using cached exploits ({hours_old:.1f} hours old)")
                return cache["data"]
            else:
                print(f"⚠️  Exploit cache expired ({cache_age.total_seconds() / 3600:.1f} hours old)")
        except Exception as e:
            print(f"⚠️  Error reading exploit cache: {e}")
    
    return None


def save_cached_exploits(data):
    """Save exploits to cache with timestamp"""
    try:
        with open(EXPLOIT_CACHE_FILE, "wb") as f:
            pickle.dump({"timestamp": datetime.now(), "data": data}, f)
        print(f"💾 Exploit cache saved at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        print(f"⚠️  Error saving exploit cache: {e}")


def get_cache_info(cache_file):
    """Get cache age information"""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "rb") as f:
                cache = pickle.load(f)
            
            cache_age = datetime.now() - cache["timestamp"]
            hours_old = cache_age.total_seconds() / 3600
            
            return {
                "exists": True,
                "timestamp": cache["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "age_hours": round(hours_old, 1),
                "is_valid": cache_age < CACHE_DURATION,
                "expires_in_hours": round(24 - hours_old, 1) if cache_age < CACHE_DURATION else 0
            }
        except Exception as e:
            return {"exists": False, "error": str(e)}
    
    return {"exists": False}


# ===================================================================
# STIX GENERATION
# ===================================================================

from stix_generator import generate_stix_from_report

stix_status = {
    "is_generating": False, 
    "progress": None, 
    "error": None, 
    "download_ready": False
}

def generate_stix_task():
    """Background task to generate STIX file"""
    try:
        stix_status.update({
            "is_generating": True, 
            "error": None, 
            "download_ready": False,
            "progress": "Reading vulnerability data..."
        })
        
        print("[*] Starting STIX generation...")
        
        stix_status["progress"] = "Generating STIX format with AI..."
        
        output_path = generate_stix_from_report(
            json_report_path=JSON_FILE,
            output_path=STIX_FILE_PATH
        )
        
        stix_status["progress"] = "Validating STIX file..."
        
        if not os.path.exists(output_path):
            raise Exception("STIX file generation failed")
        
        stix_status["download_ready"] = True
        stix_status["progress"] = "STIX file ready! ✅"
        print("[+] STIX generation complete!")
        
    except Exception as e:
        stix_status["error"] = str(e)
        stix_status["progress"] = "Generation failed"
        print(f"[!] STIX generation error: {e}")
        traceback.print_exc()
    finally:
        stix_status["is_generating"] = False


# ===================================================================
# VULNERABILITY SCANNING
# ===================================================================

report_status = {
    "is_generating": False,
    "progress": "",
    "error": None,
    "download_ready": False,
    "current_step": 0,
    "total_steps": 4
}


def generate_report_task():
    """Optimized report generation with 24-hour caching"""
    try:
        print("\n" + "="*60)
        print("Starting Vulnerability Scan")
        print("="*60)
        
        report_status["is_generating"] = True
        report_status["error"] = None
        report_status["download_ready"] = False
        report_status["current_step"] = 0

        # Step 0: Check cache first
        report_status["progress"] = "Checking cache..."
        cached_data = get_cached_vulnerabilities()
        
        if cached_data:
            print("⚡ Returning cached report (< 24 hours old)")
            with open(JSON_FILE, "w", encoding="utf-8") as f:
                json.dump(cached_data, f, indent=2)
            generate_report(cached_data["vulnerabilities"])
            report_status["download_ready"] = True
            report_status["progress"] = "Scan complete! [CACHED]"
            return

        print("🔄 Cache expired or not found - starting fresh scan")

        # Clean old files
        for file in [REPORT_FILE, JSON_FILE, STIX_FILE_PATH]:
            if os.path.exists(file):
                os.remove(file)

        # Step 1: Initialize
        report_status["current_step"] = 1
        report_status["progress"] = "Initializing parallel scraping..."
        print("[*] Preparing to scrape sources...")

        # Step 2: Parallel scraping
        report_status["current_step"] = 2
        report_status["progress"] = "Scraping all sources in parallel..."
        scraped_data = scrape_all_parallel(max_workers=3)

        if not scraped_data:
            raise Exception("No vulnerability data could be scraped from any source")

        # Step 3: AI Processing
        report_status["current_step"] = 3
        report_status["progress"] = "Analyzing vulnerabilities with AI..."
        all_vulnerabilities = []
        
        for item in scraped_data:
            try:
                vulnerabilities = parse_vulnerabilities_with_ai(
                    item["content"], 
                    item["source"]
                )
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                print(f"[!] Error parsing {item['source']}: {e}")

        # Remove duplicates
        seen_cves = set()
        unique_vulns = []
        for vuln in all_vulnerabilities:
            cve_id = vuln.get("id", "").upper()
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_vulns.append(vuln)
            elif not cve_id:
                unique_vulns.append(vuln)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        unique_vulns.sort(key=lambda x: severity_order.get(x.get("severity", "UNKNOWN").upper(), 5))

        print(f"[+] Found {len(unique_vulns)} unique vulnerabilities")

        # Step 4: Generate Reports
        report_status["current_step"] = 4
        report_status["progress"] = "Generating reports..."
        generate_report(unique_vulns)
        print("[+] Text report created")

        # Generate JSON for dashboard
        dashboard_data = {
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_vulnerabilities": len(unique_vulns),
            "sources_scanned": len(scraped_data),
            "vulnerabilities": unique_vulns[:50]
        }

        with open(JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(dashboard_data, f, indent=2)
        print("[+] JSON dashboard data created")

        # Generate AI insights
        try:
            insights = generate_ai_insights(unique_vulns[:20])
            dashboard_data["ai_insights"] = insights
            
            with open(JSON_FILE, "w", encoding="utf-8") as f:
                json.dump(dashboard_data, f, indent=2)
            print("[+] AI insights added")
        except Exception as e:
            print(f"[!] Could not generate AI insights: {e}")

        # Save to cache
        save_cached_vulnerabilities(dashboard_data)

        report_status["download_ready"] = True
        report_status["progress"] = "Scan complete! [FRESH]"
        print("[+] Report generation complete")
        print("="*60 + "\n")

    except Exception as e:
        print("[!] Error in report task:", e)
        traceback.print_exc()
        report_status["error"] = str(e)
        report_status["progress"] = "Error occurred"
    finally:
        report_status["is_generating"] = False


# ===================================================================
# EXPLOIT SCRAPING WITH CACHING
# ===================================================================

exploit_status = {
    "is_scraping": False,
    "progress": "",
    "error": None,
    "download_ready": False
}


def scrape_exploits_task():
    """Scrape exploits with 24-hour caching"""
    try:
        print("\n" + "="*60)
        print("Starting Exploit Scraping")
        print("="*60)
        
        exploit_status["is_scraping"] = True
        exploit_status["error"] = None
        exploit_status["download_ready"] = False
        exploit_status["progress"] = "Checking cache..."

        # Check cache first
        cached_data = get_cached_exploits()
        
        if cached_data:
            print("⚡ Returning cached exploits (< 24 hours old)")
            with open(EXPLOITS_JSON_FILE, "w", encoding="utf-8") as f:
                json.dump(cached_data, f, indent=2)
            exploit_status["download_ready"] = True
            exploit_status["progress"] = "Exploits ready! [CACHED]"
            return

        print("🔄 Cache expired or not found - starting fresh scrape")

        exploit_status["progress"] = "Scraping exploit databases..."
        
        # Scrape all sources in parallel
        exploits = scrape_all_exploits_parallel(max_workers=3)
        
        if not exploits:
            raise Exception("No exploits found from any source")
        
        exploit_status["progress"] = f"Enriching {min(50, len(exploits))} exploits with AI..."
        
        # Enrich first 50 exploits with AI descriptions
        print(f"[*] Enriching top {min(50, len(exploits))} exploits with AI...")
        for i, exploit in enumerate(exploits[:50]):
            try:
                exploits[i] = enrich_exploit_with_ai(exploit)
            except Exception as e:
                print(f"[!] Could not enrich exploit {exploit.get('id')}: {e}")
        
        # Save to JSON file
        exploit_data = {
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_exploits": len(exploits),
            "exploits": exploits,
            "cache_expires": (datetime.now() + CACHE_DURATION).strftime("%Y-%m-%d %H:%M:%S")
        }
        
        with open(EXPLOITS_JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(exploit_data, f, indent=2)
        
        # Save to cache
        save_cached_exploits(exploit_data)
        
        exploit_status["download_ready"] = True
        exploit_status["progress"] = "Exploits ready! [FRESH]"
        
        print(f"[+] Successfully scraped {len(exploits)} exploits")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"[!] Error in exploit scraping: {e}")
        traceback.print_exc()
        exploit_status["error"] = str(e)
        exploit_status["progress"] = "Error occurred"
    finally:
        exploit_status["is_scraping"] = False


# ===================================================================
# ROUTES
# ===================================================================

@app.route('/')
def index():
    """Landing page"""
    return render_template("index.html")


@app.route('/scan', methods=['POST'])
def scan():
    """Trigger vulnerability scan"""
    if not report_status["is_generating"]:
        print("[*] Starting new vulnerability scan...")
        thread = threading.Thread(target=generate_report_task, daemon=True)
        thread.start()
    else:
        print("[!] Scan already in progress")
    return redirect(url_for("scanning"))


@app.route('/scanning')
def scanning():
    """Scanning progress page"""
    return render_template("scanning.html")


@app.route('/status')
def status():
    """Get scan status"""
    return jsonify(report_status)


@app.route('/dashboard')
def dashboard():
    """Main dashboard"""
    return render_template("dashboard.html")


@app.route('/mitigation')
def mitigation_page():
    """Mitigation finder page"""
    return render_template("mitigation.html")


@app.route('/exploits')
def exploits_page():
    """Latest exploits page"""
    return render_template('exploits.html')


# ===================================================================
# API ENDPOINTS - EXPLOITS
# ===================================================================

@app.route('/api/exploits')
def api_exploits():
    """Get latest exploits (uses cache if available)"""
    # Check if cached data exists and is valid
    if os.path.exists(EXPLOITS_JSON_FILE):
        try:
            with open(EXPLOITS_JSON_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Add cache info
            cache_info = get_cache_info(EXPLOIT_CACHE_FILE)
            data["cache_info"] = cache_info
            
            return jsonify(data)
        except Exception as e:
            print(f"[!] Error reading exploits file: {e}")
    
    return jsonify({
        "error": "No exploits available. Click 'Refresh Exploits' to fetch new data.",
        "exploits": [],
        "total_exploits": 0,
        "cache_info": get_cache_info(EXPLOIT_CACHE_FILE)
    }), 404


@app.route('/api/exploits/refresh', methods=['POST'])
def refresh_exploits():
    """Force refresh exploits (ignores cache)"""
    if not exploit_status["is_scraping"]:
        print("[*] Forcing exploit refresh...")
        
        # Delete cache to force fresh scrape
        if os.path.exists(EXPLOIT_CACHE_FILE):
            os.remove(EXPLOIT_CACHE_FILE)
            print("[*] Exploit cache cleared")
        
        thread = threading.Thread(target=scrape_exploits_task, daemon=True)
        thread.start()
        return jsonify({"status": "started", "message": "Scraping fresh exploits..."})
    else:
        return jsonify({"status": "already_running", "message": "Exploit scraping already in progress"})


@app.route('/api/exploits/status')
def exploit_scraping_status():
    """Get exploit scraping status"""
    status_data = exploit_status.copy()
    status_data["cache_info"] = get_cache_info(EXPLOIT_CACHE_FILE)
    return jsonify(status_data)


# ===================================================================
# API ENDPOINTS - VULNERABILITIES
# ===================================================================

@app.route('/get_report')
def get_report():
    """Download text report"""
    if os.path.exists(REPORT_FILE):
        return send_file(REPORT_FILE, as_attachment=True)
    return "No report found", 404


@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    """Get all vulnerabilities as JSON"""
    if not os.path.exists(JSON_FILE):
        return jsonify({"error": "No data available. Please run a scan first."}), 404

    with open(JSON_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Add cache info
    data["cache_info"] = get_cache_info(VULN_CACHE_FILE)
    
    return jsonify(data)


@app.route('/api/cache/info')
def cache_info():
    """Get cache information for both vulnerabilities and exploits"""
    return jsonify({
        "vulnerabilities": get_cache_info(VULN_CACHE_FILE),
        "exploits": get_cache_info(EXPLOIT_CACHE_FILE),
        "cache_duration_hours": 24
    })


@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Clear all caches"""
    data = request.get_json() or {}
    cache_type = data.get('type', 'all')  # 'all', 'vulnerabilities', or 'exploits'
    
    cleared = []
    
    if cache_type in ['all', 'vulnerabilities'] and os.path.exists(VULN_CACHE_FILE):
        os.remove(VULN_CACHE_FILE)
        cleared.append('vulnerabilities')
    
    if cache_type in ['all', 'exploits'] and os.path.exists(EXPLOIT_CACHE_FILE):
        os.remove(EXPLOIT_CACHE_FILE)
        cleared.append('exploits')
    
    return jsonify({
        "success": True,
        "cleared": cleared,
        "message": f"Cleared cache for: {', '.join(cleared)}" if cleared else "No cache to clear"
    })


@app.route('/api/search', methods=['GET'])
def api_search():
    """Search vulnerabilities by software, company, or CVE ID (from local database)"""
    if not os.path.exists(JSON_FILE):
        return jsonify({"error": "No data available. Please run a scan first."}), 404

    query = request.args.get('q', '').strip().lower()
    
    if not query:
        return jsonify({"error": "No search query provided"}), 400

    with open(JSON_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    vulnerabilities = data.get("vulnerabilities", [])
    
    # Search across multiple fields
    results = []
    for vuln in vulnerabilities:
        if query in vuln.get("id", "").lower():
            results.append(vuln)
            continue
        
        if query in vuln.get("title", "").lower():
            results.append(vuln)
            continue
        
        if query in vuln.get("description", "").lower():
            results.append(vuln)
            continue
        
        for product in vuln.get("affected_products", []):
            if query in product.lower():
                results.append(vuln)
                break
    
    return jsonify({
        "query": query,
        "total_results": len(results),
        "vulnerabilities": results
    })


@app.route('/api/mitigation', methods=['POST'])
def api_mitigation():
    """Find mitigation for a specific CVE or vulnerability"""
    data = request.get_json()
    query = data.get("query", "").strip()

    if not query:
        return jsonify({"error": "No query provided"}), 400

    try:
        print(f"Finding mitigation for: {query}")
        result = find_mitigation(query)
        return jsonify(result)
    except Exception as e:
        print(f"Mitigation error: {e}")
        traceback.print_exc()
        return jsonify({"error": f"Failed to get mitigation: {str(e)}"}), 500


# ===================================================================
# AI-POWERED WEB SEARCH ROUTES
# ===================================================================

@app.route('/ai_search')
def ai_search_page():
    """AI-powered vulnerability search page (uses web search)"""
    return render_template('ai_search.html')


@app.route('/api/ai_search', methods=['POST'])
def api_ai_search():
    """API endpoint for AI-powered vulnerability search with VERIFICATION"""
    data = request.get_json()
    query = data.get('query', '').strip()
    
    if not query:
        return jsonify({
            "success": False,
            "error": "Please provide a software or organization name"
        }), 400
    
    print(f"\n{'='*60}")
    print(f"AI Web Search Request: {query}")
    print(f"{'='*60}")
    
    try:
        result = search_vulnerabilities_with_ai(query)
        
        if result.get('success'):
            result['verification_stats'] = {
                'total_candidates': result.get('total_checked', 0),
                'verified_vulnerabilities': result.get('total_found', 0),
                'rejection_rate': f"{((result.get('total_checked', 0) - result.get('total_found', 0)) / max(result.get('total_checked', 1), 1) * 100):.1f}%",
                'confidence_threshold': VERIFICATION_RULES['confidence_thresholds']['medium']
            }
        
        print(f"[+] Search complete: {result.get('total_found', 0)} verified vulnerabilities")
        return jsonify(result)
        
    except Exception as e:
        print(f"[!] Error in AI search: {e}")
        traceback.print_exc()
        
        return jsonify({
            "success": False,
            "error": f"Search failed: {str(e)}"
        }), 500


@app.route('/api/verify_cve', methods=['POST'])
def api_verify_cve():
    """Manually verify a CVE ID across multiple sources"""
    data = request.get_json()
    cve_id = data.get('cve_id', '').strip().upper()
    
    if not cve_id or not cve_id.startswith('CVE-'):
        return jsonify({
            "success": False,
            "error": "Invalid CVE ID format"
        }), 400
    
    try:
        verifier = CVEVerifier()
        result = verifier.verify_cve_exists(cve_id)
        
        result['summary'] = format_verification_report(
            result.get('verified_sources', []),
            result.get('confidence', 0)
        )
        
        return jsonify({
            "success": True,
            "verification": result
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/cve_details', methods=['POST'])
def api_cve_details():
    """Get detailed information about a VERIFIED CVE"""
    data = request.get_json()
    cve_id = data.get('cve_id', '').strip().upper()
    
    if not cve_id or not cve_id.startswith('CVE-'):
        return jsonify({
            "success": False,
            "error": "Please provide a valid CVE ID"
        }), 400
    
    print(f"[*] Fetching verified details for: {cve_id}")
    
    try:
        verifier = CVEVerifier()
        verification = verifier.verify_cve_exists(cve_id)
        
        if not verification['exists']:
            return jsonify({
                "success": False,
                "error": f"CVE not verified: {verification['reason']}",
                "verification": verification
            }), 404
        
        result = search_vulnerability_details(cve_id)
        result['verification'] = verification
        result['verification_summary'] = format_verification_report(
            verification.get('verified_sources', []),
            verification.get('confidence', 0)
        )
        
        return jsonify(result)
        
    except Exception as e:
        print(f"[!] Error fetching CVE details: {e}")
        return jsonify({
            "success": False,
            "error": f"Failed to fetch details: {str(e)}"
        }), 500


# ===================================================================
# STIX GENERATION ROUTES
# ===================================================================

@app.route('/generate_stix', methods=['POST'])
def generate_stix():
    """Start STIX file generation in background"""
    if not stix_status["is_generating"]:
        if not os.path.exists(JSON_FILE):
            return jsonify({
                "status": "error",
                "message": "No vulnerability data found. Please run a scan first."
            }), 400
        
        stix_status.update({
            "is_generating": False,
            "progress": None,
            "error": None,
            "download_ready": False
        })
        
        thread = threading.Thread(target=generate_stix_task, daemon=True)
        thread.start()
        return jsonify({"status": "started"})
    return jsonify({"status": "already_running"})


@app.route('/stix_status')
def get_stix_status():
    """Get current status of STIX generation"""
    return jsonify(stix_status)


@app.route('/download_stix')
def download_stix():
    """Download the generated STIX file"""
    if os.path.exists(STIX_FILE_PATH):
        return send_file(
            STIX_FILE_PATH, 
            as_attachment=True,
            download_name=f"vulnerabilities_stix_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mimetype="application/json"
        )
    return "STIX file not found", 404


@app.route('/stix_loading')
def stix_loading_page():
    """Show STIX generation loading page"""
    return render_template('stix_loading.html')


# ===================================================================
# ERROR HANDLERS
# ===================================================================

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    return jsonify({"error": "Internal server error"}), 500


# ===================================================================
# MAIN
# ===================================================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("AI-Powered Vulnerability Scanner")
    print("="*60)
    print("\n[INFO] Starting Flask application...")
    print("[INFO] Features enabled:")
    print("  ✅ Multi-source vulnerability scanning")
    print("  ✅ AI-powered analysis (Gemini)")
    print("  ✅ Real-time web search (Gemini Grounding)")
    print("  ✅ Latest exploit tracking")
    print("  ✅ 24-hour intelligent caching")
    print("  ✅ STIX 2.1 generation")
    print("  ✅ Interactive dashboard")
    print("  ✅ Mitigation finder")
    print("\n[INFO] Cache Settings:")
    print(f"  ⏰ Cache Duration: 24 hours")
    print(f"  💾 Vulnerability Cache: {VULN_CACHE_FILE}")
    print(f"  💾 Exploit Cache: {EXPLOIT_CACHE_FILE}")
    print("\n[INFO] Server starting at http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(debug=False, use_reloader=False, host='0.0.0.0', port=5000)