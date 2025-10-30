import os
import threading
import traceback
from flask import Flask, render_template, redirect, url_for, jsonify, send_file, request
from scrape import scrape_all_parallel
from parse import parse_vulnerabilities_with_ai, generate_ai_insights, find_mitigation
from report import generate_report
import json
from datetime import datetime
from search_vulnerabilities import search_vulnerabilities_with_ai, search_vulnerability_details
from datetime import datetime, timedelta
import pickle
# Near the top with other imports:
from enhanced_verification import CVEVerifier, VulnerabilityValidator
from verification_config import (
    get_source_reliability, 
    is_authoritative_source,
    format_verification_report,
    VERIFICATION_RULES
)

CACHE_FILE = "vuln_cache.pkl"
CACHE_DURATION = timedelta(days=1)  # 1 day cache validity

def get_cached_report():
    """Return cached data if it's still valid."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "rb") as f:
            cache = pickle.load(f)
        if datetime.now() - cache["timestamp"] < CACHE_DURATION:
            print("✅ Using cached vulnerability report")
            return cache["data"]
    return None

def save_cached_report(data):
    """Save scraped + parsed report to cache."""
    with open(CACHE_FILE, "wb") as f:
        pickle.dump({"timestamp": datetime.now(), "data": data}, f)


app = Flask(__name__)

REPORT_FILE = "vulnerability_report.txt"
JSON_FILE = "vulnerability_report.json"

# STIX Generator Import
from stix_generator import generate_stix_from_report

# STIX Generation Variables
STIX_FILE_PATH = "vulnerabilities_stix.json"
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
        
        # Generate STIX file from the vulnerabilities.json
        output_path = generate_stix_from_report(
            json_report_path=JSON_FILE,
            output_path=STIX_FILE_PATH
        )
        
        stix_status["progress"] = "Validating STIX file..."
        
        # Verify file was created
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


@app.route('/generate_stix', methods=['POST'])
def generate_stix():
    """Start STIX file generation in background"""
    if not stix_status["is_generating"]:
        # Check if vulnerability data exists
        if not os.path.exists(JSON_FILE):
            return jsonify({
                "status": "error",
                "message": "No vulnerability data found. Please run a scan first."
            }), 400
        
        # Reset status
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


# Regular vulnerability scanning status
report_status = {
    "is_generating": False,
    "progress": "",
    "error": None,
    "download_ready": False,
    "current_step": 0,
    "total_steps": 4
}

def generate_report_task():
    """Optimized report generation - parallel scraping with caching"""
    try:
        print(">> Starting vulnerability scan...")
        report_status["is_generating"] = True
        report_status["error"] = None
        report_status["download_ready"] = False
        report_status["current_step"] = 0

        from datetime import datetime, timedelta
        import pickle

        CACHE_FILE = "vuln_cache.pkl"
        CACHE_DURATION = timedelta(days=1)

        def get_cached_report():
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE, "rb") as f:
                    cache = pickle.load(f)
                if datetime.now() - cache["timestamp"] < CACHE_DURATION:
                    print("✅ Using cached vulnerability report")
                    return cache["data"]
            return None

        def save_cached_report(data):
            with open(CACHE_FILE, "wb") as f:
                pickle.dump({"timestamp": datetime.now(), "data": data}, f)

        # Step 0: Check cache first
        report_status["progress"] = "Checking cache..."
        cached_data = get_cached_report()
        if cached_data:
            print("⚡ Returning cached report (same-day scan)")
            with open(JSON_FILE, "w", encoding="utf-8") as f:
                json.dump(cached_data, f, indent=2)
            generate_report(cached_data["vulnerabilities"])
            report_status["download_ready"] = True
            report_status["progress"] = "Scan complete! [CACHED]"
            return

        # Clean old files
        for file in [REPORT_FILE, JSON_FILE, STIX_FILE_PATH]:
            if os.path.exists(file):
                os.remove(file)

        # Step 1: Initialize
        report_status["current_step"] = 1
        report_status["progress"] = "Initializing parallel scraping..."
        print(f"[*] Preparing to scrape sources...")

        # Step 2: Parallel scraping (MUCH FASTER!)
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

        # Remove duplicates based on CVE ID
        seen_cves = set()
        unique_vulns = []
        for vuln in all_vulnerabilities:
            cve_id = vuln.get("id", "").upper()
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_vulns.append(vuln)
            elif not cve_id:  # Keep non-CVE vulnerabilities
                unique_vulns.append(vuln)

        # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN)
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
            "vulnerabilities": unique_vulns[:50]  # Limit to 50 for dashboard
        }

        with open(JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(dashboard_data, f, indent=2)
        print("[+] JSON dashboard data created")

        # Generate AI insights
        try:
            insights = generate_ai_insights(unique_vulns[:20])  # Use top 20 for insights
            dashboard_data["ai_insights"] = insights
            
            with open(JSON_FILE, "w", encoding="utf-8") as f:
                json.dump(dashboard_data, f, indent=2)
            print("[+] AI insights added")
        except Exception as e:
            print(f"[!] Could not generate AI insights: {e}")

        # ✅ Save to cache for same-day reuse
        save_cached_report(dashboard_data)

        report_status["download_ready"] = True
        report_status["progress"] = "Scan complete! [DONE]"
        print("[+] Report generation complete")

    except Exception as e:
        print("[!] Error in report task:", e)
        traceback.print_exc()
        report_status["error"] = str(e)
        report_status["progress"] = "Error occurred"
    finally:
        report_status["is_generating"] = False



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
    return jsonify(data)


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
        # Search in CVE ID
        if query in vuln.get("id", "").lower():
            results.append(vuln)
            continue
        
        # Search in title
        if query in vuln.get("title", "").lower():
            results.append(vuln)
            continue
        
        # Search in description
        if query in vuln.get("description", "").lower():
            results.append(vuln)
            continue
        
        # Search in affected products
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
# AI-POWERED WEB SEARCH ROUTES (NEW)
# ===================================================================

@app.route('/ai_search')
def ai_search_page():
    """AI-powered vulnerability search page (uses web search)"""
    return render_template('ai_search.html')


@app.route('/api/ai_search', methods=['POST'])
def api_ai_search():
    """
    API endpoint for AI-powered vulnerability search with VERIFICATION
    """
    data = request.get_json()
    query = data.get('query', '').strip()
    
    if not query:
        return jsonify({
            "success": False,
            "error": "Please provide a software or organization name"
        }), 400
    
    print(f"[*] AI Search Request: {query}")
    print(f"[*] Verification enabled: All results will be verified")
    
    try:
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
        
        # Use the fixed search function with Gemini grounding
        result = search_vulnerabilities_with_ai(query)
        
        # Add verification statistics
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
        import traceback
        traceback.print_exc()
        
        return jsonify({
            "success": False,
            "error": f"Search failed: {str(e)}"
        }), 500


# Add new endpoint for manual CVE verification
@app.route('/api/verify_cve', methods=['POST'])
def api_verify_cve():
    """
    Manually verify a CVE ID across multiple sources
    """
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
        
        # Add human-readable summary
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


# Add endpoint to check verification configuration
@app.route('/api/verification_config')
def api_verification_config():
    """
    Get current verification configuration
    """
    from verification_config import (
        TIER1_SOURCES,
        TIER2_SOURCES,
        TIER3_SOURCES,
        VERIFICATION_RULES
    )
    
    return jsonify({
        "tier1_sources": len(TIER1_SOURCES),
        "tier2_sources": len(TIER2_SOURCES),
        "tier3_sources": len(TIER3_SOURCES),
        "rules": VERIFICATION_RULES,
        "tier1_list": list(TIER1_SOURCES.keys()),
        "description": "Multi-tier verification system to prevent LLM hallucinations"
    })


# Update the CVE details endpoint
@app.route('/api/cve_details', methods=['POST'])
def api_cve_details():
    """
    Get detailed information about a VERIFIED CVE
    """
    data = request.get_json()
    cve_id = data.get('cve_id', '').strip().upper()
    
    if not cve_id or not cve_id.startswith('CVE-'):
        return jsonify({
            "success": False,
            "error": "Please provide a valid CVE ID"
        }), 400
    
    print(f"[*] Fetching verified details for: {cve_id}")
    
    try:
        # First verify the CVE exists
        verifier = CVEVerifier()
        verification = verifier.verify_cve_exists(cve_id)
        
        if not verification['exists']:
            return jsonify({
                "success": False,
                "error": f"CVE not verified: {verification['reason']}",
                "verification": verification
            }), 404
        
        # Get detailed information
        result = search_vulnerability_details(cve_id)
        
        # Add verification info
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
    print("  ✅ STIX 2.1 generation")
    print("  ✅ Interactive dashboard")
    print("  ✅ Mitigation finder")
    print("\n[INFO] Server starting at http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(debug=False, use_reloader=False, host='0.0.0.0', port=5000)