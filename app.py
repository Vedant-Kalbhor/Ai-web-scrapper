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
    """Optimized report generation - parallel scraping"""
    try:
        print(">> Starting vulnerability scan...")
        report_status["is_generating"] = True
        report_status["error"] = None
        report_status["download_ready"] = False
        report_status["current_step"] = 0

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

        # Generate text report
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
        print(f"[*] Finding mitigation for: {query}")
        result = find_mitigation(query)
        return jsonify(result)
    except Exception as e:
        print(f"[!] Mitigation error: {e}")
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
    API endpoint for AI-powered vulnerability search with real-time web search.
    Uses Gemini's native grounding to search the web for recent vulnerabilities.
    
    This is different from /api/search which searches the local database.
    This endpoint searches the LIVE WEB for current vulnerabilities.
    """
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        
        if not query:
            return jsonify({
                "success": False,
                "error": "Please provide a software or organization name"
            }), 400
        
        print(f"\n{'='*60}")
        print(f"[🔍] AI Web Search Request: {query}")
        print(f"{'='*60}")
        
        # Use the fixed search function with Gemini grounding
        result = search_vulnerabilities_with_ai(query)
        
        if result.get('success'):
            print(f"[✅] Search successful: Found {result.get('total_found', 0)} vulnerabilities")
        else:
            print(f"[❌] Search failed: {result.get('error', 'Unknown error')}")
        
        return jsonify(result)
        
    except Exception as e:
        print(f"[❌] API Error: {e}")
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Search failed: {str(e)}",
            "query": query if 'query' in locals() else "Unknown"
        }), 500


@app.route('/api/cve_details', methods=['POST'])
def api_cve_details():
    """
    Get detailed information about a specific CVE using web search and scraping.
    This uses real-time web data from NVD, CISA, and other sources.
    """
    try:
        data = request.get_json()
        cve_id = data.get('cve_id', '').strip()
        
        if not cve_id:
            return jsonify({
                "success": False,
                "error": "Please provide a CVE ID"
            }), 400
        
        print(f"\n{'='*60}")
        print(f"[🔍] CVE Details Request: {cve_id}")
        print(f"{'='*60}")
        
        # Use the fixed search function
        result = search_vulnerability_details(cve_id)
        
        if result.get('success'):
            print(f"[✅] CVE details retrieved successfully")
        else:
            print(f"[❌] CVE details failed: {result.get('error', 'Unknown error')}")
        
        return jsonify(result)
        
    except Exception as e:
        print(f"[❌] API Error: {e}")
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Failed to fetch details: {str(e)}",
            "cve_id": cve_id if 'cve_id' in locals() else "Unknown"
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
    print("🛡️  AI-Powered Vulnerability Scanner")
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