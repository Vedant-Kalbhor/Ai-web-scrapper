import os
import threading
import traceback
from flask import Flask, render_template, redirect, url_for, jsonify, send_file, request
from scrape import get_vulnerability_urls, scrape_content
from parse import parse_vulnerabilities_with_ai, generate_ai_insights
from report import generate_report
import json
from datetime import datetime

app = Flask(__name__)

REPORT_FILE = "vulnerability_report.txt"
JSON_FILE = "vulnerability_report.json"

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
        print("🚀 Starting vulnerability scan...")
        report_status["is_generating"] = True
        report_status["error"] = None
        report_status["download_ready"] = False
        report_status["current_step"] = 0

        # Clean old files
        for file in [REPORT_FILE, JSON_FILE]:
            if os.path.exists(file):
                os.remove(file)

        # Step 1: Initialize
        report_status["current_step"] = 1
        report_status["progress"] = "Initializing parallel scraping..."
        print(f"📋 Preparing to scrape sources...")

        # Step 2: Parallel scraping (MUCH FASTER!)
        report_status["current_step"] = 2
        report_status["progress"] = "Scraping all sources in parallel..."
        
        from scrape import scrape_all_parallel
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
                print(f"⚠️ Error parsing {item['source']}: {e}")

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

        # Sort by severity (HIGH > MEDIUM > LOW > UNKNOWN)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        unique_vulns.sort(key=lambda x: severity_order.get(x.get("severity", "UNKNOWN").upper(), 5))

        print(f"📊 Found {len(unique_vulns)} unique vulnerabilities")

        # Step 4: Generate Reports
        report_status["current_step"] = 4
        report_status["progress"] = "Generating reports..."

        # Generate text report
        generate_report(unique_vulns)
        print("📝 Text report created")

        # Generate JSON for dashboard
        dashboard_data = {
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_vulnerabilities": len(unique_vulns),
            "sources_scanned": len(scraped_data),
            "vulnerabilities": unique_vulns[:50]  # Limit to 50 for dashboard
        }

        with open(JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(dashboard_data, f, indent=2)
        print("📊 JSON dashboard data created")

        # Generate AI insights
        try:
            insights = generate_ai_insights(unique_vulns[:20])  # Use top 20 for insights
            dashboard_data["ai_insights"] = insights
            
            with open(JSON_FILE, "w", encoding="utf-8") as f:
                json.dump(dashboard_data, f, indent=2)
            print("🤖 AI insights added")
        except Exception as e:
            print(f"⚠️ Could not generate AI insights: {e}")

        report_status["download_ready"] = True
        report_status["progress"] = "Scan complete! ✅"
        print("✅ Report generation complete")

    except Exception as e:
        print("❌ Error in report task:", e)
        traceback.print_exc()
        report_status["error"] = str(e)
        report_status["progress"] = "Error occurred"
    finally:
        report_status["is_generating"] = False


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/scan', methods=['POST'])
def scan():
    if not report_status["is_generating"]:
        print("🔄 Starting new vulnerability scan...")
        thread = threading.Thread(target=generate_report_task, daemon=True)
        thread.start()
    else:
        print("⚠️ Scan already in progress")
    return redirect(url_for("scanning"))


@app.route('/scanning')
def scanning():
    return render_template("scanning.html")


@app.route('/status')
def status():
    return jsonify(report_status)


@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")


@app.route('/mitigation')
def mitigation_page():
    return render_template("mitigation.html")


@app.route('/get_report')
def get_report():
    if os.path.exists(REPORT_FILE):
        return send_file(REPORT_FILE, as_attachment=True)
    return "No report found", 404


@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    if not os.path.exists(JSON_FILE):
        return jsonify({"error": "No data available. Please run a scan first."}), 404

    with open(JSON_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return jsonify(data)


@app.route('/api/mitigation', methods=['POST'])
def api_mitigation():
    from parse import find_mitigation
    
    data = request.get_json()
    query = data.get("query", "").strip()

    if not query:
        return jsonify({"error": "No query provided"}), 400

    try:
        result = find_mitigation(query)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Failed to get mitigation: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=False, use_reloader=False)