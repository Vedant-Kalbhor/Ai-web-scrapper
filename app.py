import os
import threading
import traceback
<<<<<<< HEAD
from flask import Flask, render_template, redirect, url_for, jsonify, send_file , request
from scrape import get_vulnerability_urls, scrape_content
from parse import parse_with_ai, summarize_latest_cves , generate_ai_insights
from report import generate_report
from nvd import fetch_latest_cves
=======
from flask import Flask, render_template, redirect, url_for, jsonify, send_file, request
from scrape import get_vulnerability_urls, scrape_content
from parse import parse_vulnerabilities_with_ai, generate_ai_insights
from report import generate_report
import json
from datetime import datetime
>>>>>>> 5d6b5fa (Claude changes)

app = Flask(__name__)

REPORT_FILE = "vulnerability_report.txt"
<<<<<<< HEAD
report_status = {
    "is_generating": False,
    "progress": None,
    "error": None,
    "download_ready": False
}


import random

def generate_report_task():
    try:
        print("🚀 Starting report task...")
        report_status["is_generating"] = True
        report_status["error"] = None
        report_status["download_ready"] = False
        report_status["progress"] = "Fetching latest vulnerabilities from NVD..."

        if os.path.exists(REPORT_FILE):
            os.remove(REPORT_FILE)
        if os.path.exists("vulnerability_report.json"):
            os.remove("vulnerability_report.json")

        # ✅ Fetch top 10 latest CVEs (API)
        latest_cves = fetch_latest_cves(limit=10)
        print(f"📥 Got {len(latest_cves)} CVEs from NVD API")

        # ✅ Fetch scraped CVEs (NVD + CISA pages, limited internally to 50)
        report_status["progress"] = "Scraping vulnerability sources..."
        scraped_data = fetch_scraped_cves(limit=50)
        print(f"🌐 Scraped {len(scraped_data)} sources")

        # ✅ Summarize API CVEs with AI
        report_status["progress"] = "Generating AI summaries..."
        summary = summarize_latest_cves(latest_cves)
        print("🤖 AI summary generated for API data")

        # ✅ Merge API + Scraped results
        combined = [summary] + [s["parsed"] for s in scraped_data]

        # ✅ Shuffle for fairness
        random.shuffle(combined)

        # ✅ Restrict report to 15 vulnerabilities
        combined = combined[:15]

        generate_report(combined)
        print("📝 Report file created")

        # ✅ Summarize if report is too long
        from parse import summarize_long_report
        with open(REPORT_FILE, "r", encoding="utf-8") as f:
            report_text = f.read()

        short_report = summarize_long_report(report_text, max_lines=300)

        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            f.write(short_report)

        print("✂️ Report summarized to max 300 lines")

        # ✅ Extract structured JSON for dashboard
        from parse import extract_cves_from_report
        with open(REPORT_FILE, "r", encoding="utf-8") as f:
            report_text = f.read()
        structured_data = extract_cves_from_report(report_text)

        import json
        from datetime import datetime
        dashboard_data = {
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "vulnerabilities": structured_data
        }

        with open("vulnerability_report.json", "w", encoding="utf-8") as f:
            json.dump(dashboard_data, f, indent=2)
        print("📊 JSON dashboard data created with timestamp")

        report_status["download_ready"] = True
        report_status["progress"] = "Done ✅"
        print("✅ Finished report task.")
    except Exception as e:
        print("❌ Error in task:", e)
        traceback.print_exc()
        report_status["error"] = str(e)
=======
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
    """Optimized report generation - scraping only"""
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

        # Step 1: Get URLs
        report_status["current_step"] = 1
        report_status["progress"] = "Fetching vulnerability sources..."
        urls = get_vulnerability_urls()
        print(f"📋 Found {len(urls)} sources to scrape")

        # Step 2: Scrape all sources
        report_status["current_step"] = 2
        report_status["progress"] = "Scraping vulnerability data..."
        scraped_data = []
        
        for idx, url in enumerate(urls):
            try:
                print(f"🌐 Scraping {url}...")
                report_status["progress"] = f"Scraping source {idx + 1}/{len(urls)}..."
                
                raw_text = scrape_content(url)
                if raw_text and len(raw_text.strip()) > 100:
                    scraped_data.append({
                        "source": url,
                        "content": raw_text
                    })
                    print(f"✅ Successfully scraped {url}")
                else:
                    print(f"⚠️ Empty or insufficient data from {url}")
                    
            except Exception as e:
                print(f"❌ Error scraping {url}: {e}")

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
>>>>>>> 5d6b5fa (Claude changes)
    finally:
        report_status["is_generating"] = False


<<<<<<< HEAD


=======
>>>>>>> 5d6b5fa (Claude changes)
@app.route('/')
def index():
    return render_template("index.html")


@app.route('/scan', methods=['POST'])
def scan():
    if not report_status["is_generating"]:
<<<<<<< HEAD
        print("🔄 Starting new background scan...")
        thread = threading.Thread(target=generate_report_task)
=======
        print("🔄 Starting new vulnerability scan...")
        thread = threading.Thread(target=generate_report_task, daemon=True)
>>>>>>> 5d6b5fa (Claude changes)
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


<<<<<<< HEAD
=======
@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")


@app.route('/mitigation')
def mitigation_page():
    return render_template("mitigation.html")


>>>>>>> 5d6b5fa (Claude changes)
@app.route('/get_report')
def get_report():
    if os.path.exists(REPORT_FILE):
        return send_file(REPORT_FILE, as_attachment=True)
    return "No report found", 404


<<<<<<< HEAD

# ... existing code ...

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/mitigation", methods=["GET"])
def mitigation_page():
    # Renders a simple chat-like page
    return render_template("mitigation.html")

@app.route("/api/mitigation", methods=["POST"])
def api_mitigation():
    from flask import request
    data = request.get_json()
    query = data.get("query", "")

    if not query.strip():
        return jsonify({"error": "No query provided"}), 400

    from parse import find_mitigation
    result = find_mitigation(query)

    return jsonify(result)



@app.route("/api/vulnerabilities")
def api_vulnerabilities():
    if not os.path.exists("vulnerability_report.json"):
        return jsonify({"error": "No JSON data available"}), 404

    import json
    with open("vulnerability_report.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    return jsonify(data)




# ------------------------------
# 🔹 NEW: Scraping + AI Parsing
# ------------------------------
def fetch_scraped_cves(limit=50):
    """
    Scrapes vulnerabilities from sources (NVD, CISA) and parses them with AI.
    Only keeps the first `limit` CVEs to avoid huge context.
    """
    urls = get_vulnerability_urls()
    all_results = []

    for url in urls:
        try:
            print(f"🌐 Scraping {url}...")
            raw_text = scrape_content(url)

            # ✅ Keep only lines mentioning CVEs
            lines = raw_text.splitlines()
            cve_lines = [line for line in lines if "CVE-" in line]

            # ✅ Limit to 50 CVEs max
            limited_text = "\n".join(cve_lines[:limit])

            # Fallback: if no CVE lines found, use truncated raw text
            if not limited_text.strip():
                limited_text = "\n".join(lines[:1000])  # cap to 1000 lines

            ai_parsed = parse_with_ai(limited_text)
            all_results.append({
                "source": url,
                "parsed": ai_parsed
            })
        except Exception as e:
            print(f"⚠️ Error scraping {url}: {e}")

    return all_results



@app.route("/ai_insights")
def ai_insights():
    latest_cves = fetch_latest_cves(limit=10)
    insights = generate_ai_insights(latest_cves)
    return jsonify({"insights": insights})




if __name__ == '__main__':
    app.run(debug=False, use_reloader=False)  # ⚡ Important on Windows
=======
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
>>>>>>> 5d6b5fa (Claude changes)
