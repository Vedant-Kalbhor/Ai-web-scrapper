import os
import threading
import traceback
from flask import Flask, render_template, redirect, url_for, jsonify, send_file
from scrape import get_vulnerability_urls, scrape_content
from parse import parse_with_ai, summarize_latest_cves
from report import generate_report
from nvd import fetch_latest_cves

app = Flask(__name__)

REPORT_FILE = "vulnerability_report.txt"
report_status = {
    "is_generating": False,
    "progress": None,
    "error": None,
    "download_ready": False
}


def generate_report_task():
    try:
        print("🚀 Starting report task...")
        report_status["is_generating"] = True
        report_status["error"] = None
        report_status["download_ready"] = False
        report_status["progress"] = "Fetching latest vulnerabilities from NVD..."

        if os.path.exists(REPORT_FILE):
            os.remove(REPORT_FILE)

        # ✅ Fetch top 10 latest CVEs
        latest_cves = fetch_latest_cves(limit=10)
        print(f"📥 Got {len(latest_cves)} CVEs from NVD")

        report_status["progress"] = "Generating summary report with AI..."
        summary = summarize_latest_cves(latest_cves)
        print("🤖 AI summary generated")

        generate_report([summary])
        print("📝 Report file created")

        report_status["download_ready"] = True
        report_status["progress"] = "Done ✅"
        print("✅ Finished report task.")
    except Exception as e:
        print("❌ Error in task:", e)
        traceback.print_exc()
        report_status["error"] = str(e)
    finally:
        report_status["is_generating"] = False


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/scan', methods=['POST'])
def scan():
    if not report_status["is_generating"]:
        print("🔄 Starting new background scan...")
        thread = threading.Thread(target=generate_report_task)
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


@app.route('/get_report')
def get_report():
    if os.path.exists(REPORT_FILE):
        return send_file(REPORT_FILE, as_attachment=True)
    return "No report found", 404



# ... existing code ...

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/vulnerabilities")
def api_vulnerabilities():
    # Fetch top 50 recent CVEs
    cves = fetch_latest_cves(limit=50)
    return jsonify(cves)



if __name__ == '__main__':
    app.run(debug=False, use_reloader=False)  # ⚡ Important on Windows
