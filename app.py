from flask import Flask, render_template, redirect, url_for, send_file
from scrape import get_vulnerability_urls, scrape_content
from parse import parse_with_ai
from report import generate_report
import time

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/scan', methods=['POST'])
def scan():
    # Redirect user to scanning page while backend runs
    return redirect(url_for("scanning"))

@app.route('/scanning')
def scanning():
    try:
        urls = get_vulnerability_urls()
        results = []

        for url in urls:
            content = scrape_content(url)
            if content:
                parsed = parse_with_ai(content)
                results.append(parsed)

        generate_report(results)

        # Once done → redirect to download page
        return redirect(url_for("download_page"))

    except Exception as e:
        return render_template("index.html", error=str(e))

@app.route('/download')
def download_page():
    return render_template("index.html", download_ready=True)

@app.route('/get_report')
def get_report():
    return send_file("vulnerability_report.txt", as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
