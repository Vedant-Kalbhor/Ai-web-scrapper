import os
import requests
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")  # Store your key in .env

def _get_headers():
    """Helper function to add API key to headers if available"""
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def fetch_latest_cves(limit=50, days_back=7):
    """
    Fetch the latest CVEs from NVD API.
    Returns CVE list with id, description, severity, cvss_score, published, vendor, product.
    """
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    # Get last X days
    pub_start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    pub_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

    params = {
        "resultsPerPage": limit,
        "startIndex": 0,
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,   # <-- This was missing
    }

    response = requests.get(BASE_URL, headers=headers, params=params)
    response.raise_for_status()
    data = response.json()

    cves = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id")

        description = ""
        if cve_data.get("descriptions"):
            description = cve_data["descriptions"][0].get("value", "")

        metrics = cve_data.get("metrics", {})
        cvss_score, severity = None, None
        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = metric.get("baseScore")
            severity = metric.get("baseSeverity")

        published = cve_data.get("published", "")

        # Vendor/Product from CPE
        vendor, product = None, None
        configs = cve_data.get("configurations", {})

        # Sometimes it's a dict, sometimes a list
        if isinstance(configs, dict):
            nodes = configs.get("nodes", [])
        elif isinstance(configs, list):
            nodes = configs
        else:
            nodes = []

        for node in nodes:
            for match in node.get("cpeMatch", []):
                cpe_uri = match.get("criteria")
                if cpe_uri and cpe_uri.startswith("cpe:2.3:"):
                    parts = cpe_uri.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        break
            if vendor:
                break


        cves.append({
            "id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "published": published,
            "vendor": vendor,
            "product": product
        })

    return cves


def enrich_cve(cve_id):
    """
    Fetch detailed CVE information from NVD by CVE ID.
    """
    url = f"{BASE_URL}?cveId={cve_id}"
    response = requests.get(url, headers=_get_headers())
    
    if response.status_code != 200:
        return {"error": f"Failed to fetch CVE {cve_id}"}
    
    data = response.json()
    if not data.get("vulnerabilities"):
        return {"error": f"No data found for {cve_id}"}
    
    cve_data = data["vulnerabilities"][0]["cve"]
    description = cve_data.get("descriptions", [{}])[0].get("value", "No description")
    
    # CVSS scoring
    metrics = cve_data.get("metrics", {})
    cvss_score, severity = None, None
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]
        cvss_score = cvss.get("baseScore")
        severity = cvss.get("baseSeverity")
    
    references = [ref["url"] for ref in cve_data.get("references", [])]

    return {
        "id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "references": references
    }
