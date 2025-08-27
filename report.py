import re
from nvd import enrich_cve

def extract_cves(text):
    """
    Extract CVE IDs (e.g., CVE-2025-12345) from text.
    """
    return re.findall(r"CVE-\d{4}-\d{4,7}", text)

def generate_report(results):
    """
    Generate vulnerability report with NVD enrichment.
    """
    report_file = "vulnerability_report.txt"

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("🔒 Vulnerability Report\n")
        f.write("="*50 + "\n\n")

        for item in results:
            f.write("Raw Extract:\n")
            f.write(item + "\n\n")

            # Check for CVEs inside the parsed text
            cves = extract_cves(item)
            if cves:
                f.write("Enriched Data from NVD:\n")
                for cve in cves:
                    cve_data = enrich_cve(cve)
                    if "error" in cve_data:
                        f.write(f"- {cve}: {cve_data['error']}\n")
                    else:
                        f.write(f"- {cve}\n")
                        f.write(f"  Description: {cve_data['description']}\n")
                        f.write(f"  Severity: {cve_data.get('severity', 'N/A')}\n")
                        f.write(f"  CVSS Score: {cve_data.get('cvss_score', 'N/A')}\n")
                        f.write("  References:\n")
                        for ref in cve_data.get("references", []):
                            f.write(f"    - {ref}\n")
                    f.write("\n")
            f.write("-"*50 + "\n\n")

    return report_file
