from datetime import datetime, timezone


def generate_report(vulnerabilities):
    """
    Generate a formatted text report from vulnerability data.
    """
    report_file = "vulnerability_report.txt"
    
    with open(report_file, "w", encoding="utf-8") as f:
        # Header
        f.write("=" * 80 + "\n")
        f.write("🔒 VULNERABILITY SECURITY REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"Total Vulnerabilities: {len(vulnerabilities)}\n")
        f.write("=" * 80 + "\n\n")

        # Summary Statistics
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        f.write("📊 SEVERITY BREAKDOWN\n")
        f.write("-" * 80 + "\n")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNKNOWN": "⚪"}
                f.write(f"{emoji.get(severity, '⚪')} {severity}: {count}\n")
        f.write("\n" + "=" * 80 + "\n\n")

        # Detailed Vulnerability List
        f.write("📋 DETAILED VULNERABILITY INFORMATION\n")
        f.write("=" * 80 + "\n\n")

        for idx, vuln in enumerate(vulnerabilities, 1):
            f.write(f"[{idx}] {vuln.get('id', 'UNKNOWN')}\n")
            f.write("-" * 80 + "\n")
            
            f.write(f"Title: {vuln.get('title', 'No title')}\n\n")
            
            f.write(f"Severity: {vuln.get('severity', 'UNKNOWN')}")
            if vuln.get('cvss_score'):
                f.write(f" (CVSS: {vuln.get('cvss_score')})")
            f.write("\n\n")
            
            f.write("Description:\n")
            f.write(f"{vuln.get('description', 'No description available')}\n\n")
            
            if vuln.get('affected_products'):
                f.write("Affected Products:\n")
                for product in vuln.get('affected_products', []):
                    f.write(f"  • {product}\n")
                f.write("\n")
            
            f.write("Solution/Mitigation:\n")
            f.write(f"{vuln.get('solution', 'Check vendor advisory')}\n\n")
            
            if vuln.get('published_date'):
                f.write(f"Published: {vuln.get('published_date')}\n")
            
            f.write(f"Source: {vuln.get('source', 'Unknown')}\n")
            
            f.write("\n" + "=" * 80 + "\n\n")

        # Footer
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")
        f.write("\n⚠️  DISCLAIMER: This report is generated from publicly available sources.\n")
        f.write("Always verify vulnerabilities through official vendor advisories.\n")

    return report_file


