import os
import re
import requests
from dotenv import load_dotenv
from datetime import datetime
import time

load_dotenv()

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

def _get_headers():
    """Helper function to add API key to headers if available"""
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def extract_cve_ids_from_text(text):
    """
    Extract all CVE IDs from text using regex.
    Returns a list of unique CVE IDs.
    """
    pattern = r'CVE-\d{4}-\d{4,7}'
    cve_ids = re.findall(pattern, text.upper())
    return list(set(cve_ids))


def fetch_cve_from_nvd(cve_id):
    """
    Fetch detailed CVE information from NVD API by CVE ID.
    Returns enriched vulnerability dict or None if not found.
    """
    try:
        url = f"{BASE_URL}?cveId={cve_id}"
        headers = _get_headers()
        
        print(f"  → Querying NVD for: {cve_id}")
        response = requests.get(url, headers=headers, timeout=10)
        
        # Rate limiting: NVD allows 5 requests per 30 seconds without API key
        # With API key: 50 requests per 30 seconds
        if not NVD_API_KEY:
            time.sleep(6)  # Wait 6 seconds between requests
        else:
            time.sleep(0.6)  # Wait 0.6 seconds with API key
        
        if response.status_code != 200:
            print(f"  ✗ NVD returned status {response.status_code} for {cve_id}")
            return None
        
        data = response.json()
        
        if not data.get("vulnerabilities"):
            print(f"  ✗ No data found in NVD for {cve_id}")
            return None
        
        cve_data = data["vulnerabilities"][0]["cve"]
        
        # Extract description
        description = "No description available"
        if cve_data.get("descriptions"):
            for desc in cve_data["descriptions"]:
                if desc.get("lang") == "en":
                    description = desc.get("value", description)
                    break
        
        # Extract CVSS metrics
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"
        
        # Try CVSS v3.1 first, then v3.0, then v2.0
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity", "UNKNOWN").upper()
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity", "UNKNOWN").upper()
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = cvss.get("baseScore")
            # Map v2 score to severity
            if cvss_score:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
        
        # Extract affected products from CPE configurations
        affected_products = []
        configurations = cve_data.get("configurations", [])
        
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for match in cpe_matches:
                    cpe_uri = match.get("criteria", "")
                    if cpe_uri and cpe_uri.startswith("cpe:2.3:"):
                        parts = cpe_uri.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3].replace("_", " ").title()
                            product = parts[4].replace("_", " ").title()
                            version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                            
                            product_str = f"{vendor} {product}"
                            if version and version != "*":
                                product_str += f" {version}"
                            
                            if product_str not in affected_products:
                                affected_products.append(product_str)
        
        # Extract references
        references = []
        for ref in cve_data.get("references", []):
            ref_url = ref.get("url")
            if ref_url:
                references.append(ref_url)
        
        # Get published date
        published_date = cve_data.get("published", "")
        if published_date:
            try:
                published_date = datetime.fromisoformat(published_date.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            except:
                pass
        
        # Generate title from description
        title = description.split(".")[0][:100] if description else f"Vulnerability in {affected_products[0] if affected_products else 'Unknown Product'}"
        
        # Generate solution
        solution = "Apply security patches from the vendor"
        if references:
            solution += f". See: {references[0]}"
        
        enriched_vuln = {
            "id": cve_id,
            "title": title,
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score,
            "affected_products": affected_products[:10],  # Limit to 10
            "solution": solution,
            "published_date": published_date,
            "source": "NVD Database (Enriched)",
            "references": references[:5]  # Limit to 5 references
        }
        
        print(f"  ✓ Successfully enriched {cve_id} from NVD")
        return enriched_vuln
        
    except requests.exceptions.Timeout:
        print(f"  ✗ Timeout while querying NVD for {cve_id}")
        return None
    except Exception as e:
        print(f"  ✗ Error fetching {cve_id} from NVD: {e}")
        return None


def enrich_unknown_vulnerabilities(vulnerabilities, max_enrich=50):
    """
    Process a list of vulnerabilities and enrich "UNKNOWN" ones using NVD API.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        max_enrich: Maximum number of unknown CVEs to enrich (to avoid rate limits)
    
    Returns:
        Tuple of (enriched_list, stats_dict)
    """
    print("\n" + "="*60)
    print("🔍 CVE ENRICHMENT SERVICE")
    print("="*60)
    
    unknown_vulns = []
    known_vulns = []
    cve_ids_to_fetch = []
    
    # Separate unknown and known vulnerabilities
    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", "")
        severity = vuln.get("severity", "").upper()
        
        # Check if it's unknown
        is_unknown = (
            severity == "UNKNOWN" or
            vuln_id.startswith("VULN-") or
            not vuln_id.startswith("CVE-") or
            vuln.get("title", "").lower().startswith("unknown")
        )
        
        if is_unknown:
            # Try to extract CVE ID from any field or fallback text
            combined_text = " ".join([
                vuln.get("id", ""),
                vuln.get("title", ""),
                vuln.get("description", ""),
                vuln.get("source", "")
            ])
            extracted_cves = extract_cve_ids_from_text(combined_text)

            # Fallback: check if "CVE-" prefix exists in scraped raw data (AI sometimes keeps lowercase)
            if not extracted_cves and "cve-" in combined_text.lower():
                extracted_cves = extract_cve_ids_from_text(combined_text.upper())

            # Fallback 2: try regex in description for “2025-” pattern
            if not extracted_cves:
                year_match = re.findall(r"20\d{2}-\d{3,7}", combined_text)
                if year_match:
                    extracted_cves = [f"CVE-{year_match[0]}"]

            if extracted_cves:
                cve_id = extracted_cves[0]
                vuln["id"] = cve_id
                cve_ids_to_fetch.append((vuln, cve_id))
            else:
                unknown_vulns.append(vuln)

    
    print(f"📊 Initial Analysis:")
    print(f"  ✓ Known vulnerabilities: {len(known_vulns)}")
    print(f"  ⚠️  Unknown vulnerabilities: {len(unknown_vulns)}")
    print(f"  🔎 CVEs to enrich from NVD: {len(cve_ids_to_fetch)}")
    
    # Limit enrichment to avoid rate limits
    if len(cve_ids_to_fetch) > max_enrich:
        print(f"\n⚠️  Limiting enrichment to {max_enrich} CVEs to respect NVD rate limits")
        cve_ids_to_fetch = cve_ids_to_fetch[:max_enrich]
    
    # Enrich vulnerabilities from NVD
    enriched_count = 0
    failed_count = 0
    
    if cve_ids_to_fetch:
        print(f"\n🔄 Enriching {len(cve_ids_to_fetch)} vulnerabilities from NVD API...")
        
        for original_vuln, cve_id in cve_ids_to_fetch:
            enriched = fetch_cve_from_nvd(cve_id)
            
            if enriched:
                # Preserve original source information
                enriched["original_source"] = original_vuln.get("source")
                known_vulns.append(enriched)
                enriched_count += 1
            else:
                # Keep original if enrichment failed
                unknown_vulns.append(original_vuln)
                failed_count += 1
    
    # Combine all vulnerabilities
    all_vulnerabilities = known_vulns + unknown_vulns
    
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_vulnerabilities.sort(key=lambda x: severity_order.get(x.get("severity", "UNKNOWN").upper(), 5))
    
    # Statistics
    stats = {
        "total_vulnerabilities": len(all_vulnerabilities),
        "enriched_from_nvd": enriched_count,
        "failed_enrichment": failed_count,
        "remaining_unknown": len(unknown_vulns),
        "known_vulnerabilities": len(known_vulns),
        "enrichment_rate": f"{(enriched_count / max(len(cve_ids_to_fetch), 1) * 100):.1f}%" if cve_ids_to_fetch else "0%"
    }
    
    print(f"\n✅ Enrichment Complete!")
    print(f"  ✓ Successfully enriched: {enriched_count}")
    print(f"  ✗ Failed to enrich: {failed_count}")
    print(f"  ⚠️  Still unknown: {len(unknown_vulns)}")
    print(f"  📈 Enrichment rate: {stats['enrichment_rate']}")
    print("="*60 + "\n")
    
    return all_vulnerabilities, stats


def enrich_vulnerability_batch(cve_ids, max_cves=50):
    """
    Batch enrichment for a list of CVE IDs.
    Useful for processing multiple CVEs at once.
    
    Args:
        cve_ids: List of CVE ID strings
        max_cves: Maximum number to process
    
    Returns:
        List of enriched vulnerability dictionaries
    """
    # Remove duplicates and limit
    unique_cves = list(set(cve_ids))[:max_cves]
    
    print(f"\n🔄 Batch enriching {len(unique_cves)} CVEs from NVD...")
    
    enriched_vulns = []
    
    for cve_id in unique_cves:
        enriched = fetch_cve_from_nvd(cve_id)
        if enriched:
            enriched_vulns.append(enriched)
    
    print(f"✓ Enriched {len(enriched_vulns)}/{len(unique_cves)} CVEs")
    
    return enriched_vulns
