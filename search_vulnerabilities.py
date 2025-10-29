"""
AI-Powered Vulnerability Search Module
Searches for recent vulnerabilities using Gemini's native web search capabilities
"""

import os
import json
import re
from datetime import datetime, timedelta
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import requests
from bs4 import BeautifulSoup

load_dotenv()

def create_search_agent():
    """Creates Gemini LLM with grounding (web search) enabled"""
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash-exp",
        temperature=0.2,
        google_api_key=os.getenv("GOOGLE_API_KEY"),
        # Enable Google Search grounding via model_kwargs
        model_kwargs={
            "tools": [{
                "google_search_retrieval": {}
            }]
        }
    )
    return llm


def search_vulnerabilities_with_ai(query: str) -> dict:
    """
    Search for recent vulnerabilities using Gemini with built-in web search.
    Gemini 2.0 has native grounding that searches the web automatically.
    
    Args:
        query: Software name or organization name
        
    Returns:
        Dictionary with vulnerabilities found
    """
    try:
        print(f"🔍 Searching for vulnerabilities related to: {query}")
        
        # Get current date for filtering
        from datetime import datetime, timedelta
        current_year = datetime.now().year
        current_month = datetime.now().month
        last_3_months = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")
        
        llm = create_search_agent()
        
        # Create a detailed search prompt that will trigger web search
        search_prompt = f"""Search the web RIGHT NOW for the MOST RECENT vulnerabilities (CVEs) related to: "{query}"

CRITICAL TEMPORAL REQUIREMENTS:
- TODAY'S DATE: {datetime.now().strftime("%Y-%m-%d")}
- ONLY search for CVEs from: {current_year} or late {current_year-1}
- Focus on vulnerabilities disclosed in the last 3-6 months (after {last_3_months})
- Prioritize CVEs from the past 30-90 days
- IGNORE anything older than {current_year-1}

SEARCH STRATEGY:
1. Search for: "{query} CVE {current_year}"
2. Search for: "{query} vulnerability {current_year}"
3. Search for: "{query} security advisory {current_year}"
4. Check CISA KEV catalog for recent additions
5. Check NVD recent vulnerabilities page
6. Check vendor security bulletins from last 3 months

WHAT TO LOOK FOR:
- CVE-{current_year}-XXXXX or CVE-{current_year-1}-XXXXX (recent ones only)
- Vulnerabilities with "Published: {current_year}" or "Updated: {current_year}"
- Security advisories from Q3-Q4 {current_year-1} or Q1-Q4 {current_year}
- Active exploits or zero-days currently being exploited
- Critical/High severity issues that need immediate patching

SOURCES TO CHECK (via web search):
- https://nvd.nist.gov/vuln/search (filter by recent)
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Vendor security advisories (Microsoft, Oracle, Adobe, etc.)
- Security news sites (BleepingComputer, SecurityWeek, etc.)

For EACH recent vulnerability you find, extract:
- CVE ID (must be CVE-{current_year}-XXXXX or CVE-{current_year-1}-XXXXX from last 6 months)
- Vulnerability Title/Name (clear, descriptive)
- Severity Level (CRITICAL/HIGH/MEDIUM/LOW based on CVSS)
- CVSS Score (numeric, e.g., 9.8) or null if not available
- Brief Description (2-3 sentences, focus on impact and attack vector)
- Affected Product/Version (be specific with version numbers)
- Date Disclosed (must be in format YYYY-MM-DD and within last 6 months)
- Exploitation Status (e.g., "Actively exploited in wild", "PoC available", "Proof-of-concept published")
- Source URL (the authoritative webpage you found this on)

FILTERING RULES:
❌ REJECT any CVE older than {current_year-1}
❌ REJECT vulnerabilities disclosed before {last_3_months}
❌ REJECT if date is missing or unclear
✅ ACCEPT only if clearly recent (2024-2025)
✅ ACCEPT if marked as "actively exploited" regardless of age (but note it)

Return your findings as a JSON array with this exact structure:
[
  {{
    "cve_id": "CVE-{current_year}-12345",
    "title": "Remote Code Execution in Apache Struts",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "description": "A critical remote code execution vulnerability exists in Apache Struts 2.x versions prior to 2.5.33. Attackers can execute arbitrary code by sending specially crafted requests. This vulnerability is being actively exploited.",
    "affected_product": "Apache Struts 2.0.0 - 2.5.32",
    "date_disclosed": "{current_year}-12-15",
    "exploitation_status": "Actively exploited in the wild - patch immediately",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-{current_year}-12345"
  }}
]

CRITICAL OUTPUT RULES:
1. Return ONLY the JSON array - no markdown code blocks, no extra text
2. ONLY include vulnerabilities from {current_year} or late {current_year-1}
3. Verify dates are recent (last 3-6 months preferred)
4. If you find fewer recent vulns, return what you found (don't pad with old data)
5. Ensure all JSON is properly formatted
6. All string values must use double quotes, not single quotes
7. Sort by date_disclosed (newest first)

Remember: Users want CURRENT threats, not historical data. Focus on what's happening NOW."""

        print("⏳ Invoking Gemini with web search grounding...")
        
        # Invoke the LLM - it will automatically search the web
        response = llm.invoke(search_prompt)
        
        # Extract content
        content = response.content.strip()
        print(f"📥 Received response ({len(content)} characters)")
        
        # Clean up the response
        content = clean_json_response(content)
        
        try:
            vulnerabilities = json.loads(content)
            
            # Validate it's a list
            if not isinstance(vulnerabilities, list):
                print("⚠️ Response is not a list, wrapping it")
                vulnerabilities = [vulnerabilities] if isinstance(vulnerabilities, dict) else []
            
            # Validate and clean each vulnerability entry
            vulnerabilities = [validate_vulnerability(v) for v in vulnerabilities if validate_vulnerability(v)]
            
            # Sort by date (newest first)
            def get_sort_date(vuln):
                date_str = vuln.get("date_disclosed", "")
                if not date_str or date_str in ["Unknown", "Recent"]:
                    return datetime.min
                try:
                    for fmt in ["%Y-%m-%d", "%Y/%m/%d"]:
                        try:
                            return datetime.strptime(date_str, fmt)
                        except ValueError:
                            continue
                    return datetime.min
                except:
                    return datetime.min
            
            vulnerabilities.sort(key=get_sort_date, reverse=True)
            
            print(f"✅ Successfully parsed {len(vulnerabilities)} RECENT vulnerabilities")
            
            # Add warning if no recent vulnerabilities found
            if len(vulnerabilities) == 0:
                print(f"⚠️  No recent vulnerabilities found for '{query}'")
                print(f"    Try: Checking if the software name is correct")
                print(f"    Try: Searching for a more specific product name")
            
            return {
                "success": True,
                "query": query,
                "total_found": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "filter_applied": f"Last 6 months + {current_year}/{current_year-1} CVEs only"
            }
            
        except json.JSONDecodeError as e:
            print(f"❌ JSON parsing failed: {e}")
            print(f"Response preview: {content[:500]}")
            
            # Fallback: try to extract structured data from text
            vulnerabilities = extract_vulns_from_text(content, query)
            
            return {
                "success": True if vulnerabilities else False,
                "query": query,
                "total_found": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "note": "Data extracted from text format"
            }
        
    except Exception as e:
        print(f"❌ Error in search: {e}")
        import traceback
        traceback.print_exc()
        
        return {
            "success": False,
            "error": str(e),
            "query": query,
            "vulnerabilities": [],
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        }


def clean_json_response(content: str) -> str:
    """Clean up LLM response to extract pure JSON"""
    # Remove markdown code blocks
    content = re.sub(r'```json\s*', '', content)
    content = re.sub(r'```\s*', '', content)
    
    # Remove any leading/trailing text before/after JSON array
    # Find the first [ and last ]
    start_idx = content.find('[')
    end_idx = content.rfind(']')
    
    if start_idx != -1 and end_idx != -1:
        content = content[start_idx:end_idx+1]
    
    return content.strip()


def validate_vulnerability(vuln: dict) -> dict:
    """Validate and clean a vulnerability dictionary"""
    if not isinstance(vuln, dict):
        return None
    
    # Get current date for validation
    from datetime import datetime, timedelta
    current_year = datetime.now().year
    cutoff_date = datetime.now() - timedelta(days=180)  # 6 months ago
    
    # Ensure required fields exist with defaults
    cleaned = {
        "cve_id": str(vuln.get("cve_id", "")).strip() or "N/A",
        "title": str(vuln.get("title", "")).strip() or "Unknown Vulnerability",
        "severity": str(vuln.get("severity", "UNKNOWN")).upper(),
        "cvss_score": vuln.get("cvss_score"),
        "description": str(vuln.get("description", "")).strip() or "No description available",
        "affected_product": str(vuln.get("affected_product", "")).strip() or "Unknown",
        "date_disclosed": str(vuln.get("date_disclosed", "")).strip() or "Unknown",
        "exploitation_status": str(vuln.get("exploitation_status", "")).strip() or "Unknown",
        "source_url": str(vuln.get("source_url", "")).strip() or None
    }
    
    # ✅ DATE VALIDATION - Filter out old vulnerabilities
    date_str = cleaned["date_disclosed"]
    is_recent = False
    
    if date_str and date_str != "Unknown" and date_str != "Recent":
        # Try to parse the date
        try:
            # Handle various date formats
            for fmt in ["%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%m/%d/%Y"]:
                try:
                    vuln_date = datetime.strptime(date_str, fmt)
                    # Check if date is within last 6 months OR from current year
                    if vuln_date >= cutoff_date or vuln_date.year >= current_year - 1:
                        is_recent = True
                    break
                except ValueError:
                    continue
        except Exception:
            pass
    
    # Also check CVE ID year
    cve_match = re.match(r'CVE-(\d{4})-\d+', cleaned["cve_id"])
    if cve_match:
        cve_year = int(cve_match.group(1))
        # Accept CVEs from current year or previous year only
        if cve_year >= current_year - 1:
            is_recent = True
    
    # If marked as "actively exploited" or "zero-day", always include
    if "actively exploited" in cleaned["exploitation_status"].lower() or \
       "zero-day" in cleaned["exploitation_status"].lower() or \
       "0-day" in cleaned["exploitation_status"].lower():
        is_recent = True
    
    # ❌ REJECT old vulnerabilities
    if not is_recent:
        print(f"⏭️  Skipping old vulnerability: {cleaned['cve_id']} (Date: {date_str})")
        return None
    
    # Validate severity
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    if cleaned["severity"] not in valid_severities:
        cleaned["severity"] = "UNKNOWN"
    
    # Validate CVSS score
    if cleaned["cvss_score"] is not None:
        try:
            score = float(cleaned["cvss_score"])
            if 0 <= score <= 10:
                cleaned["cvss_score"] = score
            else:
                cleaned["cvss_score"] = None
        except (ValueError, TypeError):
            cleaned["cvss_score"] = None
    
    print(f"✅ Validated recent vulnerability: {cleaned['cve_id']} ({cleaned['date_disclosed']})")
    return cleaned


def extract_vulns_from_text(text: str, query: str) -> list:
    """
    Fallback: Extract vulnerability information from unstructured text
    """
    vulnerabilities = []
    
    # Try to find CVE IDs in the text
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cve_ids = re.findall(cve_pattern, text)
    
    if cve_ids:
        print(f"📋 Found {len(cve_ids)} CVE IDs in text, creating entries...")
        
        for cve_id in cve_ids[:10]:  # Limit to 10
            # Try to extract context around this CVE
            pattern = rf'{cve_id}[^.]*\.(?:[^.]*\.)?(?:[^.]*\.)?'
            match = re.search(pattern, text)
            description = match.group(0) if match else f"Vulnerability {cve_id} found in {query}"
            
            vulnerabilities.append({
                "cve_id": cve_id,
                "title": f"Vulnerability in {query}",
                "severity": "UNKNOWN",
                "cvss_score": None,
                "description": description[:300],
                "affected_product": query,
                "date_disclosed": "Recent",
                "exploitation_status": "Unknown",
                "source_url": None
            })
    else:
        # Create a single generic entry with the text
        vulnerabilities.append({
            "cve_id": "N/A",
            "title": f"Recent vulnerabilities for {query}",
            "severity": "UNKNOWN",
            "cvss_score": None,
            "description": text[:500] + "..." if len(text) > 500 else text,
            "affected_product": query,
            "date_disclosed": "Recent",
            "exploitation_status": "Unknown",
            "source_url": None
        })
    
    return vulnerabilities


def search_vulnerability_details(cve_id: str) -> dict:
    """
    Get detailed information about a specific CVE using web scraping
    Falls back to NVD and CISA if web search fails
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
        
    Returns:
        Detailed vulnerability information
    """
    try:
        print(f"🔍 Fetching details for {cve_id}")
        
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith("CVE-"):
            return {
                "success": False,
                "error": "Invalid CVE ID format",
                "cve_id": cve_id
            }
        
        llm = create_search_agent()
        
        prompt = f"""Search the web for detailed information about {cve_id}.

Use web search to find authoritative information from NVD, CISA, or vendor advisories.

Provide a comprehensive summary including:
1. Full vulnerability description (2-3 paragraphs)
2. Technical details (attack vector, complexity, privileges required)
3. Impact assessment (what can an attacker do?)
4. Known exploits or proof-of-concepts
5. Affected software versions
6. Mitigation steps and patches available
7. CVSS score and severity rating
8. References and advisory URLs

Format your response as clear, well-structured text with sections.
Be thorough but concise. Include specific version numbers and patch information."""

        print("⏳ Searching web for CVE details...")
        response = llm.invoke(prompt)
        
        details = response.content.strip()
        
        # Try to extract structured data
        result = {
            "success": True,
            "cve_id": cve_id,
            "details": details,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        }
        
        # Try to extract CVSS score
        cvss_match = re.search(r'CVSS[:\s]+([0-9]\.[0-9])', details, re.IGNORECASE)
        if cvss_match:
            result["cvss_score"] = float(cvss_match.group(1))
        
        # Try to extract severity
        severity_match = re.search(r'(CRITICAL|HIGH|MEDIUM|LOW)', details, re.IGNORECASE)
        if severity_match:
            result["severity"] = severity_match.group(1).upper()
        
        print(f"✅ Retrieved details for {cve_id}")
        return result
        
    except Exception as e:
        print(f"❌ Error fetching CVE details: {e}")
        
        # Fallback: try direct NVD scraping
        try:
            print("🔄 Attempting fallback NVD scraping...")
            return scrape_nvd_details(cve_id)
        except:
            return {
                "success": False,
                "error": str(e),
                "cve_id": cve_id,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            }


def scrape_nvd_details(cve_id: str) -> dict:
    """
    Fallback: Scrape NVD directly for CVE details
    """
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract description
        desc_tag = soup.find('p', {'data-testid': 'vuln-description'})
        description = desc_tag.get_text(strip=True) if desc_tag else "No description available"
        
        # Extract CVSS score
        cvss_tag = soup.find('a', {'data-testid': 'vuln-cvss3-link'})
        cvss_score = None
        if cvss_tag:
            score_text = cvss_tag.get_text(strip=True)
            cvss_match = re.search(r'([0-9]\.[0-9])', score_text)
            if cvss_match:
                cvss_score = float(cvss_match.group(1))
        
        # Extract severity
        severity_tag = soup.find('span', {'data-testid': 'vuln-cvss3-severity-badge'})
        severity = severity_tag.get_text(strip=True).upper() if severity_tag else "UNKNOWN"
        
        details = f"""**{cve_id} Details**

**Description:**
{description}

**CVSS Score:** {cvss_score or 'N/A'}
**Severity:** {severity}

**Source:** {url}

For complete details including references and patches, visit the NVD page."""
        
        return {
            "success": True,
            "cve_id": cve_id,
            "details": details,
            "cvss_score": cvss_score,
            "severity": severity,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        }
        
    except Exception as e:
        print(f"❌ NVD scraping failed: {e}")
        raise


# Test function
if __name__ == "__main__":
    # Test search
    print("\n" + "="*50)
    print("Testing Vulnerability Search")
    print("="*50)
    
    test_query = "Apache HTTP Server"
    results = search_vulnerabilities_with_ai(test_query)
    
    print(f"\nQuery: {results.get('query')}")
    print(f"Success: {results.get('success')}")
    print(f"Total Found: {results.get('total_found')}")
    
    if results.get('vulnerabilities'):
        print("\nFirst vulnerability:")
        print(json.dumps(results['vulnerabilities'][0], indent=2))
    
    # Test CVE details
    print("\n" + "="*50)
    print("Testing CVE Details Lookup")
    print("="*50)
    
    test_cve = "CVE-2024-21413"
    details = search_vulnerability_details(test_cve)
    
    print(f"\nCVE: {details.get('cve_id')}")
    print(f"Success: {details.get('success')}")
    if details.get('details'):
        print(f"\nDetails preview:\n{details['details'][:300]}...")