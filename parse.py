from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.prompts import PromptTemplate
import os
import json
import re
from dotenv import load_dotenv

load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    google_api_key=GOOGLE_API_KEY,
    temperature=0.3
)


def parse_vulnerabilities_with_ai(text, source_url):
    """
    Parse scraped vulnerability text into structured data using AI.
    Returns a list of vulnerability dictionaries.
    """
    # Limit text size to prevent token overflow
    lines = text.splitlines()
    
    # Prioritize lines with CVE mentions
    cve_lines = [line for line in lines if re.search(r'CVE-\d{4}-\d{4,7}', line)]
    other_lines = [line for line in lines if line not in cve_lines]
    
    # Combine: CVE lines first, then fill with other content
    limited_lines = (cve_lines[:100] + other_lines[:100])[:200]

    limited_text = "\n".join(limited_lines)
    if len(limited_text) > 100000:
        limited_text = limited_text[:100000]
    prompt = f"""You are a cybersecurity analyst. Extract ALL vulnerabilities from the following text.

Text:
{limited_text}

Return a JSON array where each object has:
- id: CVE ID (e.g., "CVE-2025-1234") or generate a unique ID like "VULN-001" if no CVE
- title: Short vulnerability name/title
- description: Clear description (2-3 sentences max)
- severity: One of [CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN]
- cvss_score: Numeric score if available, otherwise null
- affected_products: Array of affected products/vendors
- solution: Mitigation steps or patch info
- published_date: Date if available, otherwise null
- source: "{source_url}"

Rules:
1. Extract at least 10 vulnerabilities if available in the text
2. Be thorough but concise
3. If no CVE ID exists, create a descriptive ID
4. Infer severity from description if not explicitly stated
5. Return ONLY valid JSON array, no markdown or explanations

Example:
[
  {{
    "id": "CVE-2025-1234",
    "title": "Apache HTTP Server Buffer Overflow",
    "description": "Critical buffer overflow in Apache HTTP Server versions 2.4.x allows remote code execution.",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "affected_products": ["Apache HTTP Server 2.4.x"],
    "solution": "Update to Apache HTTP Server 2.4.59 or later",
    "published_date": "2025-01-15",
    "source": "{source_url}"
  }}
]
"""

    try:
        response = llm.invoke(prompt)
        content = response.content.strip()
        
        # Clean markdown formatting
        content = content.replace("```json", "").replace("```", "").strip()
        
        vulnerabilities = json.loads(content)
        
        # Validate structure
        if not isinstance(vulnerabilities, list):
            vulnerabilities = [vulnerabilities]
        
        # Ensure all required fields exist
        for vuln in vulnerabilities:
            vuln.setdefault("id", "VULN-UNKNOWN")
            vuln.setdefault("title", "Unknown Vulnerability")
            vuln.setdefault("description", "No description available")
            vuln.setdefault("severity", "UNKNOWN")
            vuln.setdefault("cvss_score", None)
            vuln.setdefault("affected_products", [])
            vuln.setdefault("solution", "Check vendor advisory")
            vuln.setdefault("published_date", None)
            vuln.setdefault("source", source_url)
        
        print(f"✅ Parsed {len(vulnerabilities)} vulnerabilities from {source_url}")
        return vulnerabilities
        
    except json.JSONDecodeError as e:
        print(f"⚠️ JSON parsing error: {e}")
        print(f"Response content: {content[:500]}")
        return []
    except Exception as e:
        print(f"❌ Error parsing vulnerabilities: {e}")
        return []


def generate_ai_insights(vulnerabilities):
    """
    Generate strategic insights from vulnerability data.
    """
    if not vulnerabilities:
        return "No vulnerability data available for analysis."

    # Prepare summary data
    severity_counts = {}
    affected_vendors = set()
    critical_vulns = []

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "UNKNOWN").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for product in vuln.get("affected_products", []):
            if product:
                affected_vendors.add(product.split()[0])
        
        if severity in ["CRITICAL", "HIGH"]:
            critical_vulns.append(vuln)

    summary = f"""
Analyzed {len(vulnerabilities)} vulnerabilities:
- Severity breakdown: {severity_counts}
- Critical/High severity: {len(critical_vulns)}
- Affected vendors: {', '.join(list(affected_vendors)[:10])}

Top critical vulnerabilities:
"""
    for vuln in critical_vulns[:5]:
        summary += f"\n- {vuln.get('id')}: {vuln.get('title')}"

    prompt = f"""You are a cybersecurity strategist. Based on this vulnerability data, provide:

{summary}

Generate a professional security advisory with:
1. **Threat Landscape Overview** (2-3 sentences on emerging threats)
2. **Priority Actions** (Top 3 immediate steps organizations should take)
3. **Sector Impact** (Which industries are most affected)
4. **Remediation Strategy** (General patching/mitigation approach)

Keep it under 250 words, professional, and actionable.
"""

    try:
        response = llm.invoke(prompt)
        return response.content
    except Exception as e:
        print(f"⚠️ Error generating insights: {e}")
        return "Unable to generate AI insights at this time."


def find_mitigation(query):
    """
    Find mitigation strategies for a specific vulnerability.
    """
    prompt = f"""You are a cybersecurity expert. A user asks about:

"{query}"

Provide detailed mitigation guidance as valid JSON:
{{
  "vulnerability": "<CVE ID or vulnerability name>",
  "summary": "<brief 2-sentence description>",
  "severity": "<CRITICAL/HIGH/MEDIUM/LOW>",
  "mitigation": "<detailed step-by-step mitigation with specific commands/patches>",
  "references": ["<official advisory URL>", "<vendor patch page>"]
}}

Rules:
1. Be specific with patch versions, commands, configuration changes
2. Include both immediate workarounds and long-term fixes
3. Provide real, authoritative reference URLs
4. If you don't have specific info, provide general best practices
5. Return ONLY valid JSON, no markdown

Example:
{{
  "vulnerability": "CVE-2025-1234",
  "summary": "Remote code execution in Apache HTTP Server due to buffer overflow in mod_proxy.",
  "severity": "CRITICAL",
  "mitigation": "1. Immediately update to Apache 2.4.59 or later\\n2. If update not possible, disable mod_proxy module\\n3. Apply WAF rules to block exploit patterns\\n4. Monitor logs for suspicious activity",
  "references": [
    "https://httpd.apache.org/security/vulnerabilities_24.html",
    "https://nvd.nist.gov/vuln/detail/CVE-2025-1234"
  ]
}}
"""

    try:
        response = llm.invoke(prompt)
        content = response.content.strip()
        content = content.replace("```json", "").replace("```", "").strip()
        
        result = json.loads(content)
        return result
    except json.JSONDecodeError:
        # Fallback format
        return {
            "vulnerability": query,
            "summary": "Unable to parse AI response",
            "severity": "UNKNOWN",
            "mitigation": response.content if 'response' in locals() else "Error generating mitigation",
            "references": []
        }
    except Exception as e:
        return {
            "error": f"Failed to generate mitigation: {str(e)}"
        }
    
    