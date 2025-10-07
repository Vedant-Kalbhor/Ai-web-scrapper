from langchain_google_genai import ChatGoogleGenerativeAI
import os
from dotenv import load_dotenv
import json 

load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", google_api_key=GOOGLE_API_KEY)

def parse_with_ai(text):
    """
    Old function: still here for compatibility with scraping workflow
    """
    prompt = f"""
    Extract cybersecurity vulnerabilities and their solutions from the text below. 
    Return results in this format:

    Vulnerability: <name or CVE>
    Description: <short explanation>
    Solution: <fix/patch/mitigation>

    Text: {text}
    """
    response = llm.invoke(prompt)
    return response.content

from langchain.prompts import PromptTemplate

def extract_cves_from_report(report_text):
    """
    Parse AI-generated vulnerability report into structured JSON
    for use in dashboards.
    """
    prompt = f"""
    You are a parser. From the following vulnerability report, 
    extract all vulnerabilities in strict JSON format with these fields:

    - id (CVE or placeholder if missing)
    - description
    - severity (High/Medium/Low/Unknown)
    - cvss_score (number or null)
    - solution

    Report:
    {report_text}

    Return only valid JSON (a list of objects).
    """

    response = llm.invoke(prompt)

    # ⚠️ Ensure result is JSON
    import json
    try:
        return json.loads(response.content)
    except:
        # fallback: try to clean
        text = response.content.strip().strip("```json").strip("```")
        return json.loads(text)

def find_mitigation(query):
    """
    Given a CVE ID or vulnerability description,
    use AI to return structured mitigation advice as JSON.
    """
    prompt = f"""
    You are a cybersecurity analyst. A user is asking about mitigation for:

    "{query}"

    Return a valid JSON object with these fields:
    {{
      "vulnerability": "<CVE ID or name>",
      "summary": "<short description>",
      "mitigation": "<clear steps to fix/patch/mitigate>",
      "references": ["<link1>", "<link2>"]
    }}

    Only output valid JSON. No markdown, no explanations.
    """

    response = llm.invoke(prompt)

    # Try to parse AI output as JSON
    try:
        return json.loads(response.content)
    except:
        # cleanup if AI accidentally wraps in ```json ... ```
        text = response.content.strip().strip("```json").strip("```").strip()
        return json.loads(text)


def generate_ai_insights(cves):
    """
    Uses Gemini to analyze CVE list and generate security insights + recommendations.
    """
    llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash")

    template = """
    You are a cybersecurity analyst. Based on the following CVEs:
    {cves}

    Provide:
    1. A concise summary of recent trends (vendors, severity, attack vectors).
    2. Key security risks that stand out.
    3. Top recommendations for patching/mitigation.
    Keep it clear, professional, and under 200 words.
    """

    prompt = PromptTemplate(input_variables=["cves"], template=template)
    chain = prompt | llm

    # Convert CVE list to readable string
    cve_text = "\n".join([f"{c['id']} ({c['severity']}, {c['cvss_score']}): {c['description']}" for c in cves])

    result = chain.invoke({"cves": cve_text})
    return result.content


def generate_ai_insights(cves):
    """
    Uses Gemini to analyze CVE list and generate security insights + recommendations.
    Returns a short professional summary.
    """
    template = """
    You are a cybersecurity analyst. Based on the following CVEs:
    {cves}

    Provide:
    1. A concise summary of recent trends (vendors, severity, attack vectors).
    2. Key security risks that stand out.
    3. Top recommendations for patching/mitigation.
    Keep it clear, professional, and under 200 words.
    """

    prompt = PromptTemplate(input_variables=["cves"], template=template)
    chain = prompt | llm

    # Convert CVE list into readable string
    cve_text = "\n".join([
        f"{c['id']} ({c.get('severity', 'N/A')}, {c.get('cvss_score', 'N/A')}): {c['description']}"
        for c in cves
    ])

    result = chain.invoke({"cves": cve_text})
    return result.content


def summarize_latest_cves(cve_list):
    """
    New function: Summarizes top N latest CVEs from NVD into a clean report.
    """
    formatted = "\n".join(
        [f"{i+1}. {cve['id']} (Severity: {cve.get('severity', 'N/A')}, CVSS: {cve.get('cvss_score', 'N/A')})\n   {cve['description']}"
         for i, cve in enumerate(cve_list)]
    )

    prompt = f"""
    Here are the latest cybersecurity vulnerabilities (CVEs):

    {formatted}

    Please create a clear, professional vulnerability report with:
    - Each vulnerability as a section
    - Description
    - Severity (High/Medium/Low)
    - CVSS Score
    - Suggested Solution (based on description if no official fix is listed)
    """
    response = llm.invoke(prompt)
    return response.content

def summarize_long_report(report_text, max_lines=300):
    """
    Summarizes a vulnerability report if it's too long.
    Keeps the content concise and capped at ~max_lines.
    """
    lines = report_text.splitlines()
    
    # If report already short, return as-is
    if len(lines) <= max_lines:
        return report_text

    prompt = f"""
    The following vulnerability report is too long ({len(lines)} lines).
    Summarize and condense it into a professional report 
    with at most {max_lines} lines while preserving:
    - All unique CVEs
    - Key descriptions
    - Severity and CVSS scores
    - Mitigation suggestions

    Report:
    {report_text}
    """

    response = llm.invoke(prompt)
    return response.content
