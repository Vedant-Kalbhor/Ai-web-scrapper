from langchain_google_genai import ChatGoogleGenerativeAI
import os
from dotenv import load_dotenv

load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=GOOGLE_API_KEY)

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

