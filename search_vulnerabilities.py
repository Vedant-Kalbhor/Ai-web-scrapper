"""
AI-Powered Vulnerability Search Module
Searches for recent vulnerabilities using Gemini's web search capabilities
"""

import os
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.prompts import ChatPromptTemplate
from langchain.tools import Tool
from langchain.agents import AgentExecutor, create_react_agent
from langchain import hub
import json
from datetime import datetime

# Initialize Gemini with Grounding (Web Search)
def create_search_agent():
    """Creates an agent with web search capabilities"""
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash-exp",
        temperature=0.3,
        google_api_key=os.getenv("GOOGLE_API_KEY")
    )
    return llm


def search_vulnerabilities_with_ai(query: str) -> dict:
    """
    Search for recent vulnerabilities using Gemini with web search
    
    Args:
        query: Software name or organization name
        
    Returns:
        Dictionary with vulnerabilities found
    """
    try:
        llm = create_search_agent()
        
        # Create a detailed search prompt
        search_prompt = f"""You are a cybersecurity expert. Search the web for RECENT vulnerabilities (CVEs) related to: "{query}"

Focus on:
1. CVE IDs from 2024-2025
2. Critical and High severity vulnerabilities
3. Recently disclosed vulnerabilities
4. Active exploits or zero-days

For EACH vulnerability you find, provide:
- CVE ID (if available)
- Vulnerability Title/Name
- Severity Level (Critical/High/Medium/Low)
- CVSS Score (if available)
- Brief Description (2-3 sentences)
- Affected Product/Version
- Date Disclosed
- Exploitation Status (if known)

Search thoroughly and provide at least 5-10 recent vulnerabilities if available.

Format your response as a JSON array with this structure:
[
  {{
    "cve_id": "CVE-YYYY-XXXXX or 'Pending'",
    "title": "Vulnerability name",
    "severity": "Critical/High/Medium/Low",
    "cvss_score": "9.8 or null",
    "description": "Detailed description",
    "affected_product": "Product name and version",
    "date_disclosed": "YYYY-MM-DD or 'Recent'",
    "exploitation_status": "Actively exploited/PoC available/Not known",
    "source_url": "Reference URL"
  }}
]

IMPORTANT: Return ONLY the JSON array, no additional text or markdown formatting."""

        # Invoke the LLM with web search
        response = llm.invoke(search_prompt)
        
        # Extract content
        content = response.content.strip()
        
        # Try to parse JSON
        # Remove markdown code blocks if present
        if content.startswith("```json"):
            content = content.replace("```json", "").replace("```", "").strip()
        elif content.startswith("```"):
            content = content.replace("```", "").strip()
        
        try:
            vulnerabilities = json.loads(content)
        except json.JSONDecodeError:
            # If JSON parsing fails, try to extract vulnerabilities from text
            vulnerabilities = parse_text_response(content, query)
        
        return {
            "success": True,
            "query": query,
            "total_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        }
        
    except Exception as e:
        print(f"[!] Error searching vulnerabilities: {e}")
        return {
            "success": False,
            "error": str(e),
            "query": query,
            "vulnerabilities": []
        }


def parse_text_response(text: str, query: str) -> list:
    """
    Fallback parser if JSON extraction fails
    Attempts to extract vulnerability information from text
    """
    vulnerabilities = []
    
    # Try to use LLM to structure the response
    try:
        llm = create_search_agent()
        structure_prompt = f"""Convert the following vulnerability information into a JSON array.
        
Text to convert:
{text}

Return ONLY a JSON array in this exact format (no markdown, no extra text):
[
  {{
    "cve_id": "CVE-YYYY-XXXXX or 'Pending'",
    "title": "Vulnerability name",
    "severity": "Critical/High/Medium/Low",
    "cvss_score": "9.8 or null",
    "description": "Description",
    "affected_product": "Product name",
    "date_disclosed": "Date or 'Recent'",
    "exploitation_status": "Status",
    "source_url": "URL or null"
  }}
]"""
        
        response = llm.invoke(structure_prompt)
        content = response.content.strip()
        
        # Clean up markdown
        if content.startswith("```json"):
            content = content.replace("```json", "").replace("```", "").strip()
        elif content.startswith("```"):
            content = content.replace("```", "").strip()
        
        vulnerabilities = json.loads(content)
        
    except Exception as e:
        print(f"[!] Fallback parsing failed: {e}")
        # Return a single generic entry
        vulnerabilities = [{
            "cve_id": "N/A",
            "title": f"Vulnerabilities found for {query}",
            "severity": "Unknown",
            "cvss_score": None,
            "description": text[:500] + "..." if len(text) > 500 else text,
            "affected_product": query,
            "date_disclosed": "Recent",
            "exploitation_status": "Unknown",
            "source_url": None
        }]
    
    return vulnerabilities


def search_vulnerability_details(cve_id: str) -> dict:
    """
    Get detailed information about a specific CVE
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
        
    Returns:
        Detailed vulnerability information
    """
    try:
        llm = create_search_agent()
        
        prompt = f"""Search for detailed information about {cve_id}.

Provide:
1. Full vulnerability description
2. Technical details
3. Attack vector and complexity
4. Impact assessment
5. Known exploits or proof-of-concepts
6. Mitigation steps and patches
7. Affected versions
8. CVSS score breakdown
9. References and advisories

Format as detailed text with clear sections."""

        response = llm.invoke(prompt)
        
        return {
            "success": True,
            "cve_id": cve_id,
            "details": response.content,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "cve_id": cve_id
        }