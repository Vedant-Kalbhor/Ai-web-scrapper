import os
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv

load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=GOOGLE_API_KEY)

def parse_with_ai(text):
    prompt = f"""
    Extract cybersecurity vulnerabilities and their solutions from the text below. 
    Return the results in a structured format:

    Vulnerability: <name or CVE>
    Description: <short explanation>
    Solution: <fix/patch/mitigation>

    Text: {text}
    """
    response = llm.invoke(prompt)
    return response.content
