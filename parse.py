import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate

# Load API key
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Define your prompt template
template = (
    "You are an expert cybersecurity analyst. From the following text content: {dom_content}, "
    "extract the latest cybersecurity vulnerabilities and their solutions.\n\n"
    "Please follow these instructions carefully:\n\n"
    "1. **Extract Vulnerabilities and Solutions:** Identify and extract the names of the vulnerabilities and any corresponding solutions, mitigations, or recommended actions provided in the text.\n"
    "2. **Format the Output:** For each vulnerability, format the output as follows:\n"
    "   Vulnerability: [Name of the Vulnerability]\n"
    "   Solution: [Description of the solution or mitigation]\n\n"
    "3. **No Extra Content:** Do not include any additional text, comments, or explanations in your response.\n"
    "4. **Empty Response:** If no vulnerabilities or solutions are found, return an empty string ('')."
)

# Create the Gemini-based LLM instance
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", google_api_key=GOOGLE_API_KEY)

def parse_with_gemini(dom_chunks):
    prompt = ChatPromptTemplate.from_template(template)
    chain = prompt | llm

    parsed_results = []
    for i, chunk in enumerate(dom_chunks, start=1):
        response = chain.invoke({
            "dom_content": chunk,
        })
        print(f"Parsed batch: {i} of {len(dom_chunks)}")
        parsed_results.append(response.content)

    return "\n".join(parsed_results)