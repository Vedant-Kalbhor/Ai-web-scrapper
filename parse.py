import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate

# Load API key
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Define your prompt template
template = (
    "You are tasked with extracting specific information from the following text content: {dom_content}. "
    "Please follow these instructions carefully:\n\n"
    "1. **Extract Information:** Only extract the information that directly matches the provided description: {parse_description}.\n"
    "2. **No Extra Content:** Do not include any additional text, comments, or explanations in your response.\n"
    "3. **Empty Response:** If no information matches the description, return an empty string ('').\n"
    "4. **Direct Data Only:** Your output should contain only the data that is explicitly requested, with no other text."
)

# Create the Gemini-based LLM instance
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", google_api_key=GOOGLE_API_KEY)

def parse_with_gemini(dom_chunks, parse_description):
    prompt = ChatPromptTemplate.from_template(template)
    chain = prompt | llm

    parsed_results = []
    for i, chunk in enumerate(dom_chunks, start=1):
        response = chain.invoke({
            "dom_content": chunk,
            "parse_description": parse_description
        })
        print(f"Parsed batch: {i} of {len(dom_chunks)}")
        parsed_results.append(response.content)  # .content contains the generated text

    return "\n".join(parsed_results)


