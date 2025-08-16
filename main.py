import streamlit as st
from scrape import (
    get_vulnerability_urls,
    scrape_website,
    extract_body_content,
    clean_body_content,
    split_dom_content,
)
from parse import parse_with_gemini

def save_report(report_content):
    """
    Saves the parsed vulnerability report to a text file.
    """
    with open("vulnerability_report.txt", "w", encoding="utf-8") as f:
        f.write(report_content)

def run_scraper_and_parser():
    """
    Orchestrates the entire process of scraping, parsing, and generating the report.
    """
    st.write("Starting the vulnerability scan...")

    # Step 1: Get URLs
    urls = get_vulnerability_urls()
    st.write(f"Found {len(urls)} website(s) to scan.")

    all_parsed_content = []

    for url in urls:
        st.write(f"Scraping: {url}")
        # Step 2: Scrape the Website
        dom_content = scrape_website(url)
        body_content = extract_body_content(dom_content)
        cleaned_content = clean_body_content(body_content)

        # Step 3: Parse the Content with Gemini
        st.write("Parsing content with Gemini...")
        dom_chunks = split_dom_content(cleaned_content)
        parsed_result = parse_with_gemini(dom_chunks)
        all_parsed_content.append(parsed_result)

    # Step 4: Combine and Save the Report
    final_report = "\n\n".join(all_parsed_content)
    save_report(final_report)

    st.success("Vulnerability report generated successfully!")
    st.download_button(
        label="Download Report",
        data=final_report,
        file_name="vulnerability_report.txt",
        mime="text/plain"
    )

# Streamlit UI
st.title("Automated Cybersecurity Vulnerability Scanner")

if st.button("Generate Vulnerability Report"):
    run_scraper_and_parser()

    