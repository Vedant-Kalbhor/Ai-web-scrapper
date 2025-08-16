from selenium.webdriver import Remote, ChromeOptions
from selenium.webdriver.chromium.remote_connection import ChromiumRemoteConnection
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import os
import time
import selenium.webdriver as webdriver
from selenium.webdriver.chrome.service import Service


# SBR_WEBDRIVER = os.getenv("SBR_WEBDRIVER")

from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options

options = Options()
# options.add_argument("--headless") # optional: run without GUI

def get_vulnerability_urls():
    """
    Returns a list of URLs for websites that list top cybersecurity vulnerabilities.
    """
    return [
        "https://www.cm-alliance.com/cybersecurity-blog/top-10-biggest-cyber-attacks-of-2024-25-other-attacks-to-know-about",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://www.tenable.com/cve/newest",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-23006"

    ]


def scrape_website(website):
    print("Connecting to Scraping Browser...")
    chrome_driver_path = "./chromedriver.exe"
    options = webdriver.ChromeOptions()
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    try:
        driver.get(website)
        print("Page Loaded...")
        html = driver.page_source
        time.sleep(5)

        return html
    finally:
        driver.quit()


def extract_body_content(html_content):
    soup = BeautifulSoup(html_content, "html.parser")
    body_content = soup.body
    if body_content:
        return str(body_content)
    return ""


def clean_body_content(body_content):
    soup = BeautifulSoup(body_content, "html.parser")

    for script_or_style in soup(["script", "style"]):
        script_or_style.extract()

    # Get text or further process the content
    cleaned_content = soup.get_text(separator="\n")
    cleaned_content = "\n".join(
        line.strip() for line in cleaned_content.splitlines() if line.strip()
    )

    return cleaned_content


def split_dom_content(dom_content, max_length=6000):
    return [
        dom_content[i : i + max_length] for i in range(0, len(dom_content), max_length)
    ]