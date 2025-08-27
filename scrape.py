from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import time

def get_vulnerability_urls():
    # Replace with actual sources you want to scrape
    return [
        "https://nvd.nist.gov/vuln/recent",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        
    ]

def scrape_content(url):
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    try:
        driver.get(url)
        time.sleep(3)  # wait for JS content
        soup = BeautifulSoup(driver.page_source, "html.parser")

        # Clean the content
        for tag in soup(["script", "style"]):
            tag.decompose()

        return soup.get_text(separator="\n", strip=True)
    finally:
        driver.quit()

