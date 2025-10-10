from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import time


def get_vulnerability_urls():
    """
    Returns list of vulnerability sources to scrape.
    Add more sources here as needed.
    """
    return [
        "https://nvd.nist.gov/vuln/recent",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        # Add more sources:
        # "https://www.exploit-db.com/",
        # "https://www.securityfocus.com/vulnerabilities",
    ]


def scrape_content(url, timeout=10):
    """
    Scrapes content from a URL using Selenium (for JS-rendered pages).
    Returns cleaned text content.
    """
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    
    # Suppress logs
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    
    driver = None
    try:
        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()), 
            options=options
        )
        driver.set_page_load_timeout(timeout)
        
        print(f"  → Loading {url}...")
        driver.get(url)
        
        # Wait for content to load
        time.sleep(5)
        
        # Get page source
        soup = BeautifulSoup(driver.page_source, "html.parser")
        
        # Remove script, style, and other non-content tags
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        
        # Extract text
        text = soup.get_text(separator="\n", strip=True)
        
        # Clean up excessive whitespace
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        cleaned_text = "\n".join(lines)
        
        print(f"  ✓ Extracted {len(cleaned_text)} characters from {url}")
        return cleaned_text
        
    except Exception as e:
        print(f"  ✗ Error scraping {url}: {e}")
        raise
    finally:
        if driver:
            driver.quit()


def scrape_with_retry(url, max_retries=2):
    """
    Scrape with retry logic for robustness.
    """
    for attempt in range(max_retries):
        try:
            return scrape_content(url)
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"  ⟳ Retrying {url} (attempt {attempt + 2}/{max_retries})...")
                time.sleep(3)
            else:
                raise e
            