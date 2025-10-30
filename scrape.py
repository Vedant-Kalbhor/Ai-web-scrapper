import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def get_vulnerability_urls():
    """
    Returns list of vulnerability sources to scrape.
    Optimized for MAXIMUM SPEED using direct feeds.
    Total time: ~5-10 seconds with parallel scraping!
    """
    return [
        # ⚡ ULTRA FAST: Direct JSON API (< 2 seconds)
        {
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "type": "json",
            "name": "CISA KEV JSON"
        },
        # ⚡ VERY FAST: RSS XML Feed (< 3 seconds)
        {
            "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
            "type": "rss",
            "name": "NVD RSS Feed"
        },
        # 🚀 FAST: Lightweight HTML (5-8 seconds)
        # Uncomment if you want more sources:
        # {
        #     "url": "https://nvd.nist.gov/vuln/recent",
        #     "type": "html",
        #     "name": "NVD Recent"
        # }
           {"url": "https://www.oracle.com/security-alerts/", 
            "type": "html",
              "name": "Oracle Critical Patch Updates (CPU)"},
                {"url": "https://osv.dev/feed.json", "type": "json", "name": "Open Source Vulnerabilities (OSV.dev)"},
            {"url": "https://app.opencve.io/cve/", 
             "type": "html", 
             "name": "OpenCVE"}

    ]


def scrape_rss_feed(url):
    """
    Fast RSS/XML scraping using requests (no Selenium needed).
    """
    try:
        print(f"  → Fetching RSS feed: {url}")
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        response.raise_for_status()
        content = response.content[:150000]
        soup = BeautifulSoup(content, 'xml')
        
        # Extract all text content
        text = soup.get_text(separator="\n", strip=True)
        
        print(f"  ✓ Fetched {len(text)} characters from RSS")
        return text
        
    except Exception as e:
        print(f"  ✗ RSS feed error: {e}")
        return ""


def scrape_json_api(url):
    """
    Fast JSON API scraping with retries and session reset.
    """
    try:
        print(f"  → Fetching JSON API: {url}")
        
        # Create a new session each time to avoid stale connections
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        response = session.get(url, timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })
        response.raise_for_status()
        data = response.json()
        session.close()  # Explicitly close session

        if 'vulnerabilities' in data:
            vulnerabilities = data['vulnerabilities']
            print(f"  ✓ Found {len(vulnerabilities)} vulnerabilities in JSON")
            
            text_lines = []
            for vuln in vulnerabilities[:50]:
                cve_id = vuln.get('cveID', 'Unknown')
                title = vuln.get('vulnerabilityName', 'Unknown')
                description = vuln.get('shortDescription', 'No description')
                vendor = vuln.get('vendorProject', 'Unknown')
                product = vuln.get('product', 'Unknown')
                date = vuln.get('dateAdded', 'Unknown')
                text_lines.extend([
                    f"CVE: {cve_id}",
                    f"Title: {title}",
                    f"Description: {description}",
                    f"Vendor: {vendor}",
                    f"Product: {product}",
                    f"Date: {date}",
                    "-" * 50
                ])
            text = "\n".join(text_lines)
        else:
            import json
            text = json.dumps(data, indent=2)
        
        print(f"  ✓ Fetched JSON data ({len(text)} characters)")
        return text
        
    except Exception as e:
        print(f"  ✗ JSON API error: {e}")
        return ""

def scrape_html_fast(url, timeout=8):
    """
    Fast HTML scraping with minimal wait time.
    Only use Selenium when absolutely necessary.
    """
    # Try requests first (fastest)
    try:
        print(f"  → Trying fast requests for: {url}")
        response = requests.get(url, timeout=5, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if response.status_code == 200 and len(response.text) > 1000:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Remove unwanted tags
            for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
                tag.decompose()
            
            text = soup.get_text(separator="\n", strip=True)
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            cleaned_text = "\n".join(lines)
            
            print(f"  ✓ Fast-scraped {len(cleaned_text)} characters")
            return cleaned_text
    except:
        pass
    
    # Fallback to Selenium (slower)
    print(f"  → Using Selenium for: {url}")
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-images")  # Speed up
    options.add_argument("--disable-javascript")  # Try without JS first
    options.add_argument("--blink-settings=imagesEnabled=false")
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    
    driver = None
    try:
        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()), 
            options=options
        )
        driver.set_page_load_timeout(timeout)
        
        driver.get(url)
        time.sleep(2)  # Reduced from 5 to 2 seconds
        
        soup = BeautifulSoup(driver.page_source, "html.parser")
        
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        
        text = soup.get_text(separator="\n", strip=True)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        cleaned_text = "\n".join(lines)
        
        print(f"  ✓ Selenium-scraped {len(cleaned_text)} characters")
        return cleaned_text
        
    except Exception as e:
        print(f"  ✗ Selenium error: {e}")
        return ""
    finally:
        if driver:
            driver.quit()


def scrape_content(source_dict):
    """
    Smart scraper that chooses the right method based on source type.
    """
    url = source_dict.get("url")
    source_type = source_dict.get("type", "html")
    name = source_dict.get("name", url)
    
    print(f"\n🌐 Scraping: {name}")
    
    try:
        if source_type == "rss":
            return scrape_rss_feed(url)
        elif source_type == "json":
            return scrape_json_api(url)
        else:
            return scrape_html_fast(url)
    except Exception as e:
        print(f"  ✗ Failed to scrape {name}: {e}")
        return ""


def scrape_all_parallel(max_workers=3):
    sources = get_vulnerability_urls()
    results = []

    print(f"\n🚀 Starting parallel scraping of {len(sources)} sources...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_source = {
            executor.submit(scrape_content, source): source for source in sources
        }

        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                content = future.result(timeout=30)
                if content and len(content) > 100:
                    results.append({
                        "source": source.get("name", source.get("url")),
                        "url": source.get("url"),
                        "content": content
                    })
            except Exception as e:
                print(f"  ✗ Error processing {source.get('name')}: {e}")

    print(f"\n✅ Parallel scraping complete: {len(results)} sources successful")
    
    # 🧼 Explicitly clean up thread pool resources
    executor.shutdown(wait=True, cancel_futures=True)
    return results