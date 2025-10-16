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


# -------------------------------------------------------
# 🔗 1. Define All Vulnerability Sources
# -------------------------------------------------------
def get_vulnerability_urls():
    """
    Returns list of major global vulnerability databases and feeds.
    Optimized for parallel scraping.
    """
    return [

        {"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json", "name": "CISA KEV JSON"},
        {"url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "type": "rss", "name": "NVD RSS Feed"},

        {"url": "https://cve.mitre.org/data/downloads/allitems.html", "type": "html", "name": "MITRE CVE Database"},
        {"url": "https://www.exploit-db.com/", "type": "html", "name": "Exploit Database (Exploit-DB)"},
        {"url": "https://www.kb.cert.org/vuls/", "type": "html", "name": "CERT/CC Vulnerability Notes"},
        {"url": "https://access.redhat.com/security/updates/advisory", "type": "html", "name": "Red Hat Security Advisories (RHSA)"},
        {"url": "https://ubuntu.com/security/notices", "type": "html", "name": "Ubuntu Security Notices (USN)"},
        {"url": "https://msrc.microsoft.com/update-guide", "type": "html", "name": "Microsoft Security Response Center (MSRC)"},
        {"url": "https://www.oracle.com/security-alerts/", "type": "html", "name": "Oracle Critical Patch Updates (CPU)"},
        {"url": "https://support.apple.com/en-in/HT201222", "type": "html", "name": "Apple Security Updates"},
        {"url": "https://github.com/advisories", "type": "html", "name": "GitHub Security Advisories (GHSA)"},
        {"url": "https://osv.dev/feed.json", "type": "json", "name": "Open Source Vulnerabilities (OSV.dev)"},
        {"url": "https://security-tracker.debian.org/", "type": "html", "name": "Debian Security Tracker"},
        {"url": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x", "type": "html", "name": "Cisco Security Advisories"},
        {"url": "https://www.mozilla.org/en-US/security/advisories/", "type": "html", "name": "Mozilla Security Advisories"},
        {"url": "https://source.android.com/security/bulletin", "type": "html", "name": "Android Security Bulletins"},
        {"url": "https://www.ncsc.gov.uk/section/advice-guidance/all-topics", "type": "html", "name": "NCSC (UK) Advisories"},
    ]


# -------------------------------------------------------
# ⚡ Utility Functions
# -------------------------------------------------------
def create_retry_session():
    """Create session with retry policy."""
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
    return session


# -------------------------------------------------------
# 📰 2. Scrapers
# -------------------------------------------------------
def scrape_rss_feed(url):
    """Scrape simple RSS or XML feed."""
    try:
        print(f"  → Fetching RSS feed: {url}")
        session = create_retry_session()
        response = session.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.content, 'xml')
        text = soup.get_text(separator="\n", strip=True)
        print(f"  ✓ RSS fetched ({len(text)} chars)")
        return text
    except Exception as e:
        print(f"  ✗ RSS error: {e}")
        return ""


def scrape_json_api(url):
    """Scrape and parse JSON feeds."""
    try:
        print(f"  → Fetching JSON API: {url}")
        session = create_retry_session()
        response = session.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
        data = response.json()
        session.close()

        import json
        text = json.dumps(data, indent=2)
        print(f"  ✓ JSON fetched ({len(text)} chars)")
        return text
    except Exception as e:
        print(f"  ✗ JSON error: {e}")
        return ""


def scrape_html_fast(url, timeout=10):
    """Fast HTML scraping using requests, fallback to Selenium."""
    try:
        print(f"  → Fast HTML fetch: {url}")
        response = requests.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
                tag.decompose()
            text = soup.get_text(separator="\n", strip=True)
            print(f"  ✓ HTML fetched ({len(text)} chars)")
            return text
    except Exception as e:
        print(f"  ✗ HTML error (requests): {e}")

    # Fallback: Selenium (for JS-heavy sites)
    print(f"  → Selenium fallback: {url}")
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-images")
    options.add_argument("--blink-settings=imagesEnabled=false")
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    driver = None

    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        time.sleep(2)
        soup = BeautifulSoup(driver.page_source, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        text = soup.get_text(separator="\n", strip=True)
        print(f"  ✓ Selenium scraped ({len(text)} chars)")
        return text
    except Exception as e:
        print(f"  ✗ Selenium error: {e}")
        return ""
    finally:
        if driver:
            driver.quit()


# -------------------------------------------------------
# 🤖 3. Smart Scraping Dispatcher
# -------------------------------------------------------
def scrape_content(source_dict):
    """Decide which scraper to use based on type."""
    url, typ, name = source_dict.get("url"), source_dict.get("type"), source_dict.get("name")
    print(f"\n Scraping: {name}")
    try:
        if typ == "rss":
            return scrape_rss_feed(url)
        elif typ == "json":
            return scrape_json_api(url)
        else:
            return scrape_html_fast(url)
    except Exception as e:
        print(f"  ✗ Failed {name}: {e}")
        return ""


# -------------------------------------------------------
# 🚀 4. Parallel Execution
# -------------------------------------------------------
def scrape_all_parallel(max_workers=6):
    sources = get_vulnerability_urls()
    results = []

    print(f"\n Starting parallel scraping of {len(sources)} sources...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_source = {
            executor.submit(scrape_content, source): source for source in sources
        }

        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                content = future.result(timeout=40)
                if isinstance(content, str) and len(content) > 100:
                    results.append({
                        "source": source.get("name", source.get("url")),
                        "url": source.get("url"),
                        "content": content
                    })
                elif isinstance(content, dict) and "content" in content:
                    results.append(content)
                else:
                    print(f"⚠️ {source.get('name')} returned no usable content.")
            except Exception as e:
                print(f"  ✗ Error processing {source.get('name')}: {e}")

    print(f"\n✅ Parallel scraping complete: {len(results)} successful sources")

    # Explicit cleanup
    executor.shutdown(wait=True, cancel_futures=True)

    # Verify structure
    if not results or not all("content" in r for r in results):
        print("Some sources missing 'content' key; parsing will fail.")
    else:
        print("All sources properly structured with 'content' key.")
    
    return results

    sources = get_vulnerability_urls()
    results = []
    print(f"\n Starting parallel scraping of {len(sources)} sources...\n")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_source = {executor.submit(scrape_content, src): src for src in sources}
        for future in as_completed(future_to_source):
            src = future_to_source[future]
            try:
                content = future.result(timeout=40)
                if content and len(content) > 100:
                    results.append({
                        "source": src["name"],
                        "url": src["url"],
                        "content_length": len(content)
                    })
                    print(f" {src['name']} done.")
            except Exception as e:
                print(f"  ✗ Error processing {src['name']}: {e}")

    print(f"\n Completed scraping {len(results)} / {len(sources)} sources.")
    return results


# -------------------------------------------------------
# 🧪 5. Run Test
# -------------------------------------------------------
if __name__ == "__main__":
    all_data = scrape_all_parallel()
    print("\n--- SUMMARY ---")
    for item in all_data:
        print(f"{item['source']}: {item['content_length']} chars fetched")
