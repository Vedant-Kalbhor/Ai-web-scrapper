import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


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
        
        soup = BeautifulSoup(response.content, 'xml')
        
        # Extract all text content
        text = soup.get_text(separator="\n", strip=True)
        
        print(f"  ✓ Fetched {len(text)} characters from RSS")
        return text
        
    except Exception as e:
        print(f"  ✗ RSS feed error: {e}")
        return ""


def scrape_json_api(url):
    """
    Fast JSON API scraping using requests.
    """
    try:
        print(f"  → Fetching JSON API: {url}")
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        response.raise_for_status()
        
        data = response.json()
        
        # Convert JSON to readable text format for AI parsing
        # For CISA KEV, extract vulnerabilities array
        if 'vulnerabilities' in data:
            vulnerabilities = data['vulnerabilities']
            print(f"  ✓ Found {len(vulnerabilities)} vulnerabilities in JSON")
            
            # Format nicely for AI
            text_lines = []
            for vuln in vulnerabilities[:100]:  # Limit to 100 most recent
                cve_id = vuln.get('cveID', 'Unknown')
                title = vuln.get('vulnerabilityName', 'Unknown')
                description = vuln.get('shortDescription', 'No description')
                vendor = vuln.get('vendorProject', 'Unknown')
                product = vuln.get('product', 'Unknown')
                date = vuln.get('dateAdded', 'Unknown')
                
                text_lines.append(f"CVE: {cve_id}")
                text_lines.append(f"Title: {title}")
                text_lines.append(f"Description: {description}")
                text_lines.append(f"Vendor: {vendor}")
                text_lines.append(f"Product: {product}")
                text_lines.append(f"Date: {date}")
                text_lines.append("-" * 50)
            
            text = "\n".join(text_lines)
        else:
            # Generic JSON formatting
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
    """
    Scrape multiple sources in parallel for maximum speed.
    """
    sources = get_vulnerability_urls()
    results = []
    
    print(f"\n🚀 Starting parallel scraping of {len(sources)} sources...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all scraping tasks
        future_to_source = {
            executor.submit(scrape_content, source): source 
            for source in sources
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                content = future.result()
                if content and len(content) > 100:
                    results.append({
                        "source": source.get("name", source.get("url")),
                        "url": source.get("url"),
                        "content": content
                    })
            except Exception as e:
                print(f"  ✗ Error processing {source.get('name')}: {e}")
    
    print(f"\n✅ Parallel scraping complete: {len(results)} sources successful")
    return results