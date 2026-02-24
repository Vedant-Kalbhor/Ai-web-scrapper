import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_urls = set()
        self.forms = []
        self.links = []

    def get_links(self, url):
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('a', href=True)
        except Exception as e:
            print(f"Error crawling links at {url}: {e}")
            return []

    def get_forms(self, url):
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"Error crawling forms at {url}: {e}")
            return []

    def crawl(self, url=None, depth=2):
        if url is None:
            url = self.base_url
        
        if depth == 0 or url in self.visited_urls:
            return

        print(f"[*] Crawling: {url}")
        self.visited_urls.add(url)

        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action')
                post_url = urljoin(url, action)
                method = form.get('method', 'get').lower()
                
                inputs = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    input_value = input_tag.get('value', '')
                    if input_name:
                        inputs.append({"name": input_name, "type": input_type, "value": input_value})
                
                self.forms.append({
                    "url": url,
                    "action": post_url,
                    "method": method,
                    "inputs": inputs
                })

            # Extract links
            for link in soup.find_all('a', href=True):
                link_url = urljoin(url, link.get('href'))
                
                # Filter links to stay on the same domain
                if urlparse(link_url).netloc == urlparse(self.base_url).netloc:
                    if link_url not in self.visited_urls:
                        self.links.append(link_url)
                        self.crawl(link_url, depth - 1)

        except Exception as e:
            print(f"Crawling error at {url}: {e}")

    def get_scan_targets(self):
        return {
            "urls": list(self.visited_urls),
            "forms": self.forms
        }
