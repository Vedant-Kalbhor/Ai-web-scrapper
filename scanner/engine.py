import threading
from scanner.crawler import Crawler
from scanner.detectors.sqli import scan_sqli
from scanner.detectors.xss import scan_xss, scan_url_xss
from scanner.detectors.headers import scan_headers

class ScannerEngine:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.status = "Idle"
        self.progress = 0
        self.is_running = False

    def run_scan(self):
        self.is_running = True
        self.vulnerabilities = []
        
        # Phase 1: Crawling
        self.status = "Crawling target site..."
        self.progress = 10
        crawler = Crawler(self.target_url)
        crawler.crawl(depth=2)
        targets = crawler.get_scan_targets()
        
        # Phase 2: Vulnerability Testing
        self.status = "Testing for Security Misconfigurations (Headers)..."
        self.progress = 30
        for url in targets["urls"]:
            self.vulnerabilities.extend(scan_headers(url))
            
        self.status = "Testing for Cross-Site Scripting (XSS)..."
        self.progress = 50
        # Test forms for XSS
        for form in targets["forms"]:
            self.vulnerabilities.extend(scan_xss(form, self.target_url))
        
        # Test URLs for XSS
        for url in targets["urls"]:
            self.vulnerabilities.extend(scan_url_xss(url))

        self.status = "Testing for SQL Injection (SQLi)..."
        self.progress = 80
        # Test forms for SQLi
        for form in targets["forms"]:
            self.vulnerabilities.extend(scan_sqli(form, self.target_url))

        self.status = "Scan Complete"
        self.progress = 100
        self.is_running = False
        
        return self.vulnerabilities

    def start_background_scan(self):
        thread = threading.Thread(target=self.run_scan)
        thread.start()
        return thread
