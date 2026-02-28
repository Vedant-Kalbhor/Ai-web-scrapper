import requests

def scan_headers(url):
    """
    Check for missing security headers (OWASP Security Misconfiguration).
    """
    vulnerabilities = []
    
    important_headers = {
        "Content-Security-Policy": "Helps prevent XSS and clickjacking.",
        "X-Frame-Options": "Prevents clickjacking by controlling if site can be embedded in an iframe.",
        "X-Content-Type-Options": "Prevents MIME-sniffing vulnerabilities.",
        "Strict-Transport-Security": "Enforces HTTPS connections.",
        "Referrer-Policy": "Controls how much referrer information is sent with requests."
    }

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        for header, description in important_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    "type": "Missing Security Header",
                    "severity": "LOW",
                    "url": url,
                    "header": header,
                    "description": f"The security header '{header}' is missing. {description}",
                    "evidence": "Header not found in HTTP response"
                })
        
        # Check for Server header (Information Leakage)
        if "Server" in headers:
            vulnerabilities.append({
                "type": "Information Leakage",
                "severity": "LOW",
                "url": url,
                "header": "Server",
                "description": f"The 'Server' header is present ({headers['Server']}), which may leak software version info.",
                "evidence": f"Server: {headers['Server']}"
            })

    except Exception as e:
        print(f"Header Test Error: {e}")

    return vulnerabilities
