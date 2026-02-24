import requests
import html

def scan_xss(form, target_url):
    """
    Test for Reflected Cross-Site Scripting (XSS).
    """
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "vulnerable<script>alert(1)</script>"
    ]
    vulnerabilities = []

    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.get("inputs", [])

    for payload in payloads:
        data = {}
        for input_field in inputs:
            if input_field["type"] != "submit":
                data[input_field["name"]] = payload
            else:
                data[input_field["name"]] = input_field["value"]

        try:
            if method == "post":
                response = requests.post(action, data=data, timeout=5)
            else:
                response = requests.get(action, params=data, timeout=5)

            # Check if payload is reflected in the response UNESCAPED
            if payload in response.text:
                vulnerabilities.append({
                    "type": "Reflected XSS",
                    "severity": "HIGH",
                    "url": action,
                    "payload": payload,
                    "description": f"Reflected XSS detected at {action}. The input submitted is rendered back to page without proper sanitization.",
                    "evidence": "Payload found in response body"
                })
                return vulnerabilities
        except Exception as e:
            print(f"XSS Test Error: {e}")

    return vulnerabilities

def scan_url_xss(url):
    """
    Test direct URL parameters for XSS.
    """
    payload = "<script>alert(1)</script>"
    vulnerabilities = []
    
    if "?" in url:
        # Simple test: append payload to existing params or try to inject into them
        # This is a naive implementation for the demo
        base_url = url.split("?")[0]
        params_str = url.split("?")[1]
        params = params_str.split("&")
        
        test_params = {}
        for p in params:
            if "=" in p:
                key, val = p.split("=", 1)
                test_params[key] = payload
            else:
                test_params[p] = payload
        
        try:
            response = requests.get(base_url, params=test_params, timeout=5)
            if payload in response.text:
                vulnerabilities.append({
                    "type": "Reflected XSS (URL)",
                    "severity": "HIGH",
                    "url": url,
                    "payload": payload,
                    "description": "Reflected XSS detected in URL parameters.",
                    "evidence": "Payload found in response body"
                })
        except:
            pass
            
    return vulnerabilities
