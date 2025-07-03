import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Known CSRF token input field names
CSRF_TOKEN_NAMES = [
    "csrf_token", "csrf", "authenticity_token", "_token", "__RequestVerificationToken"
]

# Unsafe HTTP methods that should require CSRF protection
UNSAFE_METHODS = ["post", "put", "delete"]

# Common sensitive actions in URLs/forms
SENSITIVE_KEYWORDS = [
    "delete", "update", "edit", "change-password", "admin", "reset", "account", "settings"
]

def looks_like_token(name, value):
    """Heuristically check if a hidden input field could be a CSRF token."""
    return (
        name and value and
        len(value) > 20 and
        ("token" in name.lower() or "csrf" in name.lower())
    )

def find_forms(url):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form"), res.url  # Return actual URL after redirects
    except:
        return [], url

def get_form_details(form, base_url):
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    full_action = urljoin(base_url, action) if action else base_url

    hidden_fields = []
    has_token = False

    for input_tag in form.find_all("input", {"type": "hidden"}):
        name = input_tag.attrs.get("name", "")
        value = input_tag.attrs.get("value", "")
        hidden_fields.append({"name": name, "value": value})

        if name.lower() in CSRF_TOKEN_NAMES or looks_like_token(name, value):
            has_token = True

    # Determine severity of CSRF risk
    severity = "None"
    if not has_token:
        if method in UNSAFE_METHODS:
            if any(keyword in full_action.lower() for keyword in SENSITIVE_KEYWORDS):
                severity = "High"
            else:
                severity = "Medium"
        else:
            severity = "Low"

    return {
        "action": full_action,
        "method": method,
        "has_csrf_token": has_token,
        "input_count": len(form.find_all(["input", "textarea", "select"])),
        "hidden_fields": hidden_fields,
        "raw_form_html": form.prettify(),
        "severity": severity
    }

def scan_csrf(url):
    results = {
        "url": url,
        "forms_checked": 0,
        "forms_with_token": [],
        "forms_without_token": [],
        "vulnerable_forms": [],
    }

    forms, final_url = find_forms(url)
    results["forms_checked"] = len(forms)

    for form in forms:
        details = get_form_details(form, final_url)
        if details["has_csrf_token"]:
            results["forms_with_token"].append(details)
        else:
            results["forms_without_token"].append(details)
            if details["severity"] in ["High", "Medium"]:
                results["vulnerable_forms"].append(details)

    results["vulnerable"] = bool(results["vulnerable_forms"])
    return results
