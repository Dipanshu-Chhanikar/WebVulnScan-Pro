import requests
from bs4 import BeautifulSoup

# Common CSRF token field names
CSRF_TOKEN_NAMES = [
    "csrf_token", "csrf", "authenticity_token", "_token", "__RequestVerificationToken"
]

def find_forms(url):
    """Get all forms from the URL"""
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def has_csrf_token(form):
    """Check if form has known CSRF token input fields"""
    for input_tag in form.find_all("input", {"type": "hidden"}):
        name = input_tag.attrs.get("name", "").lower()
        if name in CSRF_TOKEN_NAMES:
            return True
    return False

def scan_csrf(url):
    results = {
        "url": url,
        "forms_checked": 0,
        "forms_without_token": [],
        "forms_with_token": [],
    }

    forms = find_forms(url)
    results["forms_checked"] = len(forms)

    for i, form in enumerate(forms):
        if has_csrf_token(form):
            results["forms_with_token"].append(f"form_{i+1}")
        else:
            results["forms_without_token"].append(f"form_{i+1}")

    return results
