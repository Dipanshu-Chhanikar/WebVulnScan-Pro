import requests
from urllib.parse import urlparse, urlencode, urljoin
import re

# Common redirection parameters
REDIRECT_PARAMS = ["next", "url", "target", "rurl", "redirect", "redir", "return", "dest", "destination", "continue"]

# Payloads that simulate external or path-based redirection
REDIRECT_PAYLOADS = [
    "https://example.com",  # external redirect
    "//example.com",        # scheme-relative redirect
    "/\\example.com",       # backslash escape
    "/%2F%2Fexample.com",   # double encoded
    "%2F%2Fexample.com",    # encoded leading //
    "/%5Cexample.com",      # encoded backslash
    "///example.com",       # triple slashes
    "..%2f..%2fexample.com",# directory traversal
    "/%09/example.com",     # tab encoded
    "/%00example.com",      # null byte
    "///\\example.com",     # combo
]

REDIRECT_TEST_URL = "https://example.com"
REDIRECT_TEST_HOST = "example.com"
POST_REDIRECT_PARAMS = ["redirect", "return", "next", "target"]
POLLUTION_VARIANTS = [
    lambda p, v: f"{p}=/home&{p}={v}",
    lambda p, v: f"{p}={v}&{p}=",
    lambda p, v: f"{p}={v}&safe=1"
]

JS_REDIRECT_PATTERNS = [
    "location.href", "location.replace", "window.location", "document.location",
    "eval", "URLSearchParams", "exec", "/url="  # regex-based extraction
]

def scan_open_redirect(url):
    vulnerable = []
    tested_urls = []

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # 🔹 Test GET payloads
    for param in REDIRECT_PARAMS:
        for payload in REDIRECT_PAYLOADS:
            test_query = {param: payload}
            full_url = base + "?" + urlencode(test_query)
            tested_urls.append(full_url)

            try:
                res = requests.get(full_url, allow_redirects=False, timeout=10)
                location = res.headers.get("Location", "")
                body = res.text

                # ✅ Server-side redirection
                if location and REDIRECT_TEST_HOST in location:
                    vulnerable.append({
                        "type": "location-header",
                        "parameter": param,
                        "payload": payload,
                        "test_url": full_url,
                        "redirect_to": location
                    })

                # ✅ HTML or JS-based redirection
                elif REDIRECT_TEST_HOST in body:
                    if (
                        re.search(r'<meta\s+http-equiv=["\']refresh["\']', body, re.IGNORECASE) or
                        any(keyword in body for keyword in JS_REDIRECT_PATTERNS)
                    ):
                        vulnerable.append({
                            "type": "html-based",
                            "parameter": param,
                            "payload": payload,
                            "test_url": full_url,
                            "snippet": body[:300]
                        })

            except requests.RequestException:
                continue

    # 🔹 Test redirect chains (follow 302 history)
    for param in REDIRECT_PARAMS:
        try:
            test_query = {param: REDIRECT_TEST_URL}
            full_url = base + "?" + urlencode(test_query)
            res = requests.get(full_url, allow_redirects=True, timeout=10)
            for r in res.history:
                loc = r.headers.get("Location", "")
                if REDIRECT_TEST_HOST in loc:
                    vulnerable.append({
                        "type": "redirect-chain",
                        "parameter": param,
                        "intermediate": loc,
                        "test_url": full_url
                    })
        except requests.RequestException:
            continue

    # 🔹 Test parameter pollution
    for param in REDIRECT_PARAMS:
        for variant in POLLUTION_VARIANTS:
            test_url = f"{base}?{variant(param, REDIRECT_TEST_URL)}"
            tested_urls.append(test_url)
            try:
                res = requests.get(test_url, allow_redirects=False, timeout=10)
                loc = res.headers.get("Location", "")
                if REDIRECT_TEST_HOST in loc:
                    vulnerable.append({
                        "type": "param-pollution",
                        "parameter": param,
                        "test_url": test_url,
                        "redirect_to": loc
                    })
            except requests.RequestException:
                continue

    # 🔹 Test POST-based redirection
    for param in POST_REDIRECT_PARAMS:
        for payload in REDIRECT_PAYLOADS:
            try:
                data = {param: payload}
                res = requests.post(url, data=data, allow_redirects=False, timeout=10)
                loc = res.headers.get("Location", "")
                if REDIRECT_TEST_HOST in loc:
                    vulnerable.append({
                        "type": "post-param",
                        "parameter": param,
                        "payload": payload,
                        "redirect_to": loc
                    })
            except requests.RequestException:
                continue

    return {
        "target": url,
        "vulnerable": len(vulnerable) > 0,
        "vulnerable_redirects": vulnerable,
        "tested": tested_urls
    }
