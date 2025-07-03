import requests
from urllib.parse import urljoin, urlparse, urlencode

# Common redirection parameters
REDIRECT_PARAMS = ["next", "url", "target", "rurl", "redirect", "redir", "return"]

# Payload that clearly shows external redirection
REDIRECT_TEST_URL = "https://example.com"

def scan_open_redirect(url):
    vulnerable = []
    tested_urls = []

    for param in REDIRECT_PARAMS:
        test_params = {param: REDIRECT_TEST_URL}
        full_url = f"{url}?{urlencode(test_params)}"
        tested_urls.append(full_url)

        try:
            res = requests.get(full_url, allow_redirects=False, timeout=10)
            location = res.headers.get("Location")

            if location and REDIRECT_TEST_URL in location:
                vulnerable.append({
                    "parameter": param,
                    "test_url": full_url,
                    "redirect_to": location
                })

        except Exception as e:
            continue

    return {
        "target": url,
        "vulnerable": len(vulnerable) > 0,
        "vulnerable_redirects": vulnerable,
        "tested": tested_urls
    }
