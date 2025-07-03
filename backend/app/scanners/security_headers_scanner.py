import requests

EXPECTED_HEADERS = [
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy"
]

def scan_security_headers(url):
    try:
        res = requests.get(url, timeout=10)
        response_headers = res.headers

        found = {}
        missing = []

        for header in EXPECTED_HEADERS:
            if header in response_headers:
                found[header] = response_headers[header]
            else:
                missing.append(header)

        return {
            "url": url,
            "secure": len(missing) == 0,
            "found_headers": found,
            "missing_headers": missing
        }

    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "secure": False,
            "found_headers": {},
            "missing_headers": EXPECTED_HEADERS
        }
