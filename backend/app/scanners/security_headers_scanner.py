import requests

EXPECTED_HEADERS = [
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
    "Expect-CT",
    "Access-Control-Allow-Origin",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy"
]

HEADER_SEVERITY = {
    "Strict-Transport-Security": "high",
    "Content-Security-Policy": "high",
    "X-Frame-Options": "medium",
    "X-XSS-Protection": "medium",
    "X-Content-Type-Options": "medium",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
    "Expect-CT": "low",
    "Access-Control-Allow-Origin": "info",
    "Cross-Origin-Opener-Policy": "low",
    "Cross-Origin-Embedder-Policy": "low",
    "Cross-Origin-Resource-Policy": "low"
}

HEADER_SUGGESTIONS = {
    "Strict-Transport-Security": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'",
    "Content-Security-Policy": "Define a strict Content-Security-Policy to mitigate XSS and clickjacking.",
    "X-Frame-Options": "Use 'DENY' or 'SAMEORIGIN' to prevent clickjacking.",
    "X-XSS-Protection": "Enable XSS filter with '1; mode=block' (legacy).",
    "X-Content-Type-Options": "Use 'nosniff' to prevent MIME type sniffing.",
    "Referrer-Policy": "Set 'strict-origin-when-cross-origin' or 'no-referrer' for privacy.",
    "Permissions-Policy": "Restrict access to features like camera, geolocation, microphone.",
    "Expect-CT": "Enable Certificate Transparency to detect misissued certificates.",
    "Access-Control-Allow-Origin": "Set appropriate origin or disable if not needed (check CORS config).",
    "Cross-Origin-Opener-Policy": "Set to 'same-origin' to enable COOP for Spectre protection.",
    "Cross-Origin-Embedder-Policy": "Use 'require-corp' for cross-origin isolation.",
    "Cross-Origin-Resource-Policy": "Use 'same-origin' or 'same-site' to restrict resource sharing."
}

def scan_security_headers(url):
    try:
        res = requests.get(url, timeout=10)
        response_headers = {k.lower(): v for k, v in res.headers.items()}

        found = {}
        missing = []

        for header in EXPECTED_HEADERS:
            header_lc = header.lower()
            if header_lc in response_headers:
                found[header] = response_headers[header_lc]
            else:
                missing.append({
                    "header": header,
                    "severity": HEADER_SEVERITY.get(header, "unknown"),
                    "suggestion": HEADER_SUGGESTIONS.get(header, "Add this header to improve security.")
                })

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
            "missing_headers": [
                {
                    "header": h,
                    "severity": HEADER_SEVERITY.get(h, "unknown"),
                    "suggestion": HEADER_SUGGESTIONS.get(h, "Add this header to improve security.")
                } for h in EXPECTED_HEADERS
            ]
        }
