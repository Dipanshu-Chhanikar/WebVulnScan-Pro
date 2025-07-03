import requests

def scan_clickjacking(url):
    try:
        res = requests.get(url, timeout=10)
        headers = res.headers

        x_frame_options = headers.get("X-Frame-Options", "").lower()
        csp = headers.get("Content-Security-Policy", "").lower()

        protected = False
        details = {}

        # Check for X-Frame-Options
        if "deny" in x_frame_options or "sameorigin" in x_frame_options:
            protected = True
            details["X-Frame-Options"] = x_frame_options

        # Check for CSP frame-ancestors directive
        if "frame-ancestors" in csp:
            protected = True
            details["Content-Security-Policy"] = csp

        return {
            "url": url,
            "protected": protected,
            "protection_details": details,
            "vulnerable": not protected
        }

    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "protected": False,
            "protection_details": {},
            "vulnerable": True
        }
