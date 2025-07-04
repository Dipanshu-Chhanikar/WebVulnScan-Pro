import requests
import re

def scan_clickjacking(url):
    try:
        res = requests.get(url, timeout=10)
        headers = res.headers
        body = res.text.lower()

        x_frame_options = headers.get("X-Frame-Options", "").lower()
        csp = headers.get("Content-Security-Policy", "").lower()

        protected = False
        details = {}
        severity = "medium"
        suggestion = "Set 'X-Frame-Options' to 'DENY' or 'SAMEORIGIN', or use CSP with 'frame-ancestors'."

        # --- X-Frame-Options analysis ---
        if x_frame_options in ["deny", "sameorigin"]:
            protected = True
            details["X-Frame-Options"] = x_frame_options
        elif x_frame_options:
            details["X-Frame-Options"] = f"⚠️ Weak or deprecated value: {x_frame_options}"

        # --- CSP frame-ancestors analysis ---
        frame_ancestors_match = re.search(r"frame-ancestors\s+([^;]+)", csp)
        if frame_ancestors_match:
            ancestors_value = frame_ancestors_match.group(1).strip()
            if ancestors_value in ["'none'", "'self'"]:
                protected = True
                details["Content-Security-Policy"] = f"✅ frame-ancestors: {ancestors_value}"
            else:
                details["Content-Security-Policy"] = f"⚠️ Weak frame-ancestors: {ancestors_value}"

        # --- Meta tag fallback (legacy) ---
        if not protected and '<meta http-equiv="x-frame-options"' in body:
            protected = True
            details["Meta-Tag"] = "⚠️ Found legacy <meta http-equiv='X-Frame-Options'> tag"

        # --- Final severity/suggestion ---
        if not x_frame_options and not frame_ancestors_match:
            details["protection"] = "❌ No anti-clickjacking headers present"

        if protected:
            severity = "none"
            suggestion = "Already protected against clickjacking."

        return {
            "url": url,
            "protected": protected,
            "vulnerable": not protected,
            "protection_details": details,
            "severity": severity,
            "suggestion": suggestion
        }

    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "protected": False,
            "vulnerable": True,
            "protection_details": {},
            "severity": "medium",
            "suggestion": "Ensure the site sets 'X-Frame-Options' or CSP 'frame-ancestors' to prevent clickjacking."
        }
