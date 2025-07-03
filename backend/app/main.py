from fastapi import FastAPI
from app.db import scan_results
from app.scanners.sqli import run_sqlmap
from app.models import ScanResult
from app.scanners.xss_scanner import scan_xss
from app.scanners.csrf_scanner import scan_csrf
from app.scanners.open_redirect_scanner import scan_open_redirect
from app.scanners.security_headers_scanner import scan_security_headers
from app.scanners.clickjacking_scanner import scan_clickjacking

app = FastAPI()

@app.get("/")
def root():
    return {"message": "WebVulnScan-Pro API"}

@app.post("/scan/sqli")
def scan_sqli(target: str):
    output = run_sqlmap(target)
    record = {
        "target_url": target,
        "scanner": "SQL Injection",
        "result": output
    }
    scan_results.insert_one(record)
    return {"status": "done", "details": output[:1000]}  # trim large output

@app.post("/scan/xss")
async def run_xss_scan(target: str):
    results = scan_xss(target)
    # Save to MongoDB if needed
    return {
        "target": target,
        "vulnerable": results["vulnerable"],
        "payloads": results["payloads"],
        "reflected_urls": results["reflected"]
    }

@app.post("/scan/csrf")
async def run_csrf_scan(target: str):
    results = scan_csrf(target)
    return results

@app.post("/scan/open-redirect")
async def run_open_redirect_scan(target: str):
    results = scan_open_redirect(target)
    return results

@app.post("/scan/security-headers")
async def run_security_headers_scan(target: str):
    return scan_security_headers(target)

@app.post("/scan/clickjacking")
async def run_clickjacking_scan(target: str):
    return scan_clickjacking(target)