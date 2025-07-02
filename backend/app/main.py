from fastapi import FastAPI
from app.db import scan_results
from app.scanners.sqli import run_sqlmap
from app.models import ScanResult
from app.scanners.xss_scanner import scan_xss

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