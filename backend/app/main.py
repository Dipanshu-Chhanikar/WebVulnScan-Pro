from fastapi import FastAPI
from app.db import scan_results
from app.scanners.sqli import run_sqlmap
from app.models import ScanResult

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
