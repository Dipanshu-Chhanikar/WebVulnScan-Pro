from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
from bson import json_util
import json

from app.db import save_scan_result, collection
from app.models import ScanResult
from app.scanners.sqli_scanner import scan_sql_injection
from app.scanners.xss_scanner import scan_xss
from app.scanners.csrf_scanner import scan_csrf
from app.scanners.open_redirect_scanner import scan_open_redirect
from app.scanners.security_headers_scanner import scan_security_headers
from app.scanners.clickjacking_scanner import scan_clickjacking
from app.scanners.path_traversal_scanner import scan_path_traversal
from app.scanners.rce_scanner import scan_rce

app = FastAPI()

# Enable CORS for frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # You can restrict this to your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "WebVulnScan-Pro API"}

@app.post("/scan/sqli")
def run_sqli_scan(target: str = Query(...)):
    result = scan_sql_injection(target)
    save_scan_result("SQL Injection", target, result)
    return result

@app.post("/scan/xss")
async def run_xss_scan(target: str):
    result = scan_xss(target)
    save_scan_result("XSS", target, result)
    return result

@app.post("/scan/csrf")
async def run_csrf_scan(target: str):
    result = scan_csrf(target)
    save_scan_result("CSRF", target, result)
    return result

@app.post("/scan/open-redirect")
async def run_open_redirect_scan(target: str):
    result = scan_open_redirect(target)
    save_scan_result("Open Redirect", target, result)
    return result

@app.post("/scan/security-headers")
async def run_security_headers_scan(target: str):
    result = scan_security_headers(target)
    save_scan_result("Security Headers", target, result)
    return result

@app.post("/scan/clickjacking")
async def run_clickjacking_scan(target: str):
    result = scan_clickjacking(target)
    save_scan_result("Clickjacking", target, result)
    return result

@app.post("/scan/path-traversal")
async def run_path_traversal_scan(target: str):
    result = scan_path_traversal(target)
    save_scan_result("Path Traversal", target, result)
    return result

@app.post("/scan/rce")
async def run_rce_scan(target: str):
    result = scan_rce(target)
    save_scan_result("RCE", target, result)
    return result

@app.post("/scan/all")
async def run_full_scan(target: str):
    xss = scan_xss(target)
    csrf = scan_csrf(target)
    redirect = scan_open_redirect(target)
    headers = scan_security_headers(target)
    clickjacking = scan_clickjacking(target)

    full_result = {
        "target": target,
        "xss": xss,
        "csrf": csrf,
        "open_redirect": redirect,
        "security_headers": headers,
        "clickjacking": clickjacking,
    }

    save_scan_result("FULL", target, full_result)
    return full_result

@app.get("/history")
async def get_scan_history(limit: int = 20):
    try:
        results = collection.find().sort("timestamp", -1).limit(limit)
        json_results = json.loads(json_util.dumps(list(results)))
        return JSONResponse(content=json_results)
    except Exception as e:
        return {"error": str(e)}
