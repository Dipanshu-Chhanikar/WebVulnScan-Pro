from fastapi import FastAPI, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
from bson import json_util
import json
from time import time  # ⏱️ for duration tracking

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
    start = time()
    result = scan_sql_injection(target)
    result["duration"] = f"{round(time() - start, 2)} seconds"
    save_scan_result("SQL Injection", target, result)
    return result


@app.post("/scan/xss")
async def run_xss_scan(target: str):
    start = time()
    result = scan_xss(target)
    result["duration"] = f"{round(time() - start, 2)} seconds"
    save_scan_result("XSS", target, result)
    return result


@app.post("/scan/csrf")
async def run_csrf_scan(target: str):
    start = time()
    result = scan_csrf(target)
    result["duration"] = f"{round(time() - start, 2)} seconds"
    save_scan_result("CSRF", target, result)
    return result


@app.post("/scan/open-redirect")
async def run_open_redirect_scan(target: str):
    start = time()
    result = scan_open_redirect(target)
    result["duration"] = f"{round(time() - start, 2)} seconds"
    save_scan_result("Open Redirect", target, result)
    return result


@app.post("/scan/security-headers")
async def run_security_headers_scan(target: str):
    start = time()
    result = scan_security_headers(target)
    result["duration"] = f"{round(time() - start, 2)} seconds"
    save_scan_result("Security Headers", target, result)
    return result


@app.post("/scan/clickjacking")
async def run_clickjacking_scan(target: str):
    start = time()
    result = scan_clickjacking(target)
    result["duration"] = f"{round(time() - start, 2)} seconds"
    save_scan_result("Clickjacking", target, result)
    return result


@app.post("/scan/path-traversal")
async def run_path_traversal_scan(target: str):
    start = time()
    result = scan_path_traversal(target)
    result["duration"] = f"{round(time() - start, 2)} seconds"
    save_scan_result("Path Traversal", target, result)
    return result


@app.post("/scan/rce")
async def run_rce_scan(target: str):
    start = time()
    result = scan_rce(target)
    result["duration"] = f"{round(time() - start, 2)} seconds"
    save_scan_result("RCE", target, result)
    return result


# ✅ Background full scan with total duration
def perform_full_scan(target: str):
    start = time()
    xss = scan_xss(target)
    csrf = scan_csrf(target)
    redirect = scan_open_redirect(target)
    headers = scan_security_headers(target)
    clickjacking = scan_clickjacking(target)
    sqli = scan_sql_injection(target)
    path = scan_path_traversal(target)
    rce = scan_rce(target)
    end = time()

    total_duration = round(end - start, 2)

    full_result = {
        "xss": xss,
        "csrf": csrf,
        "open_redirect": redirect,
        "security_headers": headers,
        "clickjacking": clickjacking,
        "sql_injection": sqli,
        "path_traversal": path,
        "rce": rce,
        "total_duration": f"{total_duration} seconds"
    }

    save_scan_result("FULL", target, {
        "target": target,
        **full_result
    })


@app.post("/scan/all")
async def run_full_scan(target: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(perform_full_scan, target)
    return {"message": f"Full scan started for {target}. Results will be saved soon."}


@app.get("/history")
async def get_scan_history(skip: int = 0, limit: int = 10):
    try:
        results = collection.find().sort("timestamp", -1).skip(skip).limit(limit)
        json_results = json.loads(json_util.dumps(list(results)))
        return JSONResponse(content=json_results)
    except Exception as e:
        return {"error": str(e)}
