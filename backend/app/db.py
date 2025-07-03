from datetime import datetime
from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["WebVulnScanPro"]
collection = db["scan_results"]

def save_scan_result(scan_type, target_url, result):
    record = {
        "type": scan_type,
        "target": target_url,
        "result": result,
        "timestamp": datetime.utcnow()
    }
    collection.insert_one(record)
