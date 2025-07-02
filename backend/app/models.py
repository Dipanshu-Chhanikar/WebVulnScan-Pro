from pydantic import BaseModel
from typing import Optional, List

class ScanResult(BaseModel):
    target_url: str
    scanner: str
    result: str
    timestamp: Optional[str] = None
