import requests
import urllib3
from config import FORTIGATE_IP, API_TOKEN, VERIFY_SSL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = f"https://{FORTIGATE_IP}/api/v2"
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

import logging

logger = logging.getLogger("fortigate_agent")

import time

def _safe_request(method: str, url: str, retries: int = 3, **kwargs) -> dict:
    """Execute a request safely, with exponential backoff for network/transient errors."""
    kwargs.setdefault('timeout', 10)
    
    for attempt in range(retries):
        try:
            response = requests.request(method, url, headers=HEADERS, verify=VERIFY_SSL, **kwargs)
            
            # If 502/503/504, we should retry. Otherwise, break and process.
            if response.status_code in (502, 503, 504) and attempt < retries - 1:
                wait_time = 2 ** attempt
                logger.warning(f"[API RETRY] {response.status_code} on {url}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue

            try:
                data = response.json()
                if isinstance(data, dict) and response.status_code >= 400 and "status" not in data:
                    data["status"] = "error"
                    data["http_status"] = response.status_code
                return data
            except ValueError:
                error_msg = f"Invalid JSON response (HTTP {response.status_code})"
                logger.error(f"[API ERROR] {error_msg}: {response.text[:200]}")
                return {"status": "error", "error": error_msg, "http_status": response.status_code}
                
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                wait_time = 2 ** attempt
                logger.warning(f"[API TIMEOUT] on {url}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
            logger.error(f"[API TIMEOUT] Reached timeout connecting to {url} after {retries} attempts.")
            return {"status": "error", "error": "Connection timed out. The FortiGate may be offline."}
            
        except requests.exceptions.RequestException as e:
            # Immediate fail on hard network errors (e.g. DNS failure, connection refused)
            logger.error(f"[API NETWORK ERROR] Failed to connect: {e}")
            return {"status": "error", "error": f"Network error: {str(e)}"}
            
    return {"status": "error", "error": "Max retries exceeded."}

def get(endpoint):
    return _safe_request("GET", f"{BASE_URL}{endpoint}")

def post(endpoint, data=None):
    return _safe_request("POST", f"{BASE_URL}{endpoint}", json=data or {})

def put(endpoint, data):
    return _safe_request("PUT", f"{BASE_URL}{endpoint}", json=data)

def delete(endpoint):
    return _safe_request("DELETE", f"{BASE_URL}{endpoint}")