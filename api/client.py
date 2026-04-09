import requests
import urllib3
from config import FORTIGATE_IP, API_TOKEN, VERIFY_SSL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = f"https://{FORTIGATE_IP}/api/v2"
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

def get(endpoint):
    url = f"{BASE_URL}{endpoint}"
    response = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)
    return response.json()

def post(endpoint, data):
    url = f"{BASE_URL}{endpoint}"
    response = requests.post(url, headers=HEADERS, json=data, verify=VERIFY_SSL)
    return response.json()

def put(endpoint, data):
    url = f"{BASE_URL}{endpoint}"
    response = requests.put(url, headers=HEADERS, json=data, verify=VERIFY_SSL)
    return response.json()

def delete(endpoint):
    url = f"{BASE_URL}{endpoint}"
    response = requests.delete(url, headers=HEADERS, verify=VERIFY_SSL)
    return response.json()