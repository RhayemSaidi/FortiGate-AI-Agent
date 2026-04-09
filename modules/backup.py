from api.client import get
import datetime

def backup_config(save_path=None):
    """Download and save the FortiGate configuration locally"""
    import requests
    from config import FORTIGATE_IP, API_TOKEN, VERIFY_SSL

    url = f"https://{FORTIGATE_IP}/api/v2/monitor/system/config/backup?scope=global"
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    response = requests.get(url, headers=headers, verify=VERIFY_SSL)

    if save_path is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = f"backup_{timestamp}.conf"

    with open(save_path, "w") as f:
        f.write(response.text)

    return f"Config saved to {save_path}"