import os
import datetime
import requests
from config import FORTIGATE_IP, API_TOKEN, VERIFY_SSL


def backup_config(save_path=None):
    """Download and save the FortiGate configuration locally."""
    url = f"https://{FORTIGATE_IP}/api/v2/monitor/system/config/backup?scope=global"
    headers = {"Authorization": f"Bearer {API_TOKEN}"}

    try:
        response = requests.get(
            url,
            headers=headers,
            verify=VERIFY_SSL,
            timeout=15  # 15 second timeout
        )
        response.raise_for_status()
    except requests.exceptions.ConnectTimeout:
        return "Backup failed: Connection to FortiGate timed out. Check network connectivity."
    except requests.exceptions.ConnectionError:
        return "Backup failed: Cannot reach FortiGate at the configured IP."
    except Exception as e:
        return f"Backup failed: {str(e)}"

    if save_path is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = f"backup_{timestamp}.conf"

    with open(save_path, "w") as f:
        f.write(response.text)

    return f"Configuration backed up successfully to {save_path}"