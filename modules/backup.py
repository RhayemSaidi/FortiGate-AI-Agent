import os
import datetime
import requests
from config import FORTIGATE_IP, API_TOKEN, VERIFY_SSL


def backup_config(save_path: str = None) -> str:
    """
    Download and save the FortiGate configuration locally.
    FIX: removed broken FortiOS 6.x fallback (wrong endpoint).
    FIX: added explicit timeout to prevent hanging.
    """
    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type":  "application/json",
    }

    # FortiOS 7.x endpoints only — scope=global preferred, scope=vdom as fallback
    strategies = [
        {
            "label":  "scope=global",
            "url":    f"https://{FORTIGATE_IP}/api/v2/monitor/system/config/backup",
            "params": {"scope": "global"},
        },
        {
            "label":  "scope=vdom root",
            "url":    f"https://{FORTIGATE_IP}/api/v2/monitor/system/config/backup",
            "params": {"scope": "vdom", "vdom": "root"},
        },
    ]

    last_error = "No strategy attempted."

    for strategy in strategies:
        try:
            response = requests.get(
                strategy["url"],
                headers=headers,
                params=strategy["params"],
                verify=VERIFY_SSL,
                timeout=20,
            )

            if response.status_code == 401:
                return "[BACKUP FAILED] Authentication error — check API token permissions."
            if response.status_code == 403:
                return "[BACKUP FAILED] Forbidden — API token lacks System Config read permission."
            if response.status_code == 405:
                last_error = f"405 on strategy '{strategy['label']}'"
                continue

            response.raise_for_status()

            content = response.text
            if not content or not content.strip():
                last_error = f"Empty response from strategy '{strategy['label']}'"
                continue

            # A real config starts with '#config-version' — JSON means failure
            if content.strip().startswith("{"):
                last_error = f"JSON response (not config) from '{strategy['label']}'"
                continue

            if save_path is None:
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                save_path = f"backup_{ts}.conf"

            parent = os.path.dirname(save_path)
            if parent:
                os.makedirs(parent, exist_ok=True)

            with open(save_path, "w", encoding="utf-8") as f:
                f.write(content)

            size_kb = len(content.encode("utf-8")) / 1024
            return (
                f"Configuration backed up to '{save_path}' "
                f"({size_kb:.1f} KB) — strategy: {strategy['label']}"
            )

        except requests.exceptions.ConnectTimeout:
            return (
                f"[BACKUP FAILED] Connection timed out reaching {FORTIGATE_IP}. "
                f"Check network connectivity."
            )
        except requests.exceptions.ConnectionError:
            return (
                f"[BACKUP FAILED] Cannot connect to {FORTIGATE_IP}. "
                f"Check IP address and network."
            )
        except requests.exceptions.HTTPError as exc:
            last_error = f"HTTP error on '{strategy['label']}': {exc}"
            continue
        except OSError as exc:
            return f"[BACKUP FAILED] Cannot write file to disk: {exc}"
        except Exception as exc:
            last_error = f"Unexpected error on '{strategy['label']}': {exc}"
            continue

    return (
        f"[BACKUP FAILED] All strategies failed.\n"
        f"Last error: {last_error}\n"
        f"Check: API token permissions, REST API enabled, FortiOS version."
    )