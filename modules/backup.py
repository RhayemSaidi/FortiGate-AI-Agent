import os
import datetime
import requests
from config import FORTIGATE_IP, API_TOKEN, VERIFY_SSL


def backup_config(save_path: str = None) -> str:
    """
    Download and save the FortiGate configuration locally.

    Tries multiple endpoint strategies to handle differences
    across FortiOS versions (6.x, 7.0, 7.2, 7.4+).

    Returns a human-readable result string — never raises.
    """
    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json",
    }

    # ── Endpoint strategies in priority order ─────────────
    # FortiOS 7.2+ recommends scope=global on the monitor API.
    # FortiOS 7.0 sometimes requires scope=vdom.
    # FortiOS 6.x uses a different base path.
    endpoint_strategies = [
        {
            "label":  "FortiOS 7.x (scope=global)",
            "method": "GET",
            "url":    f"https://{FORTIGATE_IP}/api/v2/monitor/system/config/backup",
            "params": {"scope": "global"},
        },
        {
            "label":  "FortiOS 7.x (scope=vdom root)",
            "method": "GET",
            "url":    f"https://{FORTIGATE_IP}/api/v2/monitor/system/config/backup",
            "params": {"scope": "vdom", "vdom": "root"},
        },
        {
            "label":  "FortiOS 6.x fallback",
            "method": "GET",
            "url":    f"https://{FORTIGATE_IP}/api/v2/cmdb/system/config/backup",
            "params": {},
        },
    ]

    last_error = "No strategy was attempted."

    for strategy in endpoint_strategies:
        try:
            response = requests.request(
                method=strategy["method"],
                url=strategy["url"],
                headers=headers,
                params=strategy["params"],
                verify=VERIFY_SSL,
                timeout=20,
            )

            # ── HTTP-level error handling ─────────────────
            if response.status_code == 405:
                last_error = (
                    f"405 Method Not Allowed — strategy '{strategy['label']}' "
                    f"rejected. Trying next."
                )
                continue

            if response.status_code == 401:
                return (
                    "[BACKUP FAILED] Authentication error — "
                    "check your API token and its admin profile permissions."
                )

            if response.status_code == 403:
                return (
                    "[BACKUP FAILED] Forbidden — the API token does not have "
                    "'System Config' read permissions. "
                    "Update the admin profile on the FortiGate."
                )

            response.raise_for_status()

            # ── Content validation ────────────────────────
            # A successful backup returns plain text starting with '#config-version'.
            # If we get JSON back the endpoint silently failed.
            content = response.text
            if not content or not content.strip():
                last_error = (
                    f"Strategy '{strategy['label']}' returned an empty response."
                )
                continue

            if content.strip().startswith("{"):
                # JSON error response rather than config text
                last_error = (
                    f"Strategy '{strategy['label']}' returned JSON instead of "
                    f"config text: {content[:200]}"
                )
                continue

            # ── Resolve save path ─────────────────────────
            if save_path is None:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                resolved_path = f"backup_{timestamp}.conf"
            else:
                resolved_path = save_path

            # ── Ensure parent directory exists ────────────
            parent_dir = os.path.dirname(resolved_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

            # ── Write with explicit UTF-8 encoding ───────
            with open(resolved_path, "w", encoding="utf-8") as f:
                f.write(content)

            size_kb = len(content.encode("utf-8")) / 1024
            return (
                f"Configuration backed up successfully to '{resolved_path}' "
                f"({size_kb:.1f} KB) — using strategy: {strategy['label']}"
            )

        except requests.exceptions.ConnectTimeout:
            return (
                "[BACKUP FAILED] Connection timed out. "
                f"Verify FortiGate is reachable at {FORTIGATE_IP}."
            )
        except requests.exceptions.ConnectionError:
            return (
                f"[BACKUP FAILED] Cannot connect to FortiGate at {FORTIGATE_IP}. "
                "Check IP address and network connectivity."
            )
        except requests.exceptions.HTTPError as exc:
            last_error = (
                f"HTTP error on strategy '{strategy['label']}': {exc}"
            )
            continue
        except OSError as exc:
            return f"[BACKUP FAILED] Could not write file to disk: {exc}"
        except Exception as exc:
            last_error = f"Unexpected error on strategy '{strategy['label']}': {exc}"
            continue

    # ── All strategies exhausted ──────────────────────────
    return (
        f"[BACKUP FAILED] All endpoint strategies failed.\n"
        f"Last error : {last_error}\n"
        f"Possible causes:\n"
        f"  1. API token lacks 'System > Config' read permission.\n"
        f"  2. FortiGate REST API is disabled "
        f"(check System > Administrators > REST API).\n"
        f"  3. Your FortiOS version uses an unsupported endpoint variant.\n"
        f"     Run 'get system status' on the CLI to confirm firmware version."
    )