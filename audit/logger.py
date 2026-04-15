import json
import os
import hashlib
from datetime import datetime

# Audit log file location
AUDIT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
AUDIT_FILE = os.path.join(AUDIT_DIR, "audit.jsonl")  # .jsonl = one JSON object per line

# Make sure the logs directory exists
os.makedirs(AUDIT_DIR, exist_ok=True)


def _compute_hash(entry: dict) -> str:
    """
    Compute a SHA-256 hash of the log entry.
    This makes the log tamper-evident — if someone edits a line,
    the hash won't match anymore.
    """
    entry_str = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(entry_str.encode("utf-8")).hexdigest()


def log_action(
    action: str,
    user_input: str,
    tool_called: str,
    tool_input: str,
    result: str,
    status: str = "success",
    extra: dict = None
):
    """
    Write a structured audit entry to the log file.

    Parameters:
    - action      : short name of the action (e.g. 'CREATE_POLICY', 'LIST_ADDRESSES')
    - user_input  : the original message the user typed
    - tool_called : which tool function was called
    - tool_input  : what input was passed to the tool
    - result      : what the tool returned
    - status      : 'success' or 'error'
    - extra       : any additional metadata (optional dict)
    """
    timestamp = datetime.utcnow().isoformat() + "Z"

    entry = {
        "timestamp": timestamp,
        "action": action,
        "user_input": user_input,
        "tool_called": tool_called,
        "tool_input": tool_input,
        "result": result,
        "status": status,
        "extra": extra or {}
    }

    # Add tamper-evident hash AFTER building the entry
    entry["hash"] = _compute_hash({k: v for k, v in entry.items() if k != "hash"})

    # Append to the .jsonl file (one line per entry)
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return entry


def log_conversation(user_input: str, agent_response: str):
    """
    Log a full conversation turn (even when no tool was called).
    Useful for tracking what the agent said to the user.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"

    entry = {
        "timestamp": timestamp,
        "type": "conversation",
        "user_input": user_input,
        "agent_response": agent_response,
    }

    entry["hash"] = _compute_hash({k: v for k, v in entry.items() if k != "hash"})

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return entry


def read_logs(limit: int = 50, status_filter: str = None) -> list:
    """
    Read and return the last N audit entries.
    Optionally filter by status ('success' or 'error').
    """
    if not os.path.exists(AUDIT_FILE):
        return []

    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entries = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if status_filter and entry.get("status") != status_filter:
                continue
            entries.append(entry)
        except json.JSONDecodeError:
            continue

    # Return the last N entries
    return entries[-limit:]


def verify_integrity() -> dict:
    """
    Verify that no log entries have been tampered with.
    Returns a report with how many entries are valid vs corrupted.
    """
    if not os.path.exists(AUDIT_FILE):
        return {"total": 0, "valid": 0, "corrupted": 0, "corrupted_entries": []}

    total = 0
    valid = 0
    corrupted = []

    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            total += 1

            stored_hash = entry.pop("hash", None)
            expected_hash = _compute_hash(entry)

            if stored_hash == expected_hash:
                valid += 1
            else:
                corrupted.append({
                    "line": i + 1,
                    "timestamp": entry.get("timestamp"),
                    "stored_hash": stored_hash,
                    "expected_hash": expected_hash
                })
        except json.JSONDecodeError:
            corrupted.append({"line": i + 1, "error": "Invalid JSON"})

    return {
        "total": total,
        "valid": valid,
        "corrupted": len(corrupted),
        "corrupted_entries": corrupted
    }


def export_csv(output_path: str = None) -> str:
    """
    Export the audit log to a CSV file for compliance reports.
    """
    import csv

    if output_path is None:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(AUDIT_DIR, f"audit_export_{timestamp}.csv")

    entries = read_logs(limit=99999)  # get all entries

    if not entries:
        return "No audit entries to export."

    # Define CSV columns
    fieldnames = ["timestamp", "action", "user_input", "tool_called",
                  "tool_input", "result", "status", "hash"]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(entries)

    return f"Audit log exported to {output_path} ({len(entries)} entries)"