import json
import os
import hashlib
from datetime import datetime

AUDIT_DIR  = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
AUDIT_FILE = os.path.join(AUDIT_DIR, "audit.jsonl")

os.makedirs(AUDIT_DIR, exist_ok=True)


def _compute_hash(entry: dict) -> str:
    entry_str = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(entry_str.encode("utf-8")).hexdigest()


def log_action(action: str, user_input: str, tool_called: str,
               tool_input: str, result: str,
               status: str = "success", extra: dict = None):
    """
    Write a structured audit entry for a tool execution.
    FIX: added explicit type='action' field so report filtering
    is reliable and does not depend on the absence of a field.
    """
    ts = datetime.utcnow().isoformat() + "Z"
    entry = {
        "type":        "action",       # FIX: explicit type field
        "timestamp":   ts,
        "action":      action,
        "user_input":  user_input,
        "tool_called": tool_called,
        "tool_input":  tool_input,
        "result":      result,
        "status":      status,
        "extra":       extra or {},
    }
    entry["hash"] = _compute_hash({k: v for k, v in entry.items() if k != "hash"})
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def log_conversation(user_input: str, agent_response: str):
    """Write a conversation turn to the audit log."""
    ts = datetime.utcnow().isoformat() + "Z"
    entry = {
        "type":           "conversation",
        "timestamp":      ts,
        "user_input":     user_input,
        "agent_response": agent_response,
    }
    entry["hash"] = _compute_hash({k: v for k, v in entry.items() if k != "hash"})
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def read_logs(limit: int = 50, status_filter: str = None) -> list:
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
    return entries[-limit:]


def verify_integrity() -> dict:
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
            expected    = _compute_hash(entry)
            if stored_hash == expected:
                valid += 1
            else:
                corrupted.append({
                    "line":        i + 1,
                    "timestamp":   entry.get("timestamp"),
                    "stored_hash": stored_hash,
                    "expected":    expected,
                })
        except json.JSONDecodeError:
            corrupted.append({"line": i + 1, "error": "Invalid JSON"})

    return {
        "total":             total,
        "valid":             valid,
        "corrupted":         len(corrupted),
        "corrupted_entries": corrupted,
    }


def export_csv(output_path: str = None) -> str:
    import csv
    if output_path is None:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(AUDIT_DIR, f"audit_export_{ts}.csv")
    entries = read_logs(limit=99999)
    if not entries:
        return "No audit entries to export."
    fieldnames = ["timestamp", "type", "action", "user_input",
                  "tool_called", "tool_input", "result", "status", "hash"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(entries)
    return f"Exported {len(entries)} entries to {output_path}"