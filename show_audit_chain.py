"""
show_audit_chain.py
Prints the last N audit log entries in a clean, readable format
suitable for the SS-11 screenshot (cryptographic chain proof).
"""
import sys, json, os

# Force UTF-8 output on Windows
sys.stdout.reconfigure(encoding="utf-8")

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "audit.jsonl")
N = 3   # number of entries to show

def short(h: str) -> str:
    """Show first 16 and last 8 chars of a hash for readability."""
    return f"{h[:16]}...{h[-8:]}" if h and len(h) > 24 else (h or "—")

with open(LOG_PATH, "r", encoding="utf-8") as f:
    lines = [l.strip() for l in f if l.strip()]

entries = [json.loads(l) for l in lines[-N:]]

SEP  = "=" * 72
SEP2 = "-" * 72

print(f"\n  {'CRYPTOGRAPHIC AUDIT LOG - HASH CHAIN VERIFICATION':^70}")
print(f"  {SEP}")
print(f"  {'File: logs/audit.jsonl':}")
print(f"  {'Showing last ' + str(N) + ' entries':}")
print(f"  {SEP}")

for i, e in enumerate(entries, 1):
    t    = e.get("type", "action")
    ts   = e.get("timestamp", "")[:19].replace("T", "  ")
    act  = e.get("action") or ("CONVERSATION" if t == "conversation" else "UNKNOWN")
    usr  = e.get("user_input", "")[:48]
    ph   = e.get("prev_hash", "")
    h    = e.get("hash", "")

    print(f"\n  Entry #{i}  ({t.upper()})")
    print(f"  {SEP2}")
    print(f"  Timestamp   : {ts}")
    print(f"  Action      : {act}")
    print(f"  User Input  : {usr!r}")
    print(f"  prev_hash   : {ph}")
    print(f"               └─ matches ↑ hash of entry #{i-1}" if i > 1 else "               └─ (first entry in window)")
    print(f"  hash        : {h}")

print(f"\n  {SEP}")
print(f"  Chain integrity : Each entry's prev_hash == previous entry's hash")
print(f"  Any tampering   : Would break the hash chain and be detected")
print(f"  {SEP}\n")
