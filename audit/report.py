from audit.logger import read_logs, verify_integrity
from datetime import datetime


def generate_summary_report() -> str:
    """
    Generate a plain-text summary report of recent activity.
    This is what you'd show a security manager.
    """
    entries = read_logs(limit=99999)

    if not entries:
        return "No audit entries found."

    total = len(entries)
    successes = sum(1 for e in entries if e.get("status") == "success")
    errors = sum(1 for e in entries if e.get("status") == "error")

    # Count actions by type
    action_counts = {}
    for e in entries:
        action = e.get("action", "UNKNOWN")
        action_counts[action] = action_counts.get(action, 0) + 1

    # Most recent 5 entries
    recent = entries[-5:]

    report = []
    report.append("=" * 60)
    report.append("  FORTIGATE AGENT — AUDIT REPORT")
    report.append(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    report.append("=" * 60)
    report.append(f"\nTotal actions logged : {total}")
    report.append(f"Successful           : {successes}")
    report.append(f"Errors               : {errors}")

    report.append("\n--- Actions by type ---")
    for action, count in sorted(action_counts.items(), key=lambda x: -x[1]):
        report.append(f"  {action:<30} {count}")

    report.append("\n--- Last 5 actions ---")
    for e in recent:
        ts = e.get("timestamp", "?")
        action = e.get("action", "?")
        status = e.get("status", "?")
        user_input = e.get("user_input", "?")
        report.append(f"  [{ts}] {action} — {status}")
        report.append(f"    User said: \"{user_input}\"")

    # Integrity check
    integrity = verify_integrity()
    report.append("\n--- Integrity Check ---")
    report.append(f"  Valid entries    : {integrity['valid']}")
    report.append(f"  Corrupted entries: {integrity['corrupted']}")
    if integrity["corrupted"] > 0:
        report.append("  ⚠️  WARNING: Some log entries may have been tampered with!")

    report.append("=" * 60)
    return "\n".join(report)