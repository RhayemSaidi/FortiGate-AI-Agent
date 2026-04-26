from audit.logger import read_logs, verify_integrity
from datetime import datetime


def generate_summary_report() -> str:
    entries = read_logs(limit=99999)
    if not entries:
        return "No audit entries found."

    # FIX: filter by explicit type field instead of absence of field
    tool_entries = [e for e in entries if e.get("type") == "action"]
    conv_entries = [e for e in entries if e.get("type") == "conversation"]

    total_tool = len(tool_entries)
    total_conv = len(conv_entries)
    successes  = sum(1 for e in tool_entries if e.get("status") == "success")
    errors     = sum(1 for e in tool_entries if e.get("status") == "error")
    cancelled  = sum(1 for e in tool_entries if e.get("status") == "cancelled")

    action_counts: dict = {}
    for e in tool_entries:
        action = e.get("action", "UNKNOWN")
        action_counts[action] = action_counts.get(action, 0) + 1

    report = []
    report.append("=" * 60)
    report.append("  FORTIGATE AGENT — AUDIT REPORT")
    report.append(f"  Generated : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    report.append("=" * 60)

    report.append("\n── STATISTICS ──────────────────────────────────────────")
    report.append(f"  Tool actions logged      : {total_tool}")
    report.append(f"  Successful               : {successes}")
    report.append(f"  Failed                   : {errors}")
    report.append(f"  Cancelled                : {cancelled}")
    report.append(f"  Conversation turns logged: {total_conv}")

    if action_counts:
        report.append("\n── ACTIONS BY TYPE ─────────────────────────────────────")
        for action, count in sorted(action_counts.items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 30)
            report.append(f"  {action:<40} {bar} ({count})")

    if tool_entries:
        report.append("\n── LAST 5 TOOL ACTIONS ─────────────────────────────────")
        for e in tool_entries[-5:]:
            ts         = e.get("timestamp", "?")[:19].replace("T", " ")
            action     = e.get("action", "?")
            status     = e.get("status", "?")
            user_input = e.get("user_input", "?")
            result     = e.get("result", "?")
            icon = "OK" if status == "success" else ("XX" if status == "error" else "--")
            report.append(f"\n  [{icon}] [{ts}] {action}")
            report.append(f"       User   : \"{user_input}\"")
            report.append(f"       Result : {str(result)[:80]}{'...' if len(str(result)) > 80 else ''}")

    if conv_entries:
        report.append("\n── LAST 5 CONVERSATION TURNS ───────────────────────────")
        for e in conv_entries[-5:]:
            ts         = e.get("timestamp", "?")[:19].replace("T", " ")
            user_input = e.get("user_input", "?")
            response   = e.get("agent_response", "?")
            report.append(f"\n  [{ts}]")
            report.append(f"     User  : \"{user_input}\"")
            report.append(f"     Agent : \"{str(response)[:100]}{'...' if len(str(response)) > 100 else ''}\"")

    integrity = verify_integrity()
    report.append("\n── INTEGRITY CHECK ─────────────────────────────────────")
    report.append(f"  Total entries   : {integrity['total']}")
    report.append(f"  Valid entries   : {integrity['valid']}")
    report.append(f"  Corrupted       : {integrity['corrupted']}")
    if integrity["corrupted"] > 0:
        report.append("  WARNING: Tampered entries detected!")
        for c in integrity["corrupted_entries"]:
            report.append(f"     Line {c.get('line')}: {c.get('timestamp', 'unknown')}")
    else:
        report.append("  All entries verified — no tampering detected.")

    report.append("\n" + "=" * 60)
    return "\n".join(report)


def generate_error_report() -> str:
    entries = read_logs(limit=99999, status_filter="error")
    if not entries:
        return "No errors found in audit log."

    report = ["=" * 60, "  FORTIGATE AGENT — ERROR REPORT",
              f"  Generated : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
              "=" * 60]

    for e in entries:
        ts = e.get("timestamp", "?")[:19].replace("T", " ")
        report.append(f"\n  [ERROR] [{ts}]")
        report.append(f"     Action     : {e.get('action', '?')}")
        report.append(f"     User said  : \"{e.get('user_input', '?')}\"")
        report.append(f"     Tool input : {e.get('tool_input', '?')}")
        report.append(f"     Error      : {e.get('result', '?')}")

    report.append("\n" + "=" * 60)
    return "\n".join(report)