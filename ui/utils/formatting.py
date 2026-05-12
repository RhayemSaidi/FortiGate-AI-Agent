"""
formatting.py — Text → structured HTML renderers.
"""
from __future__ import annotations

import re


def escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )


def render_policy_table(raw: str) -> str:
    """
    Convert a pipe-separated ASCII policy table into styled HTML.
    Returns the HTML string, or the raw text if no table detected.
    """
    lines = [l.strip() for l in raw.strip().splitlines()]
    table_lines = [l for l in lines if "|" in l]
    if len(table_lines) < 2:
        return f"<div style='font-family:JetBrains Mono,monospace;font-size:0.84rem;white-space:pre-wrap;color:#c9d1d9'>{escape_html(raw)}</div>"

    header_idx = 0
    header = [c.strip() for c in table_lines[0].split("|") if c.strip()]
    rows   = []
    for line in table_lines[1:]:
        if re.match(r'^[\|\-\s]+$', line):
            continue
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if cells:
            rows.append(cells)

    # Build HTML table
    th_cells = "".join(f"<th>{escape_html(h)}</th>" for h in header)
    tr_rows  = ""
    for row in rows:
        cells = "".join(
            f"<td>{_colorise_cell(header[i] if i < len(header) else '', cell)}</td>"
            for i, cell in enumerate(row)
        )
        tr_rows += f"<tr>{cells}</tr>"

    return f"""
<table style="width:100%;border-collapse:collapse;font-size:0.82rem;
font-family:'JetBrains Mono',monospace;margin:0.5rem 0;">
<thead><tr style="background:#21262d;">{th_cells}</tr></thead>
<tbody>{tr_rows}</tbody>
</table>"""


def _colorise_cell(header: str, value: str) -> str:
    """Apply semantic colour to known cell values."""
    h = header.lower()
    v = value.lower()

    if h == "action":
        if v == "accept":
            return f'<span style="color:#3fb950;font-weight:600">{escape_html(value)}</span>'
        if v in ("deny", "drop"):
            return f'<span style="color:#f85149;font-weight:600">{escape_html(value)}</span>'

    if h == "status":
        if v in ("enable", "enabled"):
            return f'<span style="color:#3fb950">{escape_html(value)}</span>'
        if v in ("disable", "disabled"):
            return f'<span style="color:#8b949e">{escape_html(value)}</span>'

    if h == "nat":
        if v in ("enable", "enabled"):
            return f'<span style="color:#58a6ff">{escape_html(value)}</span>'

    if "[error]" in v or "fail" in v:
        return f'<span style="color:#f85149">{escape_html(value)}</span>'
    if "[success]" in v or "ok" in v:
        return f'<span style="color:#3fb950">{escape_html(value)}</span>'

    return escape_html(value)


def parse_verification_block(text: str) -> dict:
    """
    Parse a verification result block from agent output.
    Returns dict with: passed, fields, mismatches.
    """
    passed     = "[Verified" in text and "WARNING" not in text
    fields     = re.findall(r'\[Verified.*?\]\n(.*?)(?=\n\[|$)', text, re.S)
    mismatches = re.findall(r'MISMATCH: (.+)', text)
    return {
        "passed":     passed,
        "fields":     [f.strip() for f in fields],
        "mismatches": mismatches,
    }


def detect_content_type(text: str) -> str:
    """
    Returns: 'table' | 'verification' | 'confirmation' | 'error' | 'security' | 'text'
    """
    if "CONFIRMATION REQUIRED" in text:
        return "confirmation"
    if "[Verified" in text or "MISMATCH:" in text:
        return "verification"
    if re.search(r'\|[-\s|]+\|', text):
        return "table"
    if any(k in text for k in ("CRITICAL:", "HIGH:", "MEDIUM:", "LOW:", "INFO:")):
        return "security"
    if "[ERROR]" in text.upper() or "OPERATION FAILED:" in text:
        return "error"
    return "text"