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


def md_to_html(text: str) -> str:
    """
    Markdown → HTML: bold, italic, inline code, line breaks.
    Preserves monospace blocks.
    """
    text = escape_html(text)
    
    # Extract multi-line code blocks to prevent mangling
    code_blocks = []
    def replace_block(match):
        code = match.group(1).strip()
        if "\n" in code:
            first_line, rest = code.split("\n", 1)
            # Remove language identifier if present
            if not first_line.strip() or first_line.strip().isalnum():
                code = rest.strip()
        code_blocks.append(f'<div class="mono-out">{code}</div>')
        return f"__CODE_BLOCK_{len(code_blocks)-1}__"
        
    text = re.sub(r'```(.*?)```', replace_block, text, flags=re.DOTALL)

    # Process inline markdown
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.+?)\*',     r'<em>\1</em>', text)
    text = re.sub(r'`([^`]+)`',     r'<code>\1</code>', text)
    
    # Line breaks for standard text
    text = text.replace("\n", "<br>")
    
    # Restore multi-line blocks
    for i, block in enumerate(code_blocks):
        text = text.replace(f"__CODE_BLOCK_{i}__", block)
        
    return text


def render_policy_table(raw: str) -> str:
    """
    Convert a pipe-separated ASCII table into a styled HTML table.
    Returns empty string if no table detected.
    """
    lines       = [l.strip() for l in raw.strip().splitlines()]
    table_lines = [l for l in lines if "|" in l]
    if len(table_lines) < 2:
        return (
            f'<div class="mono-block">{escape_html(raw)}</div>'
        )

    header = [c.strip() for c in table_lines[0].split("|") if c.strip()]
    rows   = []
    for line in table_lines[1:]:
        if re.match(r'^[\|\-\s]+$', line):
            continue
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if cells:
            rows.append(cells)

    th_cells = "".join(f"<th>{escape_html(h)}</th>" for h in header)
    tr_rows  = ""
    for row in rows:
        cells_html = ""
        for i, cell in enumerate(row):
            h     = header[i].lower() if i < len(header) else ""
            styled = _style_cell(h, cell)
            cells_html += f"<td>{styled}</td>"
        tr_rows += f"<tr>{cells_html}</tr>"

    return (
        f'<div style="overflow-x:auto;margin:0.5rem 0">'
        f'<table class="policy-table">'
        f'<thead><tr>{th_cells}</tr></thead>'
        f'<tbody>{tr_rows}</tbody>'
        f'</table></div>'
    )


def _style_cell(header: str, value: str) -> str:
    v = value.lower()
    if header == "action":
        if v == "accept":
            return f'<span class="cell-accept">{escape_html(value)}</span>'
        if v in ("deny", "drop"):
            return f'<span class="cell-deny">{escape_html(value)}</span>'
    if header == "status":
        if v in ("enable", "enabled"):
            return f'<span class="cell-enabled">{escape_html(value)}</span>'
        if v in ("disable", "disabled"):
            return f'<span class="cell-disabled">{escape_html(value)}</span>'
    if header == "nat":
        if v in ("enable", "enabled"):
            return f'<span class="cell-nat">{escape_html(value)}</span>'
    if "[error]" in v or "fail" in v:
        return f'<span style="color:#fc6b6b">{escape_html(value)}</span>'
    if "[success]" in v:
        return f'<span style="color:#3ecf8e">{escape_html(value)}</span>'
    return escape_html(value)


def parse_verification_block(text: str) -> dict:
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
    Returns: 'table' | 'verification' | 'confirmation' | 'error'
             | 'security' | 'success' | 'text'
    """
    t = text.upper()
    if re.search(r'(?m)^\s*CONFIRMATION REQUIRED\s*$', t) or re.search(r'(?m)^\s*VALIDATION WARNING\s*$', t):
        return "confirmation"
    if "[VERIFIED" in t or "MISMATCH:" in t:
        return "verification"
    if re.search(r'\|[-\s|]+\|', text):
        return "table"
    if any(k in t for k in ("CRITICAL:", "HIGH:", "MEDIUM:", "LOW:", "INFO:")):
        return "security"
    if "[ERROR]" in t or "OPERATION FAILED:" in t:
        return "error"
    if "[SUCCESS]" in t:
        return "success"
    return "text"