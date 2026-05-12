"""
chat.py — Message rendering components.
"""
from __future__ import annotations

import streamlit as st
from ui.utils.formatting import (
    render_policy_table,
    detect_content_type,
    parse_verification_block,
    escape_html,
)


def render_user_message(text: str) -> None:
    st.markdown(
        f'<div class="msg-user"><div class="bubble">{escape_html(text)}</div></div>',
        unsafe_allow_html=True,
    )


def render_agent_message(text: str, kind: str = "answer") -> None:
    """Route the agent's reply to the correct renderer."""
    content_type = detect_content_type(text)

    if kind == "confirmation" or content_type == "confirmation":
        _render_confirmation_preview(text)
        return

    if content_type == "verification":
        _render_verification(text)
        return

    if content_type == "table":
        _render_table_message(text)
        return

    if content_type == "security":
        _render_security_findings(text)
        return

    if content_type == "error":
        _render_error_message(text)
        return

    _render_plain_message(text)


def _render_plain_message(text: str) -> None:
    # Split text: if it contains a markdown table, render it separately
    st.markdown(
        f"""
<div class="msg-agent">
  <div class="avatar">FG</div>
  <div class="bubble">{_md_to_html(text)}</div>
</div>""",
        unsafe_allow_html=True,
    )


def _render_table_message(text: str) -> None:
    parts     = text.split("\n")
    pre_table = []
    table_buf = []
    in_table  = False

    for line in parts:
        if "|" in line:
            in_table = True
        if in_table:
            table_buf.append(line)
        else:
            pre_table.append(line)

    pre_html   = _md_to_html("\n".join(pre_table)) if pre_table else ""
    table_html = render_policy_table("\n".join(table_buf)) if table_buf else ""

    st.markdown(
        f"""
<div class="msg-agent">
  <div class="avatar">FG</div>
  <div class="bubble">{pre_html}{table_html}</div>
</div>""",
        unsafe_allow_html=True,
    )


def _render_verification(text: str) -> None:
    vr = parse_verification_block(text)

    if vr["passed"]:
        badge = '<span class="badge-verified">✓ Verified on FortiGate</span>'
        lines = "".join(
            f'<div style="font-size:0.82rem;color:#8b949e;font-family:JetBrains Mono,monospace;">'
            f'  {escape_html(f)}</div>'
            for f in vr["fields"]
        )
        body = f"{badge}{lines}"
    else:
        badge = '<span class="badge-failed">⚠ Verification issues detected</span>'
        mismatches = "".join(
            f'<div style="font-size:0.82rem;color:#f85149;font-family:JetBrains Mono,monospace;">'
            f'  ✗ {escape_html(m)}</div>'
            for m in vr["mismatches"]
        )
        body = f"{badge}{mismatches}"

    # Also show the surrounding message text
    main_text = text.split("[Verified")[0].split("[WARNING")[0].strip()
    if main_text:
        body = f'<div style="margin-bottom:0.6rem">{_md_to_html(main_text)}</div>{body}'

    st.markdown(
        f"""
<div class="msg-agent">
  <div class="avatar">FG</div>
  <div class="bubble">{body}</div>
</div>""",
        unsafe_allow_html=True,
    )


def _render_confirmation_preview(text: str) -> None:
    """
    Render a confirmation request as a styled preview card.
    The actual YES/NO buttons are in confirmation.py and rendered
    in the main app separately.
    """
    is_danger = any(k in text.upper() for k in ("DELETE", "PERMANENTLY", "BLOCK"))
    card_class = "confirm-card danger" if is_danger else "confirm-card"
    title_text = "⚠ Dangerous Operation — Confirm" if is_danger else "Confirmation Required"

    # Clean the text
    clean = (
        text.replace("=" * 55, "")
            .replace("Type 'yes' to confirm or 'no' to cancel.", "")
            .strip()
    )
    lines = [l for l in clean.splitlines() if l.strip()]
    body  = "<br>".join(escape_html(l) for l in lines)

    st.markdown(
        f"""
<div class="msg-agent">
  <div class="avatar">FG</div>
  <div style="max-width:82%">
    <div class="{card_class}">
      <div class="confirm-title">{title_text}</div>
      <div class="confirm-body">{body}</div>
    </div>
  </div>
</div>""",
        unsafe_allow_html=True,
    )


def _render_security_findings(text: str) -> None:
    """Parse and render a security analysis report as finding cards."""
    import re

    severity_map = {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "low":      "low",
        "info":     "info",
    }

    # Extract header/summary (text before first severity keyword)
    header_match = re.split(
        r'\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b', text, maxsplit=1, flags=re.I
    )
    header_html = (
        f'<div style="margin-bottom:0.75rem;font-size:0.9rem">'
        f'{_md_to_html(header_match[0].strip())}</div>'
        if header_match[0].strip() else ""
    )

    # Extract finding blocks
    blocks    = re.split(r'\b(CRITICAL|HIGH|MEDIUM|LOW|INFO):', text, flags=re.I)
    cards_html = ""
    i = 1
    while i < len(blocks) - 1:
        level   = blocks[i].lower().strip()
        content = blocks[i + 1].strip() if i + 1 < len(blocks) else ""
        sclass  = severity_map.get(level, "info")

        # Split content into first line (title) + rest (detail)
        lines      = content.strip().splitlines()
        title_text  = lines[0].strip() if lines else ""
        detail_text = "\n".join(lines[1:]).strip() if len(lines) > 1 else ""

        detail_html = (
            f'<div style="font-size:0.82rem;color:#8b949e;margin-top:0.3rem;'
            f'line-height:1.5">{escape_html(detail_text)}</div>'
            if detail_text else ""
        )

        cards_html += f"""
<div class="finding-card {sclass}">
  <span class="severity-badge {sclass}">{level}</span>
  <div style="font-size:0.88rem;font-weight:500;color:#e6edf3">
    {escape_html(title_text)}
  </div>
  {detail_html}
</div>"""
        i += 2

    # Footer / next steps
    footer_match = re.search(r'(next\s+steps?|recommended?|priority).*$', text, re.I | re.S)
    footer_html  = (
        f'<div style="margin-top:0.75rem;font-size:0.85rem;color:#8b949e">'
        f'{_md_to_html(footer_match.group(0))}</div>'
        if footer_match else ""
    )

    body = header_html + cards_html + footer_html

    st.markdown(
        f"""
<div class="msg-agent">
  <div class="avatar">FG</div>
  <div class="bubble" style="max-width:92%">{body}</div>
</div>""",
        unsafe_allow_html=True,
    )


def _render_error_message(text: str) -> None:
    clean = (
        text.replace("OPERATION FAILED:", "")
            .replace("[ERROR]", "")
            .strip()
    )
    st.markdown(
        f"""
<div class="msg-agent">
  <div class="avatar" style="background:linear-gradient(135deg,#6e2020,#f85149)">FG</div>
  <div class="bubble" style="border-color:#30363d">
    <div style="color:#f85149;font-weight:600;font-size:0.82rem;
    margin-bottom:0.3rem">Operation Failed</div>
    <div style="font-size:0.88rem">{_md_to_html(clean)}</div>
  </div>
</div>""",
        unsafe_allow_html=True,
    )


def _md_to_html(text: str) -> str:
    """
    Minimal markdown → HTML conversion.
    Handles: **bold**, `code`, line breaks.
    """
    import re
    text = escape_html(text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    text = text.replace("\n", "<br>")
    return text


def render_thinking_indicator() -> None:
    st.markdown(
        """
<div class="msg-agent">
  <div class="avatar">FG</div>
  <div class="bubble" style="color:#8b949e;font-style:italic;font-size:0.88rem">
    <span class="status-dot pending"></span>Thinking...
  </div>
</div>""",
        unsafe_allow_html=True,
    )