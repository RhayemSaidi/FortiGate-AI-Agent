"""
chat.py — Minimal message rendering.
One user renderer. One agent renderer. Content-type routing kept simple.
"""
from __future__ import annotations

import re
import streamlit as st
from ui.utils.formatting import (
    escape_html, md_to_html, render_policy_table, detect_content_type,
    parse_verification_block,
)

_ICON = '<div class="agent-icon">SYS</div>'


def render_user_message(text: str) -> None:
    st.markdown(
        f'<div class="msg-user"><div class="bubble">{escape_html(text)}</div></div>',
        unsafe_allow_html=True,
    )


def render_agent_message(text: str, kind: str = "answer") -> None:
    ct = detect_content_type(text)

    # Guard: only route to confirmation card if the text actually carries
    # confirmation content. Prevents stale session kind values from
    # accidentally rendering capability/answer text as a confirmation card.
    _is_real_confirmation = (
        "CONFIRMATION REQUIRED" in text.upper()
        or "VALIDATION WARNING" in text.upper()
        or "Type 'yes'" in text
    )

    if (kind == "confirmation" or ct == "confirmation") and _is_real_confirmation:
        _render_confirmation(text)
    elif ct == "verification":
        _render_verification(text)
    elif ct == "table":
        _render_table(text)
    elif ct == "security":
        _render_security(text)
    elif ct == "error":
        _render_with_tag(text, "ERROR", "err",
                         text.replace("OPERATION FAILED:", "").replace("[ERROR]", "").strip())
    elif ct == "success":
        _render_with_tag(text, "OK", "ok",
                         text.replace("[SUCCESS]", "").strip())
    else:
        _render_plain(text)


# ── Plain ──────────────────────────────────────────────────────────────────
def _render_plain(text: str) -> None:
    st.markdown(
        f'<div class="msg-agent">{_ICON}'
        f'<div class="bubble">{md_to_html(text)}</div></div>',
        unsafe_allow_html=True,
    )


# ── Table ──────────────────────────────────────────────────────────────────
def _render_table(text: str) -> None:
    parts     = text.split("\n")
    pre, tbl  = [], []
    in_table  = False
    for line in parts:
        if "|" in line and not in_table:
            in_table = True
        (tbl if in_table else pre).append(line)

    pre_html = md_to_html("\n".join(pre)).strip()
    tbl_html = render_policy_table("\n".join(tbl)) if tbl else ""
    pre_block = f'<div style="margin-bottom:0.5rem;color:#c4c4c4">{pre_html}</div>' if pre_html else ""

    st.markdown(
        f'<div class="msg-agent">{_ICON}'
        f'<div class="bubble" style="max-width:92%">{pre_block}{tbl_html}</div></div>',
        unsafe_allow_html=True,
    )


# ── Verification ───────────────────────────────────────────────────────────
def _render_verification(text: str) -> None:
    vr = parse_verification_block(text)
    if vr["passed"]:
        tag  = '<span class="tag ok">Verified</span>'
        rows = "".join(
            f'<div style="font-size:0.76rem;color:#666666;font-family:\'JetBrains Mono\',monospace;'
            f'padding:0.05rem 0">  {escape_html(f)}</div>'
            for f in vr["fields"]
        )
        body = f'<div style="margin-top:0.8rem">{tag}{rows}</div>'
    else:
        tag  = '<span class="tag err">Mismatch</span>'
        rows = "".join(
            f'<div style="font-size:0.76rem;color:#888888;font-family:\'JetBrains Mono\',monospace;'
            f'padding:0.05rem 0">  ✗ {escape_html(m)}</div>'
            for m in vr["mismatches"]
        )
        body = f'<div style="margin-top:0.8rem">{tag}{rows}</div>'

    lead = text.split("[Verified")[0].split("[WARNING")[0].strip()
    if lead:
        if re.search(r'\|[-\s|]+\|', lead):
            parts = lead.split("\n")
            pre, tbl = [], []
            in_table = False
            for line in parts:
                if "|" in line and not in_table:
                    in_table = True
                (tbl if in_table else pre).append(line)
            
            pre_html = md_to_html("\n".join(pre)).strip()
            tbl_html = render_policy_table("\n".join(tbl)) if tbl else ""
            pre_block = f'<div style="margin-bottom:0.5rem;color:#c4c4c4">{pre_html}</div>' if pre_html else ""
            lead_html = f'{pre_block}{tbl_html}'
        else:
            lead_html = f'<div style="margin-bottom:0.4rem;color:#dddddd;">{md_to_html(lead)}</div>'
            
        body = f'{lead_html}{body}'

    st.markdown(
        f'<div class="msg-agent">{_ICON}'
        f'<div class="bubble" style="width:100%; max-width:92%">{body}</div></div>',
        unsafe_allow_html=True,
    )


# ── Confirmation preview ───────────────────────────────────────────────────
def _render_confirmation(text: str) -> None:
    is_danger  = any(k in text.upper() for k in ("DELETE", "PERMANENTLY", "BLOCK", "REBOOT", "[WARNING]"))
    is_create  = "CREATE" in text.upper()
    card_cls   = "confirm-card danger" if is_danger else "confirm-card"
    
    if "VALIDATION WARNING" in text.upper():
        label_text = "VALIDATION WARNING"
    elif is_danger:
        label_text = "DESTRUCTIVE OPERATION"
    else:
        label_text = "CONFIRMATION REQUIRED"

    # Capture the instruction before removing it
    has_instruction = False
    instruction_text = ""
    if "Type 'yes' to proceed anyway or 'no' to cancel." in text:
        has_instruction = True
        instruction_text = "Type 'yes' to proceed anyway or 'no' to cancel."
    elif "Type 'yes' to confirm or 'no' to cancel." in text:
        has_instruction = True
        instruction_text = "Type 'yes' to confirm or 'no' to cancel."

    clean = re.sub(r'={10,}', '', text)
    clean = re.sub(r"-{10,}", "", clean)
    clean = re.sub(r'─{4,}', '', clean)           # strip new ─ separator lines
    clean = clean.replace("Type 'yes' to confirm or 'no' to cancel.", "")
    clean = clean.replace("Type 'yes' to proceed anyway or 'no' to cancel.", "")
    clean = clean.strip()
    
    lines = [
        l.strip() for l in clean.splitlines()
        if l.strip() and "CONFIRMATION REQUIRED" not in l.upper()
        and "VALIDATION WARNING" not in l.upper()
    ]
    
    formatted_lines = []
    for l in lines:
        if "[WARNING]" in l or l.lstrip().startswith("⚠"):
            l_clean = l.replace("[WARNING]", "").replace("⚠", "").strip()
            formatted_lines.append(f'<span style="color:#ffaa00;font-weight:500;">⚠ WARNING:</span> <span style="color:#eeeeee">{escape_html(l_clean)}</span>')
        elif l.lstrip().startswith("✖"):
            l_clean = l.replace("✖", "").strip()
            formatted_lines.append(f'<span style="color:#ff6666;">✖</span> <span style="color:#eeeeee">{escape_html(l_clean)}</span>')
        elif l.lstrip().startswith("→"):
            l_clean = l.replace("→", "").strip()
            formatted_lines.append(f'<span style="color:#888888;">→</span> <span style="color:#aaaaaa;font-size:0.85rem">{escape_html(l_clean)}</span>')
        else:
            formatted_lines.append(escape_html(l))
            
    body = "<br>".join(formatted_lines)
    
    if is_create:
        body += '<br><br><span style="font-size:0.75rem;color:#ffaa00;">⚠ Note: CREATE operations cannot be automatically rolled back.</span>'

    if has_instruction:
        body += f'<div style="margin-top:0.8rem;padding-top:0.8rem;border-top:1px solid #222;font-size:0.75rem;color:#888888;">{escape_html(instruction_text)}</div>'

    st.markdown(
        f'<div class="msg-agent">{_ICON}'
        f'<div style="max-width:85%">'
        f'<div class="{card_cls}">'
        f'<div class="confirm-label">{label_text}</div>'
        f'{body}'
        f'</div></div></div>',
        unsafe_allow_html=True,
    )


# ── Security findings ──────────────────────────────────────────────────────
def _render_security(text: str) -> None:
    """Render security report as minimal tagged list — no heavy cards."""
    # Extract header
    parts  = re.split(r'\b(CRITICAL|HIGH|MEDIUM|LOW|INFO):', text, flags=re.I)
    header = parts[0].strip()
    header_html = f'<div style="margin-bottom:0.6rem;color:#c4c4c4">{md_to_html(header)}</div>' if header else ""

    rows_html = ""
    sev_color = {
        "critical": "#ffffff",
        "high":     "#dddddd",
        "medium":   "#aaaaaa",
        "low":      "#777777",
        "info":     "#555555",
    }
    i = 1
    while i < len(parts) - 1:
        level   = parts[i].lower().strip()
        content = parts[i + 1].strip() if i + 1 < len(parts) else ""
        lines   = content.strip().splitlines()
        title   = lines[0].strip() if lines else ""
        detail  = " ".join(lines[1:]).strip() if len(lines) > 1 else ""
        color   = sev_color.get(level, "#777777")

        rows_html += (
            f'<div style="padding:0.4rem 0;border-bottom:1px solid #222222">'
            f'<span style="font-size:0.7rem;font-weight:500;text-transform:uppercase;'
            f'letter-spacing:0.07em;color:{color};margin-right:0.6rem">{level}</span>'
            f'<span style="font-size:0.85rem;color:#dddddd;font-weight:400">{escape_html(title)}</span>'
            f'{"<div style=font-size:0.8rem;color:#999;margin-top:0.2rem;margin-left:0.5rem;font-weight:300>" + escape_html(detail) + "</div>" if detail else ""}'
            f'</div>'
        )
        i += 2

    st.markdown(
        f'<div class="msg-agent">{_ICON}'
        f'<div class="bubble" style="max-width:90%">'
        f'{header_html}'
        f'<div style="border-top:1px solid #1e1e1e">{rows_html}</div>'
        f'</div></div>',
        unsafe_allow_html=True,
    )


# ── Success / error with tag ───────────────────────────────────────────────
def _render_with_tag(original: str, tag_text: str, tag_cls: str, clean: str) -> None:
    tag = f'<span class="tag {tag_cls}" style="margin-bottom:0.4rem;display:inline-block">{tag_text}</span>'
    st.markdown(
        f'<div class="msg-agent">{_ICON}'
        f'<div class="bubble">{tag}<br>{md_to_html(clean)}</div></div>',
        unsafe_allow_html=True,
    )


# ── Thinking indicator ─────────────────────────────────────────────────────
def render_thinking_indicator() -> None:
    st.markdown(
        f'<div class="msg-agent">{_ICON}'
        f'<div class="bubble" style="color:#555555;font-size:0.88rem;padding:0.3rem 0">'
        f'<span class="dot1" style="display:inline-block">.</span>'
        f'<span class="dot2" style="display:inline-block">.</span>'
        f'<span class="dot3" style="display:inline-block">.</span>'
        f'</div></div>',
        unsafe_allow_html=True,
    )