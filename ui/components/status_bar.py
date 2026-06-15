"""
status_bar.py — Clean sidebar for FortiGate AI Agent.

Sections:
  1. Brand header
  2. Device — connection, hostname, model, serial, uptime
  3. Resources — CPU / MEM bars
  4. Counts — policies, interfaces
  5. Session — turns, pending state, last command
  6. Quick commands — grouped by category
  7. Footer
"""
from __future__ import annotations

import streamlit as st
from ui.utils.state import check_fortigate_connection


# ── Quick command groups ──────────────────────────────────────────────────────
_COMMANDS = {
    "MONITOR": [
        ("Policies",        "list all policies"),
        ("Interfaces",      "show interfaces"),
        ("Routes",          "show routes"),
        ("VPN Status",      "show vpn status"),
        ("Traffic Logs",    "show traffic logs"),
        ("System Status",   "system status"),
    ],
    "SECURITY": [
        ("Audit Firewall",  "analyze my firewall security"),
        ("Backup Config",   "backup config"),
    ],
}


# ── Public entry point ────────────────────────────────────────────────────────
def render_sidebar() -> None:
    with st.sidebar:
        _brand()
        _gap("1.2rem")
        _device_panel()
        _rule()
        _session_panel()
        _rule()
        _audit_panel()
        _rule()
        _quick_panel()
        _footer()


# ── Brand ─────────────────────────────────────────────────────────────────────
def _brand() -> None:
    import base64
    import os
    logo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "logo_trans.png")
    b64_img = ""
    try:
        with open(logo_path, "rb") as f:
            b64_img = base64.b64encode(f.read()).decode("utf-8")
    except Exception:
        pass

    img_html = f'<img src="data:image/png;base64,{b64_img}" style="width:2.4rem;height:2.4rem;margin-right:0.8rem;object-fit:contain">' if b64_img else ''

    st.markdown(
        f"""
        <div style="padding:1.4rem 1rem 0; display:flex; align-items:center;">
          {img_html}
          <div>
            <div style="font-size:0.6rem;font-weight:500;letter-spacing:0.2em;
                        text-transform:uppercase;color:#555555;margin-bottom:0.2rem">
              FortiGate
            </div>
            <div style="font-size:1.15rem;font-weight:300;color:#dddddd;
                        letter-spacing:-0.01em;line-height:1">
              AI Agent
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ── Live uptime clock (re-runs every 1 second automatically) ─────────────────
@st.fragment(run_every=1)
def _uptime_clock() -> None:
    import time as _time
    boot_epoch = st.session_state.get("fg_boot_time")
    connected  = st.session_state.get("fg_connected")
    if not connected or not boot_epoch:
        st.markdown(
            '<div style="font-size:0.78rem;color:#cccccc;font-weight:300">—</div>',
            unsafe_allow_html=True,
        )
        return
    elapsed = int(_time.time() - boot_epoch)
    d = elapsed // 86400
    h = (elapsed % 86400) // 3600
    m = (elapsed % 3600) // 60
    s = elapsed % 60
    if d > 0:
        txt = f"{d}d {h}h {m}m"
    elif h > 0:
        txt = f"{h}h {m}m {s}s"
    else:
        txt = f"{m}m {s}s"
    st.markdown(
        f'<div style="font-size:0.78rem;color:#cccccc;font-weight:300;white-space:nowrap">{txt}</div>',
        unsafe_allow_html=True,
    )


# ── Device / connection panel ─────────────────────────────────────────────────
def _device_panel() -> None:
    connected = st.session_state.get("fg_connected")
    fg_info   = st.session_state.get("fg_info", {})
    resources = st.session_state.get("fg_resources", {})
    counts    = st.session_state.get("fg_counts", {})

    hostname  = fg_info.get("hostname", "—") if connected else "—"
    model     = fg_info.get("model",    "—") if connected else "—"
    serial    = fg_info.get("serial",   "—") if connected else "—"

    if connected is True:
        dot, dot_color, label, label_color = "●", "#ffffff", "ONLINE", "#ffffff"
    elif connected is False:
        dot, dot_color, label, label_color = "●", "#444444", "OFFLINE", "#555555"
    else:
        dot, dot_color, label, label_color = "◐", "#777777", "CONNECTING", "#777777"

    st.markdown(
        f"""
        <div style="padding:0 1rem">
          <!-- Status row -->
          <div style="display:flex;align-items:center;justify-content:space-between;
                      margin-bottom:1rem">
            <span style="font-size:0.6rem;font-weight:500;letter-spacing:0.14em;
                         text-transform:uppercase;color:#666666">Device</span>
            <span style="font-size:0.68rem;font-weight:500;letter-spacing:0.1em;
                         color:{label_color}">
              <span style="font-size:0.45rem;color:{dot_color};margin-right:0.3rem">{dot}</span>
              {label}
            </span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Use st.columns for both rows to guarantee perfect alignment
    col1, col2 = st.columns(2, gap="small")
    with col1:
        st.markdown(f'<div style="padding-left:1rem">{_info_cell("HOST", hostname)}</div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div style="padding-left:0.2rem">{_info_cell("MODEL", model)}</div>', unsafe_allow_html=True)

    st.markdown('<div style="height:0.7rem"></div>', unsafe_allow_html=True)

    col3, col4 = st.columns(2, gap="small")
    with col3:
        st.markdown(f'<div style="padding-left:1rem">{_info_cell("SERIAL", serial, mono=True)}</div>', unsafe_allow_html=True)
    with col4:
        st.markdown(
            '<div style="padding-left:0.2rem">'
            '<div style="font-size:0.58rem;letter-spacing:0.1em;color:#555555;'
            'text-transform:uppercase;margin-bottom:0.2rem">UPTIME</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        _uptime_clock()

    # Resource bars
    cpu = resources.get("cpu", 0) if connected else 0
    mem = resources.get("memory", 0) if connected else 0

    _gap("0.8rem")
    st.markdown('<div style="padding:0 1rem">', unsafe_allow_html=True)
    _bar("CPU", cpu)
    _bar("MEM", mem)
    st.markdown("</div>", unsafe_allow_html=True)

    # Policy / interface counts
    pc = counts.get("policies", 0) if connected else 0
    ic = counts.get("interfaces", 0) if connected else 0

    st.markdown(
        f"""
        <div style="display:flex;gap:1.5rem;padding:0.8rem 1rem 0.2rem">
          {_stat_block(str(pc), "Policies")}
          {_stat_block(str(ic), "Interfaces")}
        </div>
        """,
        unsafe_allow_html=True,
    )

    _gap("0.5rem")
    st.markdown('<div style="padding:0 1rem">', unsafe_allow_html=True)
    if st.button("↻  Refresh", use_container_width=True, key="btn_refresh_conn"):
        check_fortigate_connection()
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)


def _info_cell(label: str, value: str, mono: bool = False) -> str:
    font = "font-family:JetBrains Mono,monospace;" if mono else ""
    return (
        f'<div>'
        f'<div style="font-size:0.58rem;letter-spacing:0.1em;color:#555555;'
        f'text-transform:uppercase;margin-bottom:0.2rem">{label}</div>'
        f'<div style="font-size:0.78rem;color:#cccccc;{font}font-weight:300;'
        f'white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{value}</div>'
        f'</div>'
    )


def _stat_block(value: str, label: str) -> str:
    return (
        f'<div>'
        f'<div style="font-size:1.1rem;font-weight:300;color:#dddddd;line-height:1">{value}</div>'
        f'<div style="font-size:0.58rem;letter-spacing:0.1em;color:#555555;'
        f'text-transform:uppercase;margin-top:0.25rem">{label}</div>'
        f'</div>'
    )


def _bar(label: str, pct: int) -> None:
    try:
        pct = max(0, min(100, int(pct)))
    except (TypeError, ValueError):
        return
    bar_color = "#ffffff" if pct > 80 else "#aaaaaa" if pct > 55 else "#555555"
    st.markdown(
        f"""
        <div style="margin-bottom:0.5rem">
          <div style="display:flex;justify-content:space-between;
                      font-size:0.62rem;color:#666666;margin-bottom:0.2rem">
            <span>{label}</span><span style="color:{bar_color}">{pct}%</span>
          </div>
          <div style="height:2px;background:#1e1e1e">
            <div style="width:{pct}%;height:100%;background:{bar_color}"></div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ── Session panel ─────────────────────────────────────────────────────────────
def _session_panel() -> None:
    msgs       = st.session_state.get("messages", [])
    user_count = sum(1 for m in msgs if m["role"] == "user")
    pending    = st.session_state.get("pending", False)
    last_act   = st.session_state.get("last_action", "")

    try:
        agent = st.session_state.get("agent")
        if agent and hasattr(agent, "snapshots"):
            snapshot_count = len(agent.snapshots._snapshots)
        else:
            snapshot_count = 0
    except Exception:
        snapshot_count = 0

    st.markdown(
        f"""
        <div style="padding:0 1rem">
          <div style="font-size:0.6rem;font-weight:500;letter-spacing:0.14em;
                      text-transform:uppercase;color:#666666;margin-bottom:0.8rem">
            Session
          </div>
          <div style="display:flex;gap:1.5rem;margin-bottom:0.6rem">
            {_stat_block(str(user_count), "Commands")}
            {_stat_block(str(len(msgs)),  "Messages")}
            {_stat_block(str(snapshot_count), "Snapshots")}
          </div>
        """,
        unsafe_allow_html=True,
    )

    if last_act:
        st.markdown(
            f'<div style="font-size:0.72rem;color:#555555;margin-bottom:0.4rem;'
            f'white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'
            f'<span style="color:#444">↳ </span>{last_act}</div>',
            unsafe_allow_html=True,
        )

    if pending:
        st.markdown(
            '<div style="font-size:0.72rem;color:#eeeeee;border:1px solid #333333;'
            'padding:0.35rem 0.6rem;letter-spacing:0.04em;margin-bottom:0.4rem">'
            '⬡  Awaiting confirmation</div>',
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)

    _gap("0.4rem")
    st.markdown('<div style="padding:0 1rem">', unsafe_allow_html=True)
    if st.button("New conversation", use_container_width=True, key="btn_new_conv"):
        _reset()
    st.markdown("</div>", unsafe_allow_html=True)


# ── Audit panel ───────────────────────────────────────────────────────────────
def _audit_panel() -> None:
    try:
        from audit.logger import read_logs
    except ImportError:
        return

    st.markdown(
        '<div style="padding:0 1rem;font-size:0.6rem;font-weight:500;'
        'letter-spacing:0.14em;text-transform:uppercase;color:#666666;'
        'margin-bottom:0.5rem">Recent Activity</div>',
        unsafe_allow_html=True,
    )
    
    logs = read_logs(limit=20)
    action_logs = [l for l in logs if l.get("type") == "action"]
    recent_actions = action_logs[-3:]
    
    if not recent_actions:
        st.markdown('<div style="padding:0 1rem;font-size:0.75rem;color:#555">No entries</div>', unsafe_allow_html=True)
        return
        
    for entry in reversed(recent_actions):
        ts = entry.get("timestamp", "")[:19].replace("T", " ")
        action = entry.get("action", "UNKNOWN").replace("TOOL_", "").replace("_", " ")
        
        st.markdown(
            f'<div style="padding:0.4rem 0.8rem; border-left: 2px solid #333333; margin-bottom: 0.5rem; background: #0a0a0a;">'
            f'<div style="font-size:0.6rem; color:#777777; font-family:\'JetBrains Mono\',monospace; margin-bottom:0.2rem;">{ts}</div>'
            f'<div style="font-size:0.75rem; color:#eeeeee; font-weight:600; letter-spacing:0.02em;">{action}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    _gap("0.6rem")


# ── Quick commands panel ──────────────────────────────────────────────────────
def _quick_panel() -> None:
    for group_label, commands in _COMMANDS.items():
        st.markdown(
            f'<div style="padding:0 1rem;font-size:0.6rem;font-weight:500;'
            f'letter-spacing:0.14em;text-transform:uppercase;color:#666666;'
            f'margin-bottom:0.5rem">{group_label}</div>',
            unsafe_allow_html=True,
        )
        for label, command in commands:
            if st.button(label, use_container_width=True, key=f"qc_{label}"):
                _run(command)
        _gap("0.6rem")


# ── Footer ────────────────────────────────────────────────────────────────────
def _footer() -> None:
    st.markdown(
        '<div style="padding:1rem 1rem 0.5rem;font-size:0.62rem;color:#555555;'
        'letter-spacing:0.06em">Mistral AI · Safety Engine</div>',
        unsafe_allow_html=True,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────
def _rule() -> None:
    st.markdown(
        '<div style="border-top:1px solid #222222;margin:0.9rem 0"></div>',
        unsafe_allow_html=True,
    )


def _gap(size: str) -> None:
    st.markdown(
        f'<div style="height:{size}"></div>',
        unsafe_allow_html=True,
    )


def _section_label(text: str) -> None:
    st.markdown(
        f'<div style="padding:0 1rem;font-size:0.6rem;font-weight:500;'
        f'letter-spacing:0.14em;text-transform:uppercase;color:#444444;'
        f'margin-bottom:0.5rem">{text}</div>',
        unsafe_allow_html=True,
    )


# ── Actions ───────────────────────────────────────────────────────────────────
def _run(command: str) -> None:
    from ui.utils.state import get_agent, push_message
    from core import ResponseKind

    push_message("user", command)
    response = get_agent().process(command)
    push_message(role="agent", content=response.text, kind=response.kind.value)

    if response.kind == ResponseKind.CONFIRMATION:
        st.session_state.pending      = True
        st.session_state.pending_text = response.text
    else:
        st.session_state.pending = False
    st.rerun()


def _reset() -> None:
    from core import AgentSession

    st.session_state.agent        = AgentSession()
    st.session_state.messages     = []
    st.session_state.pending      = False
    st.session_state.pending_text = ""
    st.session_state.last_action  = ""
    st.session_state.input_key    = st.session_state.get("input_key", 0) + 1
    st.rerun()