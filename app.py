"""
app.py — Streamlit UI for the FortiGate AI Agent.
All logic is in agent/core.py. This file handles rendering only.
"""
import sys
import os

_ROOT      = os.path.dirname(os.path.abspath(__file__))
_AGENT_DIR = os.path.join(_ROOT, "agent")
sys.path.insert(0, _ROOT)
sys.path.insert(0, _AGENT_DIR)

import streamlit as st
from core import AgentSession, ResponseKind

from audit.logger import read_logs
from modules.system import get_system_status
from modules.monitor import get_cpu_usage, get_memory_usage
from modules.policies import list_policies

st.set_page_config(
    page_title="FortiGate AI Agent",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={}
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500&display=swap');
*,*::before,*::after{box-sizing:border-box}
html,body,.stApp{background:#0a0c0f;color:#c9d1d9;font-family:'IBM Plex Sans',sans-serif}
#MainMenu,footer,header,[data-testid="stToolbar"],[data-testid="stDecoration"]{display:none!important}
[data-testid="stSidebar"]{background:#0d1117;border-right:1px solid #1c2128}
[data-testid="stSidebar"]>div{padding:1.5rem 1rem}
.main .block-container{padding:0 2rem 2rem 2rem;max-width:100%}
.app-header{display:flex;align-items:center;gap:.75rem;padding:1.25rem 0 1rem 0;border-bottom:1px solid #1c2128;margin-bottom:1.5rem}
.app-header-title{font-size:.95rem;font-weight:500;color:#e6edf3;letter-spacing:.02em}
.app-header-sub{font-size:.75rem;color:#484f58;margin-left:auto;font-family:'IBM Plex Mono',monospace}
.status-dot{width:7px;height:7px;border-radius:50%;background:#3fb950;box-shadow:0 0 6px #3fb95088;flex-shrink:0}
.msg-user{display:flex;justify-content:flex-end;margin:.75rem 0 .25rem 0}
.msg-user-bubble{background:#1c2a3a;color:#cdd9e5;padding:.6rem 1rem;border-radius:14px 14px 2px 14px;max-width:72%;font-size:.9rem;line-height:1.5;border:1px solid #1f6feb22}
.msg-agent{display:flex;align-items:flex-start;gap:.6rem;margin:.25rem 0 .75rem 0}
.msg-agent-icon{width:24px;height:24px;border-radius:6px;background:linear-gradient(135deg,#1f6feb,#388bfd);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:.65rem;color:white;font-weight:700;font-family:'IBM Plex Mono',monospace;margin-top:.1rem}
.msg-agent-content{background:#0d1117;color:#c9d1d9;padding:.6rem 1rem;border-radius:2px 14px 14px 14px;max-width:85%;font-size:.88rem;line-height:1.6;border:1px solid #1c2128;white-space:pre-wrap}
.confirm-panel{background:#161005;border:1px solid #d2992244;border-radius:8px;padding:1rem 1.25rem;margin:.5rem 0 1rem 0;font-family:'IBM Plex Mono',monospace;font-size:.82rem}
.confirm-title{color:#d29922;font-weight:500;font-size:.78rem;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.6rem}
.warning-panel{background:#100a0a;border:1px solid #f8514944;border-radius:8px;padding:.75rem 1rem;margin:.5rem 0;font-size:.85rem;color:#ffa198}
.stTextInput>div>div>input{background:#0d1117!important;color:#c9d1d9!important;border:1px solid #30363d!important;border-radius:8px!important;padding:.65rem 1rem!important;font-family:'IBM Plex Sans',sans-serif!important;font-size:.9rem!important}
.stTextInput>div>div>input:focus{border-color:#1f6feb!important;box-shadow:0 0 0 3px #1f6feb18!important}
.stTextInput>div>div>input::placeholder{color:#484f58!important}
.stTextInput>label{display:none}
.stButton>button{background:#1c2128!important;color:#8b949e!important;border:1px solid #30363d!important;border-radius:6px!important;font-size:.78rem!important;padding:.3rem .7rem!important}
.stButton>button:hover{background:#21262d!important;color:#c9d1d9!important}
button[kind="primary"]{background:#1f6feb!important;color:#fff!important;border-color:#1f6feb!important}
button[kind="primary"]:hover{background:#388bfd!important}
button[kind="secondary"]{background:#21262d!important;color:#e6edf3!important;border-color:#30363d!important}
.sidebar-label{font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;color:#484f58;margin:1rem 0 .4rem 0;font-family:'IBM Plex Mono',monospace}
.stat-row{display:flex;justify-content:space-between;padding:.3rem 0;font-size:.8rem}
.stat-label{color:#484f58}
.stat-value{color:#c9d1d9;font-family:'IBM Plex Mono',monospace;font-size:.78rem}
.policy-row{display:flex;align-items:center;gap:.5rem;padding:.35rem .5rem;border-radius:4px;font-size:.78rem;margin:.15rem 0}
.policy-name{color:#c9d1d9;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.policy-badge{font-family:'IBM Plex Mono',monospace;font-size:.68rem;padding:.1rem .4rem;border-radius:3px}
.badge-accept{background:#12261e;color:#3fb950}
.badge-deny{background:#2d1117;color:#f85149}
.badge-dis{background:#1c2128;color:#484f58}
.bar-track{height:3px;background:#21262d;border-radius:2px;margin:.2rem 0 .6rem 0;overflow:hidden}
.bar-cpu{height:100%;background:#1f6feb;border-radius:2px}
.bar-mem{height:100%;background:#3fb950;border-radius:2px}
.bar-warn{background:#d29922!important}
.bar-crit{background:#f85149!important}
.divider{height:1px;background:#1c2128;margin:.75rem 0}
.audit-entry{padding:.3rem 0;border-bottom:1px solid #1c2128;font-size:.75rem}
.audit-ts{color:#484f58;font-family:'IBM Plex Mono',monospace;font-size:.7rem}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:#21262d;border-radius:2px}
</style>
""", unsafe_allow_html=True)

# ── Session state ─────────────────────────────────────────
if "session" not in st.session_state:
    st.session_state.session = AgentSession()
if "messages" not in st.session_state:
    st.session_state.messages = []
if "show_suggestions" not in st.session_state:
    st.session_state.show_suggestions = True
if "input_key" not in st.session_state:
    st.session_state.input_key = 0


def _add(role, content, kind="answer"):
    st.session_state.messages.append({"role": role, "content": content, "kind": kind})


def _send(text: str):
    if not text.strip():
        return
    st.session_state.show_suggestions = False
    _add("user", text)
    try:
        resp = st.session_state.session.process(text)
        _add("agent", resp.text, resp.kind.value)
    except Exception as exc:
        _add("agent", f"Error: {exc}", "error")
    st.session_state.input_key += 1


def _confirm():
    try:
        resp = st.session_state.session.process("yes")
        _add("agent", resp.text, resp.kind.value)
    except Exception as exc:
        _add("agent", f"Error: {exc}", "error")
    st.session_state.input_key += 1


def _cancel():
    try:
        resp = st.session_state.session.process("no")
        _add("agent", resp.text, resp.kind.value)
    except Exception as exc:
        _add("agent", f"Error: {exc}", "error")
    st.session_state.input_key += 1


# ── Sidebar ───────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="sidebar-label">System</div>', unsafe_allow_html=True)
    try:
        r   = get_system_status()
        res = r.get("results", {})
        st.markdown(
            f'<div class="stat-row"><span class="stat-label">Host</span><span class="stat-value">{res.get("hostname","—")}</span></div>'
            f'<div class="stat-row"><span class="stat-label">Model</span><span class="stat-value">{res.get("model_name","—")}</span></div>'
            f'<div class="stat-row"><span class="stat-label">Version</span><span class="stat-value">{r.get("version","—")}</span></div>',
            unsafe_allow_html=True
        )
    except Exception:
        st.markdown('<span style="color:#484f58;font-size:.78rem">Unreachable</span>', unsafe_allow_html=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-label">Resources</div>', unsafe_allow_html=True)
    try:
        cpu = get_cpu_usage()["results"]["cpu"][0]["current"]
        mem = get_memory_usage()["results"]["mem"][0]["current"]
        cc  = "bar-crit" if cpu > 85 else ("bar-warn" if cpu > 65 else "bar-cpu")
        mc  = "bar-crit" if mem > 85 else ("bar-warn" if mem > 65 else "bar-mem")
        st.markdown(
            f'<div class="stat-row"><span class="stat-label">CPU</span><span class="stat-value">{cpu}%</span></div>'
            f'<div class="bar-track"><div class="{cc}" style="width:{cpu}%"></div></div>'
            f'<div class="stat-row"><span class="stat-label">Memory</span><span class="stat-value">{mem}%</span></div>'
            f'<div class="bar-track"><div class="{mc}" style="width:{mem}%"></div></div>',
            unsafe_allow_html=True
        )
    except Exception:
        st.markdown('<span style="color:#484f58;font-size:.78rem">Unavailable</span>', unsafe_allow_html=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-label">Policies</div>', unsafe_allow_html=True)
    try:
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        for p in results:
            action   = p.get("action","?")
            disabled = p.get("status","enable") == "disable"
            badge    = "badge-dis" if disabled else ("badge-deny" if action == "deny" else "badge-accept")
            badge_t  = "DIS" if disabled else action.upper()
            st.markdown(
                f'<div class="policy-row">'
                f'<span style="color:#484f58;font-family:IBM Plex Mono,monospace;font-size:.68rem">#{p.get("policyid")}</span>'
                f'<span class="policy-name">{p.get("name")}</span>'
                f'<span class="policy-badge {badge}">{badge_t}</span>'
                f'</div>', unsafe_allow_html=True
            )
    except Exception:
        st.markdown('<span style="color:#484f58;font-size:.78rem">Unavailable</span>', unsafe_allow_html=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-label">Recent Actions</div>', unsafe_allow_html=True)
    try:
        logs = [l for l in read_logs(limit=20) if l.get("type") == "action"][-5:]
        for e in reversed(logs):
            ok  = e.get("status") == "success"
            dot = '<span style="color:#3fb950">&#9679;</span>' if ok else '<span style="color:#f85149">&#9679;</span>'
            ts  = e.get("timestamp","")[:16].replace("T"," ")
            st.markdown(
                f'<div class="audit-entry">{dot} <span style="color:#c9d1d9">{e.get("action","?")}</span><br>'
                f'<span class="audit-ts">{ts}</span></div>',
                unsafe_allow_html=True
            )
    except Exception:
        pass

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Refresh", use_container_width=True):
            st.rerun()
    with c2:
        if st.button("Clear", use_container_width=True):
            st.session_state.session = AgentSession()
            st.session_state.messages = []
            st.session_state.show_suggestions = True
            st.session_state.input_key += 1
            st.rerun()


# ── Main ──────────────────────────────────────────────────
st.markdown(
    '<div class="app-header">'
    '<div class="status-dot"></div>'
    '<span class="app-header-title">FortiGate AI Agent</span>'
    '<span class="app-header-sub">Mistral AI · FortiOS Knowledge Base</span>'
    '</div>',
    unsafe_allow_html=True
)

for msg in st.session_state.messages:
    role    = msg["role"]
    content = msg["content"]
    kind    = msg.get("kind","answer")

    if role == "user":
        st.markdown(
            f'<div class="msg-user"><div class="msg-user-bubble">{content}</div></div>',
            unsafe_allow_html=True
        )
    else:
        if kind == "confirmation":
            st.markdown(
                f'<div class="confirm-panel"><div class="confirm-title">Confirmation required</div>'
                f'<pre style="margin:0;color:#c9d1d9;white-space:pre-wrap;font-size:.8rem">{content}</pre></div>',
                unsafe_allow_html=True
            )
        elif kind in ("blocked","error"):
            st.markdown(f'<div class="warning-panel">{content}</div>', unsafe_allow_html=True)
        elif kind == "warning":
            st.markdown(
                f'<div class="confirm-panel"><div class="confirm-title">Security warning — review before proceeding</div>'
                f'<pre style="margin:0;color:#ffa198;white-space:pre-wrap;font-size:.8rem">{content}</pre></div>',
                unsafe_allow_html=True
            )
        else:
            safe = content.replace("<","&lt;").replace(">","&gt;")
            st.markdown(
                f'<div class="msg-agent"><div class="msg-agent-icon">FG</div>'
                f'<div class="msg-agent-content">{safe}</div></div>',
                unsafe_allow_html=True
            )

if st.session_state.session.has_pending:
    c1, c2, _ = st.columns([1, 1, 7])
    with c1:
        if st.button("Confirm", type="primary", key="btn_yes"):
            _confirm()
            st.rerun()
    with c2:
        if st.button("Cancel", type="secondary", key="btn_no"):
            _cancel()
            st.rerun()

st.markdown("---")
col_in, col_send = st.columns([8, 1])
with col_in:
    user_input = st.text_input(
        "msg", placeholder="Ask anything about your FortiGate...",
        key=f"inp_{st.session_state.input_key}",
        label_visibility="collapsed",
        disabled=st.session_state.session.has_pending,
    )
with col_send:
    submitted = st.button(
        "Send", type="primary", use_container_width=True,
        disabled=st.session_state.session.has_pending,
    )

if submitted and user_input and user_input.strip():
    _send(user_input.strip())
    st.rerun()

if st.session_state.show_suggestions and not st.session_state.session.has_pending:
    suggestions = [
        "list all policies", "analyze firewall security",
        "check cpu and memory", "show all interfaces",
        "what does error -651 mean?", "how to create a VLAN?",
    ]
    cols = st.columns(len(suggestions))
    for i, s in enumerate(suggestions):
        with cols[i]:
            if st.button(s, key=f"sug_{i}", use_container_width=True):
                _send(s)
                st.rerun()