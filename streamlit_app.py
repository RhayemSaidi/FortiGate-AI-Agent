"""
streamlit_app.py — FortiGate AI Agent.

Run with:
    streamlit run streamlit_app.py
"""
from __future__ import annotations

import sys
import os

_THIS_DIR  = os.path.dirname(os.path.abspath(__file__))
_AGENT_DIR = os.path.join(_THIS_DIR, "agent")
for p in (_THIS_DIR, _AGENT_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

import streamlit as st
import streamlit.components.v1 as components

try:
    from PIL import Image
    _icon = Image.open(os.path.join(_THIS_DIR, "ui", "assets", "logo_trans.png"))
except Exception:
    _icon = "🛡️"

st.set_page_config(
    page_title="FortiGate AI Agent",
    page_icon=_icon,
    layout="wide",
    initial_sidebar_state="expanded",
)

from ui.styles.theme            import DARK_CSS
from ui.utils.state             import init_state, get_agent, push_message, check_fortigate_connection
from ui.components.chat         import render_user_message, render_agent_message, render_thinking_indicator
from ui.components.confirmation import render_confirmation_buttons
from ui.components.status_bar   import render_sidebar

# ── Theme ─────────────────────────────────────────────────────────────────────
st.markdown(DARK_CSS, unsafe_allow_html=True)

# ── Focus Script (Non-invasive) ────────────────────────────────────────────────
st.html("""
<script>
    requestAnimationFrame(() => {
        const input = document.querySelector('input[data-testid="stChatInput"]') || 
                      document.querySelector('textarea[data-testid="stChatInputTextArea"]');
        if (input && document.activeElement !== input) input.focus();
    });
</script>
""")
# ── State & connection ─────────────────────────────────────────────────────────
init_state()

if st.session_state.fg_connected is None:
    check_fortigate_connection()

# ── Sidebar ───────────────────────────────────────────────────────────────────
try:
    render_sidebar()
except Exception as _sb_err:
    with st.sidebar:
        st.error(f"Sidebar error: {_sb_err}")
        import traceback
        st.code(traceback.format_exc())

# ── Chat area ─────────────────────────────────────────────────────────────────
st.markdown(
    '<div style="max-width:780px;margin:0 auto;padding:0.25rem 1.25rem 6.5rem 1.25rem">',
    unsafe_allow_html=True,
)

if st.session_state.get("fg_connected") is False:
    st.markdown(
        '<div style="background-color:rgba(255, 68, 68, 0.1); border-left: 4px solid #ff4444; '
        'padding: 1rem; margin: 1rem 0 2rem; border-radius: 4px;">'
        '<span style="color: #ff4444; font-weight: bold;">⚠ FortiGate Offline</span>'
        '<br><span style="color: #dddddd; font-size: 0.9rem;">'
        'Read operations may return stale data. Write operations will fail. '
        'Please check the management connection.</span></div>',
        unsafe_allow_html=True
    )

if not st.session_state.messages:
    st.markdown(
        """
<div class="msg-agent" style="margin-top:2rem">
  <div class="agent-icon">AI</div>
  <div class="bubble">
    <div style="font-size:1rem;font-weight:400;color:#eeeeee;margin-bottom:0.5rem;letter-spacing:-0.01em">
      FortiGate AI Agent
    </div>
    <div style="font-size:0.88rem;color:#555555;line-height:1.7;font-weight:300">
      Natural language interface to your FortiGate firewall.
    </div>
    <div style="margin-top:1.2rem;display:flex;flex-wrap:wrap;gap:0.5rem">
      <span style="font-size:0.75rem;font-family:JetBrains Mono,monospace;color:#444444;
                   border:1px solid #222222;padding:0.2rem 0.6rem">list all policies</span>
      <span style="font-size:0.75rem;font-family:JetBrains Mono,monospace;color:#444444;
                   border:1px solid #222222;padding:0.2rem 0.6rem">block ip 10.0.0.5</span>
      <span style="font-size:0.75rem;font-family:JetBrains Mono,monospace;color:#444444;
                   border:1px solid #222222;padding:0.2rem 0.6rem">audit my firewall</span>
      <span style="font-size:0.75rem;font-family:JetBrains Mono,monospace;color:#444444;
                   border:1px solid #222222;padding:0.2rem 0.6rem">show vpn status</span>
    </div>
  </div>
</div>""",
        unsafe_allow_html=True,
    )

for msg in st.session_state.messages:
    if msg["role"] == "user":
        render_user_message(msg["content"])
    else:
        render_agent_message(msg["content"], kind=msg.get("kind", "answer"))

render_confirmation_buttons()

st.markdown("</div>", unsafe_allow_html=True)

# ── Input ─────────────────────────────────────────────────────────────────────
placeholder = (
    "Type 'yes' to confirm or 'no' to cancel…"
    if st.session_state.get("pending", False)
    else "Ask me anything about your FortiGate…"
)

user_input = st.chat_input(
    placeholder=placeholder,
    key=f"chat_input_{st.session_state.input_key}",
)

# ── Process ───────────────────────────────────────────────────────────────────
if user_input and user_input.strip():
    text = user_input.strip()

    push_message("user", text)
    
    st.markdown('<div style="max-width:780px;margin:0 auto;padding:0.25rem 1.25rem 0.5rem 1.25rem">', unsafe_allow_html=True)
    render_user_message(text)
    render_thinking_indicator()
    st.markdown('</div>', unsafe_allow_html=True)

    agent    = get_agent()
    response = agent.process(text)

    from core import ResponseKind

    push_message(role="agent", content=response.text, kind=response.kind.value)

    # Track last action for sidebar
    if response.kind not in (ResponseKind.CONFIRMATION, ResponseKind.ANSWER):
        st.session_state.last_action = text[:40]

    if response.kind == ResponseKind.CONFIRMATION:
        st.session_state.pending      = True
        st.session_state.pending_text = response.text
    elif response.kind in (ResponseKind.CANCELLED, ResponseKind.ANSWER):
        was_pending = st.session_state.get("pending", False)
        st.session_state.pending      = False
        st.session_state.pending_text = ""
        
        # If an operation was just confirmed and executed, sync the device counts
        if was_pending and response.kind == ResponseKind.ANSWER:
            from ui.utils.state import check_fortigate_connection
            check_fortigate_connection()

    st.session_state.input_key += 1
    st.rerun()