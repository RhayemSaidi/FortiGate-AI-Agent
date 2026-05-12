"""
streamlit_app.py — FortiGate AI Agent — Streamlit interface.

Entry point. Run with:
    streamlit run streamlit_app.py

Architecture:
  - st.session_state owns all conversational state
  - AgentSession (from core.py) owns all execution logic
  - UI never bypasses: NLU → grounding → confirmation → executor → verifier
  - All writes go through AgentSession.process()
"""
from __future__ import annotations

import sys
import os

# ── Path setup ────────────────────────────────────────────────────────────────
_THIS_DIR  = os.path.dirname(os.path.abspath(__file__))
_AGENT_DIR = os.path.join(_THIS_DIR, "agent")
for p in (_THIS_DIR, _AGENT_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

# ── Streamlit ─────────────────────────────────────────────────────────────────
import streamlit as st

# ── UI modules ────────────────────────────────────────────────────────────────
from ui.styles.theme       import DARK_CSS
from ui.utils.state        import init_state, get_agent, push_message, check_fortigate_connection
from ui.components.chat    import render_user_message, render_agent_message, render_thinking_indicator
from ui.components.confirmation import render_confirmation_buttons
from ui.components.status_bar   import render_sidebar

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="FortiGate AI Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Inject CSS ────────────────────────────────────────────────────────────────
st.markdown(DARK_CSS, unsafe_allow_html=True)

# ── Initialise state ──────────────────────────────────────────────────────────
init_state()

# ── Background: check FortiGate connection on first load ──────────────────────
if st.session_state.fg_connected is None:
    check_fortigate_connection()

# ── Sidebar ───────────────────────────────────────────────────────────────────
render_sidebar()

# ── Main layout ───────────────────────────────────────────────────────────────
st.markdown(
    """
<div style="max-width:860px;margin:0 auto;padding:1.5rem 1rem 0 1rem">
  <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.5rem">
    <div style="width:38px;height:38px;background:linear-gradient(135deg,#1f6feb,#58a6ff);
    border-radius:10px;display:flex;align-items:center;justify-content:center;
    font-size:1.1rem">🛡️</div>
    <div>
      <div style="font-size:1.15rem;font-weight:700;color:#e6edf3">
        FortiGate AI Agent
      </div>
      <div style="font-size:0.78rem;color:#8b949e">
        Natural language firewall administration
      </div>
    </div>
  </div>
</div>""",
    unsafe_allow_html=True,
)

# ── Chat history ──────────────────────────────────────────────────────────────
chat_area = st.container()

with chat_area:
    st.markdown('<div class="chat-container">', unsafe_allow_html=True)

    if not st.session_state.messages:
        # Welcome message
        st.markdown(
            """
<div class="msg-agent">
  <div class="avatar">FG</div>
  <div class="bubble">
    <div style="font-weight:600;margin-bottom:0.4rem">
      Welcome to FortiGate AI Agent
    </div>
    <div style="color:#8b949e;font-size:0.88rem;line-height:1.65">
      I manage FortiGate firewalls using natural language.<br>
      Ask me to show policies, update rules, analyze security, or anything else.<br><br>
      <strong style="color:#e6edf3">Try:</strong><br>
      &nbsp;&bull; <code>list all policies</code><br>
      &nbsp;&bull; <code>add SSH to policy 4</code><br>
      &nbsp;&bull; <code>analyze my firewall security</code><br>
      &nbsp;&bull; <code>what does policy BlockSSH do?</code>
    </div>
  </div>
</div>""",
            unsafe_allow_html=True,
        )

    # Render conversation history
    for msg in st.session_state.messages:
        if msg["role"] == "user":
            render_user_message(msg["content"])
        else:
            render_agent_message(msg["content"], kind=msg.get("kind", "answer"))

    # Confirmation buttons (shown below last message if pending)
    render_confirmation_buttons()

    st.markdown('</div>', unsafe_allow_html=True)

# ── Chat input ────────────────────────────────────────────────────────────────
st.markdown(
    '<div style="position:fixed;bottom:0;left:0;right:0;'
    'background:linear-gradient(transparent,#0d1117 30%);'
    'padding:1rem 1rem 1.5rem 1rem;z-index:100">',
    unsafe_allow_html=True,
)

# Determine placeholder based on state
if st.session_state.get("pending", False):
    placeholder = "Type 'yes' to confirm or 'no' to cancel…"
else:
    placeholder = "Ask me anything about your FortiGate…"

user_input = st.chat_input(
    placeholder=placeholder,
    key=f"chat_input_{st.session_state.input_key}",
)

st.markdown('</div>', unsafe_allow_html=True)

# ── Process input ─────────────────────────────────────────────────────────────
if user_input and user_input.strip():
    text = user_input.strip()

    # Push user message immediately
    push_message("user", text)

    # Show thinking indicator while processing
    with chat_area:
        render_thinking_indicator()

    # Get agent response
    agent    = get_agent()
    response = agent.process(text)

    # Import here to avoid circular at module level
    from core import ResponseKind

    # Push agent response
    push_message(
        role="agent",
        content=response.text,
        kind=response.kind.value,
    )

    # Handle confirmation state
    if response.kind == ResponseKind.CONFIRMATION:
        st.session_state.pending      = True
        st.session_state.pending_text = response.text
    elif response.kind in (ResponseKind.CANCELLED, ResponseKind.ANSWER):
        st.session_state.pending      = False
        st.session_state.pending_text = ""

    # Increment key to clear input
    st.session_state.input_key += 1

    st.rerun()