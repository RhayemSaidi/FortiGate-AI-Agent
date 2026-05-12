"""
status_bar.py — Sidebar status and metrics rendering.
"""
from __future__ import annotations

import streamlit as st
from ui.utils.state import check_fortigate_connection


def render_sidebar() -> None:
    """Render the full sidebar with connection status and system info."""
    with st.sidebar:
        # Logo / title
        st.markdown(
            """
<div style="text-align:center;padding:1rem 0 1.5rem 0">
  <div style="font-size:1.6rem;font-weight:700;color:#58a6ff;
  letter-spacing:-0.02em">FortiGate AI</div>
  <div style="font-size:0.75rem;color:#8b949e;margin-top:0.2rem">
    Intelligent Operations Platform
  </div>
</div>""",
            unsafe_allow_html=True,
        )

        st.divider()

        # Connection status
        _render_connection_status()

        st.divider()

        # Session controls
        st.markdown(
            '<div style="font-size:0.75rem;font-weight:600;color:#8b949e;'
            'text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.5rem">'
            'Session</div>',
            unsafe_allow_html=True,
        )

        if st.button("🔄 New conversation", use_container_width=True):
            _reset_session()

        # Show pending state
        if st.session_state.get("pending", False):
            st.markdown(
                """
<div style="background:rgba(210,153,34,0.1);border:1px solid rgba(210,153,34,0.3);
border-radius:6px;padding:0.5rem 0.75rem;margin:0.5rem 0;font-size:0.8rem;color:#d29922">
  <span class="status-dot pending"></span>
  Awaiting confirmation
</div>""",
                unsafe_allow_html=True,
            )

        st.divider()

        # Conversation stats
        msg_count = len(st.session_state.get("messages", []))
        user_msgs = sum(
            1 for m in st.session_state.get("messages", [])
            if m["role"] == "user"
        )

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Messages", msg_count)
        with col2:
            st.metric("Commands", user_msgs)

        st.divider()

        # Quick commands
        st.markdown(
            '<div style="font-size:0.75rem;font-weight:600;color:#8b949e;'
            'text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.5rem">'
            'Quick commands</div>',
            unsafe_allow_html=True,
        )

        _render_quick_command("📋 List all policies", "list all policies")
        _render_quick_command("🔒 Security audit",    "analyze my firewall security")
        _render_quick_command("📊 System status",     "system status")
        _render_quick_command("🌐 Active sessions",   "show active sessions")

        st.divider()

        # Footer
        st.markdown(
            '<div style="text-align:center;font-size:0.7rem;color:#484f58;'
            'padding-top:0.5rem">FortiGate AI Agent<br>'
            'Powered by Mistral AI</div>',
            unsafe_allow_html=True,
        )


def _render_connection_status() -> None:
    st.markdown(
        '<div style="font-size:0.75rem;font-weight:600;color:#8b949e;'
        'text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.5rem">'
        'Firewall</div>',
        unsafe_allow_html=True,
    )

    connected = st.session_state.get("fg_connected")
    fg_info   = st.session_state.get("fg_info", {})

    if connected is True:
        hostname = fg_info.get("hostname", "FortiGate")
        version  = fg_info.get("version", "")
        st.markdown(
            f"""
<div style="background:#0f2a1a;border:1px solid rgba(63,185,80,0.3);
border-radius:6px;padding:0.6rem 0.75rem;font-size:0.82rem">
  <div><span class="status-dot connected"></span>
  <span style="color:#3fb950;font-weight:600">Connected</span></div>
  <div style="color:#8b949e;margin-top:0.3rem;font-size:0.78rem">
    {hostname}<br><code style="font-size:0.72rem">{version}</code>
  </div>
</div>""",
            unsafe_allow_html=True,
        )
    elif connected is False:
        st.markdown(
            """
<div style="background:#2a0f0f;border:1px solid rgba(248,81,73,0.3);
border-radius:6px;padding:0.6rem 0.75rem;font-size:0.82rem">
  <span class="status-dot disconnected"></span>
  <span style="color:#f85149;font-weight:600">Disconnected</span>
  <div style="color:#8b949e;margin-top:0.25rem;font-size:0.76rem">
    Check FortiGate connectivity
  </div>
</div>""",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
<div style="background:#161b22;border:1px solid #30363d;
border-radius:6px;padding:0.6rem 0.75rem;font-size:0.82rem;color:#8b949e">
  <span class="status-dot pending"></span>Connecting...
</div>""",
            unsafe_allow_html=True,
        )

    # Refresh button
    if st.button("↺ Check connection", use_container_width=True):
        check_fortigate_connection()
        st.rerun()


def _render_quick_command(label: str, command: str) -> None:
    """Render a clickable quick-command button."""
    if st.button(label, use_container_width=True):
        from ui.utils.state import get_agent, push_message
        from core import ResponseKind

        push_message("user", command)
        agent    = get_agent()
        response = agent.process(command)

        push_message(
            role="agent",
            content=response.text,
            kind=response.kind.value,
        )

        if response.kind == ResponseKind.CONFIRMATION:
            st.session_state.pending      = True
            st.session_state.pending_text = response.text

        st.rerun()


def _reset_session() -> None:
    from ui.utils.state import get_agent
    # Recreate agent
    from core import AgentSession
    st.session_state.agent    = AgentSession()
    st.session_state.messages = []
    st.session_state.pending  = False
    st.session_state.pending_text = ""
    st.rerun()