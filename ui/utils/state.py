"""
state.py — Streamlit session state management.
"""
from __future__ import annotations

import sys
import os
from typing import Any, List, Optional

import streamlit as st

# Ensure agent directory is on path
_UI_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT_DIR = os.path.dirname(_UI_DIR)
_AGENT_DIR = os.path.join(_ROOT_DIR, "agent")
for p in (_ROOT_DIR, _AGENT_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)


def init_state() -> None:
    """Initialise all required session_state keys on first load."""
    defaults = {
        "agent":        None,     # AgentSession instance
        "messages":     [],       # List[dict] — {role, content, kind, meta}
        "pending":      False,    # Write confirmation awaiting yes/no
        "pending_text": "",       # The confirmation text to show
        "fg_connected": None,     # None=unknown, True=ok, False=fail
        "fg_info":      {},       # {"hostname": ..., "version": ...}
        "input_key":    0,        # Forces chat_input to reset
        "thinking":     False,    # Show "thinking" indicator
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default


def get_agent():
    """Return the AgentSession, creating it if needed."""
    if st.session_state.agent is None:
        from core import AgentSession
        st.session_state.agent = AgentSession()
    return st.session_state.agent


def push_message(
    role:    str,
    content: str,
    kind:    str  = "answer",
    meta:    dict = None,
) -> None:
    """Append a message to conversation history."""
    st.session_state.messages.append({
        "role":    role,
        "content": content,
        "kind":    kind,
        "meta":    meta or {},
    })


def check_fortigate_connection() -> bool:
    """
    Quick connectivity check against FortiGate.
    Returns True if reachable, False otherwise.
    Updates st.session_state.fg_connected and fg_info.
    """
    try:
        from modules.system import get_system_status
        r = get_system_status()
        results = r if isinstance(r, dict) else {}
        hostname = results.get("hostname", "FortiGate")
        version  = results.get("version", "unknown")
        st.session_state.fg_connected = True
        st.session_state.fg_info      = {
            "hostname": hostname,
            "version":  version,
        }
        return True
    except Exception:
        st.session_state.fg_connected = False
        st.session_state.fg_info      = {}
        return False