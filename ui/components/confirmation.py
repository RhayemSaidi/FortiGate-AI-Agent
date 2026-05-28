"""
confirmation.py — Minimal YES/NO confirmation buttons.
"""
from __future__ import annotations

import streamlit as st
from ui.utils.state import get_agent, push_message


def render_confirmation_buttons() -> None:
    if not st.session_state.get("pending", False):
        return

    is_danger = any(
        k in st.session_state.get("pending_text", "").upper()
        for k in ("DELETE", "PERMANENTLY", "BLOCK", "REBOOT")
    )

    st.markdown('<div style="margin-left:2.2rem;margin-top:0.35rem;margin-bottom:0.5rem">', unsafe_allow_html=True)

    col_yes, col_no, _ = st.columns([0.9, 0.9, 5])

    with col_yes:
        cls = "btn-danger" if is_danger else "btn-ok"
        st.markdown(f'<div class="{cls}">', unsafe_allow_html=True)
        if st.button("Confirm", key="btn_yes", use_container_width=True):
            _handle("yes")
        st.markdown("</div>", unsafe_allow_html=True)

    with col_no:
        st.markdown('<div class="btn-cancel">', unsafe_allow_html=True)
        if st.button("Cancel", key="btn_no", use_container_width=True):
            _handle("no")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)


def _handle(answer: str) -> None:
    agent = get_agent()
    push_message("user", "Confirmed" if answer == "yes" else "Cancelled")

    response = agent.process(answer)
    push_message(role="agent", content=response.text, kind=response.kind.value)

    from core import ResponseKind
    if response.kind == ResponseKind.CONFIRMATION:
        st.session_state.pending      = True
        st.session_state.pending_text = response.text
    else:
        st.session_state.pending      = False
        st.session_state.pending_text = ""

    st.session_state.input_key += 1
    st.rerun()