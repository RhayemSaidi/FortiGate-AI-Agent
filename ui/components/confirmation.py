"""
confirmation.py — YES/NO confirmation buttons and flow.
"""
from __future__ import annotations

import streamlit as st
from ui.utils.state import get_agent, push_message


def render_confirmation_buttons() -> None:
    """
    Render YES / NO buttons for pending write confirmations.
    Buttons are only shown when st.session_state.pending is True.
    """
    if not st.session_state.get("pending", False):
        return

    st.markdown(
        '<div style="max-width:420px;margin:0.25rem 0 1rem 2.75rem">',
        unsafe_allow_html=True,
    )

    col_yes, col_no, _ = st.columns([1.2, 1, 3])

    with col_yes:
        st.markdown('<div class="btn-confirm">', unsafe_allow_html=True)
        if st.button("✓ Confirm", key="btn_yes", use_container_width=True):
            _handle_confirmation("yes")
        st.markdown('</div>', unsafe_allow_html=True)

    with col_no:
        st.markdown('<div class="btn-cancel">', unsafe_allow_html=True)
        if st.button("✗ Cancel", key="btn_no", use_container_width=True):
            _handle_confirmation("no")
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)


def _handle_confirmation(answer: str) -> None:
    """Process a yes/no answer through the agent's confirmation handler."""
    from ui.utils.state import push_message

    agent = get_agent()

    # Push user's answer as a message
    label = "✓ Confirmed" if answer == "yes" else "✗ Cancelled"
    push_message("user", label)

    # Process through agent — this calls _handle_confirmation() internally
    response = agent.process(answer)

    push_message(
        role="agent",
        content=response.text,
        kind=response.kind.value,
    )

    # Clear pending state
    st.session_state.pending     = False
    st.session_state.pending_text = ""
    st.session_state.input_key  += 1

    st.rerun()