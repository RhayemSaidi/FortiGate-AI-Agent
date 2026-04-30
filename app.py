import sys
import os
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from agent.agent import (
    build_llms, detect_intent, is_knowledge_question, is_write_intent,
    extract_params, execute_tool, format_response, format_confirmation,
    handle_confirmation_yes, handle_with_mistral, trim_conversation,
)
from agent.prompt import SYSTEM_PROMPT
from agent.tools import TOOL_MAP, ALL_TOOLS
from audit.logger import read_logs
from modules.system import get_system_status
from modules.monitor import get_cpu_usage, get_memory_usage
from modules.policies import list_policies
from audit.logger import log_action, log_conversation

st.set_page_config(
    page_title="FortiGate AI Agent",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Minimal CSS — clean and professional ─────────────────
st.markdown("""
<style>
    .stApp { background-color: #0d1117; color: #e6edf3; }
    .main .block-container { padding: 1.5rem 2rem; max-width: 100%; }
    .chat-user {
        background: #1c2a3a;
        border-left: 3px solid #1f6feb;
        padding: 0.75rem 1rem;
        border-radius: 4px;
        margin: 0.5rem 0;
        font-size: 0.95rem;
    }
    .chat-agent {
        background: #161b22;
        border-left: 3px solid #3fb950;
        padding: 0.75rem 1rem;
        border-radius: 4px;
        margin: 0.5rem 0;
        font-size: 0.95rem;
        white-space: pre-wrap;
    }
    .confirm-box {
        background: #1a1400;
        border: 1px solid #d29922;
        border-radius: 6px;
        padding: 1rem 1.25rem;
        margin: 0.75rem 0;
        font-family: monospace;
        font-size: 0.9rem;
    }
    .warning-box {
        background: #1a0a00;
        border: 1px solid #f85149;
        border-radius: 6px;
        padding: 1rem 1.25rem;
        margin: 0.75rem 0;
        font-size: 0.9rem;
    }
    .stat-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.5rem;
        font-size: 0.85rem;
    }
    #MainMenu, footer, header { visibility: hidden; }
    .stTextInput > div > div > input {
        background-color: #161b22;
        color: #e6edf3;
        border: 1px solid #30363d;
    }
    .stButton > button {
        background-color: #1f6feb;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 0.4rem 1.2rem;
    }
    .stButton > button:hover { background-color: #388bfd; }
    button[kind="secondary"] {
        background-color: #21262d !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
    }
</style>
""", unsafe_allow_html=True)


# ── Session state ─────────────────────────────────────────
if "conversation" not in st.session_state:
    st.session_state.conversation = [SystemMessage(content=SYSTEM_PROMPT)]
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "pending_confirmation" not in st.session_state:
    st.session_state.pending_confirmation = None
if "llms_built" not in st.session_state:
    llm_tools, llm_plain = build_llms()
    st.session_state.llm_tools = llm_tools
    st.session_state.llm_plain = llm_plain
    st.session_state.llms_built = True


# ── Helpers ───────────────────────────────────────────────

def add_message(role: str, content: str, msg_type: str = "normal"):
    st.session_state.chat_history.append({
        "role":    role,
        "content": content,
        "type":    msg_type,
    })


def process_message(user_input: str):
    """
    Main message processing pipeline — mirrors agent.py logic
    but stores results in session state instead of printing.
    """
    add_message("user", user_input)
    conv      = st.session_state.conversation
    llm_plain = st.session_state.llm_plain
    llm_tools = st.session_state.llm_tools

    try:
        if is_knowledge_question(user_input):
            from agent.tools import tool_search_knowledge as _sk
            tool_result = str(_sk.invoke({"query": user_input}))
            log_action(
                action="TOOL_SEARCH_KNOWLEDGE",
                user_input=user_input,
                tool_called="tool_search_knowledge",
                tool_input=user_input,
                result=tool_result,
                status="success",
            )
            answer = format_response(llm_plain, conv, tool_result, user_input)
            conv.append(HumanMessage(content=user_input))
            conv.append(AIMessage(content=answer))
            add_message("agent", answer)
            log_conversation(user_input, answer)
            return

        intent = detect_intent(user_input)

        if intent:
            tool_name, tool_args = intent

            if tool_name in WRITE_TOOLS and tool_args is None:
                tool_args = extract_params(tool_name, user_input, llm_plain)

                if tool_args is None:
                    missing = {
                        "tool_create_policy":
                            "Please provide: policy name, interfaces, service, action.",
                        "tool_create_address":
                            "Please provide: address name and subnet (e.g. 192.168.1.0/24).",
                        "tool_delete_address":
                            "Please provide the exact name of the address to delete.",
                        "tool_delete_policy":
                            "Please provide the policy ID or name.",
                        "tool_enable_disable_policy":
                            "Please provide the policy ID or name.\nExample: enable policy 4",
                        "tool_move_policy":
                            "Example: move policy 3 before policy 1",
                        "tool_block_ip":
                            "Please provide the IP address.\nExample: block ip 192.168.1.55",
                        "tool_update_interface_access":
                            "Example: disable HTTP and TELNET on port2",
                    }
                    msg = missing.get(tool_name, "Please provide required details.")
                    add_message("agent", msg)
                    return

            if tool_name in WRITE_TOOLS:
                confirmation_text = format_confirmation(tool_name, tool_args)
                st.session_state.pending_confirmation = {
                    "name":           tool_name,
                    "args":           tool_args,
                    "original_input": user_input,
                    "warnings_shown": False,
                }
                add_message("agent", confirmation_text, "confirmation")
                return

            # Read tool
            tool_result = execute_tool(tool_name, tool_args, user_input)
            answer = format_response(llm_plain, conv, tool_result, user_input)
            conv.append(HumanMessage(content=user_input))
            conv.append(AIMessage(content=answer))
            add_message("agent", answer)
            log_conversation(user_input, answer)

        else:
            pending_ref = [None]
            handle_with_mistral(user_input, conv, llm_tools, llm_plain, pending_ref)
            if pending_ref[0]:
                pc = pending_ref[0]
                confirmation_text = format_confirmation(pc["name"], pc["args"])
                st.session_state.pending_confirmation = {
                    "name":           pc["name"],
                    "args":           pc["args"],
                    "original_input": user_input,
                    "warnings_shown": False,
                }
                add_message("agent", confirmation_text, "confirmation")
            else:
                # Get last AI message from conversation
                ai_msgs = [m for m in conv if isinstance(m, AIMessage)]
                if ai_msgs:
                    last = ai_msgs[-1].content
                    add_message("agent", last)

    except Exception as exc:
        st.session_state.pending_confirmation = None
        add_message("agent", f"Error: {str(exc)}", "error")


def handle_confirm():
    pc        = st.session_state.pending_confirmation
    conv      = st.session_state.conversation
    llm_plain = st.session_state.llm_plain

    stay, updated = handle_confirmation_yes(pc, conv, llm_plain)
    st.session_state.pending_confirmation = updated

    if not stay:
        # Get the answer that was added to conversation
        ai_msgs = [m for m in conv if isinstance(m, AIMessage)]
        if ai_msgs:
            add_message("agent", ai_msgs[-1].content)


def handle_cancel():
    pc = st.session_state.pending_confirmation
    if pc:
        log_action(
            action="CANCELLED",
            user_input=pc.get("original_input", ""),
            tool_called=pc["name"],
            tool_input=str(pc["args"]),
            result="User cancelled",
            status="cancelled",
        )
    add_message("agent", "Action cancelled.")
    st.session_state.pending_confirmation = None


# ── Sidebar ───────────────────────────────────────────────

def render_sidebar():
    with st.sidebar:
        st.markdown("### FortiGate Status")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Refresh", use_container_width=True):
                st.rerun()
        with col2:
            if st.button("Clear chat", use_container_width=True):
                st.session_state.chat_history = []
                st.session_state.conversation = [SystemMessage(content=SYSTEM_PROMPT)]
                st.session_state.pending_confirmation = None
                st.rerun()

        st.markdown("---")

        try:
            r   = get_system_status()
            res = r.get("results", {})
            st.markdown(
                f'<div class="stat-card">'
                f'<b>Hostname</b>: {res.get("hostname","N/A")}<br>'
                f'<b>Model</b>: {res.get("model_name","N/A")}<br>'
                f'<b>Version</b>: {r.get("version","N/A")}'
                f'</div>',
                unsafe_allow_html=True
            )
        except Exception:
            st.error("Cannot reach FortiGate")

        try:
            cpu_data = get_cpu_usage()
            mem_data = get_memory_usage()
            cpu = cpu_data["results"]["cpu"][0]["current"]
            mem = mem_data["results"]["mem"][0]["current"]

            c1, c2 = st.columns(2)
            c1.metric("CPU", f"{cpu}%")
            c2.metric("Memory", f"{mem}%")
            st.progress(cpu / 100)
            st.progress(mem / 100)
        except Exception:
            st.warning("Resource stats unavailable")

        st.markdown("---")
        st.markdown("### Firewall Policies")

        try:
            r       = list_policies()
            results = r if isinstance(r, list) else r.get("results", [])
            for p in results:
                action   = p.get("action", "?")
                status   = p.get("status", "enable")
                color    = "#f85149" if action == "deny" else "#3fb950"
                disabled = " (disabled)" if status == "disable" else ""
                st.markdown(
                    f'<div class="stat-card">'
                    f'<span style="color:{color}">&#9679;</span> '
                    f'[{p.get("policyid")}] {p.get("name")}'
                    f'<br><small>{action.upper()}{disabled}</small>'
                    f'</div>',
                    unsafe_allow_html=True
                )
        except Exception:
            st.warning("Could not load policies")

        st.markdown("---")
        st.markdown("### Recent Actions")

        try:
            logs      = read_logs(limit=20)
            tool_logs = [l for l in logs if l.get("type") == "action"][-5:]
            for entry in reversed(tool_logs):
                ts     = entry.get("timestamp","")[:16].replace("T"," ")
                action = entry.get("action","?")
                status = entry.get("status","?")
                color  = "#3fb950" if status == "success" else "#f85149"
                st.markdown(
                    f'<small><span style="color:{color}">[{status.upper()[:2]}]</span>'
                    f' {ts}<br>{action}</small>',
                    unsafe_allow_html=True
                )
        except Exception:
            pass


# ── Chat display ──────────────────────────────────────────

def render_chat():
    for msg in st.session_state.chat_history:
        role     = msg["role"]
        content  = msg["content"]
        msg_type = msg.get("type", "normal")

        if role == "user":
            st.markdown(
                f'<div class="chat-user"><b>You:</b> {content}</div>',
                unsafe_allow_html=True
            )
        elif role == "agent":
            if msg_type == "confirmation":
                st.markdown(
                    f'<div class="confirm-box">{content}</div>',
                    unsafe_allow_html=True
                )
            elif msg_type == "error":
                st.markdown(
                    f'<div class="warning-box">{content}</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f'<div class="chat-agent">{content}</div>',
                    unsafe_allow_html=True
                )


# ── Confirmation panel ────────────────────────────────────

def render_confirmation_panel():
    pc = st.session_state.pending_confirmation
    if not pc:
        return

    args           = pc["args"]
    tool_name      = pc["name"]
    warnings_shown = pc.get("warnings_shown", False)

    title = "Security Warning — Proceed?" if warnings_shown else "Confirm Action"

    with st.container():
        st.markdown(f"**{title}**")

        if not warnings_shown:
            lines = []
            if tool_name == "tool_create_policy":
                lines = [
                    f"Action    : CREATE policy",
                    f"Name      : {args.get('name','?')}",
                    f"Interfaces: {args.get('srcintf','?')} -> {args.get('dstintf','?')}",
                    f"Service   : {args.get('service','ALL')}",
                    f"Action    : {args.get('action','accept').upper()}",
                ]
            elif tool_name == "tool_delete_policy":
                lines = [
                    f"Action    : DELETE policy ID {args.get('policy_id','?')}",
                    "WARNING: This cannot be undone.",
                ]
            elif tool_name == "tool_enable_disable_policy":
                verb = args.get("status","?").upper()
                lines = [f"Action: {verb} policy ID {args.get('policy_id','?')}"]
            elif tool_name == "tool_move_policy":
                lines = [
                    f"Action: MOVE policy {args.get('policy_id','?')} "
                    f"{args.get('move_action','?')} policy {args.get('neighbor_id','?')}"
                ]
            elif tool_name == "tool_create_address":
                lines = [
                    f"Action : CREATE address",
                    f"Name   : {args.get('name','?')}",
                    f"Subnet : {args.get('subnet','?')}",
                ]
            elif tool_name == "tool_delete_address":
                lines = [
                    f"Action : DELETE address '{args.get('name','?')}'",
                    "WARNING: This cannot be undone.",
                ]
            elif tool_name == "tool_update_interface_access":
                lines = [
                    f"Action    : UPDATE interface {args.get('name','?')}",
                    f"Allow only: {args.get('allowaccess','?').upper()}",
                ]
            elif tool_name == "tool_block_ip":
                lines = [
                    f"Action   : BLOCK {args.get('ip_address','?')}",
                    f"Direction: {args.get('direction','both')}",
                ]
            elif tool_name == "tool_backup_config":
                lines = ["Action: BACKUP configuration"]

            for line in lines:
                st.text(line)

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Confirm", type="primary", use_container_width=True,
                         key="btn_confirm"):
                handle_confirm()
                st.rerun()
        with col2:
            if st.button("Cancel", use_container_width=True,
                         key="btn_cancel"):
                handle_cancel()
                st.rerun()


# ── Quick action buttons ──────────────────────────────────

def render_quick_actions():
    st.markdown("Quick actions:")
    cols = st.columns(5)
    actions = [
        "list all policies",
        "show all interfaces",
        "check cpu and memory",
        "analyze firewall security",
        "list all addresses",
    ]
    for i, action in enumerate(actions):
        with cols[i]:
            if st.button(action, use_container_width=True,
                         key=f"quick_{i}"):
                process_message(action)
                st.rerun()


# ── Main ──────────────────────────────────────────────────

def main():
    render_sidebar()
    st.session_state.conversation = trim_conversation(
        st.session_state.conversation
    )

    st.markdown("## FortiGate AI Agent")
    st.caption("Powered by Mistral AI and FortiOS Knowledge Base")
    st.markdown("---")

    # Chat history
    render_chat()

    # Confirmation panel (if active)
    render_confirmation_panel()

    # Input area
    st.markdown("---")
    col1, col2 = st.columns([6, 1])
    with col1:
        user_input = st.text_input(
            "Message",
            placeholder="Ask anything about your FortiGate...",
            key="user_input",
            label_visibility="collapsed",
            disabled=st.session_state.pending_confirmation is not None,
        )
    with col2:
        send = st.button(
            "Send",
            type="primary",
            use_container_width=True,
            disabled=st.session_state.pending_confirmation is not None,
        )

    if send and user_input.strip():
        process_message(user_input.strip())
        st.rerun()

    # Quick actions (disabled during confirmation)
    if not st.session_state.pending_confirmation:
        render_quick_actions()


if __name__ == "__main__":
    main()