import sys
import os
import re
import time
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langchain_mistralai import ChatMistralAI
from langchain_core.messages import (
    HumanMessage, SystemMessage, ToolMessage, AIMessage
)
from tools  import ALL_TOOLS, TOOL_MAP
from prompt import SYSTEM_PROMPT
from audit.logger import log_action, log_conversation

from config import MISTRAL_API_KEY

from validator import (
    validate_create_policy,
    validate_delete_policy,
    validate_update_policy,
    validate_enable_disable_policy,
    validate_move_policy,
    validate_create_address,
    validate_delete_address,
    validate_update_interface_access,
    validate_block_ip,
    clear_cache,
    ValidationResult,
)

WRITE_TOOLS = {
    "tool_create_policy",
    "tool_update_policy",
    "tool_enable_disable_policy",
    "tool_delete_policy",
    "tool_move_policy",
    "tool_create_address",
    "tool_delete_address",
    "tool_update_interface_access",
    "tool_block_ip",
    "tool_backup_config",
}

VALIDATORS = {
    "tool_create_policy":           validate_create_policy,
    "tool_delete_policy":           validate_delete_policy,
    "tool_update_policy":           validate_update_policy,
    "tool_enable_disable_policy":   validate_enable_disable_policy,
    "tool_move_policy":             validate_move_policy,
    "tool_create_address":          validate_create_address,
    "tool_delete_address":          validate_delete_address,
    "tool_update_interface_access": validate_update_interface_access,
    "tool_block_ip":                validate_block_ip,
}

# Maximum conversation turns to keep (each turn = 1 Human + 1 AI message)
MAX_TURNS = 15


# ══════════════════════════════════════════════════════════
#  LLM
# ══════════════════════════════════════════════════════════

def build_llms():
    """
    Two LLM instances with clear separation of purpose:
    - llm_tools : tools bound — used ONLY for tool selection
    - llm_plain : no tools   — used ONLY for formatting responses

    ARCHITECTURE NOTE:
    llm_plain never receives ToolMessage objects — it only receives
    clean HumanMessage/AIMessage conversation history.
    This permanently eliminates the 400 "Unexpected role tool" error.
    """
    base = ChatMistralAI(
        model="mistral-small-latest",
        temperature=0,
        api_key=MISTRAL_API_KEY,
    )
    return base.bind_tools(ALL_TOOLS), base


# ══════════════════════════════════════════════════════════
#  Retry
# ══════════════════════════════════════════════════════════

def invoke_with_retry(llm, messages: list, max_retries: int = 3):
    for attempt in range(max_retries):
        try:
            return llm.invoke(messages)
        except Exception as exc:
            s = str(exc)
            if "429" in s or "rate_limit" in s.lower():
                wait = 2 * (attempt + 1)
                print(f"\n[Rate limit — waiting {wait}s...]\n")
                time.sleep(wait)
            elif "503" in s or "502" in s or "unreachable" in s.lower():
                wait = 3 * (attempt + 1)
                print(f"\n[Server error — waiting {wait}s...]\n")
                time.sleep(wait)
            else:
                raise
    raise Exception("Mistral API unavailable. Please try again.")


# ══════════════════════════════════════════════════════════
#  Conversation management
#
#  KEY DESIGN: `conversation` contains ONLY SystemMessage +
#  HumanMessage/AIMessage pairs. ToolMessages NEVER enter it.
#
#  For each Mistral turn we build a temporary `turn_msgs` list:
#    turn_msgs = list(conversation) + [HumanMessage(user_input)]
#  Tool calls happen inside turn_msgs only.
#  Only the final clean answer is appended to conversation.
#
#  This completely prevents the 400 "Unexpected role tool" error.
# ══════════════════════════════════════════════════════════

def trim_conversation(conversation: list) -> list:
    """
    Keep SystemMessage + last MAX_TURNS * 2 messages.
    conversation only contains Human/AI messages so no
    ToolMessage ordering issues can occur here.
    """
    system = [m for m in conversation if isinstance(m, SystemMessage)]
    rest   = [m for m in conversation if not isinstance(m, SystemMessage)]

    if len(rest) <= MAX_TURNS * 2:
        return conversation

    return system + rest[-(MAX_TURNS * 2):]


# ══════════════════════════════════════════════════════════
#  Intent detection — fast path for unambiguous reads only
# ══════════════════════════════════════════════════════════

def detect_intent(text: str):
    """
    Fast path for unambiguous read commands and security scan.
    Covers English and French variants.
    All write operations and complex queries go to Mistral.
    Returns (tool_name, args_dict) or None.
    """
    t = text.lower().strip()

    # Policy listing — English and French
    if re.search(r'(list|show|get|display|all|lister|afficher|voir|montrer)'
                 r'\s+(all\s+)?(firewall\s+)?(polic|rules|r.gles|politiques)', t):
        return ("tool_list_policies", {})

    # Address listing
    if re.search(r'(list|show|get|display|all|lister|afficher)'
                 r'\s+(all\s+)?(address|addresse|objet)', t):
        return ("tool_list_addresses", {})

    # Interface listing
    if re.search(r'(list|show|get|display|all|lister|afficher)'
                 r'\s+(all\s+)?(interface|network\s+interface)', t):
        return ("tool_list_interfaces", {})

    # User listing
    if re.search(r'(list|show|get|display|all|lister)'
                 r'\s+(all\s+)?(user|utilisateur)', t):
        return ("tool_list_users", {})

    # Route listing
    if re.search(r'(list|show|get|display|all|lister)'
                 r'\s+(all\s+)?(route|routing|routage)', t):
        return ("tool_list_routes", {})

    # System status
    if re.search(r'(system|device|syst.me|dispositif)\s+(status|.tat|info)',t):
        return ("tool_get_system_status", {})
    if re.search(r'\b(check\s+)?(firmware|version)\b', t):
        return ("tool_get_system_status", {})

    # CPU / memory
    if re.search(r'\b(check\s+)?(cpu|memory|m.moire|ram|resource|ressource)\b', t):
        return ("tool_get_cpu_memory", {})

    # VPN
    if re.search(r'(vpn\s+(status|tunnel|.tat)|ipsec\s+tunnel'
                 r'|show\s+vpn|list\s+vpn|statut\s+vpn)', t):
        return ("tool_get_vpn_status", {})

    # Sessions
    if re.search(r'(active\s+session|session\s+count'
                 r'|connexions\s+actives|sessions\s+actives)', t):
        return ("tool_get_active_sessions", {})

    # Backup
    if re.search(r'\bbackup\b|\bsauvegarde\b|\bsave\s+config\b', t):
        return ("tool_backup_config", {})

    # Security analysis
    if re.search(r'\b(analyz|audit|security\s+check|scan\s+firewall'
                 r'|analyser|audit|v.rifier\s+s.curit.)\b', t):
        return ("tool_analyze_security", {})

    # Blocked IPs fast path
    if re.search(r'(show|list|lister|afficher)\s+(blocked|block|bloqu)', t):
        return ("tool_list_addresses", {})

    return None


# ══════════════════════════════════════════════════════════
#  Confirmation formatter
# ══════════════════════════════════════════════════════════

def format_confirmation(tool_name: str, args: dict) -> str:
    lines = ["\n" + "="*55, "  CONFIRMATION REQUIRED", "="*55]

    if tool_name == "tool_create_policy":
        lines += [
            "  CREATE firewall policy:",
            f"    Name      : {args.get('name','?')}",
            f"    Interfaces: {args.get('srcintf','?')} -> {args.get('dstintf','?')}",
            f"    Src Addr  : {args.get('srcaddr','all')}",
            f"    Dst Addr  : {args.get('dstaddr','all')}",
            f"    Service   : {args.get('service','ALL')}",
            f"    Action    : {args.get('action','accept').upper()}",
        ]
    elif tool_name == "tool_update_policy":
        lines.append("  UPDATE firewall policy:")
        lines.append(f"    Policy ID : {args.get('policy_id','?')}")
        for f in ("name","action","srcaddr","dstaddr","service","status"):
            if args.get(f):
                lines.append(f"    {f:<10}: {args[f]}")
    elif tool_name == "tool_enable_disable_policy":
        verb = "ENABLE" if args.get("status") == "enable" else "DISABLE"
        lines += [
            f"  {verb} firewall policy:",
            f"    Policy ID : {args.get('policy_id','?')}",
        ]
    elif tool_name == "tool_delete_policy":
        lines += [
            "  WARNING - PERMANENTLY DELETE policy:",
            f"    Policy ID : {args.get('policy_id','?')}",
            "  This cannot be undone.",
        ]
    elif tool_name == "tool_move_policy":
        lines += [
            "  REORDER firewall policy:",
            f"    Move policy ID {args.get('policy_id','?')} "
            f"{args.get('move_action','?')} "
            f"policy ID {args.get('neighbor_id','?')}",
            "  This changes which rule takes precedence.",
        ]
    elif tool_name == "tool_create_address":
        lines += [
            "  CREATE address object:",
            f"    Name   : {args.get('name','?')}",
            f"    Subnet : {args.get('subnet','?')}",
        ]
    elif tool_name == "tool_delete_address":
        lines += [
            "  WARNING - DELETE address object:",
            f"    Name : {args.get('name','?')}",
            "  This cannot be undone.",
        ]
    elif tool_name == "tool_update_interface_access":
        lines += [
            "  UPDATE interface management access:",
            f"    Interface : {args.get('name','?')}",
            f"    Allow     : {args.get('allowaccess','?').upper()}",
            "  All other protocols will be DISABLED.",
        ]
    elif tool_name == "tool_block_ip":
        lines += [
            "  BLOCK IP address:",
            f"    IP        : {args.get('ip_address','?')}",
            f"    Direction : {args.get('direction','both')}",
            "  Creates deny policy(ies) - reversible by deleting them.",
        ]
    elif tool_name == "tool_backup_config":
        lines += [
            "  BACKUP FortiGate configuration.",
            "  Config saved locally with timestamp.",
        ]

    lines += ["="*55, "  Type 'yes' to confirm or 'no' to cancel.", "="*55]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════
#  Tool executor
# ══════════════════════════════════════════════════════════

def execute_tool(tool_name: str, tool_args: dict, user_input: str) -> str:
    """Execute a tool safely. Never raises — always returns a string."""
    tool = TOOL_MAP.get(tool_name)
    if not tool:
        return f"[ERROR] Tool '{tool_name}' not found."

    print(f"\n[Calling: {tool_name}]")
    try:
        tool_result = str(tool.invoke(tool_args))
    except Exception as exc:
        tool_result = f"[ERROR] {exc}"

    # Clear validator cache after every write so next validation is fresh
    if tool_name in WRITE_TOOLS:
        clear_cache()

    log_action(
        action=tool_name.upper(),
        user_input=user_input,
        tool_called=tool_name,
        tool_input=str(tool_args),
        result=tool_result,
        status="error" if "[ERROR]" in tool_result else "success",
    )
    return tool_result


# ══════════════════════════════════════════════════════════
#  Response formatter
#
#  IMPORTANT: This function receives `conversation` which
#  contains ONLY SystemMessage + HumanMessage/AIMessage pairs.
#  NO ToolMessages. This prevents all 400 errors.
# ══════════════════════════════════════════════════════════

def format_response(llm_plain, conversation: list,
                    tool_result: str, user_input: str) -> str:
    """
    Format a tool result into natural language using the plain LLM.
    Uses clean conversation history only — no ToolMessages.
    """
    fmt = list(conversation) + [
        HumanMessage(
            content=(
                f"User request: {user_input}\n\n"
                f"System data retrieved:\n{tool_result}\n\n"
                f"Present this information clearly and concisely to the user.\n"
                f"Use plain text only. No emojis. No markdown headers.\n"
                f"Use simple ASCII tables if the data is tabular.\n"
                f"Do not call any tools."
            )
        )
    ]
    return invoke_with_retry(llm_plain, fmt).content


# ══════════════════════════════════════════════════════════
#  Post-execution verifier
# ══════════════════════════════════════════════════════════

def verify_after_execution(tool_name: str) -> str:
    """
    After critical policy operations, verify the change took effect
    by reading the current policy list from FortiGate.
    """
    if tool_name not in ("tool_delete_policy", "tool_move_policy",
                         "tool_enable_disable_policy", "tool_create_policy"):
        return ""

    try:
        from modules.policies import list_policies as _lp
        r       = _lp()
        results = r if isinstance(r, list) else r.get("results", [])

        if not results:
            return "\n[Verified: no policies remain]"

        lines = ["\n[Verified current policy order:]"]
        for p in results:
            src = (p.get("srcintf") or [{}])[0].get("name", "?")
            dst = (p.get("dstintf") or [{}])[0].get("name", "?")
            status_flag = " [disabled]" if p.get("status") == "disable" else ""
            lines.append(
                f"  ID {p.get('policyid','?'):>3} | "
                f"{p.get('name','?'):<25} | "
                f"{p.get('action','?'):>6}{status_flag} | "
                f"{src} -> {dst}"
            )
        return "\n".join(lines)
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════
#  Confirmation handler
# ══════════════════════════════════════════════════════════

def handle_confirmation_yes(pending: dict, conversation: list,
                             llm_plain) -> tuple:
    """
    Handle a confirmed write action.
    Returns (stay_in_confirmation_mode, updated_pending).
    """
    tool_name      = pending["name"]
    tool_args      = pending["args"]
    original_input = pending["original_input"]
    warnings_shown = pending.get("warnings_shown", False)

    # Run validation unless warnings were already shown and accepted
    if not warnings_shown:
        validator = VALIDATORS.get(tool_name)
        if validator:
            validation = validator(tool_args)

            if not validation.valid:
                print(validation.format())
                print("\nAgent: Action blocked. Please start a new request with corrected details.\n")
                return False, None

            if validation.has_warnings_only():
                print(validation.format())
                pending["warnings_shown"] = True
                return True, pending  # Stay in confirmation mode

    # Execute
    tool_result  = execute_tool(tool_name, tool_args, original_input)
    print(f"[Result: {tool_result}]\n")

    # Post-execution verification
    verification = verify_after_execution(tool_name)
    if verification:
        print(verification)

    # Format final answer using CLEAN conversation history
    answer = format_response(llm_plain, conversation, tool_result, original_input)
    print(f"Agent: {answer}\n")

    # Add to clean conversation history
    conversation.append(HumanMessage(content=original_input))
    conversation.append(AIMessage(content=answer))
    log_conversation(original_input, answer)

    return False, None  # Exit confirmation mode


# ══════════════════════════════════════════════════════════
#  Main CLI loop
# ══════════════════════════════════════════════════════════

def run_cli():
    llm_tools, llm_plain = build_llms()

    # ARCHITECTURE: conversation holds ONLY SystemMessage + Human/AI pairs
    # ToolMessages NEVER enter this list
    conversation = [SystemMessage(content=SYSTEM_PROMPT)]

    pending_confirmation = None

    print("\n" + "="*55)
    print("  FortiGate AI Agent")
    print("  Powered by Mistral AI + FortiOS Knowledge Base")
    print("="*55)
    print("Type 'exit' to quit.\n")

    while True:
        user_input = input("You: ").strip()

        if user_input.lower() in ("exit", "quit"):
            print("Goodbye!")
            break
        if not user_input:
            continue

        # Trim conversation to prevent overflow
        conversation = trim_conversation(conversation)

        # ── Handle pending confirmation ───────────────────
        if pending_confirmation:
            if user_input.lower() == "yes":
                stay, updated = handle_confirmation_yes(
                    pending_confirmation, conversation, llm_plain
                )
                pending_confirmation = updated
                if stay:
                    continue
            else:
                print("\nAgent: Action cancelled. How else can I help you?\n")
                log_action(
                    action="CANCELLED",
                    user_input=pending_confirmation["original_input"],
                    tool_called=pending_confirmation["name"],
                    tool_input=str(pending_confirmation["args"]),
                    result="User cancelled",
                    status="cancelled",
                )
                pending_confirmation = None
            continue

        # ── Fast path: unambiguous read commands ──────────
        try:
            intent = detect_intent(user_input)

            if intent:
                tool_name, tool_args = intent
                tool_result = execute_tool(tool_name, tool_args, user_input)
                answer = format_response(
                    llm_plain, conversation, tool_result, user_input
                )
                conversation.append(HumanMessage(content=user_input))
                conversation.append(AIMessage(content=answer))
                print(f"\nAgent: {answer}\n")
                log_conversation(user_input, answer)

            else:
                # ── Mistral path ──────────────────────────
                # Build a temporary turn_messages list from clean conversation.
                # Tool call messages stay in turn_msgs and are NEVER added to
                # conversation. This permanently prevents the 400 error.

                turn_msgs = list(conversation)
                turn_msgs.append(HumanMessage(content=user_input))

                response = invoke_with_retry(llm_tools, turn_msgs)
                turn_msgs.append(response)

                if response.tool_calls:
                    all_results = []
                    confirmation_triggered = False

                    for tool_call in response.tool_calls:
                        t_name = tool_call["name"]
                        t_args = tool_call["args"]
                        t_id   = tool_call["id"]

                        if t_name in WRITE_TOOLS:
                            # Add placeholder ToolMessage to keep turn_msgs valid
                            turn_msgs.append(ToolMessage(
                                content="Awaiting user confirmation.",
                                tool_call_id=t_id,
                            ))
                            print(format_confirmation(t_name, t_args))
                            pending_confirmation = {
                                "name": t_name,
                                "args": t_args,
                                "id":   t_id,
                                "original_input": user_input,
                            }
                            confirmation_triggered = True
                            break

                        # Read tool — execute and add result to turn_msgs
                        tool_result = execute_tool(t_name, t_args, user_input)
                        turn_msgs.append(ToolMessage(
                            content=tool_result or "No results.",
                            tool_call_id=t_id,
                        ))
                        all_results.append(tool_result)

                    if not confirmation_triggered and all_results:
                        # Format results using CLEAN conversation (not turn_msgs)
                        combined = "\n\n".join(all_results)
                        answer = format_response(
                            llm_plain, conversation, combined, user_input
                        )
                        # Add clean Human/AI pair to conversation
                        conversation.append(HumanMessage(content=user_input))
                        conversation.append(AIMessage(content=answer))
                        print(f"\nAgent: {answer}\n")
                        log_conversation(user_input, answer)

                else:
                    # Pure conversation — no tool needed
                    answer = response.content
                    conversation.append(HumanMessage(content=user_input))
                    conversation.append(AIMessage(content=answer))
                    print(f"\nAgent: {answer}\n")
                    log_conversation(user_input, answer)

        except Exception as exc:
            error_str = str(exc)
            print(f"\nError: {error_str}\n")

            # Clear pending_confirmation on error so ghost confirmations
            # cannot appear on the next request
            if pending_confirmation:
                pending_confirmation = None
                print("[Confirmation cleared due to error — please retry your request]\n")

            log_action(
                action="UNKNOWN",
                user_input=user_input,
                tool_called="none",
                tool_input="",
                result=error_str,
                status="error",
            )


if __name__ == "__main__":
    run_cli()