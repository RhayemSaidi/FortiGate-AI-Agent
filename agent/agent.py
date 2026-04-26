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
from tools  import ALL_TOOLS
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

TOOL_MAP = {t.name: t for t in ALL_TOOLS}

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

# Map tool name → validator function
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

# FIX: Maximum messages to keep in history to avoid context window overflow.
# Always keeps SystemMessage + last MAX_HISTORY messages.
MAX_HISTORY = 30


# ══════════════════════════════════════════════════════════
#  LLM
# ══════════════════════════════════════════════════════════

def build_llms():
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
#  Message history management
# ══════════════════════════════════════════════════════════

def trim_messages(messages: list) -> list:
    """
    FIX: Keep SystemMessage + last MAX_HISTORY messages.
    Prevents context window overflow in long sessions.
    """
    if len(messages) <= MAX_HISTORY + 1:
        return messages
    system = [m for m in messages if isinstance(m, SystemMessage)]
    rest   = [m for m in messages if not isinstance(m, SystemMessage)]
    return system + rest[-MAX_HISTORY:]


def clean_message_history(messages: list) -> list:
    """Remove orphaned AIMessages with unmatched tool calls."""
    orphaned: set = set()
    cleaned = []
    i = 0
    while i < len(messages):
        msg = messages[i]
        if isinstance(msg, ToolMessage) and msg.tool_call_id in orphaned:
            i += 1
            continue
        if isinstance(msg, AIMessage) and msg.tool_calls:
            tool_ids = {tc["id"] for tc in msg.tool_calls}
            response_ids = {
                messages[j].tool_call_id
                for j in range(i + 1, len(messages))
                if isinstance(messages[j], ToolMessage)
            }
            if not tool_ids.issubset(response_ids):
                orphaned.update(tool_ids)
                i += 1
                continue
        cleaned.append(msg)
        i += 1
    return cleaned


# ══════════════════════════════════════════════════════════
#  Intent detection — fast path for unambiguous reads only
# ══════════════════════════════════════════════════════════

def detect_intent(text: str):
    """
    Fast path for unambiguous READ commands and security scan.
    FIX: removed ^ anchors so "please list all policies" also matches.
    All write operations and complex queries go to Mistral.
    """
    t = text.lower().strip()

    # FIX: no ^ anchor — matches anywhere in sentence
    if re.search(r'(list|show|get|display|all)\s+(all\s+)?(firewall\s+)?(polic|rules)', t):
        return ("tool_list_policies", {})
    if re.search(r'(list|show|get|display|all)\s+(all\s+)?address', t):
        return ("tool_list_addresses", {})
    if re.search(r'(list|show|get|display|all)\s+(all\s+)?interface', t):
        return ("tool_list_interfaces", {})
    if re.search(r'(list|show|get|display|all)\s+(all\s+)?user', t):
        return ("tool_list_users", {})
    if re.search(r'(list|show|get|display|all)\s+(all\s+)?route', t):
        return ("tool_list_routes", {})
    if re.search(r'(system|device)\s+status|firmware\s+version', t):
        return ("tool_get_system_status", {})
    if re.search(r'\b(check\s+)?(cpu|memory|ram)\b', t):
        return ("tool_get_cpu_memory", {})
    if re.search(r'(vpn\s+(status|tunnel)|ipsec\s+tunnel|show\s+vpn|list\s+vpn)', t):
        return ("tool_get_vpn_status", {})
    if re.search(r'(active\s+session|session\s+count|how\s+many\s+session)', t):
        return ("tool_get_active_sessions", {})
    if re.search(r'\bbackup\b|\bsave\s+config\b', t):
        return ("tool_backup_config", {})
    if re.search(r'\b(analyz|audit|security\s+check|scan\s+firewall|inspect\s+firewall)\b', t):
        return ("tool_analyze_security", {})

    # FIX: blocked IP fast path — filter addresses with BLOCKED- prefix
    if re.search(r'(show|list)\s+(blocked|block)', t):
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
            "  WARNING — PERMANENTLY DELETE policy:",
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
            "  WARNING — DELETE address object:",
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
            "  Creates deny policy(ies) — reversible by deleting them.",
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

    # FIX: clear validator cache after every write so next validation is fresh
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
# ══════════════════════════════════════════════════════════

def format_response(llm_plain, messages: list,
                    tool_result: str, user_input: str) -> str:
    fmt = messages + [
        HumanMessage(
            content=(
                f"User asked: {user_input}\n\n"
                f"System data:\n{tool_result}\n\n"
                f"Present this clearly and concisely. "
                f"Do not call any tools. Just explain the results."
            )
        )
    ]
    return invoke_with_retry(llm_plain, fmt).content


# ══════════════════════════════════════════════════════════
#  Post-execution verifier
# ══════════════════════════════════════════════════════════

def verify_after_execution(tool_name: str, tool_args: dict) -> str:
    """
    FIX: After critical write operations, verify the change actually
    took effect on the FortiGate by reading the current state.
    """
    try:
        from modules.policies import list_policies as _lp

        if tool_name == "tool_create_policy" and "[SUCCESS]" in str(tool_args):
            return ""  # ID already verified inside the tool

        if tool_name in ("tool_delete_policy", "tool_move_policy",
                         "tool_enable_disable_policy"):
            r       = _lp()
            results = r if isinstance(r, list) else r.get("results", [])
            if not results:
                return "\n[Verified: no policies remain on FortiGate]"
            lines   = ["\n[Verified current policy order:]"]
            for p in results:
                src = (p.get("srcintf") or [{}])[0].get("name", "?")
                dst = (p.get("dstintf") or [{}])[0].get("name", "?")
                lines.append(
                    f"  ID {p.get('policyid','?'):>3} | "
                    f"{p.get('name','?'):<25} | "
                    f"{p.get('action','?'):>6} | "
                    f"{src} -> {dst}"
                )
            return "\n".join(lines)
    except Exception:
        pass
    return ""


# ══════════════════════════════════════════════════════════
#  Confirmation handler
# ══════════════════════════════════════════════════════════

def handle_confirmation_yes(pending: dict, messages: list, llm_plain):
    """
    Handle a confirmed action.
    Returns (should_break_confirmation_loop, updated_pending).
    """
    tool_name      = pending["name"]
    tool_args      = pending["args"]
    original_input = pending["original_input"]
    warnings_shown = pending.get("warnings_shown", False)

    if not warnings_shown:
        validator = VALIDATORS.get(tool_name)
        if validator:
            validation = validator(tool_args)

            if not validation.valid:
                print(validation.format())
                print("\nAgent: Action blocked. Please start a new request with corrected details.\n")
                # FIX: return False so the loop does NOT stay in confirmation mode
                return False, None

            if validation.has_warnings_only():
                print(validation.format())
                pending["warnings_shown"] = True
                # Stay in confirmation mode, waiting for second yes/no
                return True, pending

    # Execute the action
    tool_result  = execute_tool(tool_name, tool_args, original_input)
    print(f"[Result: {tool_result}]\n")

    # Post-execution verification for critical operations
    verification = verify_after_execution(tool_name, tool_result)
    if verification:
        print(verification)

    answer = format_response(llm_plain, messages, tool_result, original_input)
    print(f"Agent: {answer}\n")

    messages.append(HumanMessage(content=original_input))
    messages.append(AIMessage(content=answer))
    log_conversation(original_input, answer)

    return False, None


# ══════════════════════════════════════════════════════════
#  Main CLI loop
# ══════════════════════════════════════════════════════════

def run_cli():
    llm_tools, llm_plain = build_llms()
    messages = [SystemMessage(content=SYSTEM_PROMPT)]
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

        # FIX: trim history to avoid context overflow
        messages = trim_messages(messages)

        # ── Confirmation response ─────────────────────────
        if pending_confirmation:
            if user_input.lower() == "yes":
                stay_in_confirmation, updated = handle_confirmation_yes(
                    pending_confirmation, messages, llm_plain
                )
                pending_confirmation = updated
                if stay_in_confirmation:
                    continue
                # Action executed or blocked — exit confirmation mode
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
                answer = format_response(llm_plain, messages, tool_result, user_input)
                messages.append(HumanMessage(content=user_input))
                messages.append(AIMessage(content=answer))
                print(f"\nAgent: {answer}\n")
                log_conversation(user_input, answer)

            else:
                # ── Mistral path: all writes + complex queries ──
                messages.append(HumanMessage(content=user_input))
                response = invoke_with_retry(llm_tools, messages)
                messages.append(response)

                if response.tool_calls:
                    all_results = []

                    for tool_call in response.tool_calls:
                        t_name = tool_call["name"]
                        t_args = tool_call["args"]
                        t_id   = tool_call["id"]

                        if t_name in WRITE_TOOLS:
                            messages.append(ToolMessage(
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
                            break

                        tool_result = execute_tool(t_name, t_args, user_input)
                        messages.append(ToolMessage(
                            content=tool_result or "No results.",
                            tool_call_id=t_id,
                        ))
                        all_results.append(tool_result)

                    if not pending_confirmation and all_results:
                        combined = "\n\n".join(all_results)
                        answer = format_response(
                            llm_plain, messages, combined, user_input
                        )
                        messages.append(AIMessage(content=answer))
                        print(f"\nAgent: {answer}\n")
                        log_conversation(user_input, answer)

                else:
                    print(f"\nAgent: {response.content}\n")
                    log_conversation(user_input, response.content)

        except Exception as exc:
            s = str(exc)
            print(f"\nError: {s}\n")
            if "3230" in s or "function calls" in s:
                messages = clean_message_history(messages)
                print("[Message history cleaned — please retry]\n")
            log_action(
                action="UNKNOWN",
                user_input=user_input,
                tool_called="none",
                tool_input="",
                result=s,
                status="error",
            )


if __name__ == "__main__":
    run_cli()