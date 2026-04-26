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
    validate_move_policy,
    validate_create_address,
    validate_delete_address,
    validate_update_interface_access,
    validate_block_ip,
    ValidationResult,
)

TOOL_MAP = {t.name: t for t in ALL_TOOLS}

# Write tools require confirmation before execution
WRITE_TOOLS = {
    "tool_create_policy",
    "tool_update_policy",
    "tool_delete_policy",
    "tool_move_policy",
    "tool_create_address",
    "tool_delete_address",
    "tool_update_interface_access",
    "tool_block_ip",
    "tool_backup_config",
}

# Map tool names to their validators
VALIDATORS = {
    "tool_create_policy":          validate_create_policy,
    "tool_delete_policy":          validate_delete_policy,
    "tool_update_policy":          validate_update_policy,
    "tool_move_policy":            validate_move_policy,
    "tool_create_address":         validate_create_address,
    "tool_delete_address":         validate_delete_address,
    "tool_update_interface_access": validate_update_interface_access,
    "tool_block_ip":               validate_block_ip,
}


# ══════════════════════════════════════════════════════════
#  LLM setup
# ══════════════════════════════════════════════════════════

def build_llms():
    """
    Two LLM instances:
    - llm_tools : tools bound — selects which tool to call
    - llm_plain : no tools  — formats responses only

    Keeping them separate prevents Mistral from attempting
    tool calls during formatting, which caused broken history.
    """
    base = ChatMistralAI(
        model="mistral-small-latest",
        temperature=0,
        api_key=MISTRAL_API_KEY,
    )
    return base.bind_tools(ALL_TOOLS), base


# ══════════════════════════════════════════════════════════
#  Retry helper
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
#  History cleaner
# ══════════════════════════════════════════════════════════

def clean_message_history(messages: list) -> list:
    orphaned_ids: set = set()
    cleaned = []
    i = 0
    while i < len(messages):
        msg = messages[i]
        if isinstance(msg, ToolMessage) and msg.tool_call_id in orphaned_ids:
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
                orphaned_ids.update(tool_ids)
                i += 1
                continue
        cleaned.append(msg)
        i += 1
    return cleaned


# ══════════════════════════════════════════════════════════
#  Intent detection
#
#  ARCHITECTURE NOTE:
#  The fast path handles only unambiguous READ commands
#  and the analyze/backup triggers. Everything else — all
#  write operations and complex queries — goes to Mistral
#  with full tool context so it can reason properly.
#
#  The key architectural fix i chose: the old version was
#  catching write commands here with rigid regex, then
#  using extract_params() to guess parameters. Now Mistral
#  handles writes end-to-end with full conversational context.
# ══════════════════════════════════════════════════════════

def detect_intent(text: str):
    """
    Fast path for unambiguous READ commands only.
    Returns (tool_name, args) or None (→ Mistral handles it).
    """
    t = text.lower().strip()

    # ── Unambiguous list/read commands ────────────────────
    # These are single-purpose commands with no parameters.
    # Fast path saves an API call and is always reliable.

    if re.search(r'^(list|show|get|display|all)\s+polic', t):
        return ("tool_list_policies", {})
    if re.search(r'^(list|show|get|display|all)\s+address', t):
        return ("tool_list_addresses", {})
    if re.search(r'^(list|show|get|display|all)\s+interface', t):
        return ("tool_list_interfaces", {})
    if re.search(r'^(list|show|get|display|all)\s+user', t):
        return ("tool_list_users", {})
    if re.search(r'^(list|show|get|display|all)\s+route', t):
        return ("tool_list_routes", {})
    if re.search(r'^(check\s+)?(system|device)\s+status', t):
        return ("tool_get_system_status", {})
    if re.search(r'^(check\s+)?(cpu|memory|ram)\b', t):
        return ("tool_get_cpu_memory", {})
    if re.search(r'^(list|show|check)\s+vpn', t):
        return ("tool_get_vpn_status", {})
    if re.search(r'^(list|show|check)\s+session', t):
        return ("tool_get_active_sessions", {})

    # ── Unambiguous intelligence triggers ─────────────────
    if re.search(r'^(analyz|audit|security\s+check|scan\s+firewall|inspect)', t):
        return ("tool_analyze_security", {})

    # ── Everything else → Mistral ─────────────────────────
    # Write operations, knowledge questions, complex queries,
    # and anything ambiguous is handled by Mistral with full
    # tool access and conversational context.
    return None


# ══════════════════════════════════════════════════════════
#  Confirmation formatter
# ══════════════════════════════════════════════════════════

def format_confirmation(tool_name: str, args: dict) -> str:
    lines = ["\n" + "=" * 55, "  CONFIRMATION REQUIRED", "=" * 55]

    if tool_name == "tool_create_policy":
        lines.append("  CREATE firewall policy:")
        lines.append(f"    Name      : {args.get('name', '?')}")
        lines.append(f"    Interfaces: {args.get('srcintf', '?')} -> {args.get('dstintf', '?')}")
        lines.append(f"    Src Addr  : {args.get('srcaddr', 'all')}")
        lines.append(f"    Dst Addr  : {args.get('dstaddr', 'all')}")
        lines.append(f"    Service   : {args.get('service', 'ALL')}")
        lines.append(f"    Action    : {args.get('action', 'accept').upper()}")

    elif tool_name == "tool_update_policy":
        lines.append("  UPDATE firewall policy:")
        lines.append(f"    Policy ID : {args.get('policy_id', '?')}")
        for field in ("name", "action", "srcaddr", "dstaddr", "service", "status"):
            if args.get(field):
                lines.append(f"    {field:<10}: {args[field]}")

    elif tool_name == "tool_delete_policy":
        lines.append("  WARNING — PERMANENTLY DELETE firewall policy:")
        lines.append(f"    Policy ID : {args.get('policy_id', '?')}")
        lines.append("  This cannot be undone.")

    elif tool_name == "tool_move_policy":
        lines.append("  REORDER firewall policy:")
        lines.append(f"    Move policy ID {args.get('policy_id', '?')} "
                     f"{args.get('move_action', '?')} "
                     f"policy ID {args.get('neighbor_id', '?')}")
        lines.append("  This changes which rule takes precedence.")

    elif tool_name == "tool_create_address":
        lines.append("  CREATE address object:")
        lines.append(f"    Name   : {args.get('name', '?')}")
        lines.append(f"    Subnet : {args.get('subnet', '?')}")

    elif tool_name == "tool_delete_address":
        lines.append("  WARNING — DELETE address object:")
        lines.append(f"    Name : {args.get('name', '?')}")
        lines.append("  This cannot be undone.")

    elif tool_name == "tool_update_interface_access":
        lines.append("  UPDATE interface management access:")
        lines.append(f"    Interface : {args.get('name', '?')}")
        lines.append(f"    Allow     : {args.get('allowaccess', '?').upper()}")
        lines.append("  All other protocols will be DISABLED.")

    elif tool_name == "tool_block_ip":
        lines.append("  BLOCK IP address:")
        lines.append(f"    IP        : {args.get('ip_address', '?')}")
        lines.append(f"    Direction : {args.get('direction', 'both')}")
        lines.append("  Creates deny policy(ies) — can be reversed by deleting them.")

    elif tool_name == "tool_backup_config":
        lines.append("  BACKUP FortiGate configuration.")
        lines.append("  Config file will be saved locally with timestamp.")

    lines += ["=" * 55, "  Type 'yes' to confirm or 'no' to cancel.", "=" * 55]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════
#  Tool executor
# ══════════════════════════════════════════════════════════

def execute_tool(tool_name: str, tool_args: dict, user_input: str) -> str:
    """Execute a tool safely — never raises, always returns a string."""
    tool = TOOL_MAP.get(tool_name)
    if not tool:
        return f"[ERROR] Tool '{tool_name}' not found."

    print(f"\n[Calling: {tool_name}]")
    try:
        tool_result = str(tool.invoke(tool_args))
    except Exception as exc:
        tool_result = f"[ERROR] {exc}"

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
    """Format a tool result into natural language using the plain LLM."""
    fmt_msgs = messages + [
        HumanMessage(
            content=(
                f"User asked: {user_input}\n\n"
                f"System data:\n{tool_result}\n\n"
                f"Present this clearly and concisely. "
                f"Do not call any tools. Just explain the results."
            )
        )
    ]
    return invoke_with_retry(llm_plain, fmt_msgs).content


# ══════════════════════════════════════════════════════════
#  Confirmation handler
# ══════════════════════════════════════════════════════════

def handle_confirmation_yes(pending: dict, messages: list,
                             llm_plain) -> tuple:
    """
    Handle a 'yes' response to a pending confirmation.
    Returns (answer_str, should_continue, updated_pending).
    """
    tool_name      = pending["name"]
    tool_args      = pending["args"]
    original_input = pending["original_input"]
    warnings_shown = pending.get("warnings_shown", False)

    # Run validation (skip if warnings already shown and user confirmed)
    if not warnings_shown:
        validator = VALIDATORS.get(tool_name)
        if validator:
            validation = validator(tool_args)

            if not validation.valid:
                print(validation.format())
                print("\nAgent: Action blocked. Fix the issues above and try again.\n")
                return None, True, None

            if validation.has_warnings_only():
                print(validation.format())
                pending["warnings_shown"] = True
                return None, True, pending

    # Execute
    tool_result = execute_tool(tool_name, tool_args, original_input)
    print(f"[Result: {tool_result}]\n")

    answer = format_response(llm_plain, messages, tool_result, original_input)
    print(f"Agent: {answer}\n")

    messages.append(HumanMessage(content=original_input))
    messages.append(AIMessage(content=answer))
    log_conversation(original_input, answer)

    return answer, False, None


# ══════════════════════════════════════════════════════════
#  Main CLI loop
# ══════════════════════════════════════════════════════════

def run_cli():
    llm_tools, llm_plain = build_llms()
    messages = [SystemMessage(content=SYSTEM_PROMPT)]
    pending_confirmation = None

    print("\n" + "=" * 55)
    print("  FortiGate AI Agent")
    print("  Powered by Mistral AI + FortiOS Knowledge Base")
    print("=" * 55)
    print("Type 'exit' to quit.\n")

    while True:
        user_input = input("You: ").strip()

        if user_input.lower() in ("exit", "quit"):
            print("Goodbye!")
            break
        if not user_input:
            continue

        # ── Confirmation response ─────────────────────────
        if pending_confirmation:
            if user_input.lower() == "yes":
                _, should_continue, updated_pending = handle_confirmation_yes(
                    pending_confirmation, messages, llm_plain
                )
                pending_confirmation = updated_pending
                if should_continue:
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
                answer = format_response(llm_plain, messages, tool_result, user_input)
                messages.append(HumanMessage(content=user_input))
                messages.append(AIMessage(content=answer))
                print(f"\nAgent: {answer}\n")
                log_conversation(user_input, answer)

            else:
                # ── Mistral path: all writes + complex queries ──
                # Mistral sees full tool list and conversation history.
                # It decides which tool to call based on natural language
                # understanding — not rigid regex patterns.
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
                            # Placeholder keeps history balanced
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

                        # Read tool — execute immediately
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
                    # Pure conversation — no tool needed
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