import sys
import os
import re
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_mistralai import ChatMistralAI
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage, AIMessage
from tools import ALL_TOOLS
from prompt import SYSTEM_PROMPT
from audit.logger import log_action, log_conversation

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import MISTRAL_API_KEY

TOOL_MAP = {t.name: t for t in ALL_TOOLS}

WRITE_TOOLS = {
    "tool_create_policy",
    "tool_create_address",
    "tool_delete_address",
    "tool_backup_config",
}


def build_llms():
    """
    Two LLM instances:
    - llm_tools : has tools bound, used ONLY for deciding which tool to call
    - llm_plain : no tools, used ONLY for formatting responses
    This prevents Mistral from calling tools during formatting
    which was causing empty responses and broken history.
    """
    base = ChatMistralAI(
        model="mistral-small-latest",
        temperature=0,
        api_key=MISTRAL_API_KEY
    )
    llm_tools = base.bind_tools(ALL_TOOLS)
    llm_plain = base
    return llm_tools, llm_plain


def invoke_with_retry(llm, messages, max_retries=3):
    """Retry on rate limit and server errors with exponential backoff."""
    for attempt in range(max_retries):
        try:
            time.sleep(0.5)
            return llm.invoke(messages)
        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "rate_limit" in error_str.lower():
                wait = 2 * (attempt + 1)
                print(f"\n[Rate limit — waiting {wait}s...]\n")
                time.sleep(wait)
            elif "503" in error_str or "502" in error_str or "unreachable" in error_str.lower():
                wait = 3 * (attempt + 1)
                print(f"\n[Mistral server error — waiting {wait}s before retry...]\n")
                time.sleep(wait)
            else:
                raise e
    raise Exception("Mistral API unavailable after retries. Please try again in a moment.")


def clean_message_history(messages: list) -> list:
    """
    Remove orphaned AIMessages that have tool_calls but
    no matching ToolMessage responses after them.
    Mistral rejects requests with broken tool call order.
    """
    cleaned = []
    i = 0
    while i < len(messages):
        msg = messages[i]
        if isinstance(msg, AIMessage) and msg.tool_calls:
            tool_ids = {tc["id"] for tc in msg.tool_calls}
            # Collect all ToolMessage IDs that follow this message
            response_ids = set()
            for j in range(i + 1, len(messages)):
                if isinstance(messages[j], ToolMessage):
                    response_ids.add(messages[j].tool_call_id)
            # Only keep if all tool calls have responses
            if tool_ids.issubset(response_ids):
                cleaned.append(msg)
            else:
                # Skip this message and its orphaned ToolMessages
                i += 1
                continue
        else:
            cleaned.append(msg)
        i += 1
    return cleaned


def detect_intent(text: str):
    """
    Python-level intent detection.
    Handles knowledge questions, read commands, AND write commands.
    Write commands return (tool_name, None) — None means
    parameters need to be extracted separately.
    """
    t = text.lower().strip()

    # ── Knowledge questions — always use RAG ──────────────
    knowledge_triggers = [
        r'\bwhat\b', r'\bhow\b', r'\bwhy\b', r'\bexplain\b',
        r'\bwhat is\b', r'\bwhat does\b', r'\bwhat are\b',
        r'\bhow to\b', r'\bhow do\b', r'\bhow can\b',
        r'\berror\s*-?\d+', r'\berror code\b',
        r'\bbest practice\b', r'\brecommend\b',
        r'\bvlan\b', r'\bvpn\b', r'\bnat\b',
        r'\bospf\b', r'\bbgp\b', r'\bipsec\b',
        r'\btroubleshoot\b', r'\bdiagnose\b',
        # French
        r'\bcomment\b', r'\bqu\'est\b', r'\bpourquoi\b',
        r'\bexpliquer\b', r'\berreur\b', r'\bconfigurer\b',
    ]
    for pattern in knowledge_triggers:
        if re.search(pattern, t):
            return ("tool_search_knowledge", {"query": text})

    # ── List / read commands ───────────────────────────────
    if re.search(r'(list|show|get|display|all)\s+polic', t):
        return ("tool_list_policies", {})
    if re.search(r'(list|show|get|display|all)\s+address', t):
        return ("tool_list_addresses", {})
    if re.search(r'(list|show|get|display|all)\s+interface', t):
        return ("tool_list_interfaces", {})
    if re.search(r'(list|show|get|display|all)\s+user', t):
        return ("tool_list_users", {})
    if re.search(r'(list|show|get|display|all)\s+route', t):
        return ("tool_list_routes", {})
    if re.search(r'system\s+status|device\s+status|firmware', t):
        return ("tool_get_system_status", {})
    if re.search(r'\b(cpu|memory|ram|resource)\b', t):
        return ("tool_get_cpu_memory", {})
    if re.search(r'backup|save\s+config|export\s+config', t):
        return ("tool_backup_config", {})

    # ── Write commands — parameters extracted separately ──
    if re.search(r'(create|add|new|make)\s+(a\s+)?(firewall\s+)?polic', t):
        return ("tool_create_policy", None)
    if re.search(r'(block|deny|allow|permit)\s+\w+\s+(from|on|between)', t):
        return ("tool_create_policy", None)
    if re.search(r'(create|add|new)\s+(a\s+)?address', t):
        return ("tool_create_address", None)
    if re.search(r'(delete|remove)\s+(address|object)', t):
        return ("tool_delete_address", None)

    return None

def format_confirmation(tool_name: str, args: dict) -> str:
    """Show structured confirmation before any write operation."""
    lines = ["\n" + "="*55]
    lines.append("  CONFIRMATION REQUIRED")
    lines.append("="*55)

    if tool_name == "tool_create_policy":
        lines.append("  You are about to CREATE a firewall policy:")
        lines.append(f"    Name      : {args.get('name', '?')}")
        lines.append(f"    Source    : {args.get('srcintf', '?')} -> {args.get('dstintf', '?')}")
        lines.append(f"    Src Addr  : {args.get('srcaddr', 'all')}")
        lines.append(f"    Dst Addr  : {args.get('dstaddr', 'all')}")
        lines.append(f"    Service   : {args.get('service', 'ALL')}")
        lines.append(f"    Action    : {args.get('action', 'accept').upper()}")
    elif tool_name == "tool_create_address":
        lines.append("  You are about to CREATE an address object:")
        lines.append(f"    Name   : {args.get('name', '?')}")
        lines.append(f"    Subnet : {args.get('subnet', '?')}")
    elif tool_name == "tool_delete_address":
        lines.append("  WARNING — You are about to DELETE an address object:")
        lines.append(f"    Name : {args.get('name', '?')}")
        lines.append("  This action cannot be undone.")
    elif tool_name == "tool_backup_config":
        lines.append("  You are about to BACKUP the FortiGate configuration.")
        lines.append("  The config file will be saved locally.")

    lines.append("="*55)
    lines.append("  Type 'yes' to confirm or 'no' to cancel.")
    lines.append("="*55)
    return "\n".join(lines)


def execute_tool(tool_name: str, tool_args: dict, user_input: str) -> str:
    """Execute a tool, log it, return the result."""
    tool = TOOL_MAP.get(tool_name)
    if not tool:
        return f"Error: tool '{tool_name}' not found."

    print(f"\n[Calling: {tool_name}]")
    tool_result = tool.invoke(tool_args)

    log_action(
        action=tool_name.upper(),
        user_input=user_input,
        tool_called=tool_name,
        tool_input=str(tool_args),
        result=str(tool_result),
        status="error" if "[ERROR]" in str(tool_result) else "success"
    )

    return str(tool_result)


def format_response(llm_plain, messages: list,
                    tool_result: str, user_input: str) -> str:
    """
    Use plain LLM (no tools) to format a tool result into
    a clean natural language response. No tool calls possible here.
    """
    format_messages = messages + [
        HumanMessage(
            content=f"The user asked: {user_input}\n\n"
                    f"The system retrieved this data:\n{tool_result}\n\n"
                    f"Present this information clearly and concisely to the user. "
                    f"Do not call any tools. Just format and explain the results."
        )
    ]
    response = invoke_with_retry(llm_plain, format_messages)
    return response.content

def extract_params(tool_name: str, user_input: str, llm_plain) -> dict:
    """
    Use plain LLM to extract structured parameters from user message.
    Returns None if required parameters cannot be extracted.
    """
    import json

    if tool_name == "tool_create_policy":
        prompt = f"""Extract firewall policy parameters from this request:
"{user_input}"

Reply with ONLY a valid JSON object, nothing else:
{{"name": "PolicyName", "srcintf": "port1", "dstintf": "port2", "srcaddr": "all", "dstaddr": "all", "service": "SSH", "action": "deny"}}

Rules:
- action must be exactly "accept" or "deny"
- if request says block/deny/restrict, use "deny"; otherwise use "accept"
- service must be one of: ALL, HTTP, HTTPS, SSH, FTP, DNS, SMTP, RDP, PING
- if not mentioned, srcaddr and dstaddr default to "all"
- name must be a single word with no spaces (use hyphens if needed)
"""
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            raw = response.content.strip()
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if match:
                params = json.loads(match.group())
                if params.get("name") and params.get("srcintf") and params.get("dstintf"):
                    return params
        except Exception:
            pass
        return None

    elif tool_name == "tool_create_address":
        prompt = f"""Extract address object parameters from this request:
"{user_input}"

Reply with ONLY a valid JSON object, nothing else:
{{"name": "ObjectName", "subnet": "192.168.1.10/32"}}

Rules:
- subnet must be in CIDR notation (e.g. 192.168.1.0/24 or 10.0.0.1/32)
- name must be a single word with no spaces
"""
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            raw = response.content.strip()
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if match:
                params = json.loads(match.group())
                if params.get("name") and params.get("subnet"):
                    return params
        except Exception:
            pass
        return None

    elif tool_name == "tool_delete_address":
        # Extract name directly from sentence
        match = re.search(
            r'(delete|remove)\s+(?:address\s+)?["\']?(\S+)["\']?',
            user_input, re.IGNORECASE
        )
        if match:
            return {"name": match.group(2)}
        return None

    return {}

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

        if user_input.lower() in ["exit", "quit"]:
            print("Goodbye!")
            break
        if not user_input:
            continue

        # ── Handle pending confirmation ───────────────────
        if pending_confirmation:
            if user_input.lower() == "yes":
                tool_name = pending_confirmation["name"]
                tool_args = pending_confirmation["args"]
                original_input = pending_confirmation["original_input"]

                tool_result = execute_tool(tool_name, tool_args, original_input)
                print(f"[Result: {tool_result}]\n")

                answer = format_response(
                    llm_plain, messages, tool_result, original_input
                )
                print(f"Agent: {answer}\n")
                log_conversation(original_input, answer)

            else:
                print("\nAgent: Action cancelled. How else can I help you?\n")
                log_action(
                    action="CANCELLED",
                    user_input=pending_confirmation["original_input"],
                    tool_called=pending_confirmation["name"],
                    tool_input=str(pending_confirmation["args"]),
                    result="User cancelled",
                    status="cancelled"
                )

            pending_confirmation = None
            continue

        try:
            # ── Fast path: Python intent detection ───────
            intent = detect_intent(user_input)

            if intent:
                tool_name, tool_args = intent

                # Write operations need parameter extraction
                if tool_name in WRITE_TOOLS and tool_args is None:
                    tool_args = extract_params(tool_name, user_input, llm_plain)

                    if tool_args is None:
                        # Could not extract required parameters — ask user
                        print("\nAgent: I need more details to complete this request.")
                        if tool_name == "tool_create_policy":
                            print("  Please provide: policy name, source interface,")
                            print("  destination interface, service, and action (accept/deny).\n")
                        elif tool_name == "tool_create_address":
                            print("  Please provide: object name and subnet")
                            print("  (e.g. 192.168.1.10/32).\n")
                        elif tool_name == "tool_delete_address":
                            print("  Please provide the exact name of the address to delete.\n")
                        continue

                    print(format_confirmation(tool_name, tool_args))
                    pending_confirmation = {
                        "name": tool_name,
                        "args": tool_args,
                        "original_input": user_input
                    }
                    continue

                # Write operations with known args (e.g. backup)
                if tool_name in WRITE_TOOLS:
                    print(format_confirmation(tool_name, tool_args))
                    pending_confirmation = {
                        "name": tool_name,
                        "args": tool_args,
                        "original_input": user_input
                    }
                    continue

                # Read tools and knowledge — execute immediately
                tool_result = execute_tool(tool_name, tool_args, user_input)
                answer = format_response(llm_plain, messages, tool_result, user_input)
                messages.append(HumanMessage(content=user_input))
                messages.append(AIMessage(content=answer))
                print(f"\nAgent: {answer}\n")
                log_conversation(user_input, answer)

            else:
                # ── Mistral path: write operations ───────
                # Only create/delete/backup reach here
                messages.append(HumanMessage(content=user_input))
                response = invoke_with_retry(llm_tools, messages)
                messages.append(response)

                if response.tool_calls:
                    all_tool_results = []

                    for tool_call in response.tool_calls:
                        tool_name = tool_call["name"]
                        tool_args = tool_call["args"]
                        tool_id = tool_call["id"]

                        if tool_name in WRITE_TOOLS:
                            # Add placeholder ToolMessage to keep history valid
                            messages.append(ToolMessage(
                                content="Awaiting user confirmation.",
                                tool_call_id=tool_id
                            ))
                            print(format_confirmation(tool_name, tool_args))
                            pending_confirmation = {
                                "name": tool_name,
                                "args": tool_args,
                                "id": tool_id,
                                "original_input": user_input
                            }
                            break

                        # Read tool called by Mistral
                        tool_result = execute_tool(
                            tool_name, tool_args, user_input
                        )
                        messages.append(ToolMessage(
                            content=tool_result or "No results.",
                            tool_call_id=tool_id
                        ))
                        all_tool_results.append(tool_result)

                    # Format all results with plain LLM
                    if not pending_confirmation and all_tool_results:
                        combined = "\n\n".join(all_tool_results)
                        answer = format_response(
                            llm_plain, messages, combined, user_input
                        )
                        messages.append(AIMessage(content=answer))
                        print(f"\nAgent: {answer}\n")
                        log_conversation(user_input, answer)

                else:
                    # Pure conversation
                    print(f"\nAgent: {response.content}\n")
                    log_conversation(user_input, response.content)

        except Exception as e:
            error_str = str(e)
            print(f"\nError: {error_str}\n")

            if "3230" in error_str or "function calls" in error_str:
                messages = clean_message_history(messages)
                print("[Message history cleaned — please retry]\n")

            log_action(
                action="UNKNOWN",
                user_input=user_input,
                tool_called="none",
                tool_input="",
                result=error_str,
                status="error"
            )


if __name__ == "__main__":
    run_cli()