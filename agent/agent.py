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

# All write tools — these ALWAYS go through confirmation
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

# Validator map
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

# Keep last N Human/AI pairs in conversation
MAX_TURNS = 12


# ══════════════════════════════════════════════════════════
#  LLM
# ══════════════════════════════════════════════════════════

def build_llms():
    """
    llm_tools : selects which tool to call — only used for
                knowledge/analysis questions and complex queries
    llm_plain : formats tool results — NEVER receives ToolMessages
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
#  `conversation` contains ONLY SystemMessage + Human/AI pairs.
#  ToolMessages NEVER enter it. This prevents all 400 errors.
# ══════════════════════════════════════════════════════════

def trim_conversation(conversation: list) -> list:
    system = [m for m in conversation if isinstance(m, SystemMessage)]
    rest   = [m for m in conversation if not isinstance(m, SystemMessage)]
    if len(rest) <= MAX_TURNS * 2:
        return conversation
    return system + rest[-(MAX_TURNS * 2):]


# ══════════════════════════════════════════════════════════
#  Intent detection
#
#  ARCHITECTURE: detect_intent catches ALL clear commands.
#  Mistral is only used for knowledge questions and
#  genuinely ambiguous conversational inputs.
#  Write commands return (tool_name, None) — params extracted later.
# ══════════════════════════════════════════════════════════

def detect_intent(text: str):
    t = text.lower().strip()

    # ── READ commands ─────────────────────────────────────
    if re.search(r'(list|show|get|display|all|lister|afficher|voir|montrer)'
                 r'\s+(all\s+)?(firewall\s+)?(polic|rules|r.gles|politiques)', t):
        return ("tool_list_policies", {})

    if re.search(r'(list|show|get|display|all|lister|afficher)'
                 r'\s+(all\s+)?(address|adresse|objet\s+d)', t):
        return ("tool_list_addresses", {})

    if re.search(r'(list|show|get|display|all|lister|afficher)'
                 r'\s+(all\s+)?(network\s+)?(interface)', t):
        return ("tool_list_interfaces", {})

    if re.search(r'(list|show|get|display|all|lister)'
                 r'\s+(all\s+)?(user|utilisateur)', t):
        return ("tool_list_users", {})

    if re.search(r'(list|show|get|display|all|lister)'
                 r'\s+(all\s+)?(static\s+)?(route|routage)', t):
        return ("tool_list_routes", {})

    if re.search(r'(system|device|syst.me)\s+(status|.tat|info)', t):
        return ("tool_get_system_status", {})
    if re.search(r'\b(check\s+)?(firmware|version)\b', t):
        return ("tool_get_system_status", {})

    if re.search(r'\b(check\s+)?(cpu|memory|m.moire|ram|resource)\b', t):
        return ("tool_get_cpu_memory", {})

    if re.search(r'(vpn\s+(status|tunnel|.tat)|ipsec\s+tunnel'
                 r'|show\s+vpn|list\s+vpn|statut\s+vpn)', t):
        return ("tool_get_vpn_status", {})

    if re.search(r'(active\s+session|session\s+count'
                 r'|connexions\s+actives)', t):
        return ("tool_get_active_sessions", {})

    if re.search(r'\b(analyz|audit|security\s+check|scan\s+firewall'
                 r'|analyser|v.rifier\s+s.curit.)\b', t):
        return ("tool_analyze_security", {})

    if re.search(r'(show|list|lister|afficher)\s+(blocked|block|bloqu)', t):
        return ("tool_list_addresses", {})

    # ── WRITE commands — all caught here to guarantee confirmation ──
    # Policy operations
    if re.search(r'(create|add|new|make|ajouter|cr.er|nouvelle?)\s+'
                 r'(a\s+)?(firewall\s+)?(polic|r.gle)', t):
        return ("tool_create_policy", None)

    if re.search(r'(block|deny|allow|permit|bloquer|autoriser|interdire)'
                 r'\s+\w+\s+(from|on|between|traffic|de|sur)', t):
        return ("tool_create_policy", None)

    if re.search(r'(update|modify|change|edit|modifier|changer|mettre\s+.+jour)'
                 r'\s+(policy|polic|r.gle)\s+\d+', t):
        return ("tool_update_policy", None)

    if re.search(r'(enable|disable|activer|d.sactiver)\s+'
                 r'(policy|polic|r.gle)\s+\d+', t):
        return ("tool_enable_disable_policy", None)

    if re.search(r'(delete|remove|supprimer|effacer)\s+'
                 r'(policy|polic|r.gle)', t):
        return ("tool_delete_policy", None)

    if re.search(r'(move|reorder|d.placer|r.organiser)\s+'
                 r'(policy|polic|r.gle)', t):
        return ("tool_move_policy", None)

    # Address operations
    if re.search(r'(create|add|new|ajouter|cr.er)\s+'
                 r'(a\s+)?(address|addr|objet\s+d.adresse)', t):
        return ("tool_create_address", None)

    if re.search(r'(delete|remove|supprimer)\s+'
                 r'(address|addr|objet)', t):
        return ("tool_delete_address", None)

    # Interface operations
    if re.search(r'(disable|enable|update|change|d.sactiver|activer|mettre\s+.+jour)'
                 r'\s+(http|telnet|ssh|https|management|gestion|access)', t):
        return ("tool_update_interface_access", None)

    # Block IP
    if re.search(r'(block\s+ip|bloquer\s+ip|block\s+the\s+ip'
                 r'|bloquer\s+l.ip)\s+[\d\.]+', t):
        return ("tool_block_ip", None)

    # Backup
    if re.search(r'\bbackup\b|\bsauvegarde\b|\bsave\s+config\b', t):
        return ("tool_backup_config", {})

    # Policy details by ID
    if re.search(r'(show|get|display|detail|info)\s+'
                 r'(of\s+)?(policy|polic|r.gle)\s+\d+', t):
        return ("tool_get_policy_details", None)

    return None


# ══════════════════════════════════════════════════════════
#  Parameter extraction
# ══════════════════════════════════════════════════════════

def extract_params(tool_name: str, user_input: str, llm_plain) -> dict:
    """
    Use the plain LLM to extract structured parameters from natural language.
    Returns a dict or None if required fields cannot be extracted.
    """

    if tool_name == "tool_create_policy":
        prompt = (
            f'Extract firewall policy parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON, nothing else:\n"
            '{"name":"PolicyName","srcintf":"port1","dstintf":"port2",'
            '"srcaddr":"all","dstaddr":"all","service":"SSH","action":"deny"}\n\n'
            "Rules:\n"
            "- action: exactly 'accept' or 'deny' (block/deny/restrict -> 'deny')\n"
            "- service: ALL HTTP HTTPS SSH FTP DNS SMTP RDP PING\n"
            "- srcaddr and dstaddr default to 'all' if not mentioned\n"
            "- name: single word, no spaces, use hyphens\n"
            "- If you cannot determine srcintf or dstintf, use 'port1' and 'port2'"
        )
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            match = re.search(r'\{.*\}', response.content.strip(), re.DOTALL)
            if match:
                params = json.loads(match.group())
                if params.get("name") and params.get("srcintf") and params.get("dstintf"):
                    return params
        except Exception:
            pass
        return None

    elif tool_name == "tool_update_policy":
        prompt = (
            f'Extract policy update parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"policy_id":2,"action":"deny","service":"HTTPS"}\n\n'
            "Rules:\n"
            "- policy_id is required (integer)\n"
            "- Only include fields that change\n"
            "- action: 'accept' or 'deny'\n"
            "- status: 'enable' or 'disable'"
        )
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            match = re.search(r'\{.*\}', response.content.strip(), re.DOTALL)
            if match:
                params = json.loads(match.group())
                if params.get("policy_id"):
                    return params
        except Exception:
            pass
        return None

    elif tool_name == "tool_enable_disable_policy":
        # Extract ID and status from text
        id_match  = re.search(r'\b(\d+)\b', user_input)
        if re.search(r'\b(disable|d.sactiver|deactivate)\b', user_input.lower()):
            status = "disable"
        else:
            status = "enable"
        if id_match:
            return {"policy_id": int(id_match.group(1)), "status": status}
        return None

    elif tool_name == "tool_delete_policy":
        id_match = re.search(r'\b(\d+)\b', user_input)
        if id_match:
            return {"policy_id": int(id_match.group(1))}
        # Try name extraction
        prompt = (
            f'Extract the policy ID to delete from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"policy_id":3}\n\n'
            "policy_id must be an integer."
        )
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            match = re.search(r'\{.*\}', response.content.strip(), re.DOTALL)
            if match:
                params = json.loads(match.group())
                if params.get("policy_id"):
                    return {"policy_id": int(params["policy_id"])}
        except Exception:
            pass
        return None

    elif tool_name == "tool_move_policy":
        prompt = (
            f'Extract policy move parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"policy_id":3,"move_action":"before","neighbor_id":2}\n\n'
            "- move_action: 'before' or 'after'\n"
            "- all values are integers"
        )
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            match = re.search(r'\{.*\}', response.content.strip(), re.DOTALL)
            if match:
                params = json.loads(match.group())
                if (params.get("policy_id") and
                        params.get("move_action") and
                        params.get("neighbor_id")):
                    return params
        except Exception:
            pass
        return None

    elif tool_name == "tool_create_address":
        prompt = (
            f'Extract address object parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"name":"ObjectName","subnet":"192.168.1.10/32"}\n\n'
            "- subnet in CIDR notation\n"
            "- name: single word, no spaces"
        )
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            match = re.search(r'\{.*\}', response.content.strip(), re.DOTALL)
            if match:
                params = json.loads(match.group())
                if params.get("name") and params.get("subnet"):
                    return params
        except Exception:
            pass
        return None

    elif tool_name == "tool_delete_address":
        prompt = (
            f'Extract the address object name to delete from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"name":"ExactObjectName"}\n\n'
            "Extract only the exact object name."
        )
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            match = re.search(r'\{.*\}', response.content.strip(), re.DOTALL)
            if match:
                params = json.loads(match.group())
                if params.get("name"):
                    return params
        except Exception:
            pass
        return None

    elif tool_name == "tool_update_interface_access":
        prompt = (
            f'Extract interface access parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"name":"port1","allowaccess":"https ssh ping"}\n\n'
            "- name: interface name\n"
            "- allowaccess: space-separated safe protocols only\n"
            "- NEVER include http or telnet\n"
            "- If user says disable http/telnet: set allowaccess to 'https ssh ping'\n"
            "- Do NOT add snmp unless explicitly requested"
        )
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            match = re.search(r'\{.*\}', response.content.strip(), re.DOTALL)
            if match:
                params = json.loads(match.group())
                if params.get("name") and params.get("allowaccess"):
                    return params
        except Exception:
            pass
        return None

    elif tool_name == "tool_block_ip":
        ip_match = re.search(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b',
            user_input
        )
        if ip_match:
            direction = "both"
            if re.search(r'\binbound\b|\bentr.e\b', user_input.lower()):
                direction = "inbound"
            elif re.search(r'\boutbound\b|\bsortant\b', user_input.lower()):
                direction = "outbound"
            return {
                "ip_address": ip_match.group(1),
                "direction":  direction,
            }
        return None

    elif tool_name == "tool_get_policy_details":
        id_match = re.search(r'\b(\d+)\b', user_input)
        if id_match:
            return {"policy_id": int(id_match.group(1))}
        return None

    elif tool_name == "tool_backup_config":
        return {}

    return {}


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
    tool = TOOL_MAP.get(tool_name)
    if not tool:
        return f"[ERROR] Tool '{tool_name}' not found."

    print(f"\n[Calling: {tool_name}]")
    try:
        tool_result = str(tool.invoke(tool_args))
    except Exception as exc:
        tool_result = f"[ERROR] {exc}"

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
#  Response formatter — NEVER receives ToolMessages
# ══════════════════════════════════════════════════════════

def format_response(llm_plain, conversation: list,
                    tool_result: str, user_input: str) -> str:
    fmt = list(conversation) + [
        HumanMessage(
            content=(
                f"User request: {user_input}\n\n"
                f"System data:\n{tool_result}\n\n"
                "Present this clearly and concisely.\n"
                "Use plain text only. No emojis. No markdown headers or bold.\n"
                "Use simple ASCII tables for tabular data.\n"
                "Respond in the same language as the user request above.\n"
                "Do not call any tools."
            )
        )
    ]
    return invoke_with_retry(llm_plain, fmt).content


# ══════════════════════════════════════════════════════════
#  Post-execution verification
# ══════════════════════════════════════════════════════════

def verify_after_execution(tool_name: str) -> str:
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
            flag = " [disabled]" if p.get("status") == "disable" else ""
            lines.append(
                f"  ID {p.get('policyid','?'):>3} | "
                f"{p.get('name','?'):<25} | "
                f"{p.get('action','?'):>6}{flag} | "
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
                return False, None

            if validation.has_warnings_only():
                print(validation.format())
                pending["warnings_shown"] = True
                return True, pending

    tool_result  = execute_tool(tool_name, tool_args, original_input)
    print(f"[Result: {tool_result}]\n")

    verification = verify_after_execution(tool_name)
    if verification:
        print(verification)

    answer = format_response(llm_plain, conversation, tool_result, original_input)
    print(f"Agent: {answer}\n")

    conversation.append(HumanMessage(content=original_input))
    conversation.append(AIMessage(content=answer))
    log_conversation(original_input, answer)

    return False, None


# ══════════════════════════════════════════════════════════
#  Knowledge/analysis handler — uses Mistral
# ══════════════════════════════════════════════════════════

def handle_knowledge_or_analysis(user_input: str, conversation: list,
                                   llm_tools, llm_plain) -> bool:
    """
    Uses Mistral to handle knowledge questions and analysis queries.
    Returns True if handled, False if should fall through.
    """
    turn_msgs = list(conversation)
    turn_msgs.append(HumanMessage(content=user_input))

    response = invoke_with_retry(llm_tools, turn_msgs)
    turn_msgs.append(response)

    if response.tool_calls:
        all_results = []
        for tool_call in response.tool_calls:
            t_name = tool_call["name"]
            t_args = tool_call["args"]
            t_id   = tool_call["id"]

            # Safety net: if Mistral tries to call a write tool, block it
            if t_name in WRITE_TOOLS:
                print(f"\n[Write tool intercepted in Mistral path: {t_name}]")
                print("[Use an explicit command to perform write operations]\n")
                return True

            tool_result = execute_tool(t_name, t_args, user_input)
            turn_msgs.append(ToolMessage(
                content=tool_result or "No results.",
                tool_call_id=t_id,
            ))
            all_results.append(tool_result)

        if all_results:
            combined = "\n\n".join(all_results)
            answer = format_response(llm_plain, conversation, combined, user_input)
            conversation.append(HumanMessage(content=user_input))
            conversation.append(AIMessage(content=answer))
            print(f"\nAgent: {answer}\n")
            log_conversation(user_input, answer)
            return True

    else:
        answer = response.content
        conversation.append(HumanMessage(content=user_input))
        conversation.append(AIMessage(content=answer))
        print(f"\nAgent: {answer}\n")
        log_conversation(user_input, answer)
        return True

    return False


# ══════════════════════════════════════════════════════════
#  Knowledge question detector
# ══════════════════════════════════════════════════════════

def is_knowledge_question(text: str) -> bool:
    """
    Returns True if this looks like a knowledge/documentation question
    that should be answered by searching the RAG knowledge base.
    """
    t = text.lower().strip()
    patterns = [
        r'\bwhat\s+(is|are|does|do)\b',
        r'\bhow\s+(do|does|to|can)\b',
        r'\bwhy\b',
        r'\bexplain\b',
        r'\berror\s*-?\d+',
        r'\berror\s+code\b',
        r'\bbest\s+practice\b',
        r'\brecommend\b',
        r'\bvlan\b',
        r'\bvpn\b.*\b(how|what|config)\b',
        r'\bnat\b.*\b(what|how)\b',
        r'\bospf\b',
        r'\bbgp\b',
        r'\bipsec\b.*\b(how|what|config)\b',
        r'\btroubleshoot\b',
        r'\bdiagnose\b',
        r'\bdifference\b',
        # French
        r'\bqu.est.ce\b',
        r'\bcomment\s+(faire|cr.er|configurer)\b',
        r'\bpourquoi\b',
        r'\bexpliquer\b',
        r'\berreur\b',
        r'\bconfigurer\b',
        r'\bzone\s+de\s+s.curit.\b',
    ]
    return any(re.search(p, t) for p in patterns)


# ══════════════════════════════════════════════════════════
#  Main CLI loop
# ══════════════════════════════════════════════════════════

def run_cli():
    llm_tools, llm_plain = build_llms()
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
                print("\nAgent: Action cancelled.\n")
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

        try:
            intent = detect_intent(user_input)

            if intent:
                tool_name, tool_args = intent

                # ── Write operation: extract params → confirm ──
                if tool_name in WRITE_TOOLS and tool_args is None:
                    tool_args = extract_params(tool_name, user_input, llm_plain)

                    if tool_args is None:
                        # Missing required parameters — ask user
                        if tool_name == "tool_create_policy":
                            msg = ("I need more details to create this policy.\n"
                                   "Please provide: policy name, source interface, "
                                   "destination interface, service, and action (accept/deny).")
                        elif tool_name == "tool_create_address":
                            msg = ("I need the address object name and subnet "
                                   "(e.g. 192.168.1.10/32).")
                        elif tool_name == "tool_delete_address":
                            msg = "Please provide the exact name of the address object to delete."
                        elif tool_name in ("tool_delete_policy",
                                           "tool_enable_disable_policy"):
                            msg = "Please provide the policy ID number."
                        elif tool_name == "tool_move_policy":
                            msg = ("Please provide: policy ID to move, "
                                   "direction (before/after), and reference policy ID.")
                        elif tool_name == "tool_block_ip":
                            msg = "Please provide the IP address to block (e.g. 192.168.1.55)."
                        else:
                            msg = "Please provide the required details for this operation."

                        print(f"\nAgent: {msg}\n")
                        log_conversation(user_input, msg)
                        continue

                    print(format_confirmation(tool_name, tool_args))
                    pending_confirmation = {
                        "name": tool_name,
                        "args": tool_args,
                        "original_input": user_input,
                    }
                    continue

                # ── Write with known args (backup, etc.) ──────
                if tool_name in WRITE_TOOLS:
                    print(format_confirmation(tool_name, tool_args))
                    pending_confirmation = {
                        "name": tool_name,
                        "args": tool_args,
                        "original_input": user_input,
                    }
                    continue

                # ── Read tool: execute immediately ────────────
                tool_result = execute_tool(tool_name, tool_args, user_input)
                answer = format_response(
                    llm_plain, conversation, tool_result, user_input
                )
                conversation.append(HumanMessage(content=user_input))
                conversation.append(AIMessage(content=answer))
                print(f"\nAgent: {answer}\n")
                log_conversation(user_input, answer)

            elif is_knowledge_question(user_input):
                # ── Knowledge/documentation question → RAG ────
                # Force tool_search_knowledge directly without Mistral deciding
                from tools import tool_search_knowledge
                print(f"\n[Calling: tool_search_knowledge]")
                tool_result = str(tool_search_knowledge.invoke({"query": user_input}))
                log_action(
                    action="TOOL_SEARCH_KNOWLEDGE",
                    user_input=user_input,
                    tool_called="tool_search_knowledge",
                    tool_input=user_input,
                    result=tool_result,
                    status="success",
                )
                answer = format_response(
                    llm_plain, conversation, tool_result, user_input
                )
                conversation.append(HumanMessage(content=user_input))
                conversation.append(AIMessage(content=answer))
                print(f"\nAgent: {answer}\n")
                log_conversation(user_input, answer)

            else:
                # ── Fallback: Mistral for complex/ambiguous queries ──
                handle_knowledge_or_analysis(
                    user_input, conversation, llm_tools, llm_plain
                )

        except Exception as exc:
            error_str = str(exc)
            print(f"\nError: {error_str}\n")
            pending_confirmation = None
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