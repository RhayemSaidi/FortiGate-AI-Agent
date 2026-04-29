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

MAX_TURNS = 12

#  LLM

def build_llms():
    base = ChatMistralAI(
        model="mistral-small-latest",
        temperature=0,
        api_key=MISTRAL_API_KEY,
    )
    return base.bind_tools(ALL_TOOLS), base


#  Retry

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


#  Conversation management
#  conversation = ONLY SystemMessage + Human/AI pairs
#  ToolMessages NEVER enter conversation

def trim_conversation(conversation: list) -> list:
    system = [m for m in conversation if isinstance(m, SystemMessage)]
    rest   = [m for m in conversation if not isinstance(m, SystemMessage)]
    if len(rest) <= MAX_TURNS * 2:
        return conversation
    return system + rest[-(MAX_TURNS * 2):]


# Verbs that start commands — never route these to knowledge search
_COMMAND_STARTERS = re.compile(
    r'^(list|show|get|display|create|add|delete|remove|move|switch|swap|'
    r'block|disable|enable|update|modify|change|backup|analyze|audit|scan|'
    r'lister|afficher|cr.er|supprimer|bloquer|activer|d.sactiver|'
    r'sauvegarder|analyser|v.rifier|d.placer|intervertir)\b',
    re.IGNORECASE
)

# Phrases that indicate a genuine knowledge/documentation question
_QUESTION_PATTERNS = [
    r'\bhow\s+(do|does|to|can|should|would|is|are)\b',
    r'\bwhat\s+(is|are|does|do|should|would)\b',
    r'\bwhat\s+is\s+the\b',
    r'\bwhat\s+command\b',
    r'\bwhich\s+command\b',
    r'\bwhy\b',
    r'\bexplain\b',
    r'\bcan\s+i\b',
    r'\bis\s+there\b',
    r"\bwhat's\b",
    r'\berror\s*-?\d+\b',
    r'\berror\s+code\b',
    r'\bbest\s+practice\b',
    r'\brecommend\b',
    r'\btroubleshoot\b',
    r'\bdiagnose\b',
    r'\bdifference\s+between\b',
    r'\bi\s+meant\b',
    r'\bi\s+mean\b',
    r'\bgeneral\s+knowledge\b',
    r'\bin\s+(the\s+)?cli\b',
    r'\bcommand\s+(to|for)\b',
    # French
    r'\bqu.est.ce\b',
    r'\bcomment\s+(faire|cr.er|configurer|v.rifier|afficher|utiliser)\b',
    r'\bpourquoi\b',
    r'\bexpliquer\b',
    r'\bquelle\s+commande\b',
    r"\bc'est\s+quoi\b",
    r'\bzone\s+de\s+s.curit.\b',
    r'\bc.est\s+quoi\b',
]


def is_knowledge_question(text: str) -> bool:
    """
    Returns True if this is a knowledge/documentation question.
    Command-starter sentences are never knowledge questions even if
    they contain question words (e.g. "show all policies" is a command).
    """
    t = text.lower().strip()

    # Commands that start with action verbs are never knowledge questions
    if _COMMAND_STARTERS.search(t):
        return False

    return any(re.search(p, t) for p in _QUESTION_PATTERNS)


#  Intent detection — ALL clear commands caught here
#
#  Priority order:
#    1. is_knowledge_question() runs FIRST (before this)
#    2. Read commands — immediate execution
#    3. Write commands — go to confirmation flow
#    4. None — fall through to Mistral for ambiguous input


def detect_intent(text: str):
    t = text.lower().strip()

    # ── READ commands ──────────────────────────────────────
    if re.search(
        r'(list|show|get|display|all|lister|afficher|voir|montrer)'
        r'\s+(all\s+)?(firewall\s+)?(polic|rules|r.gles|politiques)', t
    ):
        return ("tool_list_policies", {})

    if re.search(
        r'(list|show|get|display|all|lister|afficher)'
        r'\s+(all\s+)?(address|adresse|objet\s+d)', t
    ):
        return ("tool_list_addresses", {})

    if re.search(
        r'(list|show|get|display|all|lister|afficher)'
        r'\s+(all\s+)?(network\s+)?(interface)', t
    ):
        return ("tool_list_interfaces", {})

    if re.search(
        r'(list|show|get|display|all|lister)'
        r'\s+(all\s+)?(user|utilisateur)', t
    ):
        return ("tool_list_users", {})

    if re.search(
        r'(list|show|get|display|all|lister)'
        r'\s+(all\s+)?(static\s+)?(route|routage)', t
    ):
        return ("tool_list_routes", {})

    if re.search(r'(system|device|syst.me)\s+(status|.tat|info)', t):
        return ("tool_get_system_status", {})
    if re.search(r'\b(check\s+)?(firmware|version)\b', t):
        return ("tool_get_system_status", {})

    if re.search(r'\b(check\s+)?(cpu|memory|m.moire|ram|resource)\b', t):
        return ("tool_get_cpu_memory", {})

    if re.search(
        r'(vpn\s+(status|tunnel|.tat)|ipsec\s+tunnel'
        r'|show\s+vpn|list\s+vpn|statut\s+vpn)', t
    ):
        return ("tool_get_vpn_status", {})

    if re.search(
        r'(active\s+session|session\s+count|connexions\s+actives)', t
    ):
        return ("tool_get_active_sessions", {})

    if re.search(
        r'\b(analyz|audit|security\s+check|scan\s+firewall'
        r'|analyser|v.rifier\s+s.curit.)\b', t
    ):
        return ("tool_analyze_security", {})

    if re.search(r'(show|list|lister|afficher)\s+(blocked|block|bloqu)', t):
        return ("tool_list_addresses", {})

    # ── WRITE commands — all caught here for deterministic confirmation ──

    # Policy creation — catches natural language patterns
    if re.search(
        r'(create|add|new|make|ajouter|cr.er|nouvelle?)'
        r'\s+(a\s+)?(firewall\s+)?(polic|r.gle)', t
    ):
        return ("tool_create_policy", None)

    # Policy creation via service blocking pattern
    if re.search(
        r'(block|deny|allow|permit|bloquer|autoriser|interdire)'
        r'\s+\w+\s+(traffic|from|on|between|de|sur|depuis)', t
    ):
        return ("tool_create_policy", None)

    # Policy update
    if re.search(
        r'(update|modify|change|edit|modifier|changer|mettre\s+.+jour)'
        r'\s+(policy|polic|r.gle)\s+\d+', t
    ):
        return ("tool_update_policy", None)

    # Policy enable/disable
    if re.search(
        r'(enable|disable|activer|d.sactiver|deactivate)'
        r'\s+(policy|polic|r.gle)\s+\d+', t
    ):
        return ("tool_enable_disable_policy", None)

    # Policy deletion
    if re.search(
        r'(delete|remove|supprimer|effacer)'
        r'\s+(policy|polic|r.gle)', t
    ):
        return ("tool_delete_policy", None)

    # Policy move — catches all synonyms
    if re.search(
        r'(move|switch|swap|reorder|place|put|d.placer|r.organiser|intervertir)'
        r'\s+(policy|polic|r.gle)', t
    ):
        return ("tool_move_policy", None)

    # Address creation
    if re.search(
        r'(create|add|new|ajouter|cr.er)'
        r'\s+(a\s+)?(address|addr|objet\s+d.adresse|objet)', t
    ):
        return ("tool_create_address", None)

    # Address deletion
    if re.search(
        r'(delete|remove|supprimer)\s+(address|addr|objet)', t
    ):
        return ("tool_delete_address", None)

    # Interface management
    if re.search(
        r'(disable|enable|update|change|d.sactiver|activer|mettre\s+.+jour)'
        r'\s+(http|telnet|ssh|https|management|gestion|access|protocol)', t
    ):
        return ("tool_update_interface_access", None)

    # Block IP — require an actual IP address in the sentence
    if re.search(
        r'(block\s+ip|bloquer\s+l.?ip|block\s+the\s+ip|block\s+ip\s+address)', t
    ) or (
        re.search(r'\bblock\b|\bbloquer\b', t) and
        re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', t)
    ):
        return ("tool_block_ip", None)

    # Backup
    if re.search(r'\bbackup\b|\bsauvegarde\b|\bsave\s+config\b', t):
        return ("tool_backup_config", {})

    # Policy details by ID
    if re.search(
        r'(show|get|display|detail|info)\s+(of\s+)?(policy|polic|r.gle)\s+\d+', t
    ):
        return ("tool_get_policy_details", None)

    return None


#  Parameter extraction
#  FIX: Regex-first for all numeric patterns

def extract_params(tool_name: str, user_input: str, llm_plain) -> dict:
    """
    Extract structured parameters from natural language.
    Uses regex where possible, LLM only as fallback.
    Returns dict or None if required fields cannot be extracted.
    """

    if tool_name == "tool_create_policy":
        prompt = (
            f'Extract firewall policy parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON, nothing else:\n"
            '{"name":"PolicyName","srcintf":"port1","dstintf":"port2",'
            '"srcaddr":"all","dstaddr":"all","service":"SSH","action":"deny"}\n\n'
            "Rules:\n"
            "- action: 'accept' or 'deny' (block/deny/restrict -> 'deny')\n"
            "- service: ALL HTTP HTTPS SSH FTP DNS SMTP RDP PING\n"
            "- srcaddr and dstaddr default to 'all' if not mentioned\n"
            "- name: single word no spaces use hyphens\n"
            "- If srcintf/dstintf not specified use port1/port2 as defaults"
        )
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            match = re.search(r'\{.*\}', response.content.strip(), re.DOTALL)
            if match:
                params = json.loads(match.group())
                if (params.get("name") and
                        params.get("srcintf") and
                        params.get("dstintf")):
                    return params
        except Exception:
            pass
        return None

    elif tool_name == "tool_update_policy":
        # Regex: extract ID first
        id_match = re.search(r'\b(\d+)\b', user_input)
        if not id_match:
            return None
        policy_id = int(id_match.group(1))

        prompt = (
            f'Extract policy update parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            f'{{"policy_id":{policy_id},"action":"deny"}}\n\n'
            "Rules:\n"
            f"- policy_id is always {policy_id}\n"
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
        # Pure regex — no LLM needed
        id_match = re.search(r'\b(\d+)\b', user_input)
        if not id_match:
            return None
        status = "disable" if re.search(
            r'\b(disable|d.sactiver|deactivate|off)\b',
            user_input.lower()
        ) else "enable"
        return {"policy_id": int(id_match.group(1)), "status": status}

    elif tool_name == "tool_delete_policy":
        # Pure regex — extract the number
        id_match = re.search(r'\b(\d+)\b', user_input)
        if id_match:
            return {"policy_id": int(id_match.group(1))}
        # Fallback: LLM to find ID from policy name
        prompt = (
            f'Extract the numeric policy ID to delete from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"policy_id":3}\n'
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
        # FIX: Pure regex — most reliable for "move X before/after Y"
        # Handles: move, switch, swap, reorder, place, put
        match = re.search(
            r'(?:move|switch|swap|reorder|place|put|d.placer|intervertir)'
            r'\s+(?:policy\s+)?(\d+)\s+'
            r'(before|after|avant|apr.s|devant|derri.re)\s+'
            r'(?:policy\s+)?(\d+)',
            user_input, re.IGNORECASE
        )
        if match:
            policy_id   = int(match.group(1))
            direction   = match.group(2).lower()
            neighbor_id = int(match.group(3))
            move_action = "before" if direction in ("before", "avant", "devant") else "after"
            return {
                "policy_id":   policy_id,
                "move_action": move_action,
                "neighbor_id": neighbor_id,
            }

        # Fallback: LLM with explicit example to prevent ID reversal
        prompt = (
            f'Extract policy move parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"policy_id":3,"move_action":"before","neighbor_id":4}\n\n'
            "CRITICAL RULE: policy_id is the policy BEING MOVED.\n"
            "neighbor_id is the REFERENCE policy.\n"
            "Example: 'move policy 3 before policy 4' "
            "-> policy_id=3, move_action=before, neighbor_id=4\n"
            "Example: 'move policy 5 after policy 2' "
            "-> policy_id=5, move_action=after, neighbor_id=2\n"
            "move_action must be exactly 'before' or 'after'."
        )
        response = llm_plain.invoke([HumanMessage(content=prompt)])
        try:
            match2 = re.search(r'\{.*\}', response.content.strip(), re.DOTALL)
            if match2:
                params = json.loads(match2.group())
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
            "- subnet in CIDR notation (e.g. 192.168.1.0/24 or 10.0.0.1/32)\n"
            "- name: single word no spaces"
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
        # Try regex pattern first
        regex_match = re.search(
            r'(?:delete|remove|supprimer)\s+(?:address\s+)?'
            r'["\']?([a-zA-Z0-9_\-\.]+)["\']?',
            user_input, re.IGNORECASE
        )
        if regex_match:
            name = regex_match.group(1)
            # Filter out common non-name words
            if name.lower() not in ("address", "object", "the", "objet"):
                return {"name": name}

        prompt = (
            f'Extract the exact address object name to delete from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"name":"ExactObjectName"}\n'
            "Extract only the exact object name, not surrounding words."
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
            f'Extract interface management access update parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"name":"port1","allowaccess":"https ssh ping"}\n\n'
            "Rules:\n"
            "- name: exact interface name (port1, port2, wan1, etc.)\n"
            "- allowaccess: space-separated SAFE protocols to ALLOW\n"
            "- NEVER include http or telnet in allowaccess\n"
            "- If user says disable http/telnet: set allowaccess to 'https ssh ping'\n"
            "- Do NOT add snmp unless the user explicitly says so\n"
            "- Only include: https ssh ping (and snmp only if explicitly requested)"
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
        # Pure regex — extract IP and direction
        ip_match = re.search(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b',
            user_input
        )
        if ip_match:
            t = user_input.lower()
            if re.search(r'\binbound\b|\bentr.e\b|\bincoming\b', t):
                direction = "inbound"
            elif re.search(r'\boutbound\b|\bsortant\b|\boutgoing\b', t):
                direction = "outbound"
            else:
                direction = "both"
            return {
                "ip_address": ip_match.group(1),
                "direction":  direction,
            }
        return None

    elif tool_name == "tool_get_policy_details":
        # Pure regex
        id_match = re.search(r'\b(\d+)\b', user_input)
        if id_match:
            return {"policy_id": int(id_match.group(1))}
        return None

    elif tool_name == "tool_backup_config":
        return {}

    return {}


#  Confirmation formatter

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
            "  Creates deny policy(ies) — reversible by deleting them.",
        ]
    elif tool_name == "tool_backup_config":
        lines += [
            "  BACKUP FortiGate configuration.",
            "  Config file saved locally with timestamp.",
        ]

    lines += ["="*55, "  Type 'yes' to confirm or 'no' to cancel.", "="*55]
    return "\n".join(lines)


#  Tool executor

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


#  Response formatter
#  NEVER receives ToolMessages — only clean conversation

def format_response(llm_plain, conversation: list,
                    tool_result: str, user_input: str) -> str:
    fmt = list(conversation) + [
        HumanMessage(
            content=(
                f"User request: {user_input}\n\n"
                f"System data retrieved:\n{tool_result}\n\n"
                "Instructions for your response:\n"
                "- Plain text only\n"
                "- No emojis\n"
                "- No markdown headers (no ###, ##, #)\n"
                "- No bold or italic (**text** or *text*)\n"
                "- Use simple ASCII tables with | and - for tabular data\n"
                "- Be concise and direct\n"
                "- Respond in the SAME LANGUAGE as the user request above\n"
                "- Do not call any tools"
            )
        )
    ]
    return invoke_with_retry(llm_plain, fmt).content


#  Post-execution verification

def verify_after_execution(tool_name: str) -> str:
    if tool_name not in (
        "tool_delete_policy", "tool_move_policy",
        "tool_enable_disable_policy", "tool_create_policy"
    ):
        return ""

    try:
        from modules.policies import list_policies as _lp
        r       = _lp()
        results = r if isinstance(r, list) else r.get("results", [])

        if not results:
            return "\n[Verified: no policies remain on FortiGate]"

        lines = ["\n[Verified current policy order:]"]
        for p in results:
            src  = (p.get("srcintf") or [{}])[0].get("name", "?")
            dst  = (p.get("dstintf") or [{}])[0].get("name", "?")
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


#  Confirmation handler

def handle_confirmation_yes(pending: dict, conversation: list,
                             llm_plain) -> tuple:
    """
    Returns (stay_in_confirmation_mode, updated_pending).
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


#  Mistral path — for ambiguous/conversational input only

def handle_with_mistral(user_input: str, conversation: list,
                         llm_tools, llm_plain,
                         pending_confirmation_ref: list) -> None:
    """
    Uses Mistral for genuinely ambiguous conversational input.
    Write tools are intercepted as a safety net even here.
    pending_confirmation_ref is a single-element list used as a mutable ref.
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

            # Safety net: intercept write tools that slipped through
            if t_name in WRITE_TOOLS:
                turn_msgs.append(ToolMessage(
                    content="Awaiting user confirmation.",
                    tool_call_id=t_id,
                ))
                print(format_confirmation(t_name, t_args))
                pending_confirmation_ref[0] = {
                    "name": t_name,
                    "args": t_args,
                    "original_input": user_input,
                }
                return

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

    else:
        answer = response.content
        conversation.append(HumanMessage(content=user_input))
        conversation.append(AIMessage(content=answer))
        print(f"\nAgent: {answer}\n")
        log_conversation(user_input, answer)


#  Main CLI loop


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
                # Confirmation resolved (executed or blocked)
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

        # ── Main processing ───────────────────────────────
        try:
            # PRIORITY 1: Knowledge questions — MUST check before detect_intent
            # Prevents fast path from intercepting "how do I..." questions
            if is_knowledge_question(user_input):
                from tools import tool_search_knowledge as _sk
                print("\n[Calling: tool_search_knowledge]")
                tool_result = str(_sk.invoke({"query": user_input}))
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
                # PRIORITY 2: Deterministic command detection
                intent = detect_intent(user_input)

                if intent:
                    tool_name, tool_args = intent

                    if tool_name in WRITE_TOOLS and tool_args is None:
                        # Extract parameters for write operations
                        tool_args = extract_params(
                            tool_name, user_input, llm_plain
                        )

                        if tool_args is None:
                            # Missing required params — ask user
                            missing_param_messages = {
                                "tool_create_policy": (
                                    "I need more details to create this policy.\n"
                                    "Please provide: policy name, source interface, "
                                    "destination interface, service, and action (accept/deny)."
                                ),
                                "tool_create_address": (
                                    "Please provide the address object name and "
                                    "subnet (e.g. create address WebServer 192.168.10.50/32)."
                                ),
                                "tool_delete_address": (
                                    "Please provide the exact name of the address object to delete."
                                ),
                                "tool_delete_policy": (
                                    "Please provide the policy ID number to delete."
                                ),
                                "tool_enable_disable_policy": (
                                    "Please provide the policy ID number."
                                ),
                                "tool_move_policy": (
                                    "Please provide: policy ID to move, "
                                    "direction (before/after), and reference policy ID.\n"
                                    "Example: move policy 3 before policy 1"
                                ),
                                "tool_block_ip": (
                                    "Please provide the IP address to block.\n"
                                    "Example: block ip 192.168.1.55"
                                ),
                                "tool_update_interface_access": (
                                    "Please provide the interface name and "
                                    "the protocols to allow.\n"
                                    "Example: disable HTTP and TELNET on port2"
                                ),
                            }
                            msg = missing_param_messages.get(
                                tool_name,
                                "Please provide the required details."
                            )
                            print(f"\nAgent: {msg}\n")
                            log_conversation(user_input, msg)

                        elif tool_name in WRITE_TOOLS:
                            print(format_confirmation(tool_name, tool_args))
                            pending_confirmation = {
                                "name": tool_name,
                                "args": tool_args,
                                "original_input": user_input,
                            }

                        else:
                            # Write tool with known args (e.g. backup)
                            tool_result = execute_tool(
                                tool_name, tool_args, user_input
                            )
                            answer = format_response(
                                llm_plain, conversation, tool_result, user_input
                            )
                            conversation.append(HumanMessage(content=user_input))
                            conversation.append(AIMessage(content=answer))
                            print(f"\nAgent: {answer}\n")
                            log_conversation(user_input, answer)

                    elif tool_name in WRITE_TOOLS:
                        # Write tool with args already known (backup, etc.)
                        print(format_confirmation(tool_name, tool_args))
                        pending_confirmation = {
                            "name": tool_name,
                            "args": tool_args,
                            "original_input": user_input,
                        }

                    else:
                        # Read tool — execute immediately
                        tool_result = execute_tool(
                            tool_name, tool_args, user_input
                        )
                        answer = format_response(
                            llm_plain, conversation, tool_result, user_input
                        )
                        conversation.append(HumanMessage(content=user_input))
                        conversation.append(AIMessage(content=answer))
                        print(f"\nAgent: {answer}\n")
                        log_conversation(user_input, answer)

                else:
                    # PRIORITY 3: Mistral for genuinely ambiguous/conversational input
                    pending_ref = [None]
                    handle_with_mistral(
                        user_input, conversation, llm_tools, llm_plain,
                        pending_ref
                    )
                    if pending_ref[0]:
                        pending_confirmation = pending_ref[0]

        except Exception as exc:
            error_str = str(exc)
            print(f"\nError: {error_str}\n")
            # Always clear pending confirmation on error
            # to prevent ghost confirmation on next request
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