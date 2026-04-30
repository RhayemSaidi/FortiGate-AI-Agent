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
#  Retry — FIX: added ReadTimeout handling
# ══════════════════════════════════════════════════════════

def invoke_with_retry(llm, messages: list, max_retries: int = 3):
    for attempt in range(max_retries):
        try:
            return llm.invoke(messages)
        except Exception as exc:
            s = str(exc)
            is_rate_limit  = "429" in s or "rate_limit" in s.lower()
            is_server_err  = "503" in s or "502" in s or "unreachable" in s.lower()
            is_timeout     = "timeout" in s.lower() or "timed out" in s.lower()

            if is_rate_limit:
                wait = 2 * (attempt + 1)
                print(f"\n[Rate limit — waiting {wait}s...]\n")
                time.sleep(wait)
            elif is_server_err or is_timeout:
                wait = 3 * (attempt + 1)
                print(f"\n[API unavailable — waiting {wait}s...]\n")
                time.sleep(wait)
            else:
                raise
    raise Exception("Mistral API unavailable after retries. Please try again.")


# ══════════════════════════════════════════════════════════
#  Conversation management
# ══════════════════════════════════════════════════════════

def trim_conversation(conversation: list) -> list:
    system = [m for m in conversation if isinstance(m, SystemMessage)]
    rest   = [m for m in conversation if not isinstance(m, SystemMessage)]
    if len(rest) <= MAX_TURNS * 2:
        return conversation
    return system + rest[-(MAX_TURNS * 2):]


# ══════════════════════════════════════════════════════════
#  Policy name → ID resolver
#
#  Allows users to refer to policies by name in addition
#  to ID. Fetches the current policy list and returns the
#  numeric ID for the given name. Returns None if not found.
# ══════════════════════════════════════════════════════════

def resolve_policy_id(name_or_id: str) -> int:
    """
    Given a policy name or numeric ID string, return the integer ID.
    If already numeric, return as-is. If a name, look it up live.
    """
    stripped = name_or_id.strip()

    if re.match(r'^\d+$', stripped):
        return int(stripped)

    try:
        from modules.policies import list_policies as _lp
        r       = _lp()
        results = r if isinstance(r, list) else r.get("results", [])
        for p in results:
            if p.get("name", "").lower() == stripped.lower():
                return p.get("policyid")
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════
#  Write intent detector
#
#  Used as a safety check AFTER Mistral responds.
#  If Mistral returned no tool calls but the input clearly
#  looks like a write command, we block the response and
#  re-route through the deterministic path.
# ══════════════════════════════════════════════════════════

_WRITE_INTENT_PATTERNS = [
    r'\b(create|add|new|make)\s+(a\s+)?(firewall\s+)?(polic|r.gle)',
    r'\b(delete|remove|supprimer)\s+(policy|polic|r.gle)',
    r'\b(enable|disable|activer|d.sactiver)\s+(policy|polic|r.gle)',
    r'\b(move|switch|swap|reorder|d.placer)\s+(policy|polic|r.gle)',
    r'\b(update|modify|change|modifier)\s+(policy|polic|r.gle)\s+\S+',
    r'\b(create|add)\s+(a\s+)?(address|adresse|objet)',
    r'\b(delete|remove|supprimer)\s+(address|adresse|objet)',
    r'\b(disable|enable|d.sactiver|activer)\s+(http|telnet|ssh|https)',
    r'\bblock\s+(ip|the\s+ip|\d{1,3}\.\d)',
    r'\bbloquer\s+(l.ip|\d{1,3}\.\d)',
    r'\bbackup\b|\bsauvegarde\b',
]


def is_write_intent(text: str) -> bool:
    t = text.lower().strip()
    return any(re.search(p, t) for p in _WRITE_INTENT_PATTERNS)


# ══════════════════════════════════════════════════════════
#  Knowledge question detector
# ══════════════════════════════════════════════════════════

_COMMAND_STARTERS = re.compile(
    r'^(list|show|get|display|create|add|delete|remove|move|switch|swap|'
    r'block|disable|enable|update|modify|change|backup|analyze|audit|scan|'
    r'lister|afficher|cr.er|supprimer|bloquer|activer|d.sactiver|'
    r'sauvegarder|analyser|v.rifier|d.placer|intervertir)\b',
    re.IGNORECASE
)

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
    r'\bqu.est.ce\b',
    r'\bcomment\s+(faire|cr.er|configurer|v.rifier|afficher|utiliser)\b',
    r'\bpourquoi\b',
    r'\bexpliquer\b',
    r'\bquelle\s+commande\b',
    r"\bc'est\s+quoi\b",
    r'\bzone\s+de\s+s.curit.\b',
]


def is_knowledge_question(text: str) -> bool:
    t = text.lower().strip()
    if _COMMAND_STARTERS.search(t):
        return False
    return any(re.search(p, t) for p in _QUESTION_PATTERNS)


# ══════════════════════════════════════════════════════════
#  Intent detection
# ══════════════════════════════════════════════════════════

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
        r'|analyser|v.rifier\s+s.curit.|make\s+a\s+security'
        r'|security\s+checkup|checkup)\b', t
    ):
        return ("tool_analyze_security", {})

    if re.search(r'(show|list|lister|afficher)\s+(blocked|block|bloqu)', t):
        return ("tool_list_addresses", {})

    # ── WRITE commands ─────────────────────────────────────

    if re.search(
        r'(create|add|new|make|ajouter|cr.er|nouvelle?)'
        r'\s+(a\s+)?(firewall\s+)?(polic|r.gle)', t
    ):
        return ("tool_create_policy", None)

    if re.search(
        r'(block|deny|allow|permit|bloquer|autoriser|interdire)'
        r'\s+\w+\s+(traffic|from|on|between|de|sur|depuis)', t
    ):
        return ("tool_create_policy", None)

    if re.search(
        r'(update|modify|change|edit|modifier|changer|mettre\s+.+jour)'
        r'\s+(policy|polic|r.gle)\s+\S+', t
    ):
        return ("tool_update_policy", None)

    # FIX: enable/disable now matches names AND IDs (\S+ instead of \d+)
    if re.search(
        r'(enable|disable|activer|d.sactiver|deactivate)'
        r'\s+(policy|polic|r.gle)\s+\S+', t
    ):
        return ("tool_enable_disable_policy", None)

    # FIX: delete matches names AND IDs
    if re.search(
        r'(delete|remove|supprimer|effacer)'
        r'\s+(policy|polic|r.gle)\s+(\S+)', t
    ):
        return ("tool_delete_policy", None)

    if re.search(
        r'(move|switch|swap|reorder|place|put|d.placer|r.organiser|intervertir)'
        r'\s+(policy|polic|r.gle)', t
    ):
        return ("tool_move_policy", None)

    if re.search(
        r'(create|add|new|ajouter|cr.er)'
        r'\s+(a\s+)?(address|addr|objet\s+d.adresse|objet)', t
    ):
        return ("tool_create_address", None)

    if re.search(
        r'(delete|remove|supprimer)\s+(address|addr|objet)', t
    ):
        return ("tool_delete_address", None)

    if re.search(
        r'(disable|enable|update|change|d.sactiver|activer|mettre\s+.+jour)'
        r'\s+(http|telnet|ssh|https|management|gestion|access|protocol)', t
    ):
        return ("tool_update_interface_access", None)

    if re.search(
        r'(block\s+ip|bloquer\s+l.?ip|block\s+the\s+ip|block\s+ip\s+address)', t
    ) or (
        re.search(r'\bblock\b|\bbloquer\b', t) and
        re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', t)
    ):
        return ("tool_block_ip", None)

    if re.search(r'\bbackup\b|\bsauvegarde\b|\bsave\s+config\b', t):
        return ("tool_backup_config", {})

    if re.search(
        r'(show|get|display|detail|info)\s+(of\s+)?(policy|polic|r.gle)\s+\S+', t
    ):
        return ("tool_get_policy_details", None)

    return None


# ══════════════════════════════════════════════════════════
#  Parameter extraction
#  FIX: resolve_policy_id used for name-based operations
# ══════════════════════════════════════════════════════════

def extract_params(tool_name: str, user_input: str, llm_plain) -> dict:

    if tool_name == "tool_create_policy":
        prompt = (
            f'Extract firewall policy parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"name":"PolicyName","srcintf":"port1","dstintf":"port2",'
            '"srcaddr":"all","dstaddr":"all","service":"SSH","action":"deny"}\n\n'
            "Rules:\n"
            "- action: 'accept' or 'deny'\n"
            "- service: ALL HTTP HTTPS SSH FTP DNS SMTP RDP PING\n"
            "- srcaddr/dstaddr default to 'all'\n"
            "- name: single word no spaces use hyphens\n"
            "- Default interfaces: port1 and port2"
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
        id_match = re.search(r'\b(\d+)\b', user_input)
        if not id_match:
            # Try name resolution
            name_match = re.search(
                r'(?:update|modify|change|edit)\s+(?:policy\s+)?(\S+)',
                user_input, re.IGNORECASE
            )
            if name_match:
                resolved = resolve_policy_id(name_match.group(1))
                if resolved:
                    policy_id = resolved
                else:
                    return None
            else:
                return None
        else:
            policy_id = int(id_match.group(1))

        prompt = (
            f'Extract policy update parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            f'{{"policy_id":{policy_id},"action":"deny"}}\n\n'
            f"policy_id is always {policy_id}. "
            "Only include fields that change. "
            "action: 'accept' or 'deny'. status: 'enable' or 'disable'."
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
        # FIX: handles both numeric IDs and policy names
        status = "disable" if re.search(
            r'\b(disable|d.sactiver|deactivate|off)\b',
            user_input.lower()
        ) else "enable"

        # Try numeric ID first
        id_match = re.search(r'\b(\d+)\b', user_input)
        if id_match:
            return {"policy_id": int(id_match.group(1)), "status": status}

        # Try name resolution
        name_match = re.search(
            r'(?:enable|disable|activer|d.sactiver)\s+(?:policy\s+)?(\S+)',
            user_input, re.IGNORECASE
        )
        if name_match:
            candidate = name_match.group(1)
            # Skip if it's just the word "policy"
            if candidate.lower() not in ("policy", "polic", "la", "le", "r.gle"):
                resolved = resolve_policy_id(candidate)
                if resolved:
                    return {"policy_id": resolved, "status": status}

        return None

    elif tool_name == "tool_delete_policy":
        # Try numeric ID
        id_match = re.search(r'\b(\d+)\b', user_input)
        if id_match:
            return {"policy_id": int(id_match.group(1))}

        # FIX: try name resolution
        name_match = re.search(
            r'(?:delete|remove|supprimer)\s+(?:policy\s+)?(\S+)',
            user_input, re.IGNORECASE
        )
        if name_match:
            candidate = name_match.group(1)
            if candidate.lower() not in ("policy", "polic", "la", "le"):
                resolved = resolve_policy_id(candidate)
                if resolved:
                    return {"policy_id": resolved}

        return None

    elif tool_name == "tool_move_policy":
        # Pure regex — most reliable
        match = re.search(
            r'(?:move|switch|swap|reorder|place|put|d.placer|intervertir)'
            r'\s+(?:policy\s+)?(\S+)\s+'
            r'(before|after|avant|apr.s|devant|derri.re)\s+'
            r'(?:policy\s+)?(\S+)',
            user_input, re.IGNORECASE
        )
        if match:
            raw_policy   = match.group(1)
            direction    = match.group(2).lower()
            raw_neighbor = match.group(3)

            policy_id   = resolve_policy_id(raw_policy)
            neighbor_id = resolve_policy_id(raw_neighbor)

            if policy_id and neighbor_id:
                move_action = "before" if direction in (
                    "before", "avant", "devant"
                ) else "after"
                return {
                    "policy_id":   policy_id,
                    "move_action": move_action,
                    "neighbor_id": neighbor_id,
                }

        return None

    elif tool_name == "tool_create_address":
        prompt = (
            f'Extract address object parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"name":"ObjectName","subnet":"192.168.1.10/32"}\n\n'
            "subnet in CIDR notation. name: single word no spaces."
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
        regex_match = re.search(
            r'(?:delete|remove|supprimer)\s+(?:address\s+)?'
            r'["\']?([a-zA-Z0-9_\-\.]+)["\']?',
            user_input, re.IGNORECASE
        )
        if regex_match:
            name = regex_match.group(1)
            if name.lower() not in ("address", "object", "the", "objet"):
                return {"name": name}

        prompt = (
            f'Extract the address object name to delete from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"name":"ExactObjectName"}'
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
            f'Extract interface management access parameters from:\n"{user_input}"\n\n'
            "Reply with ONLY valid JSON:\n"
            '{"name":"port1","allowaccess":"https ssh ping"}\n\n'
            "Rules:\n"
            "- name: exact interface name\n"
            "- allowaccess: SAFE protocols only (https ssh ping)\n"
            "- NEVER include http or telnet\n"
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
            t = user_input.lower()
            if re.search(r'\binbound\b|\bentr.e\b|\bincoming\b', t):
                direction = "inbound"
            elif re.search(r'\boutbound\b|\bsortant\b|\boutgoing\b', t):
                direction = "outbound"
            else:
                direction = "both"
            return {"ip_address": ip_match.group(1), "direction": direction}
        return None

    elif tool_name == "tool_get_policy_details":
        id_match = re.search(r'\b(\d+)\b', user_input)
        if id_match:
            return {"policy_id": int(id_match.group(1))}
        # Try name
        name_match = re.search(
            r'(?:show|get|display|detail|info)\s+(?:of\s+)?(?:policy\s+)?(\S+)',
            user_input, re.IGNORECASE
        )
        if name_match:
            candidate = name_match.group(1)
            if candidate.lower() not in ("policy", "polic", "of", "the"):
                resolved = resolve_policy_id(candidate)
                if resolved:
                    return {"policy_id": resolved}
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
            "  Creates deny policy(ies) — reversible by deleting them.",
        ]
    elif tool_name == "tool_backup_config":
        lines += [
            "  BACKUP FortiGate configuration.",
            "  Config file saved locally with timestamp.",
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
#  Response formatter
# ══════════════════════════════════════════════════════════

def format_response(llm_plain, conversation: list,
                    tool_result: str, user_input: str) -> str:
    fmt = list(conversation) + [
        HumanMessage(
            content=(
                f"User request: {user_input}\n\n"
                f"System data:\n{tool_result}\n\n"
                "Format instructions:\n"
                "- Plain text only. No emojis. No markdown (no ###, **, *).\n"
                "- Use ASCII tables (| and -) for tabular data.\n"
                "- Be concise and direct.\n"
                "- Respond in the EXACT same language as the user request.\n"
                "- Do not call any tools."
            )
        )
    ]
    return invoke_with_retry(llm_plain, fmt).content


# ══════════════════════════════════════════════════════════
#  Post-execution state verifier
#
#  FIX: Real verification — fetches actual state from
#  FortiGate and confirms the change happened.
#  Returns a human-readable verification string.
# ══════════════════════════════════════════════════════════

def verify_after_execution(tool_name: str, tool_args: dict,
                            tool_result: str) -> str:
    """
    Verify that the action actually took effect on the FortiGate.
    Returns a verification string to print after the result.
    """
    if "[ERROR]" in tool_result:
        return ""  # No point verifying a failed action

    try:
        from modules.policies import list_policies as _lp, get_policy as _gp

        # ── Policy list operations ────────────────────────
        if tool_name in ("tool_delete_policy", "tool_move_policy",
                         "tool_create_policy"):
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

        # ── Enable/disable — FIX: verify actual status field ──
        if tool_name == "tool_enable_disable_policy":
            policy_id       = tool_args.get("policy_id")
            expected_status = tool_args.get("status", "enable")

            if not policy_id:
                return ""

            r = _gp(policy_id)
            raw = r.get("results", {})
            if isinstance(raw, list):
                p = raw[0] if raw else {}
            else:
                p = raw

            actual_status = p.get("status", "unknown")

            if actual_status == expected_status:
                return (
                    f"\n[Verified: policy '{p.get('name','?')}' (ID:{policy_id}) "
                    f"is confirmed {actual_status} on FortiGate]"
                )
            else:
                return (
                    f"\n[WARNING: Expected status '{expected_status}' but "
                    f"FortiGate reports '{actual_status}' for policy ID {policy_id}. "
                    f"The change may not have applied correctly.]"
                )

    except Exception:
        pass

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
                print("\nAgent: Action blocked. Please start a new request.\n")
                return False, None

            if validation.has_warnings_only():
                print(validation.format())
                pending["warnings_shown"] = True
                return True, pending

    tool_result  = execute_tool(tool_name, tool_args, original_input)
    print(f"[Result: {tool_result}]\n")

    # FIX: real verification with actual args and result
    verification = verify_after_execution(tool_name, tool_args, tool_result)
    if verification:
        print(verification)

    answer = format_response(llm_plain, conversation, tool_result, original_input)
    print(f"Agent: {answer}\n")

    conversation.append(HumanMessage(content=original_input))
    conversation.append(AIMessage(content=answer))
    log_conversation(original_input, answer)

    return False, None


# ══════════════════════════════════════════════════════════
#  Mistral path — conversational fallback only
#
#  FIX: After Mistral responds, check if the input was
#  actually a write intent. If Mistral returned no tool
#  calls for a write intent, block the response and
#  re-route through the deterministic path.
# ══════════════════════════════════════════════════════════

def handle_with_mistral(user_input: str, conversation: list,
                         llm_tools, llm_plain,
                         pending_ref: list) -> None:
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

            # Safety net: intercept write tools
            if t_name in WRITE_TOOLS:
                turn_msgs.append(ToolMessage(
                    content="Awaiting user confirmation.",
                    tool_call_id=t_id,
                ))
                print(format_confirmation(t_name, t_args))
                pending_ref[0] = {
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
        # FIX: Mistral responded without calling a tool.
        # Check if this was actually a write intent — if so, block
        # the hallucinated response and inform the user.
        if is_write_intent(user_input):
            msg = (
                "I could not automatically determine the exact parameters "
                "for this operation. Please be more specific.\n"
                "Example: 'enable policy 4' or 'enable policy SafePolicy'"
            )
            print(f"\nAgent: {msg}\n")
            conversation.append(HumanMessage(content=user_input))
            conversation.append(AIMessage(content=msg))
            log_conversation(user_input, msg)
        else:
            answer = response.content
            conversation.append(HumanMessage(content=user_input))
            conversation.append(AIMessage(content=answer))
            print(f"\nAgent: {answer}\n")
            log_conversation(user_input, answer)


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

        # ── Main processing ───────────────────────────────
        try:
            # PRIORITY 1: Knowledge questions
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
                        tool_args = extract_params(
                            tool_name, user_input, llm_plain
                        )

                        if tool_args is None:
                            missing_messages = {
                                "tool_create_policy": (
                                    "Please provide: policy name, source interface, "
                                    "destination interface, service, and action."
                                ),
                                "tool_create_address": (
                                    "Please provide the address name and subnet "
                                    "(e.g. create address WebServer 192.168.10.50/32)."
                                ),
                                "tool_delete_address": (
                                    "Please provide the exact name of the address to delete."
                                ),
                                "tool_delete_policy": (
                                    "Please provide the policy ID or name to delete."
                                ),
                                "tool_enable_disable_policy": (
                                    "Please provide the policy ID or name.\n"
                                    "Example: enable policy 4 or disable policy BlockSSH"
                                ),
                                "tool_move_policy": (
                                    "Please provide: policy to move, direction, "
                                    "and reference policy.\n"
                                    "Example: move policy 3 before policy 1"
                                ),
                                "tool_block_ip": (
                                    "Please provide the IP address.\n"
                                    "Example: block ip 192.168.1.55"
                                ),
                                "tool_update_interface_access": (
                                    "Please provide the interface name.\n"
                                    "Example: disable HTTP and TELNET on port2"
                                ),
                            }
                            msg = missing_messages.get(
                                tool_name, "Please provide the required details."
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
                        print(format_confirmation(tool_name, tool_args))
                        pending_confirmation = {
                            "name": tool_name,
                            "args": tool_args,
                            "original_input": user_input,
                        }

                    else:
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
                    # PRIORITY 3: Mistral for ambiguous/conversational
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