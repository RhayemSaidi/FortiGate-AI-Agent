"""
read_reasoner.py — Live FortiGate read/query reasoning layer.

Completely separate from the write path.
Read queries NEVER touch UpdateIntent, FieldDelta, missing_fields,
write grounding, or confirmation flows.

Key fixes in this version:
  - Service-based policy filtering ("policies with SSH", "show HTTP policies")
  - Intermediate-word patterns ("show the policies", "show my addresses")
  - tool_search_policies used for filtered queries instead of post_filter hack
  - _apply_post_filter handles all supported filter types correctly
  - Double API call architecture fixed — filter applied from cached data
  - French service/filter query patterns added
  - "policies on interface X" query type added
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from session_context import SessionContext

logger = logging.getLogger("fortigate_agent")


# ══════════════════════════════════════════════════════════
#  Read intent taxonomy
# ══════════════════════════════════════════════════════════

class ReadIntent:
    LIST_POLICIES     = "list_policies"
    SEARCH_POLICIES   = "search_policies"     # NEW: filtered policy search
    POLICY_DETAILS    = "policy_details"
    LIST_ADDRESSES    = "list_addresses"
    LIST_INTERFACES   = "list_interfaces"
    LIST_USERS        = "list_users"
    LIST_ROUTES       = "list_routes"
    SYSTEM_STATUS     = "system_status"
    CPU_MEMORY        = "cpu_memory"
    VPN_STATUS        = "vpn_status"
    ACTIVE_SESSIONS   = "active_sessions"
    BLOCKED_IPS       = "blocked_ips"
    ADDRESS_USAGE     = "address_usage"       # NEW: which policies use address X
    SERVICE_USAGE     = "service_usage"       # NEW: which policies use service X


@dataclass
class ReadPlan:
    """Describes the read operation to perform."""
    intent:      str
    tool_name:   str
    tool_args:   dict
    post_filter: Optional[dict] = None   # Applied after fetch (legacy path only)
    hint:        str            = ""


# ══════════════════════════════════════════════════════════
#  Known service vocabulary for extraction
# ══════════════════════════════════════════════════════════

_KNOWN_SERVICES = {
    "HTTP", "HTTPS", "SSL", "FTP", "SFTP", "SSH", "TELNET",
    "DNS", "SMTP", "SMTPS", "POP3", "POP3S", "IMAP", "IMAPS",
    "RDP", "VNC", "PING", "ICMP", "SNMP", "SYSLOG",
    "NTP", "TFTP", "LDAP", "LDAPS", "RADIUS", "SIP", "H323", "ALL",
}

_SERVICE_ALIASES = {
    "SSL":              "HTTPS",
    "TLS":              "HTTPS",
    "SECURE SHELL":     "SSH",
    "ICMP":             "PING",
    "MSTSC":            "RDP",
    "REMOTE DESKTOP":   "RDP",
    "EMAIL":            "SMTP",
    "MAIL":             "SMTP",
    "WEB":              "HTTP",
    "DOMAIN":           "DNS",
}


def _extract_service_name(text: str) -> Optional[str]:
    """
    Extract a service name from text.
    Returns the canonical FortiGate service name or None.
    """
    t = text.upper()

    # Check aliases first
    for alias, canonical in _SERVICE_ALIASES.items():
        if alias in t:
            return canonical

    # Check known services
    for svc in sorted(_KNOWN_SERVICES, key=len, reverse=True):  # Longest first
        if re.search(rf'\b{re.escape(svc)}\b', t):
            return svc

    return None


# ══════════════════════════════════════════════════════════
#  Entity extraction helpers
# ══════════════════════════════════════════════════════════

def _resolve_policy_name(name: str) -> Optional[int]:
    """Resolve a policy name to its numeric ID via live API lookup."""
    try:
        from modules.policies import list_policies
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        name_l  = name.lower()

        # Exact match first
        for p in results:
            if p.get("name", "").lower() == name_l:
                return p.get("policyid")

        # Partial match if no exact
        matches = [p for p in results if name_l in p.get("name", "").lower()]
        if len(matches) == 1:
            return matches[0].get("policyid")

    except Exception as exc:
        logger.debug(
            f'"event":"policy_name_lookup_fail","name":"{name}","error":"{exc}"'
        )
    return None


def _extract_policy_ref(text: str, ctx: SessionContext) -> Optional[int]:
    """Extract a policy ID from text or resolve from session context."""
    # Explicit numeric ID: "policy 4"
    m = re.search(r'\b(?:policy|polic\w*|rule|r[eè]gle)\s+(\d+)\b', text, re.I)
    if m:
        return int(m.group(1))

    # Bare digit
    m = re.search(r'\b(\d+)\b', text)
    if m:
        return int(m.group(1))

    # Named policy
    m = re.search(
        r'\b(?:policy|polic\w*|rule|r[eè]gle)\s+([A-Za-z][A-Za-z0-9_\-]+)\b',
        text, re.I,
    )
    if m:
        pid = _resolve_policy_name(m.group(1))
        if pid:
            return pid

    # Session context fallback
    if ctx.has_policy_focus():
        return ctx.focused_policy_id

    return None


# ══════════════════════════════════════════════════════════
#  Deterministic read plan builder
# ══════════════════════════════════════════════════════════

def _build_read_plan_deterministic(
    text: str,
    ctx:  SessionContext,
) -> Optional[ReadPlan]:
    """
    Build a ReadPlan from deterministic pattern matching.
    Returns None if the input needs LLM interpretation.

    Order matters:
    1. Specific entity queries (policy details, address usage, service usage)
    2. Service-filtered policy search — NEW
    3. Status/action-filtered policy lists
    4. Generic list operations (with flexible intermediate-word patterns)
    5. System resource queries
    """
    t = text.lower().strip()

    # ── "what does policy X do" and similar ───────────────
    if (
        re.search(r'\bwhat\s+does\s+(policy|polic\w*|rule)\s+\S+', t, re.I)
        or re.search(r'\b(tell\s+me\s+about|describe|info\s+on|info\s+about)\s+(policy|polic\w*|rule)\s+\S+', t, re.I)
        or re.search(r'\b(que\s+fait|qu.est.ce\s+que\s+fait)\s+(la\s+|cette\s+)?(politique|r[eè]gle)\s+\S+', t, re.I)
        or re.search(r'\b(montre.?moi|affiche|donne.?moi)\s+(la\s+|cette\s+)?(politique|r[eè]gle)\s+\S+', t, re.I)
    ):
        pid = _extract_policy_ref(text, ctx)
        if pid:
            return ReadPlan(ReadIntent.POLICY_DETAILS, "tool_get_policy_details", {"policy_id": pid})
        return None

    # ── Address usage query ────────────────────────────────
    # "which policies use address WebServer"
    # "what policies reference address DMZ_Server"
    if re.search(
        r'\b(which|what|show|list)\s+policies\s+(use|reference|contain|have|with)\s+'
        r'(the\s+|address\s+)?(\w[\w\-\.]+)\b',
        t, re.I,
    ):
        m = re.search(
            r'\b(?:address\s+)?([A-Za-z][\w\-\.]+)\s*$', text.strip(), re.I
        )
        if m:
            addr = m.group(1)
            # Exclude generic words
            if addr.lower() not in ("policy", "policies", "rule", "rules", "service", "services"):
                return ReadPlan(
                    ReadIntent.ADDRESS_USAGE,
                    "tool_get_address_usage",
                    {"address_name": addr},
                    hint=f"policies referencing address {addr}",
                )

    # ── Service usage query ────────────────────────────────
    # "which policies use SSH"
    # "what policies have HTTP"
    # "show policies with HTTPS service" — KEY FIX
    # "show the policies that has http as service" — KEY FIX
    # "policies using FTP"

    # First try to extract a service name from the text
    svc = _extract_service_name(t)

    if svc:
        # Service name found — now check if user is asking to filter by it
        _SERVICE_FILTER_PATTERNS = [
            re.compile(r'\bpolic\w*\b.*\b(service|protocol|using|with|that\s+ha[sv]e?|allow\w*)\b', re.I),
            re.compile(r'\bpolic\w*\s+that\s+(ha[sv]e?|use|contain|include|allow)\b', re.I),
            re.compile(r'\b(which|what|show|list|find)\b.*\bpolic\w*\b', re.I),
            re.compile(r'\bpolitiques?\s+(qui|avec|utilisant|contenant)\b', re.I),
            re.compile(r'\b(find|show|list|display)\s+\w+\s+polic\w*\b', re.I),
        ]
        if any(p.search(t) for p in _SERVICE_FILTER_PATTERNS):
            return ReadPlan(
                ReadIntent.SEARCH_POLICIES,
                "tool_search_policies",
                {"service": svc},
                hint=f"policies using service {svc}",
            )

        # ── Status-filtered policy lists ───────────────────────
        if (
            re.search(r'\b(enabled?|active|activ[eé])\s+polic\w*\b', t, re.I)
            or re.search(r'\bpolic\w*\s+that\s+are\s+(enabled?|active)\b', t, re.I)
            or re.search(r'\bpolitiques?\s+(activ[eé]es?)\b', t, re.I)
            or re.search(r'\bshow\s+(?:the\s+|all\s+)?(?:currently\s+)?enabled\s+polic\w*\b', t, re.I)
        ):
            return ReadPlan(
                ReadIntent.SEARCH_POLICIES,
                "tool_search_policies",
                {"status": "enable"},
                hint="enabled policies only",
            )

    if (
        re.search(r'\b(disabled?|inactive|inactiv\w*)\s+polic\w*\b', t, re.I)
        or re.search(r'\bpolic\w*\s+that\s+are\s+disabled?\b', t, re.I)
    ):
        return ReadPlan(
            ReadIntent.SEARCH_POLICIES,
            "tool_search_policies",
            {"status": "disable"},
            hint="disabled policies only",
        )

    if (
        re.search(r'\bdeny\w*\s+polic\w*\b', t, re.I)
        or re.search(r'\bpolic\w*\s+with\s+action\s+deny\b', t, re.I)
        or re.search(r'\bpolic\w*\s+(that\s+)?(block|deny)\b', t, re.I)
    ):
        return ReadPlan(
            ReadIntent.SEARCH_POLICIES,
            "tool_search_policies",
            {"action": "deny"},
            hint="deny policies only",
        )

    if (
        re.search(r'\baccept\w*\s+polic\w*\b', t, re.I)
        or re.search(r'\bpolic\w*\s+with\s+action\s+accept\b', t, re.I)
        or re.search(r'\bpolic\w*\s+(that\s+)?(allow|accept|permit)\b', t, re.I)
    ):
        return ReadPlan(
            ReadIntent.SEARCH_POLICIES,
            "tool_search_policies",
            {"action": "accept"},
            hint="accept policies only",
        )

    # NAT-filtered policies
    if re.search(r'\bpolic\w*\s+(with\s+|that\s+have\s+|where\s+|having\s+)?nat\s+(enabled?|on|active)\b', t, re.I):
        return ReadPlan(
            ReadIntent.SEARCH_POLICIES,
            "tool_search_policies",
            {"nat": "enable"},
            hint="policies with NAT enabled",
        )

    # Interface-filtered policies
    # "policies on port1" / "policies using wan1" / "show wan1 policies"
    _INTF_PATTERNS = [
        re.compile(r'\bpolic\w*\s+(?:on|for|using|through|via)\s+(\w+)\b', re.I),
        re.compile(r'\bshow\s+(?:\w+\s+)?polic\w*\s+(?:on|for|using|through|via)\s+(\w+)\b', re.I),
        re.compile(r'\b(on|for|using|through|via)\s+interface\s+(\w+)\b', re.I),
    ]
    for pat in _INTF_PATTERNS:
        m = pat.search(t)
        if m:
            intf = m.group(m.lastindex)
            # Rough interface name check (port1, wan1, lan, etc.)
            if re.match(r'^(port|wan|lan|dmz|mgmt|internal|external|loopback)\w*$', intf, re.I):
                return ReadPlan(
                    ReadIntent.SEARCH_POLICIES,
                    "tool_search_policies",
                    {"srcintf": intf},
                    hint=f"policies on interface {intf}",
                )

    # ── Generic policy list — flexible intermediate-word ────
    # FIX: handles "show the policies", "list my policies", "show all current policies"
    if re.search(
        r'\b(list|show|get|display|lister|afficher|voir|montrer)\b'
        r'(?:\s+\w+){0,3}\s+(?:all\s+)?(firewall\s+)?(policies|policy\s+list|rules|r[eè]gles)\b',
        t, re.I,
    ) or re.search(
        r'\b(quelles?\s+sont\s+(les?\s+)?(politiques?|r[eè]gles?))\b', t, re.I
    ) or re.search(
        r'\b(what|which)\s+policies\s+(do\s+)?(i\s+)?(have|exist)\b', t, re.I
    ) or re.search(
        r'\b(all\s+)(policies|firewall\s+policies|rules)\b', t, re.I
    ):
        return ReadPlan(ReadIntent.LIST_POLICIES, "tool_list_policies", {})

    # ── Policy details (explicit detail request) ───────────
    has_detail_verb = bool(re.search(
        r'\b(show|get|display|detail\w*|info|describe|afficher|voir|d[eé]tailler|check)\b',
        t, re.I,
    ))
    has_policy_ref  = bool(re.search(
        r'\b(policy|polic\w*|rule|r[eè]gle)\s+\S+\b', text, re.I
    ))

    if has_detail_verb and (has_policy_ref or ctx.has_policy_focus()):
        pid = _extract_policy_ref(text, ctx)
        if pid:
            return ReadPlan(
                ReadIntent.POLICY_DETAILS,
                "tool_get_policy_details",
                {"policy_id": pid},
                hint=f"details of policy {pid}",
            )

    # ── Specific policy attribute queries ──────────────────
    # "what are the services of policy X" / "is NAT enabled in policy X"
    if re.search(
        r'\b(what|is|are)\b.*(services?|action|status|nat|interfaces?|log\w*)\b.*(policy|polic\w*)\b',
        t, re.I,
    ) or re.search(
        r'\b(is|are)\s+(nat|policy)\s+.*\s+(enabled?|disabled?|on|off)\b',
        t, re.I,
    ):
        pid = _extract_policy_ref(text, ctx)
        if pid:
            return ReadPlan(
                ReadIntent.POLICY_DETAILS,
                "tool_get_policy_details",
                {"policy_id": pid},
                hint="policy attribute query",
            )

    # ── Address list — flexible intermediate-word ───────────
    # FIX: "show ip addresses", "show network addresses", "show the addresses"
    if re.search(
        r'\b(list|show|get|display|lister|afficher|voir)\b'
        r'(?:\s+\w+){0,3}\s+(addresses?|address\s+objects?|adresses?)\b',
        t, re.I,
    ) or re.search(r'\bshow\s+(existing|current)\s+(?:\w+\s+)?(addresses?|adresses?)\b', t, re.I) \
       or re.search(r'\bwhat\s+(addresses?|adresses?)\s+(do\s+)?(i\s+)?(have|exist)\b', t, re.I):
        return ReadPlan(ReadIntent.LIST_ADDRESSES, "tool_list_addresses", {})

    # ── Blocked IPs ────────────────────────────────────────
    if re.search(
        r'\b(show|list|afficher)\b.*(blocked\w*|block\w*|bloqu[eé]\w*)\b.*(ip\w*|address\w*|host\w*)?\b',
        t, re.I,
    ):
        return ReadPlan(
            ReadIntent.BLOCKED_IPS,
            "tool_list_addresses",
            {},
            post_filter={"name_prefix": "BLOCKED-"},
            hint="blocked IP addresses only",
        )

    # ── Interfaces — flexible ──────────────────────────────
    if re.search(
        r'\b(list|show|display|afficher|lister)\b'
        r'(?:\s+\w+){0,3}\s+(interfaces?)\b',
        t, re.I,
    ):
        return ReadPlan(ReadIntent.LIST_INTERFACES, "tool_list_interfaces", {})

    # ── Users ──────────────────────────────────────────────
    if re.search(
        r'\b(list|show|display|afficher|lister)\b'
        r'(?:\s+\w+){0,3}\s+(users?|utilisateurs?)\b',
        t, re.I,
    ):
        return ReadPlan(ReadIntent.LIST_USERS, "tool_list_users", {})

    # ── Routes ─────────────────────────────────────────────
    if re.search(
        r'\b(list|show|display|afficher|lister)\b'
        r'(?:\s+\w+){0,3}\s+(routes?|routage)\b',
        t, re.I,
    ):
        return ReadPlan(ReadIntent.LIST_ROUTES, "tool_list_routes", {})

    # ── System resources ───────────────────────────────────
    if re.search(r'\b(check|show|voir)\s+(?:\w+\s+)?(cpu|memory|ram|m[eé]moire|resource\w*)\b', t, re.I):
        return ReadPlan(ReadIntent.CPU_MEMORY, "tool_get_cpu_memory", {})

    if re.search(r'\b(system|device|syst[eè]me)\s+(status|info|state|[eé]tat)\b', t, re.I):
        return ReadPlan(ReadIntent.SYSTEM_STATUS, "tool_get_system_status", {})

    if re.search(r'\b(firmware|version)\s*(info|number|num[eé]ro)?\b', t, re.I):
        return ReadPlan(ReadIntent.SYSTEM_STATUS, "tool_get_system_status", {})

    # ── VPN ────────────────────────────────────────────────
    if re.search(
        r'\b(vpn\s+(status|tunnel\s+status|state|[eé]tat)|ipsec\s+tunnel|show\s+vpn)\b',
        t, re.I,
    ):
        return ReadPlan(ReadIntent.VPN_STATUS, "tool_get_vpn_status", {})

    # ── Active sessions ────────────────────────────────────
    if re.search(r'\b(active\s+sessions?|session\s+count|connexions?\s+actives?)\b', t, re.I):
        return ReadPlan(ReadIntent.ACTIVE_SESSIONS, "tool_get_active_sessions", {})

    return None


# ══════════════════════════════════════════════════════════
#  LLM read plan extraction (fallback)
# ══════════════════════════════════════════════════════════

_READ_PLANNER_PROMPT = """You are extracting a READ operation from user input for a FortiGate firewall agent.
The user wants to QUERY the current state. This is NOT a configuration change.

Output ONLY a JSON object:
{
  "tool": "<tool_name>",
  "args": {},
  "hint": "<short description>"
}

Available tools:
  "tool_list_policies"       {}                     — list ALL policies (no filter)
  "tool_search_policies"     {"service":"SSH"}      — filter policies by field
                             {"action":"deny"}
                             {"status":"enable"}
                             {"srcintf":"port1"}
                             {"dstintf":"wan1"}
                             {"nat":"enable"}
                             {"name":"BlockSSH"}
                             (combine multiple filters in one args dict)
  "tool_get_policy_details"  {"policy_id": <int>}   — full details of one policy
  "tool_get_address_usage"   {"address_name":"X"}   — which policies use address X
  "tool_get_service_usage"   {"service_name":"SSH"} — which policies use service SSH
  "tool_list_addresses"      {}                     — list address objects
  "tool_list_interfaces"     {}                     — list interfaces
  "tool_list_users"          {}                     — list local users
  "tool_list_routes"         {}                     — list static routes
  "tool_list_services"       {}                     — list custom service objects
  "tool_get_system_status"   {}                     — firmware, hostname, model
  "tool_get_cpu_memory"      {}                     — CPU and memory usage
  "tool_get_vpn_status"      {}                     — VPN tunnel status
  "tool_get_active_sessions" {}                     — active session count
  "tool_get_bandwidth_usage" {}                     — per-interface bandwidth (TX/RX)
  "tool_get_traffic_logs"    {}                     — recent firewall traffic log entries
  "tool_get_threat_logs"     {}                     — recent IPS/threat detection logs
  "tool_get_event_logs"      {}                     — recent system/admin event logs

CRITICAL RULES:
1. "show policies with HTTP service" / "policies that have SSH" → tool_search_policies with {"service":"HTTP"}
2. "show enabled policies" → tool_search_policies with {"status":"enable"}
3. "show deny policies" → tool_search_policies with {"action":"deny"}
4. "what does policy X do" → tool_get_policy_details with the policy_id
5. "which policies use address WebServer" → tool_get_address_usage
6. "policies using SSH service" → tool_search_policies with {"service":"SSH"}
7. "does test1 have http" → tool_search_policies with {"name": "test1", "service": "HTTP"}
8. NEVER use tool_list_policies when a filter is needed — use tool_search_policies instead
9. For policy name without ID: use tool_search_policies with {"name": "<policy_name>"} OR tool_get_policy_details with policy_id=null

Service name normalisation:
  "web" or "http" → "HTTP"
  "secure web" or "https" or "ssl" → "HTTPS"
  "secure shell" or "ssh" → "SSH"
  "file transfer" or "ftp" → "FTP"
  "remote desktop" or "rdp" → "RDP"
  "email" or "smtp" or "mail" → "SMTP"

Output only the JSON. No explanation."""


def _build_read_plan_llm(
    text:      str,
    ctx:       SessionContext,
    llm_plain: object,
) -> Optional[ReadPlan]:
    """LLM fallback for read plan extraction."""
    context_hint = ""
    if ctx.has_policy_focus():
        context_hint = (
            f"\nSession context: user was examining "
            f"policy ID {ctx.focused_policy_id} "
            f"({ctx.focused_policy_name or ''})."
        )

    try:
        from langchain_core.messages import HumanMessage, SystemMessage

        resp = llm_plain.invoke([
            SystemMessage(content=_READ_PLANNER_PROMPT),
            HumanMessage(content=f'User input: "{text}"{context_hint}'),
        ])

        raw  = resp.content.strip()
        raw  = re.sub(r"```(?:json)?\s*", "", raw)
        raw  = re.sub(r"```\s*", "", raw).strip()
        data = json.loads(raw)

        tool_name = str(data.get("tool", ""))
        if not tool_name:
            return None

        args = data.get("args") or {}

        # Resolve policy name to ID if needed
        if tool_name == "tool_get_policy_details":
            pid = args.get("policy_id")
            if pid is None:
                pid = _extract_policy_ref(text, ctx)
            if pid:
                args = {"policy_id": int(pid)}
            else:
                # Can't resolve — fall back to list
                tool_name = "tool_list_policies"
                args      = {}

        # Validate tool_search_policies args
        if tool_name == "tool_search_policies":
            valid_search_fields = {
                "action", "status", "service", "srcintf",
                "dstintf", "name", "nat",
            }
            args = {k: v for k, v in args.items() if k in valid_search_fields and v}
            if not args:
                # LLM asked for search with no filters → fall back to list
                tool_name = "tool_list_policies"

        return ReadPlan(
            intent=tool_name,
            tool_name=tool_name,
            tool_args=args,
            hint=str(data.get("hint", "")),
        )

    except Exception as exc:
        logger.warning(f'"event":"read_planner_llm_fail","error":"{exc}"')
        return None


# ══════════════════════════════════════════════════════════
#  Post-fetch filtering (legacy path — only for name_prefix)
#
#  NOTE: Service/action/status filtering now goes through
#  tool_search_policies directly. The _apply_post_filter
#  function handles only remaining legacy cases:
#  - "name_prefix" filtering for blocked IP addresses
#
#  The previous architecture of calling _apply_post_filter
#  for service/status/action was removed because:
#  1. It silently ignored unknown filter keys
#  2. It made a second unnecessary API call
#  3. It was less reliable than using tool_search_policies
# ══════════════════════════════════════════════════════════

def _apply_post_filter(
    tool_name:   str,
    raw_result:  str,
    post_filter: Optional[dict],
) -> str:
    """
    Apply post-fetch filtering where the tool cannot natively filter.
    Currently only handles "name_prefix" for blocked IP address lists.

    Service/status/action filters should use tool_search_policies instead.
    """
    if not post_filter:
        return raw_result

    # Only handle name_prefix filter (for blocked IPs)
    # All other filters should have been routed to tool_search_policies
    prefix = post_filter.get("name_prefix", "")
    if not prefix or tool_name != "tool_list_addresses":
        # Unknown filter or wrong tool — return raw result unchanged
        if post_filter and tool_name == "tool_list_policies":
            # Log a warning: this should not happen if routing is correct
            logger.warning(
                f'"event":"legacy_filter_on_list_policies",'
                f'"filter":{json.dumps(post_filter)},'
                '"reason":"should have used tool_search_policies"'
            )
        return raw_result

    # Name-prefix filter for blocked IPs
    try:
        from modules.addresses import list_addresses
        r       = list_addresses()
        results = r if isinstance(r, list) else r.get("results", [])
        filtered = [
            a for a in results
            if str(a.get("name", "")).startswith(prefix)
        ]

        if not filtered:
            return "No blocked IP addresses found."

        lines = [f"Blocked IP Addresses (prefix: {prefix}):"]
        for a in filtered:
            subnet = a.get("subnet", a.get("fqdn", "N/A"))
            lines.append(f"  {a.get('name', '?'):<40} {subnet}")
        return "\n".join(lines)

    except Exception:
        return raw_result


# ══════════════════════════════════════════════════════════
#  Public resolver
# ══════════════════════════════════════════════════════════

def resolve_read(
    text:        str,
    ctx:         SessionContext,
    llm_plain:   object,
    run_tool_fn: Callable,
) -> Tuple[str, Optional[str]]:
    """
    Resolve a read query to tool execution and return the result.

    Args:
        text:        User input.
        ctx:         Session context.
        llm_plain:   Plain LLM for fallback plan extraction.
        run_tool_fn: Callable(tool_name, tool_args, user_input) → ToolResult.

    Returns:
        (result_string, tool_name_used) — tool_name is None on failure.
    """
    # Stage 1: deterministic
    plan = _build_read_plan_deterministic(text, ctx)

    # Stage 2: LLM fallback
    if plan is None:
        plan = _build_read_plan_llm(text, ctx, llm_plain)

    if plan is None:
        logger.warning(f'"event":"read_plan_fail","input":"{text[:80]}"')
        return "", None

    logger.debug(
        f'"event":"read_plan",'
        f'"tool":"{plan.tool_name}",'
        f'"args":{json.dumps(plan.tool_args)},'
        f'"filter":{json.dumps(plan.post_filter)},'
        f'"hint":"{plan.hint}"'
    )

    result   = run_tool_fn(plan.tool_name, plan.tool_args, text)
    filtered = _apply_post_filter(plan.tool_name, result.for_llm(), plan.post_filter)

    # Update session context with entity focus
    if plan.tool_name == "tool_get_policy_details":
        pid = plan.tool_args.get("policy_id")
        if pid:
            ctx.set_policy_focus(int(pid))

    return filtered, plan.tool_name