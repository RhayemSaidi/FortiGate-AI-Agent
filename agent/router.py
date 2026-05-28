"""
router.py — Master intent router.

Two-stage classification:
  Stage 1: Deterministic patterns (~0 ms, no LLM, no API)
  Stage 2: LLM semantic classification (only when stage 1 returns None)

The router is conservative: it errs toward LIVE_READ and KNOWLEDGE
rather than guessing WRITE_ACTION. A misclassified read is harmless;
a misclassified write that skips the safety pipeline is not.

Key fixes in this version:
  - "what does policy X do" correctly classified as LIVE_READ
  - French query patterns added throughout
  - session_hint parameter threads context into LLM stage-2
  - _LIVE_ENTITY_INDICATORS broadened to catch name-based entity references
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from langchain_core.messages import HumanMessage, SystemMessage

logger = logging.getLogger("fortigate_agent")


# ══════════════════════════════════════════════════════════
#  Routing categories
# ══════════════════════════════════════════════════════════

class RouteCategory(Enum):
    CONVERSATIONAL    = "conversational"
    CLARIFICATION     = "clarification"
    LIVE_READ         = "live_read"
    SECURITY_ANALYSIS = "security_analysis"
    KNOWLEDGE         = "knowledge"
    WRITE_ACTION      = "write_action"
    UNKNOWN           = "unknown"


@dataclass
class RouteResult:
    category:   RouteCategory
    confidence: str   # "certain" | "high" | "medium" | "low"
    source:     str   # "deterministic" | "llm"
    hint:       str = ""


# ══════════════════════════════════════════════════════════
#  Stage 1: Deterministic patterns
# ══════════════════════════════════════════════════════════

# ── Conversational ────────────────────────────────────────
_CONVERSATIONAL_PATTERNS = [
    re.compile(
        r'^\s*(hi|hello|hey|salut|bonjour|bonsoir|coucou|howdy|yo)\s*[!?.]?\s*$',
        re.I,
    ),
    re.compile(r'\bwhat\s+can\s+(you|the\s+agent)\b', re.I),
    re.compile(r'\bwhat\s+do\s+you\s+do\b', re.I),
    re.compile(r'^\s*help\s*[!?.]?\s*$', re.I),
    re.compile(r'\bcapabilit\w+\b', re.I),
    re.compile(r'\bque\s+(peux.?tu|sais.?tu|fais.?tu)\b', re.I),
    re.compile(r'\bcomment\s+(tu\s+)?(fonctionne|marche|travaille)\b', re.I),
    re.compile(r'\bqu.est.ce\s+que\s+tu\s+(peux|fais|sais|es)\b', re.I),
    re.compile(r'\baide.moi\b', re.I),
    re.compile(r'\btu\s+(peux|sais|es\s+capable)\b', re.I),
]

# ── Security analysis ─────────────────────────────────────
_SECURITY_ANALYSIS_PATTERNS = [
    re.compile(
        r'\b(analyz|audit|scan)\w*\s+(my\s+)?(firewall|security|config\w*|policies)\b',
        re.I,
    ),
    re.compile(
        r'\b(check|find|identify|detect|spot)\s+(risk\w*|issue\w*|problem\w*|vuln\w*|threat\w*|weakness\w*)\b',
        re.I,
    ),
    re.compile(r'\b(security\s+(check|audit|review|scan|analys\w*))\b', re.I),
    re.compile(
        r'\b(insecure|misconfigur\w*|unsafe|dangerous)\s+(config\w*|polic\w*|rule\w*|setting\w*)\b',
        re.I,
    ),
    re.compile(
        r'\b(audit|analys\w*|inspecte?r?|v[eé]rifi\w*)\s+(le\s+|la\s+|les\s+)?(pare.?feu|firewall|s[eé]curit[eé])\b',
        re.I,
    ),
    re.compile(r'\bcheck\s+everything\b', re.I),
    re.compile(r'\b(full|complete|comprehensive|global)\s+(audit|check|review|scan)\b', re.I),
    re.compile(r'\bshow\s+(risky|dangerous|insecure|bad|weak)\b', re.I),
    re.compile(r'\bv[eé]rifi\w+\s+(la\s+s[eé]curit[eé]|les?\s+risques?|tout)\b', re.I),
    re.compile(r'\b(analyse|analyser)\s+(la\s+)?(s[eé]curit[eé]|configuration|les\s+politiques)\b', re.I),
    re.compile(r'\btout\s+v[eé]rifier\b', re.I),
    re.compile(r'\bscan\s+(my\s+)?(network|firewall|policies|config)\b', re.I),
    # Security state / status / posture queries
    re.compile(r'\b(security\s+(state|status|posture|level|health|overview|summary|situation))\b', re.I),
    re.compile(r'\b(firewall\s+(health|state|status|overview|security))\b', re.I),
    re.compile(r'\b(show|check|get|tell\s+me|give\s+me)\s+(me\s+)?(the\s+)?security\s+(state|status|posture|level|health|overview|summary)\b', re.I),
    re.compile(r'\b(how\s+(safe|secure)\s+(is|are)\s+(my|the)\s+(firewall|network|policies))\b', re.I),
    re.compile(r'\b(is\s+(my|the)\s+(firewall|network)\s+(secure|safe|ok|compliant))\b', re.I),
    re.compile(r'\b(any\s+(security\s+)?(issues?|risks?|problems?|vulnerabilit\w*|misconfigurations?))\b', re.I),
]

# ── Write actions ─────────────────────────────────────────
# Require BOTH a modification verb AND a target object.
_WRITE_ACTION_PATTERNS = [
    # Policy CRUD
    re.compile(
        r'\b(create|add|make|new|ajouter|cr[eé]er)\s+(a\s+)?(new\s+)?(firewall\s+)?(polic\w*|rule\w*|r[eè]gle\w*)\b',
        re.I,
    ),
    re.compile(r'\b(delete|remove)\w*\s+(policy|polic\w*|rule\w*|r[eè]gle\w*)\b', re.I),
    re.compile(r'\bsupprimer\s+(la\s+|cette\s+)?(politique|r[eè]gle)\b', re.I),
    re.compile(
        r'\b(update|modify|change|edit|modifier|changer|mettre\s+[àa]\s+jour)\s+'
        r'(policy|polic\w*|rule\w*|r[eè]gle\w*)\s+\S+',
        re.I,
    ),
    re.compile(
        r'\b(move|reorder|switch|swap|d[eé]placer|r[eé]organiser|d[eé]placer)\s+(policy|polic\w*)\b',
        re.I,
    ),
    # Service / field modifications
    re.compile(
        r'\b(add|remove|ajouter|supprimer|enlever|retirer)\s+\w+\s+'
        r'(to|from|dans|[àa]|de)\s+(policy|polic\w*|rule\w*|la\s+r[eè]gle)\b',
        re.I,
    ),
    re.compile(
        r'\b(set|change|d[eé]finir)\s+(policy|polic\w*)\s+\S+\s+(action|nat|status|logtraffic)\b',
        re.I,
    ),
    re.compile(
        r'\b(set|change|d[eé]finir)\s+(the\s+|la\s+)?action\s+(of\s+|de\s+)?(policy|polic\w*|la\s+r[eè]gle)\b',
        re.I,
    ),
    # Implicit field sets — value-only but unambiguous
    re.compile(
        r'\b(set|change)\s+(policy|polic\w*)\s+\S+\s+to\s+(deny|accept|block|allow)\b',
        re.I,
    ),
    # French deny/allow pattern for policy creation
    re.compile(
        r'\b(interdire|bloquer|refuser|d[eé]sautoriser)\s+(l\S*\s+)?(acc[eè]s|traffic|trafic|connexion)\b',
        re.I,
    ),
    re.compile(
        r'\b(autoriser|permettre|accepter)\s+(l\S*\s+)?(acc[eè]s|traffic|trafic|connexion)\b',
        re.I,
    ),
    # Enable/disable POLICY STATUS (not a field within a policy)
    re.compile(
        r'\b(enable|disable|activer|d[eé]sactiver)\s+(policy|polic\w*)\s+\S+\b',
        re.I,
    ),
    # Enable/disable NAT on a policy (field modification)
    re.compile(
        r'\b(enable|disable|activer|d[eé]sactiver)\s+nat\s+(in|on|for|dans|sur)\b',
        re.I,
    ),
    re.compile(r'\bnat\s+(enable|disable|on|off)\s+(in|on|for|dans|sur)\b', re.I),
    # Address objects
    re.compile(r'\bcreate\s+address\b|\bcr[eé]er\s+(un\s+)?(objet|adresse)\b', re.I),
    re.compile(r'\bdelete\s+(address|addr)\b|\bsupprimer\s+(adresse|objet)\b', re.I),
    # Interface management access
    re.compile(
        r'\b(disable|enable|activer|d[eé]sactiver)\s+(http|https|telnet|ssh|snmp|ping|management|web)\s+(on|sur|for|pour)\b',
        re.I,
    ),
    re.compile(
        r'\b(update|modify|change)\s+(the\s+)?management\s+(access|protocols?)\b',
        re.I,
    ),
    # Block IP
    re.compile(r'\bblock\s+(ip|the\s+ip|l.?ip|address)\b', re.I),
    re.compile(r'\bbloquer\s+(l.?ip|cette\s+ip|\d{1,3}\.\d)', re.I),
    re.compile(r'\bblock\b.*\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', re.I),
    # Backup
    re.compile(
        r'\b(backup|sauvegarde|sauvegarder)\s+(the\s+|la\s+|de\s+la\s+)?(config\w*|configuration|firewall)\b',
        re.I,
    ),
    re.compile(r'\bsave\s+(the\s+)?(config\w*|configuration)\b', re.I),
    # Port/log modifications
    re.compile(r'\b(change|set|modifier)\s+(log|logging|logtraffic)\b', re.I),
    # Reboot / System Control
    re.compile(r'\b(reboot|restart|shut\s*down)\s+(the\s+)?(firewall|system|device|appliance|fortigate)\b', re.I),
    re.compile(r'\b(red[eé]marrer|rebooter|[eé]teindre)\s+(le\s+)?(pare.?feu|firewall|syst[eè]me)\b', re.I),
]

# ── Live reads — queries about current firewall state ──────
# FIX: "what does policy X do" added here; French equivalents added.
_LIVE_READ_PATTERNS = [
    # ── List operations ───────────────────────────────────
    re.compile(
        r'\b(list|show|get|display|lister|afficher|voir)\s+'
        r'(?:all\s+)?(?:\w+\s+)?(addresses?|address\s+objects?|adresses?)\b',
        re.I,
    ),
    re.compile(
        r'\b(list|show|display|afficher|lister|voir)\s+(all\s+)?(addresses?|address\s+objects?|adresses?|objets?\s+adresses?)\b',
        re.I,
    ),
    re.compile(
        r'\b(list|show|display|afficher|lister)\s+(all\s+)?interfaces?\b',
        re.I,
    ),
    re.compile(
        r'\b(list|show|display|afficher|lister)\s+(all\s+)?(users?|utilisateurs?|comptes?)\b',
        re.I,
    ),
    re.compile(
        r'\b(list|show|display|afficher|lister)\s+(all\s+)?(static\s+)?routes?\b',
        re.I,
    ),
    re.compile(
        r'\b(list|show|display|afficher)\s+(all\s+)?(vpn\s+)?(tunnels?|connexions?)\b',
        re.I,
    ),
    # ── Status queries ────────────────────────────────────
    re.compile(r'\b(system|device|syst[eè]me|appareil)\s+(status|info|state|[eé]tat)\b', re.I),
    re.compile(r'\b(check|show|voir)\s+(cpu|memory|ram|m[eé]moire|resource\w*)\b', re.I),
    re.compile(r'\b(active\s+sessions?|session\s+count|connexions?\s+actives?)\b', re.I),
    re.compile(r'\b(vpn\s+(status|tunnel\s+status|state|[eé]tat))\b', re.I),
    re.compile(r'\b(firmware|version)\s*(version|info|number|num[eé]ro)?\b', re.I),
    # ── Specific policy queries ───────────────────────────
    # show/get/display policy X
    re.compile(
        r'\b(show|get|display|detail\w*|info|describe|afficher|voir|d[eé]tailler)\s+'
        r'(of\s+|for\s+|de\s+|la\s+)?(policy|polic\w*|rule\w*|r[eè]gle\w*)\s+\S+\b',
        re.I,
    ),
    # show policy details for X
    re.compile(
        r'\b(show|get|display|afficher)\s+(policy\s+)?(details?|info|configuration|settings?)\s+'
        r'(of|for|de|pour)?\s*(policy|polic\w*)?\s*\S+\b',
        re.I,
    ),
    # what are the services/action/status/nat of policy X
    re.compile(
        r'\bwhat\s+(are|is)\s+(the\s+)?(services?|action|status|nat|interfaces?|config\w*)\s+of\s+(policy|polic\w*)\b',
        re.I,
    ),
    # FIX: "what does policy X do/allow/block/contain"
    re.compile(
        r'\bwhat\s+does\s+(policy|polic\w*|rule)\s+\S+\s*(do|allow|block|deny|contain|include|cover|use|have)?\b',
        re.I,
    ),
    # FIX: "what does the policy X do" variants
    re.compile(
        r'\bwhat\s+does\s+(the\s+|this\s+|that\s+)?(policy|polic\w*|rule)\b',
        re.I,
    ),
    # French: "que fait la politique X" / "qu'est-ce que fait la règle X"
    re.compile(
        r'\b(que\s+fait|qu.est.ce\s+que\s+fait|comment\s+fonctionne)\s+'
        r'(la\s+|cette\s+|le\s+|ce\s+)?(politique|r[eè]gle)\s*\S*\b',
        re.I,
    ),
    # is NAT enabled in policy X
    re.compile(
        r'\b(is|are)\s+(nat|policy|polic\w*|rule)\s+.*\s+(enabled?|disabled?|on|off|active|activ[eé])\b',
        re.I,
    ),
    # what is the status/state of policy X
    re.compile(
        r'\bwhat\s+(is|are)\s+the\s+(status|state|[eé]tat|configuration)\s+of\s+(policy|polic\w*)\b',
        re.I,
    ),
    # which/what policies are enabled/disabled/deny
    re.compile(
        r'\b(what|which)\s+policies\s+are\s+(enabled?|disabled?|active|deny\w*|accept\w*|block\w*)\b',
        re.I,
    ),
    re.compile(
        r'\b(show|list|afficher|lister)\s+(enabled?|disabled?|active|deny\w*|accept\w*)\s+polic\w*\b',
        re.I,
    ),
    # show existing/current addresses/policies
    re.compile(
        r'\b(show|list|afficher)\s+(existing|current|all|les?|tous?|toutes?)\s+(addresses?|polic\w*|rules?|interfaces?|adresses?)\b',
        re.I,
    ),
    # what addresses/policies do I have
    re.compile(
        r'\bwhat\s+(addresses?|adresses?|policies|polic\w*|rules?|r[eè]gles?)\s+(do\s+)?(i\s+)?(have|exist|sont|avez|ai)\b',
        re.I,
    ),
    # show blocked IPs
    re.compile(
        r'\b(show|list|afficher)\s+(blocked\w*|block\w*|bloqu[eé]\w*)\s*(ips?|addresses?|hosts?|adresses?)?\b',
        re.I,
    ),
    # French: "quelles sont les politiques"
    re.compile(
        r'\b(quelles?\s+sont\s+(les?\s+)?(politiques?|r[eè]gles?|interfaces?|adresses?))\b',
        re.I,
    ),
    # "tell me about policy X"
    re.compile(
        r'\btell\s+me\s+(about|what\s+you\s+know\s+about)\s+(policy|polic\w*|rule)\s+\S+\b',
        re.I,
    ),
    # "describe policy X"
    re.compile(
        r'\bdescribe\s+(policy|polic\w*|rule)\s+\S+\b',
        re.I,
    ),
    # "info on policy X"
    re.compile(
        r'\binfo\s+(on|about|for|de)\s+(policy|polic\w*|rule)\s+\S+\b',
        re.I,
    ),
    # French: "montre-moi la politique X" / "affiche la règle X"
    re.compile(
        r'\b(montre.?moi|affiche|donne.?moi)\s+(la\s+|cette\s+)?(politique|r[eè]gle)\s+\S+\b',
        re.I,
    ),
]

# ── Knowledge — documentation questions ───────────────────
# Must NOT match live entity queries. _LIVE_ENTITY_INDICATORS
# is checked before returning KNOWLEDGE for any of these.
_KNOWLEDGE_STARTERS = [
    re.compile(r'\bhow\s+(do|does|to|can|should|would|could)\b', re.I),
    re.compile(
        r'\bwhat\s+is\s+(a\s+)?(vlan|vxlan|ospf|bgp|ipsec|ssl\s+vpn|nat|acl|utm|ha|vdom|sdwan|zt\w*)\b',
        re.I,
    ),
    re.compile(r'\berror\s*-?\d+\b', re.I),
    re.compile(r'\bwhat\s+does\s+error\b', re.I),
    re.compile(r'\bbest\s+practices?\b', re.I),
    re.compile(r'\bhow\s+to\s+(configure|setup|enable|disable|create|deploy)\b', re.I),
    re.compile(r'\bexplain\s+(the\s+)?(concept|feature|setting|option|term)\b', re.I),
    re.compile(r'\btroubleshoot\b', re.I),
    re.compile(r'\bdiagnose\b', re.I),
    re.compile(r'\bdifference\s+between\b', re.I),
    re.compile(r'\bwhat\s+(command|cli\s+command)\b', re.I),
    re.compile(r'\bin\s+(the\s+)?cli\b', re.I),
    re.compile(r'\bcommand\s+(to|for|that)\b', re.I),
    re.compile(r'\bqu.est.ce\s+qu.est\s+(un|une|le|la)\b', re.I),
    re.compile(r'\bcomment\s+(configurer|cr[eé]er|faire|mettre\s+en\s+place)\b', re.I),
    re.compile(r'\bpourquoi\s+(est.?ce\s+que|faut.?il|dois.?je)\b', re.I),
    re.compile(r'\bexpliquer?\s+(le|la|les|ce|cette)\b', re.I),
    re.compile(r'\bdocumentation\b', re.I),
    re.compile(r'\bmanual\b|\bguide\b', re.I),
    re.compile(r'\bwhat\s+(is\s+meant\s+by|does\s+it\s+mean)\b', re.I),
    re.compile(r'\bsignification\b|\bmeaning\b', re.I),
    re.compile(r'\b(cli\s+command|command\s+line|fortigate\s+cli|using\s+(the\s+)?cli)\b', re.I),
    re.compile(r'\bwhat\s+(command|cli)\b', re.I),
    re.compile(r'\bhow\s+do\s+i\s+(know|check|see|find|show|verify|get)\b', re.I),
    re.compile(r'\bwhat\s+is\s+the\s+cli\b', re.I),
    re.compile(r'\bcommande\s+cli\b', re.I),
    re.compile(r'\bhow\s+to\s+(check|view|show|see|find|verify)\b', re.I),
]

# Entity indicators: the presence of these patterns in the text
# means the query is about a LIVE entity on this FortiGate,
# not a documentation concept.
# Used to override knowledge classification when an entity is referenced.
_LIVE_ENTITY_INDICATORS = re.compile(
    r'\b('
    r'policy\s+\d+'
    r'|policy\s+(?!in\b|on\b|for\b|with\b|and\b|or\b|using\b|via\b|through\b|from\b|by\b|a\b|the\b|to\b|that\b|which\b|is\b|are\b|can\b|will\b|should\b|must\b|has\b|have\b|had\b)[A-Za-z][A-Za-z0-9_\-]+'
    r'|rule\s+\d+'
    r'|rule\s+(?!in\b|on\b|for\b|with\b|and\b|or\b|using\b|via\b|through\b|from\b|by\b|a\b|the\b|to\b|that\b|which\b|is\b|are\b)[A-Za-z][A-Za-z0-9_\-]+'
    r'|interface\s+\w+'
    r'|address\s+\w+'
    r'|port\d+'
    r'|wan\d*'
    r'|lan\d*'
    r'|dmz\d*'
    r'|r[eè]gle\s+\S+'
    r'|la\s+(politique|r[eè]gle)\s+\w+'
    r'|le\s+(pare.?feu|firewall)\s+\w+'
    r')\b',
    re.I,
)


def _classify_deterministic(text: str) -> Optional[RouteResult]:
    """
    Stage 1: fast deterministic classification.
    Returns RouteResult or None (caller proceeds to LLM stage).
    """
    t = text.strip()

    for p in _CONVERSATIONAL_PATTERNS:
        if p.search(t):
            return RouteResult(RouteCategory.CONVERSATIONAL, "certain", "deterministic")

    for p in _SECURITY_ANALYSIS_PATTERNS:
        if p.search(t):
            return RouteResult(RouteCategory.SECURITY_ANALYSIS, "certain", "deterministic")

    # Knowledge questions — only when NO live entity is referenced
    # Checked before write patterns so 'how can I create a policy' routes to knowledge instead of failing as an action
    for p in _KNOWLEDGE_STARTERS:
        if p.search(t):
            if _LIVE_ENTITY_INDICATORS.search(t):
                # Has knowledge phrasing but references a live entity
                return RouteResult(
                    RouteCategory.LIVE_READ,
                    "high",
                    "deterministic",
                    hint="entity_query",
                )
            return RouteResult(RouteCategory.KNOWLEDGE, "high", "deterministic")

    # Write patterns
    for p in _WRITE_ACTION_PATTERNS:
        if p.search(t):
            return RouteResult(RouteCategory.WRITE_ACTION, "high", "deterministic")

    # Live reads
    for p in _LIVE_READ_PATTERNS:
        if p.search(t):
            return RouteResult(RouteCategory.LIVE_READ, "high", "deterministic")

    return None


# ══════════════════════════════════════════════════════════
#  Stage 2: LLM semantic classification
# ══════════════════════════════════════════════════════════

_ROUTER_SYSTEM_PROMPT = """You are the routing layer of a FortiGate firewall management agent.
Classify the user input into exactly one category.

OUTPUT: a single JSON object with exactly two keys:
  "category": one of the category strings listed below
  "hint": a short phrase describing what the user wants (max 8 words)

CATEGORIES:
  "conversational"    — greeting, capability question, small talk
  "live_read"         — asking about current FortiGate state:
                        list policies/interfaces/addresses/routes/services,
                        show details of a specific policy by name or ID,
                        what does policy X do, is NAT enabled, what services does X have,
                        check CPU/memory/VPN/sessions/system status,
                        what does policy X block/allow/contain
  "security_analysis" — audit, analyze, check security, find risks, review config
  "knowledge"         — how-to questions, error codes, CLI syntax, best practices,
                        general FortiGate documentation (NOT about current live state)
  "write_action"      — create, update, delete, move, enable, disable, block, backup
  "unknown"           — cannot determine with reasonable confidence

CLASSIFICATION RULES (in priority order):
1. If the user asks about the CURRENT STATE of this specific firewall
   (what policies exist, what does policy X do, is X enabled) → live_read
2. If the user asks HOW TO do something, what a TERM means, or wants documentation → knowledge
3. If the user asks to CHANGE something on the firewall → write_action
4. If the user asks to ANALYZE or AUDIT the firewall → security_analysis
5. "What does policy X do/allow/block/contain" where X is a name or ID → live_read (NOT knowledge)
6. When ambiguous between live_read and knowledge: if a specific policy name or ID
   is mentioned, choose live_read.

EXAMPLES:
  "what does policy BlockSSH do" → {"category": "live_read", "hint": "show details of policy BlockSSH"}
  "what does policy 4 allow" → {"category": "live_read", "hint": "show details of policy 4"}
  "how do I configure NAT" → {"category": "knowledge", "hint": "NAT configuration documentation"}
  "add SSH to policy 4" → {"category": "write_action", "hint": "add service SSH to policy 4"}
  "is NAT enabled in policy test1" → {"category": "live_read", "hint": "check NAT status of policy test1"}
  "list all policies" → {"category": "live_read", "hint": "list all firewall policies"}
  "analyze my firewall" → {"category": "security_analysis", "hint": "full security audit"}
  "hi" → {"category": "conversational", "hint": "greeting"}

Output only the JSON object. No explanation. No markdown."""


def _classify_llm(
    text: str,
    llm_plain: object,
    session_hint: str = "",
) -> RouteResult:
    """
    Stage 2: LLM semantic classification for inputs that didn't match
    deterministic patterns. Uses session_hint for context-aware classification.
    """
    context_line = (
        f"\nSession context: {session_hint}\n" if session_hint else ""
    )

    try:
        import time
        retries = 3
        response = None
        for attempt in range(retries):
            try:
                response = llm_plain.invoke([
                    SystemMessage(content=_ROUTER_SYSTEM_PROMPT),
                    HumanMessage(content=f'Classify this input: "{text}"{context_line}'),
                ])
                break
            except Exception as exc:
                s = str(exc).lower()
                recoverable = any(
                    k in s
                    for k in ("429", "rate_limit", "timeout", "timed out",
                               "503", "502", "unreachable")
                )
                if recoverable and attempt < retries - 1:
                    wait = 3 * (attempt + 1)
                    logger.warning(
                        f'"event":"router_llm_retry","attempt":{attempt + 1},'
                        f'"wait":{wait},"error":"{exc}"'
                    )
                    time.sleep(wait)
                else:
                    raise

        raw = response.content.strip()
        raw = re.sub(r"```(?:json)?\s*", "", raw)
        raw = re.sub(r"```\s*", "", raw).strip()

        data     = json.loads(raw)
        cat_str  = str(data.get("category", "unknown")).lower().strip()
        hint     = str(data.get("hint", ""))

        try:
            category = RouteCategory(cat_str)
        except ValueError:
            category = RouteCategory.UNKNOWN

        logger.debug(
            f'"event":"router_llm",'
            f'"category":"{category.value}",'
            f'"hint":"{hint}",'
            f'"input":"{text[:80]}"'
        )
        return RouteResult(category, "medium", "llm", hint=hint)

    except Exception as exc:
        logger.warning(f'"event":"router_llm_fail","error":"{exc}"')
        return RouteResult(RouteCategory.UNKNOWN, "low", "llm")


# ══════════════════════════════════════════════════════════
#  Public router
# ══════════════════════════════════════════════════════════

def route(
    text:                  str,
    llm_plain:             object,
    pending_clarification: bool = False,
    session_hint:          str  = "",
) -> RouteResult:
    """
    Classify user input into a routing category.

    Args:
        text:                  Raw user input.
        llm_plain:             Plain LLM (no tools) for stage-2 classification.
        pending_clarification: True if the session is awaiting a clarification reply.
                               Short non-command inputs are classified as CLARIFICATION.
        session_hint:          One-line string describing the active session topic.
                               Injected into the LLM stage-2 prompt for context-awareness.
                               Example: "User was examining policy 'test1'."

    Returns:
        RouteResult with category, confidence, source, and optional hint.
    """
    if not text or not text.strip():
        return RouteResult(RouteCategory.UNKNOWN, "certain", "deterministic")

    # If awaiting clarification, short answers that aren't new commands are
    # classified as CLARIFICATION so the completion loop fires.
    if pending_clarification:
        t = text.strip()
        looks_like_new_command = any(
            p.search(t)
            for p in [*_WRITE_ACTION_PATTERNS, *_LIVE_READ_PATTERNS]
        )
        if not looks_like_new_command and len(t.split()) <= 12:
            return RouteResult(
                RouteCategory.CLARIFICATION, "high", "deterministic"
            )

    # Stage 1: deterministic
    result = _classify_deterministic(text)
    if result is not None:
        logger.debug(
            f'"event":"router_deterministic",'
            f'"category":"{result.category.value}",'
            f'"confidence":"{result.confidence}",'
            f'"input":"{text[:80]}"'
        )
        return result

    # Stage 2: LLM with session context
    return _classify_llm(text, llm_plain, session_hint)