"""
session_context.py — Session and conversational context model.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("fortigate_agent")

ENTITY_TTL_TURNS = 6
ENTITY_STACK_MAX = 5


class TopicKind(Enum):
    NONE              = "none"
    POLICY_FOCUS      = "policy_focus"
    SECURITY_ANALYSIS = "security_analysis"
    INTERFACE_FOCUS   = "interface_focus"
    ADDRESS_FOCUS     = "address_focus"
    GENERAL_READ      = "general_read"


class EntityKind(Enum):
    POLICY    = "policy"
    ADDRESS   = "address"
    INTERFACE = "interface"
    SERVICE   = "service"
    IP        = "ip"


@dataclass
class TrackedEntity:
    kind:       EntityKind
    ref_id:     Optional[int]
    name:       str
    turn_seen:  int
    confidence: float = 1.0


@dataclass
class EntityMemory:
    _stack: List[TrackedEntity] = field(default_factory=list)

    def push(self, entity: TrackedEntity) -> None:
        self._stack = [
            e for e in self._stack
            if not (
                e.kind == entity.kind
                and (
                    e.ref_id == entity.ref_id
                    if entity.ref_id is not None
                    else e.name == entity.name
                )
            )
        ]
        self._stack.append(entity)
        if len(self._stack) > ENTITY_STACK_MAX:
            self._stack = self._stack[-ENTITY_STACK_MAX:]

    def resolve_latest(
        self,
        kind:         EntityKind,
        current_turn: int,
    ) -> Optional[TrackedEntity]:
        candidates = [
            e for e in reversed(self._stack)
            if e.kind == kind
            and (current_turn - e.turn_seen) <= ENTITY_TTL_TURNS
        ]
        if not candidates:
            return None
        if (
            len(candidates) >= 2
            and candidates[0].turn_seen == candidates[1].turn_seen
        ):
            return None  # Ambiguous — two entities at same recency
        return candidates[0]

    def all_active(self, current_turn: int) -> List[TrackedEntity]:
        return [
            e for e in self._stack
            if (current_turn - e.turn_seen) <= ENTITY_TTL_TURNS
        ]

    def expire_old(self, current_turn: int) -> None:
        self._stack = [
            e for e in self._stack
            if (current_turn - e.turn_seen) <= ENTITY_TTL_TURNS
        ]

    def record_policy(self, policy_id: int, name: str, turn: int) -> None:
        self.push(TrackedEntity(
            kind=EntityKind.POLICY, ref_id=policy_id,
            name=name, turn_seen=turn,
        ))

    def record_address(self, name: str, turn: int) -> None:
        self.push(TrackedEntity(
            kind=EntityKind.ADDRESS, ref_id=None,
            name=name, turn_seen=turn,
        ))

    def record_interface(self, name: str, turn: int) -> None:
        self.push(TrackedEntity(
            kind=EntityKind.INTERFACE, ref_id=None,
            name=name, turn_seen=turn,
        ))


# ── Ownership helpers ─────────────────────────────────────────────────────────

_SYSTEM_ADDRESS_EXACT = {
    "all", "none", "FABRIC_DEVICE", "FIREWALL_AUTH_PORTAL_ADDRESS",
}

_SYSTEM_ADDRESS_PREFIXES = (
    "FABRIC_", "FIREWALL_AUTH_PORTAL_", "SSLVPN_TUNNEL_ADDR",
)


def classify_address_ownership(name: str, session_created: set) -> str:
    """Returns 'user_session' | 'system' | 'unknown'"""
    if name in session_created:
        return "user_session"
    if name in _SYSTEM_ADDRESS_EXACT:
        return "system"
    if any(name.startswith(p) for p in _SYSTEM_ADDRESS_PREFIXES):
        return "system"
    return "unknown"


# ── Clarification intent ──────────────────────────────────────────────────────

@dataclass
class PendingIncompleteIntent:
    original_input:   str
    missing_fields:   List[str]
    collected_fields: Dict[str, Any]
    intent_type:      str
    policy_id:        Optional[int] = None
    policy_name:      Optional[str] = None
    turn_set:         int           = 0


# ── SessionContext ────────────────────────────────────────────────────────────

@dataclass
class SessionContext:
    """
    Per-session conversational state.
    Used ONLY for routing disambiguation and conversational continuity.
    NEVER used for execution decisions.
    """

    # Topic
    active_topic:        TopicKind    = TopicKind.NONE

    # Entity focus (primary)
    focused_policy_id:   Optional[int] = None
    focused_policy_name: Optional[str] = None
    focused_interface:   Optional[str] = None
    focused_address:     Optional[str] = None

    # Entity memory
    entity_memory: EntityMemory = field(default_factory=EntityMemory)

    # Security analysis context
    last_analysis_summary: Optional[str] = None

    # Last write
    last_write_tool:   Optional[str] = None
    last_write_target: Optional[str] = None

    # Clarification
    pending_clarification:        bool = False
    clarification_question:       str  = ""
    clarification_expected_field: str  = ""
    pending_incomplete:           Optional[PendingIncompleteIntent] = None

    # Ownership registry (this session only)
    session_created_addresses: Set[str] = field(default_factory=set)
    session_created_policies:  Set[str] = field(default_factory=set)

    # Turn counter
    turn_count: int = 0

    # ── Topic setters ──────────────────────────────────────

    def set_policy_focus(
        self,
        policy_id:   Optional[int],
        policy_name: Optional[str] = None,
    ) -> None:
        self.active_topic        = TopicKind.POLICY_FOCUS
        self.focused_policy_id   = policy_id
        self.focused_policy_name = policy_name
        if policy_id is not None:
            self.entity_memory.record_policy(
                policy_id,
                policy_name or f"ID:{policy_id}",
                self.turn_count,
            )

    def set_security_analysis(self, summary: Optional[str] = None) -> None:
        self.active_topic          = TopicKind.SECURITY_ANALYSIS
        self.last_analysis_summary = summary

    def set_interface_focus(self, name: str) -> None:
        self.active_topic      = TopicKind.INTERFACE_FOCUS
        self.focused_interface = name
        self.entity_memory.record_interface(name, self.turn_count)

    def set_address_focus(self, name: str) -> None:
        self.active_topic    = TopicKind.ADDRESS_FOCUS
        self.focused_address = name
        self.entity_memory.record_address(name, self.turn_count)

    def record_write(self, tool_name: str, target: str) -> None:
        self.last_write_tool   = tool_name
        self.last_write_target = target

    def record_policy_created(self, name: str, policy_id: int) -> None:
        self.session_created_policies.add(name)
        self.entity_memory.record_policy(policy_id, name, self.turn_count)

    def record_address_created(self, name: str) -> None:
        self.session_created_addresses.add(name)
        self.entity_memory.record_address(name, self.turn_count)

    # ── Entity resolution ──────────────────────────────────

    def resolve_pronoun_policy(self) -> Optional[TrackedEntity]:
        return self.entity_memory.resolve_latest(
            EntityKind.POLICY, self.turn_count
        )

    def resolve_pronoun_address(self) -> Optional[TrackedEntity]:
        return self.entity_memory.resolve_latest(
            EntityKind.ADDRESS, self.turn_count
        )

    def record_entity_seen(
        self,
        kind:   EntityKind,
        ref_id: Optional[int],
        name:   str,
    ) -> None:
        self.entity_memory.push(TrackedEntity(
            kind=kind, ref_id=ref_id,
            name=name, turn_seen=self.turn_count,
        ))

    def get_active_entities_hint(self) -> str:
        active = self.entity_memory.all_active(self.turn_count)
        if not active:
            return ""
        parts = []
        for e in reversed(active[-3:]):
            if e.kind == EntityKind.POLICY:
                parts.append(f"policy '{e.name}' (ID:{e.ref_id})")
            elif e.kind == EntityKind.ADDRESS:
                parts.append(f"address '{e.name}'")
            elif e.kind == EntityKind.INTERFACE:
                parts.append(f"interface '{e.name}'")
        return "Recently referenced: " + ", ".join(parts)

    # ── Clarification lifecycle ────────────────────────────

    def ask_clarification(self, question: str, expected_field: str = "") -> None:
        self.pending_clarification        = True
        self.clarification_question       = question
        self.clarification_expected_field = expected_field

    def clear_clarification(self) -> None:
        self.pending_clarification        = False
        self.clarification_question       = ""
        self.clarification_expected_field = ""

    def set_incomplete_intent(
        self,
        original_input: str,
        missing_fields: List[str],
        collected:      Dict[str, Any],
        intent_type:    str,
        policy_id:      Optional[int] = None,
        policy_name:    Optional[str] = None,
    ) -> None:
        self.pending_incomplete = PendingIncompleteIntent(
            original_input=original_input,
            missing_fields=missing_fields,
            collected_fields=collected,
            intent_type=intent_type,
            policy_id=policy_id,
            policy_name=policy_name,
            turn_set=self.turn_count,
        )
        self.pending_clarification        = True
        self.clarification_expected_field = missing_fields[0] if missing_fields else ""
        self.clarification_question       = (
            f"To complete '{original_input[:60]}', I still need: "
            + ", ".join(missing_fields[:2])
        )

    def clear_incomplete_intent(self) -> None:
        self.pending_incomplete = None
        self.clear_clarification()

    def is_incomplete_expired(self, max_turns: int = 3) -> bool:
        if not self.pending_incomplete:
            return False
        return (self.turn_count - self.pending_incomplete.turn_set) >= max_turns

    def is_semantically_compatible_reply(self, user_input: str) -> bool:
        """
        Returns True only when user_input is a plausible answer to the
        stored clarification question. Conservative: defaults to False.
        """
        if not self.pending_incomplete:
            return False

        tokens = user_input.lower().strip().split()
        if len(tokens) > 8:
            return False

        _INDEPENDENT_VERBS = {
            "show", "list", "display", "get", "check", "find", "search",
            "analyze", "analyse", "audit", "create", "delete", "remove",
            "add", "update", "modify", "enable", "disable", "block",
            "backup", "move", "afficher", "lister", "voir", "analyser",
            "créer", "supprimer", "ajouter", "modifier", "activer",
            "désactiver", "bloquer", "sauvegarder", "déplacer",
        }
        if any(t in _INDEPENDENT_VERBS for t in tokens):
            return False

        field   = self.clarification_expected_field
        stripped = user_input.strip()

        _INTF = re.compile(
            r'^(port|wan|lan|dmz|mgmt|internal|external|loopback|vlan)\w*$', re.I
        )
        _PID  = re.compile(r'^\d+$')
        _PNAM = re.compile(r'^[A-Za-z][A-Za-z0-9_\-]+$')
        _KNOWN_ACTIONS  = {"deny", "accept", "block", "allow", "drop", "permit"}
        _KNOWN_SERVICES = {
            "ssh", "https", "http", "ftp", "dns", "rdp", "smtp",
            "smtps", "pop3", "imap", "ping", "icmp", "snmp", "all",
        }

        if field in ("srcintf", "dstintf", "interface_name"):
            return bool(_INTF.match(stripped))
        if field in ("policy_id", "neighbor_id"):
            return bool(_PID.match(stripped)) or (
                bool(_PNAM.match(stripped)) and len(tokens) == 1
            )
        if field == "action":
            return stripped.lower() in _KNOWN_ACTIONS
        if field == "service":
            return any(s in user_input.lower() for s in _KNOWN_SERVICES)
        if field == "name":
            return len(tokens) == 1 and _PNAM.match(stripped) is not None
        if field == "subnet":
            return bool(re.match(
                r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', stripped
            ))
        if field == "move_action":
            return stripped.lower() in ("before", "after", "avant", "après")

        return len(tokens) <= 4

    # ── Helpers ────────────────────────────────────────────

    def advance_turn(self) -> None:
        self.turn_count += 1
        self.entity_memory.expire_old(self.turn_count)

    def has_policy_focus(self) -> bool:
        return (
            self.active_topic == TopicKind.POLICY_FOCUS
            and (
                self.focused_policy_id is not None
                or self.focused_policy_name is not None
            )
        )

    def has_security_context(self) -> bool:
        return self.active_topic == TopicKind.SECURITY_ANALYSIS

    def build_hint(self) -> str:
        if self.active_topic == TopicKind.SECURITY_ANALYSIS:
            return "User recently ran a firewall security analysis."
        if self.active_topic == TopicKind.POLICY_FOCUS and self.focused_policy_id:
            name = self.focused_policy_name or f"ID:{self.focused_policy_id}"
            return f"User was examining policy '{name}'."
        if self.active_topic == TopicKind.INTERFACE_FOCUS and self.focused_interface:
            return f"User was examining interface '{self.focused_interface}'."
        return ""