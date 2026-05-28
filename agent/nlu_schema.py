"""
nlu_schema.py — Typed schema contracts for the NLU layer.

raw_input is INTERNAL METADATA — set by Python, never by Mistral.
It must never appear in missing_fields.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional


class NLUIntentType(Enum):
    UPDATE_POLICY         = "update_policy"
    CREATE_POLICY         = "create_policy"
    DELETE_POLICY         = "delete_policy"
    ENABLE_POLICY         = "enable_policy"
    DISABLE_POLICY        = "disable_policy"
    MOVE_POLICY           = "move_policy"
    CREATE_ADDRESS        = "create_address"
    DELETE_ADDRESS        = "delete_address"
    UPDATE_INTERFACE      = "update_interface"
    SET_INTERFACE_STATUS  = "set_interface_status"
    CREATE_ROUTE          = "create_route"
    DELETE_ROUTE          = "delete_route"
    CREATE_SERVICE        = "create_service"
    DELETE_SERVICE        = "delete_service"
    CREATE_USER           = "create_user"
    DELETE_USER           = "delete_user"
    BLOCK_IP              = "block_ip"
    BACKUP_CONFIG         = "backup_config"
    REBOOT_SYSTEM         = "reboot_system"
    AMBIGUOUS             = "ambiguous"
    INCOMPLETE            = "incomplete"


class NLUConfidence(Enum):
    HIGH      = "high"
    MEDIUM    = "medium"
    LOW       = "low"
    AMBIGUOUS = "ambiguous"


@dataclass
class NLUDelta:
    """One field change within an update operation."""
    field:      str
    op:         str    # set | add | remove | replace
    value:      Any    # str for scalars, List[str] for lists
    confidence: str    # high | medium | low


# Fields that are internal metadata — must NEVER appear in missing_fields.
INTERNAL_SCHEMA_FIELDS = frozenset({
    "raw_input",
    "confidence",
    "ambiguous",
    "ambiguity_msg",
    "candidates",
    "is_multi_policy",
})


@dataclass
class RawIntentSchema:
    """
    What Mistral produces. Untrusted until grounded.

    Multi-policy fields (policy_ids, policy_names, is_multi_policy) are used
    when the user targets multiple policies in one request.

    raw_input is ALWAYS set from the Python caller, never from Mistral output.
    """
    intent:          NLUIntentType
    confidence:      NLUConfidence

    # ── Single-policy (default) ────────────────────────────
    policy_id:       Optional[int]   = None
    policy_name:     Optional[str]   = None

    # ── Multi-policy ───────────────────────────────────────
    policy_ids:      List[int]       = field(default_factory=list)
    policy_names:    List[str]       = field(default_factory=list)
    is_multi_policy: bool            = False

    # ── Other entity references ────────────────────────────
    address_name:    Optional[str]   = None
    interface_name:  Optional[str]   = None
    neighbor_id:     Optional[int]   = None
    move_action:     Optional[str]   = None
    ip_address:      Optional[str]   = None
    direction:       Optional[str]   = None

    # ── Update deltas ──────────────────────────────────────
    deltas:          List[NLUDelta]  = field(default_factory=list)

    # ── Create params ──────────────────────────────────────
    create_params:   dict            = field(default_factory=dict)

    # ── Ambiguity ──────────────────────────────────────────
    ambiguous:       bool            = False
    ambiguity_msg:   str             = ""
    candidates:      List[dict]      = field(default_factory=list)

    # ── Missing fields (user-actionable only) ──────────────
    missing_fields:  List[str]       = field(default_factory=list)

    # ── Internal metadata — set by Python, never by Mistral ─
    raw_input:       str             = ""

    # ── Conditional filter — set by NLU, evaluated deterministically ──
    # e.g. {"field": "service", "op": "not_contains", "value": "SSH"}
    # Supported ops: "contains", "not_contains", "eq", "neq"
    # When present and policy_ids is empty, grounder applies this filter
    # against all live policies to resolve the target set.
    policy_filter:   Optional[dict]  = None