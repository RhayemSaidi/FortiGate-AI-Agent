"""
intent_parser.py — Intent data model for the execution layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from enum import Enum
from typing import List, Optional




class FieldOp(Enum):
    ADD     = "add"
    REMOVE  = "remove"
    REPLACE = "replace"
    SET     = "set"


# ── Field categories used by executor/verifier ───────────────────────────────
#
# LIST_FIELDS: policy fields that hold a list of {name: ...} objects.
#   item_key — the key inside each list item that holds the value.
#
# SCALAR_FIELDS: policy fields that hold a single string value.
#   values — allowed values (empty list means no restriction enforced here).
#
# Both structures are dicts so executor and verifier can do:
#   LIST_FIELDS[field]["item_key"]
#   SCALAR_FIELDS[field]["values"]

LIST_FIELDS: dict = {
    "service":  {"item_key": "name"},
    "srcaddr":  {"item_key": "name"},
    "dstaddr":  {"item_key": "name"},
    "srcintf":  {"item_key": "name"},
    "dstintf":  {"item_key": "name"},
}

SCALAR_FIELDS: dict = {
    "action":      {"values": ["accept", "deny"]},
    "nat":         {"values": ["enable", "disable"]},
    "status":      {"values": ["enable", "disable"]},
    "logtraffic":  {"values": ["all", "utm", "disable"]},
}

@dataclass
class FieldDelta:
    field_name: str
    op:         FieldOp
    values:     List[str] = dc_field(default_factory=list)
    scalar:     str       = ""

    def describe(self) -> str:
        if self.op == FieldOp.ADD:
            return f"  ADD to {self.field_name}     : {', '.join(self.values)}"
        if self.op == FieldOp.REMOVE:
            return f"  REMOVE from {self.field_name}: {', '.join(self.values)}"
        if self.op == FieldOp.REPLACE:
            return f"  SET {self.field_name} to      : {', '.join(self.values)}"
        if self.op == FieldOp.SET:
            return f"  SET {self.field_name}          : {self.scalar}"
        return f"  {self.op.value} {self.field_name}"


@dataclass
class UpdateIntent:
    """
    Single-policy update intent.
    Consumed directly by PolicyUpdateExecutor.execute().
    Contract is STABLE — do not change.
    """
    policy_id: int
    deltas:    List[FieldDelta]
    raw_input: str

    def describe(self) -> str:
        return "\n".join(d.describe() for d in self.deltas)


@dataclass
class BatchUpdateResult:
    """Per-policy result within a batch update."""
    policy_id:     int
    policy_name:   str
    success:       bool
    message:       str
    verified:      bool            = False
    verify_detail: List[str]       = dc_field(default_factory=list)


@dataclass
class BatchUpdateIntent:
    """
    Multi-policy update intent.

    Contains N individual UpdateIntent objects (one per target policy)
    each with the same set of FieldDelta operations.

    Invariants:
    - len(intents) >= 2 (single → UpdateIntent)
    - All intents share the same deltas
    - PolicyUpdateExecutor.execute() called for each intent independently
    """
    intents:     List[UpdateIntent]
    raw_input:   str
    shared_desc: str = ""

    @property
    def policy_ids(self) -> List[int]:
        return [i.policy_id for i in self.intents]

    def describe_targets(self) -> str:
        return ", ".join(f"ID:{i.policy_id}" for i in self.intents)

    def describe_deltas(self) -> str:
        if self.intents:
            return self.intents[0].describe()
        return ""