"""
intent.py — Operation intent types for update operations.

The core insight: every update is one of:
  ADD     — add items to a list field (services, source addresses)
  REMOVE  — remove items from a list field
  REPLACE — set a list field to exactly these items
  SET     — set a scalar field (action, status, name)

This classification drives the read-modify-write logic in executor.py.
"""
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class FieldOp(Enum):
    ADD     = "add"
    REMOVE  = "remove"
    REPLACE = "replace"
    SET     = "set"


@dataclass
class FieldDelta:
    """
    Describes a single field change in a policy update.
    """
    field_name: str          # FortiGate API field name: "service", "action", "status"
    op:         FieldOp
    values:     list = field(default_factory=list)  # For list fields
    scalar:     str  = ""                           # For scalar fields


@dataclass
class UpdateIntent:
    """
    Fully classified update intent extracted from user input.
    Drives read-modify-write execution.
    """
    policy_id: int
    deltas:    list  # List[FieldDelta]
    raw_input: str   # Original user text — kept for audit

    def has_list_ops(self) -> bool:
        return any(d.op in (FieldOp.ADD, FieldOp.REMOVE) for d in self.deltas)


# FortiGate list fields that require full replacement (no PATCH endpoint)
LIST_FIELDS = {
    "service":  {"api_key": "service",  "item_key": "name"},
    "srcaddr":  {"api_key": "srcaddr",  "item_key": "name"},
    "dstaddr":  {"api_key": "dstaddr",  "item_key": "name"},
    "srcintf":  {"api_key": "srcintf",  "item_key": "name"},
    "dstintf":  {"api_key": "dstintf",  "item_key": "name"},
}

# Scalar fields — direct replacement
SCALAR_FIELDS = {"action", "status", "name", "schedule", "logtraffic", "nat"}