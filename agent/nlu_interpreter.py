from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# ── Path setup ────────────────────────────────────────────────────────────────
_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.dirname(_AGENT_DIR)

if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

logger = logging.getLogger("fortigate_agent")

# ── Schema imports ────────────────────────────────────────────────────────────
from nlu_schema import (
    RawIntentSchema,
    NLUIntentType,
    NLUConfidence,
    NLUDelta,
    INTERNAL_SCHEMA_FIELDS,
)

# ── System prompt ─────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """You are the NLU layer of a FortiGate firewall management agent.
Your ONLY job: interpret user intent and output structured JSON.
You do NOT execute API calls. You do NOT verify state. You ONLY interpret.

═══════════════════════════════════════════════════════════
REQUIRED JSON SCHEMA  (every response MUST follow this exactly)
═══════════════════════════════════════════════════════════
{
  "intent":        "<REQUIRED — one of the intent values listed below>",
  "confidence":    "high" | "medium" | "low",
  "policy_id":     <integer or null>,
  "policy_name":   "<string or null>",
  "policy_ids":    [<list of integers, only for multi-policy>],
  "policy_names":  ["<list of strings, only for multi-policy>"],
  "is_multi_policy": false,
  "address_name":  "<string or null>",
  "interface_name":"<string or null>",
  "neighbor_id":   <integer or null>,
  "move_action":   "before" | "after" | null,
  "ip_address":    "<string or null>",
  "direction":     "inbound" | "outbound" | "both" | null,
  "deltas":        [],
  "create_params": {},
  "ambiguous":     false,
  "ambiguity_msg": "",
  "candidates":    [],
  "missing_fields":[]
}

═══════════════════════════════════════════════════════════
VALID INTENT VALUES  (use exactly these strings)
═══════════════════════════════════════════════════════════
  update_policy        — modify fields of an existing policy (service, action, nat, status, logtraffic)
  create_policy        — create a new firewall policy
  delete_policy        — permanently delete a policy
  enable_policy        — enable (activate) an existing policy
  disable_policy       — disable (deactivate) an existing policy
  move_policy          — reorder a policy (before/after another policy)
  create_address       — create an address object
  delete_address       — delete an address object
  update_interface     — change management access protocols on an interface
  set_interface_status — enable or disable an interface (up/down)
  create_route         — create a static route
  delete_route         — delete a static route
  create_service       — create a custom service
  delete_service       — delete a custom service
  create_user          — create a local user
  delete_user          — delete a local user
  block_ip             — block a specific IP address
  backup_config        — backup the FortiGate configuration
  ambiguous            — intent cannot be determined; set ambiguous=true and fill ambiguity_msg
  incomplete           — intent is clear but required fields are missing; fill missing_fields

═══════════════════════════════════════════════════════════
CRITICAL OUTPUT RULES
═══════════════════════════════════════════════════════════
1. Output ONLY a valid JSON object. No explanation. No markdown. No code blocks.
2. The "intent" field is MANDATORY in every response. Never omit it.
3. Use ONLY policy IDs and names from "Available policies". Never invent IDs.
4. Use ONLY service names from "Available services". Never invent service names.
5. Use ONLY interface names from "Available interfaces".
6. If uncertain about any entity: set it to null and list the field in missing_fields.
7. If intent is ambiguous: set intent="ambiguous", ambiguous=true, fill ambiguity_msg.
8. For enable/disable: use intent="enable_policy" or intent="disable_policy".
   NEVER use "enable_firewall_policy", "disable_firewall_policy", or any other variant.

EXAMPLE — disable a policy by name:
{"intent":"disable_policy","confidence":"high","policy_id":null,"policy_name":"test1",
 "policy_ids":[],"policy_names":[],"is_multi_policy":false,"address_name":null,
 "interface_name":null,"neighbor_id":null,"move_action":null,"ip_address":null,
 "direction":null,"deltas":[],"create_params":{},"ambiguous":false,
 "ambiguity_msg":"","candidates":[],"missing_fields":[]}

EXAMPLE — disable a policy by ID:
{"intent":"disable_policy","confidence":"high","policy_id":4,"policy_name":null,
 "policy_ids":[],"policy_names":[],"is_multi_policy":false,"address_name":null,
 "interface_name":null,"neighbor_id":null,"move_action":null,"ip_address":null,
 "direction":null,"deltas":[],"create_params":{},"ambiguous":false,
 "ambiguity_msg":"","candidates":[],"missing_fields":[]}

DELTA FORMAT (required for update_policy intent only)
═══════════════════════════════════════════════════════════
Each entry in "deltas" must be one of these exact structures:

  List field ops (field = "service", "srcaddr", "dstaddr", "srcintf", "dstintf"):
    {"field":"service","op":"add",    "values":["SSH","FTP"],"confidence":"high"}
    {"field":"service","op":"remove", "values":["HTTP"],    "confidence":"high"}
    {"field":"service","op":"replace","values":["HTTPS"],   "confidence":"high"}

  Scalar field ops (field = "action", "nat", "status", "logtraffic"):
    {"field":"action",    "op":"set","scalar":"deny",   "confidence":"high"}
    {"field":"nat",       "op":"set","scalar":"enable", "confidence":"high"}
    {"field":"status",    "op":"set","scalar":"disable","confidence":"high"}
    {"field":"logtraffic","op":"set","scalar":"all",    "confidence":"high"}

  Allowed scalar values:
    action     → "accept" | "deny"
    nat        → "enable" | "disable"
    status     → "enable" | "disable"
    logtraffic → "all" | "utm" | "disable"

EXAMPLE — add SSH to policy 4:
{"intent":"update_policy","confidence":"high","policy_id":4,"policy_name":null,
 "policy_ids":[],"policy_names":[],"is_multi_policy":false,"address_name":null,
 "interface_name":null,"neighbor_id":null,"move_action":null,"ip_address":null,
 "direction":null,"deltas":[{"field":"service","op":"add","values":["SSH"],"confidence":"high"}],
 "create_params":{},"ambiguous":false,"ambiguity_msg":"","candidates":[],"missing_fields":[]}

EXAMPLE — set policy 4 action to deny:
{"intent":"update_policy","confidence":"high","policy_id":4,"policy_name":null,
 "policy_ids":[],"policy_names":[],"is_multi_policy":false,"address_name":null,
 "interface_name":null,"neighbor_id":null,"move_action":null,"ip_address":null,
 "direction":null,"deltas":[{"field":"action","op":"set","scalar":"deny","confidence":"high"}],
 "create_params":{},"ambiguous":false,"ambiguity_msg":"","candidates":[],"missing_fields":[]}

EXAMPLE — move policy 4 before policy 3:
{"intent":"move_policy","confidence":"high","policy_id":4,"policy_name":null,
 "policy_ids":[],"policy_names":[],"is_multi_policy":false,"address_name":null,
 "interface_name":null,"neighbor_id":3,"move_action":"before","ip_address":null,
 "direction":null,"deltas":[],"create_params":{},"ambiguous":false,"ambiguity_msg":"","candidates":[],"missing_fields":[]}

CREATE_PARAMS FORMAT
═══════════════════════════════════════════════════════════
For these specific intents, you must put the extracted entity properties in "create_params":

  create_policy:    {"name": "...", "srcintf": "...", "dstintf": "...", "action": "...", "service": "..."}
  create_address:   {"subnet": "192.168.1.0/24"}
  create_route:     {"destination": "10.0.0.0/24", "gateway": "192.168.1.1", "device": "port1"}
  create_service:   {"name": "...", "protocol": "TCP|UDP", "port": "8080"}
  create_user:      {"name": "...", "password": "..."}
  update_interface: {"allowaccess": "https ssh ping"}
  set_interface_status: {"status": "up|down"}
  delete_service:   {"name": "..."}
  delete_user:      {"name": "..."}
  delete_route:     {"route_id": "..."}
"""

# ── Result wrapper ────────────────────────────────────────────────────────────

@dataclass
class NLUResult:
    """
    Wraps the outcome of interpret().
    Never raises — all failure modes captured here.

    IMPORTANT: 'failed' is a @property, not a dataclass field.
    Do not attempt to pass it as a constructor argument.

    Check .failed before accessing .schema.
    error_kind: "parse" | "api" | "schema" | "timeout"
    """
    schema:     Optional[RawIntentSchema]
    success:    bool
    error_kind: str = ""
    error_msg:  str = ""
    raw_output: str = ""

    @property
    def failed(self) -> bool:
        """True when NLU interpretation did not produce a usable schema."""
        return not self.success

    @classmethod
    def ok(cls, schema: "RawIntentSchema") -> "NLUResult":
        return cls(schema=schema, success=True)

    @classmethod
    def parse_error(cls, raw: str, cause: Exception) -> "NLUResult":
        return cls(
            schema=None, success=False,
            error_kind="parse", error_msg=str(cause), raw_output=raw,
        )

    @classmethod
    def api_error(cls, cause: Exception) -> "NLUResult":
        return cls(
            schema=None, success=False,
            error_kind="api", error_msg=str(cause),
        )

    @classmethod
    def schema_error(cls, raw: str, cause: Exception) -> "NLUResult":
        return cls(
            schema=None, success=False,
            error_kind="schema", error_msg=str(cause), raw_output=raw,
        )

    @classmethod
    def timeout_error(cls) -> "NLUResult":
        return cls(
            schema=None, success=False,
            error_kind="timeout", error_msg="Mistral API timed out",
        )

# ── Helpers ───────────────────────────────────────────────────────────────────

# Intent aliases: Mistral sometimes returns verbose variants not in NLUIntentType.
# Map them to canonical values BEFORE the enum lookup.
# Add new aliases here — never change the canonical enum values.
_INTENT_ALIASES: Dict[str, str] = {
    "disable_firewall_policy":  "disable_policy",
    "enable_firewall_policy":   "enable_policy",
    "create_firewall_policy":   "create_policy",
    "delete_firewall_policy":   "delete_policy",
    "update_firewall_policy":   "update_policy",
    "move_firewall_policy":     "move_policy",
    "firewall_policy_disable":  "disable_policy",
    "firewall_policy_enable":   "enable_policy",
    "policy_disable":           "disable_policy",
    "policy_enable":            "enable_policy",
    "block_ip_address":         "block_ip",
    "ip_block":                 "block_ip",
    "backup":                   "backup_config",
    "config_backup":            "backup_config",
    "interface_status":         "set_interface_status",
    "enable_interface":         "set_interface_status",
    "disable_interface":        "set_interface_status",
}


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _truncate_context(context: dict) -> dict:
    return {
        "policies": context.get("policies", [])[:50],
        "interfaces": context.get("interfaces", [])[:30],
        "services": context.get("services", [])[:100],
        "addresses": context.get("addresses", [])[:50],
    }


# ── Schema builder ────────────────────────────────────────────────────────────

def _build_schema(data: dict, raw_input: str) -> RawIntentSchema:
    """
    Convert normalised dict to RawIntentSchema.
    Handles multi-policy fields safely.
    """
    from agent_errors import NLUSchemaError

    intent_str = str(data.get("intent", "")).lower().strip()

    logger.debug(f'"event":"nlu_debug_build_schema_start","raw_data":{json.dumps(data)}')

    if not intent_str:
        raise NLUSchemaError(data, ["intent"])

    # Normalise Mistral variants before enum lookup.
    # e.g. "disable_firewall_policy" → "disable_policy"
    intent_str = _INTENT_ALIASES.get(intent_str, intent_str)

    try:
        intent = NLUIntentType(intent_str)

    except ValueError:
        # Secondary partial-match fallback — catches minor prefix/suffix drift.
        for member in NLUIntentType:
            if member.value in intent_str or intent_str in member.value:
                intent = member
                logger.debug(
                    f'"event":"intent_partial_match",'
                    f'"raw":"{intent_str}","matched":"{member.value}"'
                )
                break
        else:
            logger.warning(
                f'"event":"unknown_intent","value":"{intent_str}"'
            )
            intent = NLUIntentType.AMBIGUOUS

    conf_str = str(data.get("confidence", "low")).lower().strip()

    try:
        confidence = NLUConfidence(conf_str)
    except ValueError:
        confidence = NLUConfidence.LOW

    # ── Deltas ───────────────────────────────────────────

    deltas: List[NLUDelta] = []

    for d in data.get("deltas", []):

        if not isinstance(d, dict):
            continue

        if "value" in d:
            raw_value = d["value"]
        elif "values" in d:
            raw_value = d["values"]
        elif "scalar" in d:
            raw_value = d["scalar"]
        else:
            raw_value = ""

        if (
            d.get("field") == "service"
            and isinstance(raw_value, str)
            and "," in raw_value
        ):
            raw_value = [
                v.strip()
                for v in raw_value.split(",")
                if v.strip()
            ]

        try:
            delta_conf = NLUConfidence(
                str(d.get("confidence", "medium")).lower()
            )
        except ValueError:
            delta_conf = NLUConfidence.MEDIUM

        deltas.append(
            NLUDelta(
                field=str(d.get("field", "")),
                op=str(d.get("op", "set")),
                value=raw_value,
                confidence=delta_conf.value,
            )
        )
        logger.debug(f'"event":"nlu_debug_delta_parsed","raw_delta":{json.dumps(d)},"parsed_value":{json.dumps(raw_value)}')

    # ── Single-policy ────────────────────────────────────

    policy_id = data.get("policy_id")

    if policy_id is not None:
        try:
            policy_id = int(policy_id)
        except (TypeError, ValueError):
            policy_id = None

    # ── Multi-policy ─────────────────────────────────────

    raw_policy_ids = data.get("policy_ids") or []
    raw_policy_names = data.get("policy_names") or []

    is_multi = bool(data.get("is_multi_policy", False))

    policy_ids: List[int] = []

    for pid in raw_policy_ids:
        try:
            policy_ids.append(int(pid))
        except (TypeError, ValueError):
            pass

    policy_names: List[str] = [
        str(n).strip()
        for n in raw_policy_names
        if n and str(n).strip()
    ]

    if is_multi and policy_id and not policy_ids:
        policy_ids = [policy_id]
        policy_id = None

    # ── Missing fields cleanup ───────────────────────────

    raw_missing = list(data.get("missing_fields") or [])

    clean_missing = []
    for f in raw_missing:
        f_str = str(f).strip()
        if f_str in INTERNAL_SCHEMA_FIELDS:
            continue
        # Mistral sometimes hallucinates sentences in missing_fields
        if " " in f_str:
            continue
        # Never ask for a field if it's already provided!
        if f_str == "policy_id" and policy_id is not None:
            continue
        if f_str == "policy_name" and data.get("policy_name"):
            continue
        if f_str == "address_name" and data.get("address_name"):
            continue
        if f_str == "interface_name" and data.get("interface_name"):
            continue
        if f_str == "neighbor_id" and data.get("neighbor_id") is not None:
            continue
        if f_str == "ip_address" and data.get("ip_address"):
            continue
        
        clean_missing.append(f_str)

    if intent == NLUIntentType.MOVE_POLICY:
        is_multi = False

    return RawIntentSchema(
        intent=intent,
        confidence=confidence,
        policy_id=policy_id,
        policy_name=data.get("policy_name") or None,
        policy_ids=policy_ids,
        policy_names=policy_names,
        is_multi_policy=is_multi,
        address_name=data.get("address_name") or None,
        interface_name=data.get("interface_name") or None,
        neighbor_id=_safe_int(data.get("neighbor_id")),
        move_action=data.get("move_action") or None,
        ip_address=data.get("ip_address") or None,
        direction=data.get("direction") or None,
        deltas=deltas,
        create_params=data.get("create_params") or {},
        ambiguous=bool(data.get("ambiguous", False)),
        ambiguity_msg=str(data.get("ambiguity_msg") or ""),
        candidates=list(data.get("candidates") or []),
        missing_fields=clean_missing,
        raw_input=raw_input,
    )


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_user_prompt(
    user_input: str,
    context: dict,
    history: Optional[List[dict]] = None,
    entity_hint: str = "",
) -> str:

    context = _truncate_context(context)

    policies_text = json.dumps(
        context.get("policies", []),
        ensure_ascii=False,
    )

    interfaces_text = json.dumps(
        context.get("interfaces", []),
        ensure_ascii=False,
    )

    services_text = json.dumps(
        context.get("services", []),
        ensure_ascii=False,
    )

    addresses_text = json.dumps(
        context.get("addresses", [])[:15],
        ensure_ascii=False,
    )

    history_text = ""

    if history:
        lines = ["\nRecent conversation (last 2 turns):"]

        for m in history[-4:]:
            role = m.get("role", "?")
            content = str(m.get("content", ""))[:150]
            lines.append(f"  {role}: {content}")

        history_text = "\n".join(lines) + "\n"

    entity_text = f"\n{entity_hint}\n" if entity_hint else ""

    return (
        f"Available policies:\n{policies_text}\n\n"
        f"Available interfaces:\n{interfaces_text}\n\n"
        f"Available services:\n{services_text}\n\n"
        f"Available address objects:\n{addresses_text}\n"
        f"{history_text}"
        f"{entity_text}\n"
        f'User input: "{user_input}"\n\n'
        "Output a single JSON object following the schema above. "
        "No text before or after the JSON."
    )


# ── Live context fetch ────────────────────────────────────────────────────────

def fetch_live_context() -> Dict[str, Any]:
    """
    Fetch runtime context for grounding.
    Safe fallback implementation.
    """

    return {
        "policies": [],
        "interfaces": [],
        "addresses": [],
        "services": [
            "HTTP",
            "HTTPS",
            "FTP",
            "SSH",
            "DNS",
            "ALL",
        ],
    }


# ── Main interpreter ──────────────────────────────────────────────────────────

def interpret(
    user_input: str,
    llm_plain: object,
    context: Optional[dict] = None,
    conversation_history: Optional[List[dict]] = None,
    entity_hint: str = "",
) -> NLUResult:
    """
    Call Mistral to interpret user intent.
    """

    if not user_input or not user_input.strip():
        return NLUResult.parse_error(
            "",
            ValueError("Empty user input"),
        )

    if context is None:
        try:
            context = fetch_live_context()

        except RuntimeError as exc:
            logger.warning(
                f'"event":"ctx_total_fail","error":"{exc}"'
            )

            context = {
                "policies": [],
                "interfaces": [],
                "addresses": [],
                "services": [
                    "HTTP",
                    "HTTPS",
                    "FTP",
                    "SSH",
                    "DNS",
                    "ALL",
                ],
            }

    user_prompt = _build_user_prompt(
        user_input=user_input,
        context=context,
        history=conversation_history,
        entity_hint=entity_hint,
    )

    # Pre-initialise so the except handler always has a valid reference.
    cleaned = ""

    try:
        messages = [
            {
                "role": "system",
                "content": _SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ]

        response = llm_plain.invoke(messages)

        raw_response = getattr(
            response,
            "content",
            str(response),
        )

        if not raw_response:
            raise ValueError("Empty LLM response")

        cleaned = raw_response.strip()

        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            cleaned = match.group(0)

        parsed = json.loads(cleaned)

        logger.debug(f'"event":"nlu_debug_raw_llm_json","parsed":{json.dumps(parsed)}')

        if not isinstance(parsed, dict):
            raise ValueError(
                f"Expected JSON object from LLM, got {type(parsed).__name__}"
            )

        schema = _build_schema(parsed, user_input)

        logger.debug(f'"event":"nlu_debug_post_build_schema","schema_deltas":{json.dumps([d.__dict__ for d in schema.deltas])}')

        return NLUResult.ok(schema=schema)

    except Exception as exc:
        logger.exception(
            '"event":"nlu_interpret_failed"'
        )
        return NLUResult.parse_error(
            raw=cleaned,
            cause=exc,
        )