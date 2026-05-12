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
CRITICAL OUTPUT RULES
═══════════════════════════════════════════════════════════
1. Output ONLY a valid JSON object. No explanation. No markdown. No code blocks.
2. Use ONLY policy IDs and names from "Available policies". Never invent IDs.
3. Use ONLY service names from "Available services". Never invent service names.
4. Use ONLY interface names from "Available interfaces".
5. If uncertain about any entity: set it to null and list the field in missing_fields.
6. If intent is ambiguous: set ambiguous=true and describe both options in ambiguity_msg.
"""

# ── Result wrapper ────────────────────────────────────────────────────────────

@dataclass
class NLUResult:
    success: bool
    schema: Optional[RawIntentSchema] = None
    error: str = ""
    raw_response: str = ""

    @classmethod
    def ok(
        cls,
        schema: RawIntentSchema,
        raw_response: str = "",
    ) -> "NLUResult":
        return cls(
            success=True,
            schema=schema,
            raw_response=raw_response,
        )

    @classmethod
    def parse_error(
        cls,
        raw_response: str,
        exc: Exception,
    ) -> "NLUResult":
        return cls(
            success=False,
            error=str(exc),
            raw_response=raw_response,
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

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

    if not intent_str:
        raise NLUSchemaError(data, ["intent"])

    try:
        intent = NLUIntentType(intent_str)

    except ValueError:
        for member in NLUIntentType:
            if member.value in intent_str or intent_str in member.value:
                intent = member
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

        raw_value = d.get("value", "")

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

    clean_missing = [
        f for f in raw_missing
        if f not in INTERNAL_SCHEMA_FIELDS
    ]

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

        schema = _build_schema(parsed, user_input)

        return NLUResult.ok(
            schema=schema,
            raw_response=cleaned,
        )

    except Exception as exc:
        logger.exception(
            '"event":"nlu_interpret_failed"'
        )

        return NLUResult.parse_error(
            raw_response="",
            exc=exc,
        )