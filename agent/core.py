"""
core.py — FortiGate AI Agent execution engine.

MODULE-LEVEL functions and constants (OUTSIDE AgentSession):
    Enums       : ResultStatus, ConfirmationStage, ResponseKind
    Dataclasses : ToolResult, ConfirmationState, AgentResponse
    Constants   : VALIDATORS, _INTENT_TO_TOOL, _MISSING_HINTS, _CAPABILITY_RESPONSE
    Utilities   : _build_llms, _invoke, _trim, resolve_policy_id,
                  build_confirmation_text, _run_tool,
                  _format_tool_result, _format_verified_update,
                  _format_knowledge, _format_security_analysis,
                  _verify, _grounded_to_tool_args

AgentSession CLASS (all methods with 4-space indent):
    __init__, has_pending, process, _route, _build_session_hint,
    _handle_conversational, _handle_clarification_reply,
    _handle_live_read, _handle_security_analysis, _handle_knowledge,
    _handle_nlu, _handle_unknown,
    _handle_nlu_failure, _handle_grounding_errors,
    _handle_ambiguity, _handle_incomplete, _start_update_confirmation,
    _handle_confirmation, _execute_policy_update,
    _record, _get_recent_history, _check_noop_enable_disable

ROUTING HIERARCHY (enforced in process()):
    1. Pending confirmation (stateful, always first)
    2. Stale clarification expiry
    3. Master router → dedicated handler per RouteCategory

INVARIANTS:
    I1. _pending always cleared after resolution (execute/cancel/exception).
    I2. No API write executes without confirmed grounded intent.
    I3. State-change responses generated only from verified FortiGate state.
    I4. ToolMessages never enter self.conversation.
    I5. LLM output never crosses the trust boundary without grounding.
    I6. Read queries never touch UpdateIntent, FieldDelta, or grounding.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field as dc_field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ── Path setup ────────────────────────────────────────────────────────────────
_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR  = os.path.dirname(_AGENT_DIR)
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

# ── LangChain / Mistral ───────────────────────────────────────────────────────
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_mistralai import ChatMistralAI

# ── Project infrastructure ────────────────────────────────────────────────────
from audit.logger import log_action, log_conversation
from config import MISTRAL_API_KEY

# ── Tools ─────────────────────────────────────────────────────────────────────
from tools import ALL_TOOLS, TOOL_MAP, WRITE_TOOLS

# ── Prompt ────────────────────────────────────────────────────────────────────
from prompt import SYSTEM_PROMPT

# ── New routing architecture ──────────────────────────────────────────────────
from router import RouteCategory, route
from session_context import SessionContext
from read_reasoner import resolve_read

# ── NLU layer ─────────────────────────────────────────────────────────────────
from nlu_interpreter import NLUResult, fetch_live_context, interpret
from nlu_grounder import GroundedIntentSchema, GroundingIssue, ground
from nlu_schema import (
    INTERNAL_SCHEMA_FIELDS,
    NLUConfidence,
    NLUDelta,
    NLUIntentType,
    RawIntentSchema,
)

# ── Execution layer ───────────────────────────────────────────────────────────
from executor import ExecutionResult, PolicyUpdateExecutor
from intent_parser import FieldDelta, FieldOp, UpdateIntent
from verifier import verify_policy_update

# ── Validators ────────────────────────────────────────────────────────────────
from validator import (
    clear_cache,
    validate_block_ip,
    validate_create_address,
    validate_create_policy,
    validate_delete_address,
    validate_delete_policy,
    validate_enable_disable_policy,
    validate_move_policy,
    validate_update_interface_access,
    validate_update_policy,
)

# ── Safety guards (Phase 4) ───────────────────────────────────────────────────
from safety_guards import (
    validate_create_route,
    validate_create_service,
    validate_create_user,
    validate_delete_route,
    validate_delete_service,
    validate_delete_user,
    validate_set_interface_status,
)

# ── Snapshot / rollback engine (Phase 2) ─────────────────────────────────────
from snapshot import (
    SnapshotStore,
    capture_policy_snapshot,
    capture_policy_move_snapshot,
    capture_route_snapshot,
    capture_service_snapshot,
    capture_user_snapshot,
    execute_rollback,
)

# ── Deterministic compliance engine (Phase 3) ─────────────────────────────────
from compliance import run_compliance_check

logger = logging.getLogger("fortigate_agent")

# ══════════════════════════════════════════════════════════════════════════════
#  MODULE-LEVEL CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

MAX_TURNS = 12

_INTENT_TO_TOOL: Dict[NLUIntentType, str] = {
    NLUIntentType.UPDATE_POLICY:        "tool_update_policy",
    NLUIntentType.CREATE_POLICY:        "tool_create_policy",
    NLUIntentType.DELETE_POLICY:        "tool_delete_policy",
    NLUIntentType.ENABLE_POLICY:        "tool_enable_disable_policy",
    NLUIntentType.DISABLE_POLICY:       "tool_enable_disable_policy",
    NLUIntentType.MOVE_POLICY:          "tool_move_policy",
    NLUIntentType.CREATE_ADDRESS:       "tool_create_address",
    NLUIntentType.DELETE_ADDRESS:       "tool_delete_address",
    NLUIntentType.UPDATE_INTERFACE:     "tool_update_interface_access",
    NLUIntentType.SET_INTERFACE_STATUS: "tool_set_interface_status",
    NLUIntentType.CREATE_ROUTE:         "tool_create_route",
    NLUIntentType.DELETE_ROUTE:         "tool_delete_route",
    NLUIntentType.CREATE_SERVICE:       "tool_create_service",
    NLUIntentType.DELETE_SERVICE:       "tool_delete_service",
    NLUIntentType.CREATE_USER:          "tool_create_user",
    NLUIntentType.DELETE_USER:          "tool_delete_user",
    NLUIntentType.BLOCK_IP:             "tool_block_ip",
    NLUIntentType.BACKUP_CONFIG:        "tool_backup_config",
}

VALIDATORS: Dict[str, Any] = {
    # Policy operations
    "tool_create_policy":           validate_create_policy,
    "tool_delete_policy":           validate_delete_policy,
    "tool_update_policy":           validate_update_policy,
    "tool_enable_disable_policy":   validate_enable_disable_policy,
    "tool_move_policy":             validate_move_policy,
    # Address operations
    "tool_create_address":          validate_create_address,
    "tool_delete_address":          validate_delete_address,
    # Interface operations
    "tool_update_interface_access": validate_update_interface_access,
    "tool_set_interface_status":    validate_set_interface_status,
    # Route operations
    "tool_create_route":            validate_create_route,
    "tool_delete_route":            validate_delete_route,
    # Service operations
    "tool_create_service":          validate_create_service,
    "tool_delete_service":          validate_delete_service,
    # User operations
    "tool_create_user":             validate_create_user,
    "tool_delete_user":             validate_delete_user,
    # Incident response
    "tool_block_ip":                validate_block_ip,
}

_MISSING_HINTS: Dict[str, str] = {
    "tool_create_policy": (
        "Please provide: policy name, source interface, "
        "destination interface, service, and action.\n"
        "Example: create policy BlockHTTP from port1 to port2 denying HTTP"
    ),
    "tool_create_address": (
        "Please provide: address name and subnet.\n"
        "Example: create address WebServer 192.168.10.50/32"
    ),
    "tool_delete_address":  "Please provide the exact address object name.",
    "tool_delete_policy":   "Please provide the policy ID or name.",
    "tool_enable_disable_policy": (
        "Please provide the policy ID or name.\n"
        "Example: enable policy 4   or   disable policy BlockSSH"
    ),
    "tool_move_policy": (
        "Please provide: policy to move, direction (before/after), "
        "and reference policy.\n"
        "Example: move policy 3 before policy 1"
    ),
    "tool_block_ip": (
        "Please provide the IP address to block.\n"
        "Example: block ip 192.168.1.55"
    ),
    "tool_update_interface_access": (
        "Please provide the interface name and protocols to allow.\n"
        "Example: disable HTTP and TELNET on port2"
    ),
    "tool_update_policy": (
        "Please be specific about what to change.\n"
        "Examples:\n"
        "  add FTP to policy 4\n"
        "  remove SSH from policy BlockSSH\n"
        "  set policy 4 action to deny\n"
        "  enable NAT in policy 4\n"
        "  add FTP and remove HTTPS from policy 4"
    ),
}

_CAPABILITY_RESPONSE = """I manage FortiGate firewalls using natural language. Here is what I can do:

READ — executed immediately, no confirmation:
  list all policies / interfaces / addresses / routes / users / services
  show details of policy 4 (or by name: show details of policy BlockSSH)
  what does policy BlockSSH do?
  show enabled policies / show deny policies
  is NAT enabled in policy test1?
  what are the services of policy 4?
  check cpu and memory / show vpn status / show active sessions / system status
  show bandwidth usage per interface
  show recent traffic logs / show threat logs / show event logs

WRITE — always require your confirmation:
  add FTP to policy 4
  remove SSH from policy BlockSSH
  set policy 4 action to deny
  enable NAT in policy 4
  disable HTTP and TELNET on port2
  bring port2 down / bring port2 up
  create policy BlockHTTP from port1 to port2 denying HTTP
  delete policy 4
  move policy 4 before policy 3
  enable policy 4 / disable policy BlockSSH
  create address WebServer 192.168.10.50/32
  block ip 192.168.1.99
  add static route to 10.20.0.0 via 192.168.1.1 on wan1
  delete route 5
  create service MyApp TCP port 8443
  delete service MyApp
  create user alice password P@ss1234
  delete user alice
  backup the configuration

SECURITY ANALYSIS:
  analyze my firewall security
  check for risky policies
  audit my firewall
  find insecure configurations

KNOWLEDGE:
  what does error -651 mean?
  how do I configure a VLAN on FortiGate?
  what is the best practice for firewall policies?
  how does NAT work in FortiOS?

I work in English and French."""


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE-LEVEL ENUMS AND DATACLASSES
# ══════════════════════════════════════════════════════════════════════════════

class ResultStatus(Enum):
    SUCCESS = "success"
    ERROR   = "error"
    PARTIAL = "partial"
    NOOP    = "noop"


class ConfirmationStage(Enum):
    AWAITING_FIRST  = "awaiting_first"
    AWAITING_SECOND = "awaiting_second"


class ResponseKind(Enum):
    ANSWER       = "answer"
    CONFIRMATION = "confirmation"
    WARNING      = "warning"
    BLOCKED      = "blocked"
    CANCELLED    = "cancelled"
    ERROR        = "error"


@dataclass
class ToolResult:
    status:    ResultStatus
    message:   str
    raw:       str = ""
    tool_name: str = ""
    tool_args: dict = dc_field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.status == ResultStatus.ERROR

    @property
    def is_success(self) -> bool:
        return self.status in (ResultStatus.SUCCESS, ResultStatus.NOOP)

    def for_llm(self) -> str:
        if self.status == ResultStatus.ERROR:
            return f"OPERATION FAILED: {self.message}"
        if self.status == ResultStatus.NOOP:
            return f"NO CHANGE MADE: {self.message}"
        return self.message or self.raw

    def for_log(self) -> str:
        return self.raw or self.message


@dataclass
class ConfirmationState:
    tool_name:      str
    tool_args:      dict
    original_input: str
    stage:          ConfirmationStage = ConfirmationStage.AWAITING_FIRST
    warning_text:   str = ""

    def advance_to_second(self, warning_text: str) -> None:
        self.stage        = ConfirmationStage.AWAITING_SECOND
        self.warning_text = warning_text

    @property
    def is_first(self) -> bool:
        return self.stage == ConfirmationStage.AWAITING_FIRST


@dataclass
class AgentResponse:
    text:        str
    kind:        ResponseKind = ResponseKind.ANSWER
    tool_called: str = ""
    pending:     bool = False


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE-LEVEL UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def _build_llms() -> Tuple[Any, Any]:
    base = ChatMistralAI(
        model="mistral-small-latest",
        temperature=0,
        api_key=MISTRAL_API_KEY,
    )
    return base.bind_tools(ALL_TOOLS), base


def _invoke(llm: Any, messages: list, retries: int = 3) -> Any:
    for attempt in range(retries):
        try:
            return llm.invoke(messages)
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
                    f'"event":"llm_retry","attempt":{attempt + 1},'
                    f'"wait":{wait},"error":"{exc}"'
                )
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("Mistral API unavailable after all retries.")


def _trim(conversation: list) -> list:
    """Keep SystemMessage + last MAX_TURNS * 2 Human/AI messages."""
    system = [m for m in conversation if isinstance(m, SystemMessage)]
    rest   = [
        m for m in conversation
        if isinstance(m, (HumanMessage, AIMessage))
    ]
    if len(rest) <= MAX_TURNS * 2:
        return system + rest
    logger.debug(f'"event":"conversation_trimmed","kept":{MAX_TURNS * 2}')
    return system + rest[-(MAX_TURNS * 2):]


def resolve_policy_id(name_or_id: str) -> Optional[int]:
    s = str(name_or_id).strip()
    if re.match(r"^\d+$", s):
        return int(s)
    try:
        from modules.policies import list_policies
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        for p in results:
            if p.get("name", "").lower() == s.lower():
                return p.get("policyid")
    except Exception as exc:
        logger.debug(f'"event":"resolve_policy_id_fail","name":"{s}","error":"{exc}"')
    return None


def build_confirmation_text(tool_name: str, args: dict) -> str:
    sep   = "=" * 55
    lines = [sep, "  CONFIRMATION REQUIRED", sep]

    if tool_name == "tool_create_policy":
        lines += [
            "  CREATE firewall policy:",
            f"    Name      : {args.get('name', '?')}",
            f"    Interfaces: {args.get('srcintf', '?')} → {args.get('dstintf', '?')}",
            f"    Src Addr  : {args.get('srcaddr', 'all')}",
            f"    Dst Addr  : {args.get('dstaddr', 'all')}",
            f"    Service   : {args.get('service', 'ALL')}",
            f"    Action    : {str(args.get('action', 'accept')).upper()}",
        ]
    elif tool_name == "tool_enable_disable_policy":
        verb = "ENABLE" if args.get("status") == "enable" else "DISABLE"
        lines.append(f"  {verb} policy ID {args.get('policy_id', '?')}")
    elif tool_name == "tool_delete_policy":
        lines += [
            f"  PERMANENTLY DELETE policy ID {args.get('policy_id', '?')}",
            "  This cannot be undone.",
        ]
    elif tool_name == "tool_move_policy":
        lines.append(
            f"  REORDER: move policy {args.get('policy_id', '?')} "
            f"{args.get('move_action', '?')} "
            f"policy {args.get('neighbor_id', '?')}"
        )
    elif tool_name == "tool_create_address":
        lines += [
            "  CREATE address object:",
            f"    Name   : {args.get('name', '?')}",
            f"    Subnet : {args.get('subnet', '?')}",
        ]
    elif tool_name == "tool_delete_address":
        lines.append(
            f"  DELETE address '{args.get('name', '?')}' — cannot be undone."
        )
    elif tool_name == "tool_update_interface_access":
        lines += [
            f"  UPDATE interface {args.get('name', '?')}:",
            f"    Allow only: {str(args.get('allowaccess', '?')).upper()}",
            "  All other protocols will be DISABLED.",
        ]
    elif tool_name == "tool_block_ip":
        lines += [
            f"  BLOCK IP {args.get('ip_address', '?')} "
            f"({args.get('direction', 'both')})",
            "  Creates deny policies — reversible by deleting them.",
        ]
    elif tool_name == "tool_backup_config":
        lines.append("  BACKUP configuration to local file.")
    else:
        lines.append(f"  EXECUTE: {tool_name}")
        lines.append(f"    Args: {json.dumps(args, ensure_ascii=False)[:200]}")

    lines += [sep, "  Type 'yes' to confirm or 'no' to cancel.", sep]
    return "\n".join(lines)


def _run_tool(tool_name: str, tool_args: dict, user_input: str) -> ToolResult:
    """Execute a registered tool. Never raises. Always returns ToolResult."""
    tool = TOOL_MAP.get(tool_name)
    if not tool:
        result = ToolResult(
            status=ResultStatus.ERROR,
            message=f"Tool '{tool_name}' is not registered in TOOL_MAP.",
            tool_name=tool_name,
            tool_args=tool_args,
        )
        log_action(
            tool_name.upper(), user_input, tool_name,
            str(tool_args), result.message, "error",
        )
        return result

    print(f"\n[Calling: {tool_name}]")
    logger.debug(
        f'"event":"tool_execute","tool":"{tool_name}",'
        f'"args":{json.dumps(str(tool_args))[:300]}'
    )

    try:
        raw = str(tool.invoke(tool_args))
    except Exception as exc:
        raw = str(exc)
        logger.error(
            f'"event":"tool_exception","tool":"{tool_name}","error":"{exc}"'
        )

    if tool_name in WRITE_TOOLS:
        clear_cache()

    raw_lower = raw.lower()
    if "[error]" in raw_lower or "[failed]" in raw_lower:
        status = ResultStatus.ERROR
    elif "[success]" in raw_lower:
        status = ResultStatus.SUCCESS
    elif "error" in raw_lower and "success" in raw_lower:
        status = ResultStatus.PARTIAL
    else:
        status = ResultStatus.SUCCESS

    result = ToolResult(
        status=status, message=raw, raw=raw,
        tool_name=tool_name, tool_args=tool_args,
    )
    log_action(
        action=tool_name.upper(), user_input=user_input,
        tool_called=tool_name, tool_input=str(tool_args),
        result=result.for_log(), status=result.status.value,
    )
    return result


def _format_tool_result(
    llm_plain:   Any,
    conversation: list,
    result:      ToolResult,
    user_input:  str,
) -> str:
    if result.status == ResultStatus.ERROR:
        outcome_note = (
            "\nCRITICAL: This operation FAILED. The firewall state was NOT changed. "
            "Do NOT say it succeeded. Explain the failure and what to do next."
        )
    elif result.status == ResultStatus.PARTIAL:
        outcome_note = (
            "\nNOTE: The operation partially succeeded. "
            "Report both what worked and what failed."
        )
    elif result.status == ResultStatus.NOOP:
        outcome_note = "\nNO CHANGE was made. Explain why clearly."
    else:
        outcome_note = "\nSummarise what the system returned. Be concise."

    msgs = list(conversation) + [
        HumanMessage(content=(
            f"User request: {user_input}\n\n"
            f"System result:\n{result.for_llm()}\n\n"
            "Rules:\n"
            "- Plain text only. No emojis. No markdown headers.\n"
            "- ASCII tables (| and -) for tabular data only.\n"
            "- Be concise — 2–4 sentences unless showing a table.\n"
            "- Respond in the SAME LANGUAGE as the user request.\n"
            f"- Do not call any tools.\n{outcome_note}"
        ))
    ]
    return _invoke(llm_plain, msgs).content


def _format_verified_update(
    llm_plain:    Any,
    conversation: list,
    intent:       UpdateIntent,
    exec_result:  ExecutionResult,
    vr:           Any,
) -> str:
    """Format from verified FortiGate state only — never from user inference."""
    if not exec_result.success:
        status_text = f"FAILED: {exec_result.message}"
    elif vr.passed:
        status_text = "SUCCESS — verified on FortiGate"
    else:
        status_text = "APPLIED but verification detected mismatches"

    verified_fields = (
        "\n".join(f"  {f}" for f in vr.fields_checked) or "  (none verified)"
    )
    mismatches = "\n".join(f"  MISMATCH: {m}" for m in vr.mismatches)

    system_data = (
        f"Operation status: {status_text}\n"
        f"Policy ID: {intent.policy_id}\n"
        f"Verified state after execution:\n{verified_fields}"
        + (f"\nVerification issues:\n{mismatches}" if vr.mismatches else "")
    )

    msgs = list(conversation) + [
        HumanMessage(content=(
            f"User request: {intent.raw_input}\n\n"
            f"Execution result (from verified FortiGate state):\n{system_data}\n\n"
            "Report ONLY what the verified state shows. "
            "Do NOT infer fields not listed. "
            "If verification failed, say so explicitly. "
            "Plain text. No emojis. No markdown. "
            "Same language as the user request."
        ))
    ]
    return _invoke(llm_plain, msgs).content


def _format_knowledge(
    llm_plain:    Any,
    conversation: list,
    raw_chunks:   str,
    user_input:   str,
) -> str:
    msgs = list(conversation) + [
        HumanMessage(content=(
            f"User question: {user_input}\n\n"
            f"Documentation retrieved:\n{raw_chunks}\n\n"
            "Synthesise a clean, direct answer from the documentation above.\n"
            "Rules:\n"
            "- Extract only information that answers the question.\n"
            "- Ignore page numbers, headers, table-of-contents fragments, "
            "and PDF extraction artefacts.\n"
            "- Include CLI commands in a plain code block when relevant.\n"
            "- Plain text. No emojis. No markdown headers.\n"
            "- If the documentation does not contain the answer, say so clearly.\n"
            "- Respond in the same language as the user question."
        ))
    ]
    return _invoke(llm_plain, msgs).content


def _format_security_analysis(
    llm_plain:    Any,
    conversation: list,
    raw:          str,
    user_input:   str,
) -> str:
    msgs = list(conversation) + [
        HumanMessage(content=(
            f"User request: {user_input}\n\n"
            f"Security analysis results:\n{raw}\n\n"
            "Present these findings as a professional cybersecurity report:\n"
            "- One-sentence executive summary.\n"
            "- Group findings by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO.\n"
            "- For each finding: issue, risk, specific recommended fix.\n"
            "- End with three prioritised next steps the operator should take now.\n"
            "- Plain text. No emojis. No markdown headers.\n"
            "- ASCII tables for comparisons if helpful.\n"
            "- Direct and actionable — not verbose.\n"
            "- Same language as the user request."
        ))
    ]
    return _invoke(llm_plain, msgs).content


def _verify(tool_name: str, tool_args: dict, result: ToolResult) -> str:
    """
    Post-execution state verification for ALL write operations.

    Trust-boundary rule: this function ONLY reads FortiGate state.
    It never calls the LLM. It returns a deterministic verification string.

    Returns empty string for non-write tools or if verification is not applicable.
    """
    if not result.is_success:
        return ""

    try:
        # ── Policy operations ─────────────────────────────────────────────────
        from modules.policies import get_policy as _gp, list_policies as _lp

        if tool_name in ("tool_delete_policy", "tool_move_policy", "tool_create_policy"):
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
                    f"  ID {p.get('policyid', '?'):>3} | "
                    f"{p.get('name', '?'):<25} | "
                    f"{p.get('action', '?'):>6}{flag} | "
                    f"{src} → {dst}"
                )
            return "\n".join(lines)

        if tool_name == "tool_enable_disable_policy":
            pid      = tool_args.get("policy_id")
            expected = tool_args.get("status", "enable")
            if not pid:
                return ""
            r   = _gp(int(pid))
            raw = r.get("results", {})
            p   = (
                raw[0] if isinstance(raw, list) and raw else
                raw if isinstance(raw, dict) else {}
            )
            actual = p.get("status", "unknown")
            if actual == expected:
                return (
                    f"\n[Verified: policy '{p.get('name', '?')}' "
                    f"(ID:{pid}) is {actual} on FortiGate]"
                )
            return (
                f"\n[WARNING: Expected '{expected}' but FortiGate "
                f"reports '{actual}' for policy ID {pid}]"
            )

        if tool_name == "tool_create_address":
            from modules.addresses import list_addresses as _la
            name    = tool_args.get("name", "")
            r       = _la()
            results = r if isinstance(r, list) else r.get("results", [])
            if any(a.get("name") == name for a in results):
                return f"\n[Verified: address '{name}' confirmed on FortiGate]"
            return f"\n[WARNING: Address '{name}' not found after creation]"

    except Exception as exc:
        logger.warning(
            f'"event":"verify_fail","tool":"{tool_name}","error":"{exc}"'
        )

    return ""


def _grounded_to_tool_args(grounded: GroundedIntentSchema) -> Optional[dict]:
    """
    Convert GroundedIntentSchema to tool_args for the execution layer.

    CRITICAL: uses grounded.grounded_deltas (validated), never raw.deltas.
    Computed values (block_ip normalised IP etc.) come from grounded.computed,
    never from grounded.current_state.
    """
    raw    = grounded.raw
    intent = raw.intent

    _OP_MAP = {
        "add":     FieldOp.ADD,
        "remove":  FieldOp.REMOVE,
        "replace": FieldOp.REPLACE,
        "set":     FieldOp.SET,
    }

    try:
        if intent == NLUIntentType.UPDATE_POLICY:
            if not grounded.grounded_deltas:
                logger.error('"event":"bridge_empty_grounded_deltas"')
                return None
            if not grounded.policy_id:
                logger.error('"event":"bridge_missing_policy_id"')
                return None

            exec_deltas: List[FieldDelta] = []
            for d in grounded.grounded_deltas:
                op = _OP_MAP.get(str(d.op).lower())
                if op is None:
                    logger.warning(f'"event":"bridge_unknown_op","op":"{d.op}"')
                    continue
                exec_deltas.append(FieldDelta(
                    field_name=str(d.field),
                    op=op,
                    values=d.value if isinstance(d.value, list) else [],
                    scalar=d.value if isinstance(d.value, str) else "",
                ))

            if not exec_deltas:
                logger.error('"event":"bridge_no_valid_exec_deltas"')
                return None

            return {
                "_update_intent": UpdateIntent(
                    policy_id=grounded.policy_id,
                    deltas=exec_deltas,
                    raw_input=raw.raw_input,
                )
            }

        if intent == NLUIntentType.DELETE_POLICY:
            if not grounded.policy_id:
                return None
            return {"policy_id": grounded.policy_id}

        if intent == NLUIntentType.ENABLE_POLICY:
            if not grounded.policy_id:
                return None
            return {"policy_id": grounded.policy_id, "status": "enable"}

        if intent == NLUIntentType.DISABLE_POLICY:
            if not grounded.policy_id:
                return None
            return {"policy_id": grounded.policy_id, "status": "disable"}

        if intent == NLUIntentType.MOVE_POLICY:
            if not all([grounded.policy_id, raw.neighbor_id, raw.move_action]):
                logger.error(
                    f'"event":"bridge_incomplete_move",'
                    f'"pid":{grounded.policy_id},'
                    f'"nid":{raw.neighbor_id},'
                    f'"action":"{raw.move_action}"'
                )
                return None
            if raw.move_action not in ("before", "after"):
                return None
            return {
                "policy_id":   grounded.policy_id,
                "move_action": raw.move_action,
                "neighbor_id": int(raw.neighbor_id),
            }

        if intent == NLUIntentType.CREATE_POLICY:
            cp = raw.create_params or {}
            if not cp.get("name") or not cp.get("srcintf") or not cp.get("dstintf"):
                logger.error(
                    f'"event":"bridge_incomplete_create_policy",'
                    f'"has_name":{bool(cp.get("name"))},'
                    f'"has_src":{bool(cp.get("srcintf"))},'
                    f'"has_dst":{bool(cp.get("dstintf"))}'
                )
                return None
            return cp

        if intent == NLUIntentType.CREATE_ADDRESS:
            if not raw.address_name:
                return None
            subnet = (raw.create_params or {}).get("subnet", "")
            if not subnet:
                return None
            return {"name": raw.address_name, "subnet": subnet}

        if intent == NLUIntentType.DELETE_ADDRESS:
            if not raw.address_name:
                return None
            return {"name": raw.address_name}

        if intent == NLUIntentType.UPDATE_INTERFACE:
            if not raw.interface_name:
                return None
            # Use canonical casing if grounder resolved it
            interface_name = (
                grounded.computed.get("canonical_interface") or raw.interface_name
            )
            allowaccess = (raw.create_params or {}).get("allowaccess", "")
            if not allowaccess:
                return None
            return {"name": interface_name, "allowaccess": allowaccess}

        if intent == NLUIntentType.SET_INTERFACE_STATUS:
            if not raw.interface_name:
                return None
            cp = raw.create_params or {}
            status = cp.get("status")
            if not status:
                # Fallback to checking deltas
                for d in raw.deltas:
                    if d.field == "status":
                        status = str(d.value).lower()
            if not status:
                status = "up" if "up" in raw.raw_input.lower() or "enable" in raw.raw_input.lower() else "down"
            return {"name": raw.interface_name, "status": status}

        if intent == NLUIntentType.CREATE_ROUTE:
            cp = raw.create_params or {}
            dest = cp.get("destination")
            gw = cp.get("gateway")
            dev = cp.get("device")
            if not all([dest, gw, dev]):
                return None
            return {"destination": dest, "gateway": gw, "device": dev}

        if intent == NLUIntentType.DELETE_ROUTE:
            cp = raw.create_params or {}
            rid = cp.get("route_id")
            if not rid:
                return None
            return {"route_id": str(rid)}

        if intent == NLUIntentType.CREATE_SERVICE:
            cp = raw.create_params or {}
            name = cp.get("name")
            proto = cp.get("protocol")
            port = cp.get("port")
            if not all([name, proto, port]):
                return None
            return {"name": name, "protocol": proto, "port": str(port)}

        if intent == NLUIntentType.DELETE_SERVICE:
            cp = raw.create_params or {}
            name = cp.get("name")
            if not name:
                return None
            return {"name": name}

        if intent == NLUIntentType.CREATE_USER:
            cp = raw.create_params or {}
            name = cp.get("name")
            pw = cp.get("password")
            if not all([name, pw]):
                return None
            return {"name": name, "password": pw}

        if intent == NLUIntentType.DELETE_USER:
            cp = raw.create_params or {}
            name = cp.get("name")
            if not name:
                return None
            return {"name": name}

        if intent == NLUIntentType.BLOCK_IP:
            # Always read from computed — not from current_state
            ip  = grounded.computed.get("grounded_ip") or raw.ip_address
            dir = grounded.computed.get("grounded_direction") or raw.direction or "both"
            if not ip:
                return None
            return {"ip_address": ip, "direction": dir}

        if intent == NLUIntentType.BACKUP_CONFIG:
            return {}

        logger.error(f'"event":"bridge_unhandled_intent","intent":"{intent.value}"')
        return None

    except Exception as exc:
        logger.error(
            f'"event":"bridge_conversion_error","intent":"{intent.value}",'
            f'"error":"{exc}"',
            exc_info=True,
        )
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  AgentSession
#  ─────────────────────────────────────────────────────────────────────────────
#  Every def inside this class is indented 4 spaces.
#  Every method body is indented 8 spaces.
#  No module-level code after the class definition.
# ══════════════════════════════════════════════════════════════════════════════

class AgentSession:
    """
    Complete FortiGate agent session.

    Public interface:
        session  = AgentSession()
        response = session.process("add ssh to policy 4")  # → AgentResponse
    """

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def __init__(self) -> None:
        self.llm_tools, self.llm_plain = _build_llms()
        self.conversation: list        = [SystemMessage(content=SYSTEM_PROMPT)]
        self._pending: Optional[ConfirmationState] = None
        self.ctx:      SessionContext              = SessionContext()
        self.snapshots: SnapshotStore              = SnapshotStore()

    @property
    def has_pending(self) -> bool:
        return self._pending is not None

    # ── Main entry point ───────────────────────────────────────────────────────

    def process(self, user_input: str) -> AgentResponse:
        """
        Classify and handle user input.

        Priority order:
          1. Pending write confirmation (stateful, must be checked first)
          2. Stale clarification state expiry
          3. Master router → dedicated handler
        """
        user_input = user_input.strip()
        if not user_input:
            return AgentResponse(text="", kind=ResponseKind.ANSWER)

        self.conversation = _trim(self.conversation)

        # Priority 1: a write operation is awaiting confirmation
        if self._pending:
            return self._handle_confirmation(user_input)

        # Priority 2: expire stale clarification state before routing
        # Prevents ctx.pending_clarification from contaminating unrelated turns
        if self.ctx.is_incomplete_expired(max_turns=3):
            logger.debug('"event":"clarification_auto_expired"')
            self.ctx.clear_incomplete_intent()

        # Priority 3: route through the master router
        try:
            return self._route(user_input)
        except Exception as exc:
            logger.error(
                f'"event":"process_unhandled_exception",'
                f'"input":"{user_input[:100]}",'
                f'"error":"{exc}"',
                exc_info=True,
            )
            # Invariant I1: always clear pending on unexpected exception
            if self._pending:
                self._pending = None
                logger.warning('"event":"pending_cleared_on_exception"')
            return AgentResponse(
                text=(
                    "An unexpected error occurred. "
                    "Any pending operation has been cancelled.\n"
                    "Please try again."
                ),
                kind=ResponseKind.ERROR,
            )

    # ── Master router ──────────────────────────────────────────────────────────

    def _route(self, user_input: str) -> AgentResponse:
        """Classify the input and dispatch to the correct handler."""
        self.ctx.advance_turn()

        route_result = route(
            user_input,
            self.llm_plain,
            pending_clarification=self.ctx.pending_clarification,
            session_hint=self._build_session_hint(),
        )

        logger.debug(
            f'"event":"route_result",'
            f'"category":"{route_result.category.value}",'
            f'"confidence":"{route_result.confidence}",'
            f'"source":"{route_result.source}",'
            f'"input":"{user_input[:80]}"'
        )

        cat = route_result.category

        # Intercept rollback everywhere
        lower = user_input.lower().strip()
        if any(k in lower for k in ("rollback", "undo last", "revert last")):
            return self._handle_rollback(user_input)
        if any(k in lower for k in ("rollback history", "snapshot history", "show rollback")):
            return AgentResponse(
                text=self.snapshots.format_list(), kind=ResponseKind.ANSWER
            )

        if cat == RouteCategory.CONVERSATIONAL:
            return self._handle_conversational(user_input)
        if cat == RouteCategory.CLARIFICATION:
            return self._handle_clarification_reply(user_input)
        if cat == RouteCategory.LIVE_READ:
            return self._handle_live_read(user_input)
        if cat == RouteCategory.SECURITY_ANALYSIS:
            return self._handle_security_analysis(user_input)
        if cat == RouteCategory.KNOWLEDGE:
            return self._handle_knowledge(user_input)
        if cat == RouteCategory.WRITE_ACTION:
            return self._handle_nlu(user_input)

        # UNKNOWN
        return self._handle_unknown(user_input)

    def _build_session_hint(self) -> str:
        """
        Build a one-line context hint for the router's LLM stage-2.
        Used only to disambiguate follow-up turns — never for execution.
        """
        return self.ctx.build_hint()

    # ── Route handlers ─────────────────────────────────────────────────────────

    def _handle_conversational(self, user_input: str) -> AgentResponse:
        """Handle greetings and capability questions without calling Mistral."""
        t = user_input.lower().strip()

        capability_signals = (
            "can you", "what can", "what do you", "capabilities",
            "capable", "que peux", "aide", "what do", "how do you",
            "help me", "assist", "what are you",
        )
        if any(sig in t for sig in capability_signals) or len(t.split()) > 3:
            return AgentResponse(text=_CAPABILITY_RESPONSE, kind=ResponseKind.ANSWER)

        return AgentResponse(
            text=(
                "Hello. I manage FortiGate firewalls using natural language.\n"
                "Tell me what you need, or type 'what can you do' "
                "to see all available commands."
            ),
            kind=ResponseKind.ANSWER,
        )

    def _handle_clarification_reply(self, user_input: str) -> AgentResponse:
        """
        Handle a reply to a pending clarification question.

        Core fix: semantic compatibility check before synthesis.
        If not compatible → clear state and re-route as new request.
        This prevents "show ip addresses" from being synthesised with
        an unrelated "block ssh from port1 to port2".
        """
        incomplete = self.ctx.pending_incomplete

        if incomplete is None:
            self.ctx.clear_incomplete_intent()
            return self._route(user_input)

        # SEMANTIC COMPATIBILITY CHECK — the critical guard
        if not self.ctx.is_semantically_compatible_reply(user_input):
            logger.debug(
                f'"event":"clarification_interrupted",'
                f'"original":"{incomplete.original_input[:60]}",'
                f'"interrupt":"{user_input[:60]}"'
            )
            # Clear stale state silently and re-route as a fresh request
            self.ctx.clear_incomplete_intent()
            return self._route(user_input)

        # Clear before synthesis to prevent loop on failure
        self.ctx.clear_incomplete_intent()

        synthesised = f"{incomplete.original_input}, {user_input}"
        logger.debug(
            f'"event":"clarification_synthesis",'
            f'"synthesised":"{synthesised[:100]}"'
        )

        result = self._handle_nlu(synthesised)

        # If synthesis produced another INCOMPLETE with the same fields,
        # it means the synthesis didn't help — avoid infinite loop
        if result.kind == ResponseKind.ANSWER and "Still needed:" in result.text:
            # Don't re-store — just return the next clarification question
            pass

        return result

    def _handle_live_read(self, user_input: str) -> AgentResponse:
        logger.debug(f'"event":"live_read_start","input":"{user_input[:80]}"')

        raw_result, tool_used = resolve_read(
            user_input, self.ctx, self.llm_plain, _run_tool
        )

        if not raw_result or not tool_used:
            return AgentResponse(
                text=(
                    "I could not determine exactly what you want to query.\n\n"
                    "Try being specific:\n"
                    "  list all policies\n"
                    "  show details of policy 4\n"
                    "  what does policy BlockSSH do?\n"
                    "  show enabled policies\n"
                    "  is NAT enabled in policy test1?"
                ),
                kind=ResponseKind.ANSWER,
            )

        tool_result = ToolResult(
            status=ResultStatus.SUCCESS, message=raw_result,
            raw=raw_result, tool_name=tool_used,
        )
        answer = _format_tool_result(
            self.llm_plain, self.conversation, tool_result, user_input
        )

        # NEW: record entity references seen in this read to entity memory
        self._record_entities_from_read(tool_used, self.ctx)

        self._record(user_input, answer)
        return AgentResponse(text=answer, tool_called=tool_used, kind=ResponseKind.ANSWER)


    def _record_entities_from_read(
        self,
        tool_used: str,
        ctx:       SessionContext,
    ) -> None:
        """
        After a successful read, update entity memory with referenced entities.
        This enables "show policy 4" then "enable it" to work.
        """
        from session_context import EntityKind

        # The read_reasoner already calls ctx.set_policy_focus() for policy detail reads.
        # Here we handle the general case of tracking the focused entity.
        if tool_used == "tool_get_policy_details" and ctx.focused_policy_id:
            ctx.entity_memory.record_policy(
                ctx.focused_policy_id,
                ctx.focused_policy_name or f"ID:{ctx.focused_policy_id}",
                ctx.turn_count,
            )


    def _handle_security_analysis(self, user_input: str) -> AgentResponse:
        """
        Handle security audit and compliance requests.

        Routes:
          - 'audit my firewall' / 'analyze security' → full compliance check
          - 'check policies' / 'risky policies'       → policy-scope check
          - 'check interfaces'                        → interface-scope check
          - 'check routes'                            → route-scope check
          - 'check users'                             → user-scope check

        All findings are from the deterministic compliance engine — no LLM hallucination.
        """
        logger.debug(
            f'"event":"compliance_check_start","input":"{user_input[:80]}"'
        )

        lower = user_input.lower()
        if "interface" in lower or "intf" in lower:
            scope = "interfaces"
        elif any(k in lower for k in ("route", "routing")):
            scope = "routes"
        elif any(k in lower for k in ("user", "account")):
            scope = "users"
        elif any(k in lower for k in ("polic", "rule")):
            scope = "policies"
        else:
            scope = "full"

        try:
            report = run_compliance_check(scope=scope)
            answer = report.format()
        except Exception as exc:
            logger.error(f'"event":"compliance_check_fail","error":"{exc}"')
            answer = (
                "Compliance check could not complete.\n"
                f"Error: {exc}\n"
                "Please verify FortiGate connectivity."
            )

        self.ctx.set_security_analysis(summary=answer[:500])
        self._record(user_input, answer)
        return AgentResponse(
            text=answer,
            tool_called="compliance_engine",
            kind=ResponseKind.ANSWER,
        )

    def _handle_knowledge(self, user_input: str) -> AgentResponse:
        """Handle documentation questions via the RAG knowledge base."""
        logger.debug(f'"event":"knowledge_path","input":"{user_input[:80]}"')

        from tools import tool_search_knowledge as _sk

        raw = str(_sk.invoke({"query": user_input}))
        log_action(
            "TOOL_SEARCH_KNOWLEDGE", user_input, "tool_search_knowledge",
            user_input, raw, "success",
        )
        answer = _format_knowledge(
            self.llm_plain, self.conversation, raw, user_input
        )
        self._record(user_input, answer)
        return AgentResponse(
            text=answer,
            tool_called="tool_search_knowledge",
            kind=ResponseKind.ANSWER,
        )

    def _handle_nlu(self, user_input: str) -> AgentResponse:
        logger.debug(f'"event":"nlu_write_path","input":"{user_input[:80]}"')

        try:
            context = fetch_live_context()
        except Exception as exc:
            logger.warning(f'"event":"context_fetch_fail_nlu","error":"{exc}"')
            context = None

        # NEW: inject entity memory hint only if a pronoun/anaphora is present
        # This prevents over-aggressive fallback for random input.
        import re
        has_pronoun = bool(re.search(r'\b(it|this|that|them|him|her|il|elle|ce|cette)\b', user_input.lower()))
        entity_hint = self.ctx.get_active_entities_hint() if has_pronoun else ""

        try:
            nlu_result: NLUResult = interpret(
                user_input=user_input,
                llm_plain=self.llm_plain,
                context=context,
                conversation_history=self._get_recent_history(),
                entity_hint=entity_hint,   # NEW
            )
        except Exception as exc:
            logger.error(
                f'"event":"interpret_unhandled_raise",'
                f'"error":"{exc}"',
                exc_info=True,
            )
            return AgentResponse(
                text="An internal error occurred while interpreting your request. "
                     "Please try again.",
                kind=ResponseKind.ERROR,
            )

        # Safety guard: interpret() contract requires an NLUResult instance.
        if not isinstance(nlu_result, NLUResult):
            logger.error(
                f'"event":"nlu_result_type_error",'
                f'"type":"{type(nlu_result).__name__}"'
            )
            return AgentResponse(
                text="An internal error occurred (unexpected NLU result type). "
                     "Please try again.",
                kind=ResponseKind.ERROR,
            )

        if nlu_result.failed:
            return self._handle_nlu_failure(nlu_result)

        schema: RawIntentSchema = nlu_result.schema

        if schema.intent == NLUIntentType.AMBIGUOUS or schema.ambiguous:
            return self._handle_ambiguity(schema)

        clean_missing = [
            f for f in (schema.missing_fields or [])
            if f not in INTERNAL_SCHEMA_FIELDS
        ]
        schema.missing_fields = clean_missing

        if schema.intent == NLUIntentType.INCOMPLETE or clean_missing:
            return self._handle_incomplete(schema)

        # NEW: route multi-policy intents to dedicated handler
        if schema.is_multi_policy:
            return self._handle_multi_policy_nlu(schema)

        # Single-policy path (unchanged)
        try:
            grounded: GroundedIntentSchema = ground(schema)
        except Exception as exc:
            logger.error(
                f'"event":"grounding_crash","intent":"{schema.intent.value}",'
                f'"error":"{exc}"',
                exc_info=True,
            )
            return AgentResponse(
                text="An error occurred while validating the request. Please try again.",
                kind=ResponseKind.ERROR,
            )

        if not grounded.is_valid:
            return self._handle_grounding_errors(grounded)

        if grounded.is_noop:
            return AgentResponse(text=grounded.noop_message, kind=ResponseKind.ANSWER)

        tool_name = _INTENT_TO_TOOL.get(schema.intent)
        if not tool_name:
            return AgentResponse(
                text=f"I understood the intent ({schema.intent.value}) but could not map it to an execution step.",
                kind=ResponseKind.ANSWER,
            )

        tool_args = _grounded_to_tool_args(grounded)
        if tool_args is None:
            return AgentResponse(
                text=(
                    "I understood the request but could not build the execution parameters.\n"
                    + _MISSING_HINTS.get(tool_name, "Please be more specific.")
                ),
                kind=ResponseKind.ANSWER,
            )

        if tool_name == "tool_enable_disable_policy" and tool_args:
            skip, skip_msg = self._check_noop_enable_disable(tool_args)
            if skip:
                return AgentResponse(text=skip_msg, kind=ResponseKind.ANSWER)

        if tool_name == "tool_update_policy":
            return self._start_update_confirmation(tool_args, user_input, grounded)

        self._pending = ConfirmationState(
            tool_name=tool_name, tool_args=tool_args, original_input=user_input,
        )
        return AgentResponse(
            text=build_confirmation_text(tool_name, tool_args),
            kind=ResponseKind.CONFIRMATION, pending=True,
        )


    def _handle_multi_policy_nlu(self, schema: RawIntentSchema) -> AgentResponse:
        """
        Handle multi-policy update/enable/disable intents.

        Flow:
        1. Ground each target policy independently
        2. Report grounding failures immediately (don't hide them)
        3. Show a unified confirmation screen for all valid targets
        4. On confirm → execute BatchUpdateIntent
        """
        from nlu_grounder import ground_multi, MultiPolicyGroundingResult

        try:
            batch_grounded: MultiPolicyGroundingResult = ground_multi(schema)
        except Exception as exc:
            logger.error(
                f'"event":"multi_grounding_crash","error":"{exc}"', exc_info=True
            )
            return AgentResponse(
                text="An error occurred validating the multi-policy request. Please try again.",
                kind=ResponseKind.ERROR,
            )

        if not batch_grounded.is_valid:
            # Total failure — no valid targets at all
            error_lines = [f"  {i.message}" for i in batch_grounded.issues
                        if i.kind in ("not_found", "invalid_value", "missing", "api_unavailable", "unsupported")]
            return AgentResponse(
                text="I could not validate that request:\n" + "\n".join(error_lines or ["  Unknown validation failure."]),
                kind=ResponseKind.ANSWER,
            )

        # Build BatchUpdateIntent from grounded results
        from intent_parser import BatchUpdateIntent, UpdateIntent, FieldDelta, FieldOp

        _OP_MAP = {"add": FieldOp.ADD, "remove": FieldOp.REMOVE,
                "replace": FieldOp.REPLACE, "set": FieldOp.SET}

        batch_intents = []
        for grounded in batch_grounded.grounded_intents:
            if not grounded.policy_id:
                continue
            
            exec_deltas = []
            
            if schema.intent == NLUIntentType.ENABLE_POLICY:
                exec_deltas.append(FieldDelta(field_name="status", op=FieldOp.SET, values=[], scalar="enable"))
            elif schema.intent == NLUIntentType.DISABLE_POLICY:
                exec_deltas.append(FieldDelta(field_name="status", op=FieldOp.SET, values=[], scalar="disable"))
            else:
                if not grounded.grounded_deltas:
                    continue
                for d in grounded.grounded_deltas:
                    op = _OP_MAP.get(str(d.op).lower())
                    if op is None:
                        continue
                    exec_deltas.append(FieldDelta(
                        field_name=str(d.field),
                        op=op,
                        values=d.value if isinstance(d.value, list) else [],
                        scalar=d.value if isinstance(d.value, str) else "",
                    ))
            
            if exec_deltas:
                batch_intents.append(UpdateIntent(
                    policy_id=grounded.policy_id,
                    deltas=exec_deltas,
                    raw_input=schema.raw_input,
                ))

        if not batch_intents:
            return AgentResponse(
                text="No valid policy updates could be constructed. Please check your request.",
                kind=ResponseKind.ANSWER,
            )

        batch = BatchUpdateIntent(
            intents=batch_intents,
            raw_input=schema.raw_input,
        )

        # Build confirmation screen
        sep   = "=" * 55
        lines = [sep, "  CONFIRMATION REQUIRED (MULTI-POLICY)", sep, ""]

        for grounded in batch_grounded.grounded_intents:
            lines.append(f"  UPDATE {grounded.policy_display}:")
            if batch_intents:
                lines.append(batch_intents[0].describe())
            lines.append("")

        if batch_grounded.failed_policies:
            lines.append(
                f"  WARNING: These policies could not be validated "
                f"and will be SKIPPED: {', '.join(batch_grounded.failed_policies)}"
            )
            lines.append("")

        lines += [
            "  Current state will be fetched before applying each change.",
            sep,
            "  Type 'yes' to confirm or 'no' to cancel.",
            sep,
        ]

        self._pending = ConfirmationState(
            tool_name="tool_batch_update_policy",
            tool_args={"_batch_intent": batch},
            original_input=schema.raw_input,
        )
        return AgentResponse(
            text="\n".join(lines),
            kind=ResponseKind.CONFIRMATION,
            pending=True,
        )



    def _handle_unknown(self, user_input: str) -> AgentResponse:
        """Handle unclassified inputs with context-aware guidance."""
        t = user_input.lower().strip()

        # Security analysis follow-up
        if self.ctx.has_security_context():
            fix_signals = (
                "fix", "resolve", "correct", "address", "handle",
                "remediate", "apply", "implement", "do it",
                "corriger", "résoudre", "appliquer",
            )
            if any(sig in t for sig in fix_signals):
                return AgentResponse(
                    text=(
                        "To address the security findings, tell me specifically "
                        "what to change. For example:\n"
                        "  set policy 1 action to deny\n"
                        "  disable HTTP on port1\n"
                        "  update policy 2 services to HTTPS,DNS"
                    ),
                    kind=ResponseKind.ANSWER,
                )

        # Policy focus follow-up
        if self.ctx.has_policy_focus():
            pid  = self.ctx.focused_policy_id
            name = self.ctx.focused_policy_name or f"ID:{pid}"
            return AgentResponse(
                text=(
                    f"I was looking at policy '{name}'. What would you like to do?\n\n"
                    f"Examples:\n"
                    f"  show details of policy {pid}\n"
                    f"  add FTP to policy {pid}\n"
                    f"  set policy {pid} action to deny"
                ),
                kind=ResponseKind.ANSWER,
            )

        return AgentResponse(
            text=(
                "I am not sure what you would like to do.\n\n"
                "Examples:\n"
                "  list all policies\n"
                "  show details of policy 4\n"
                "  what does policy BlockSSH do?\n"
                "  add SSH to policy 4\n"
                "  analyze my firewall security\n"
                "  what does error -651 mean?\n\n"
                "Type 'what can you do' for the complete capability list."
            ),
            kind=ResponseKind.ANSWER,
        )

    # ── NLU sub-handlers ───────────────────────────────────────────────────────

    def _handle_nlu_failure(self, nlu_result: NLUResult) -> AgentResponse:
        kind = nlu_result.error_kind
        logger.warning(
            f'"event":"nlu_failure","kind":"{kind}",'
            f'"msg":"{nlu_result.error_msg[:200]}"'
        )

        if kind == "timeout":
            return AgentResponse(
                text="The AI interpretation service timed out. Please try again.",
                kind=ResponseKind.ERROR,
            )
        if kind == "api":
            return AgentResponse(
                text=(
                    "Could not reach the AI interpretation service.\n"
                    "Please check your network connection and Mistral API key."
                ),
                kind=ResponseKind.ERROR,
            )

        logger.debug(
            f'"event":"nlu_parse_fail",'
            f'"raw_output":"{nlu_result.raw_output[:300]}"'
        )
        return AgentResponse(
            text=(
                "I could not interpret that request.\n\n"
                "Please try rephrasing. Examples:\n"
                "  add FTP to policy 4\n"
                "  set policy 4 action to deny\n"
                "  enable NAT in policy 4\n"
                "  list all policies\n\n"
                "Type 'what can you do' for the complete capability list."
            ),
            kind=ResponseKind.ANSWER,
        )

    def _handle_grounding_errors(
        self,
        grounded: GroundedIntentSchema,
    ) -> AgentResponse:
        """
        Format grounding errors for the user.
        API unavailability is distinguished from entity-not-found.
        """
        # Check for API connectivity failures first — different message needed
        api_issues = [i for i in grounded.issues if i.kind == "api_unavailable"]
        if api_issues:
            return AgentResponse(
                text=(
                    "I cannot verify the request right now because the "
                    "FortiGate is not reachable.\n"
                    "Please check the connection and try again.\n\n"
                    f"Detail: {api_issues[0].message}"
                ),
                kind=ResponseKind.ERROR,
            )

        error_lines: List[str] = []
        for issue in grounded.issues:
            if issue.kind in ("not_found", "invalid_value", "missing"):
                error_lines.append(f"  {issue.message}")
                if issue.hint:
                    error_lines.append(f"    → {issue.hint}")

        # Show warnings after errors (lenient — don't block)
        warning_lines: List[str] = []
        for issue in grounded.issues:
            if issue.kind == "warning":
                warning_lines.append(f"  Note: {issue.message}")
                if issue.hint:
                    warning_lines.append(f"    → {issue.hint}")

        if not error_lines:
            error_lines = ["  Validation failed for an unknown reason."]

        text = "I could not validate that request:\n" + "\n".join(error_lines)
        if warning_lines:
            text += "\n\nAdditional information:\n" + "\n".join(warning_lines)

        return AgentResponse(text=text, kind=ResponseKind.ANSWER)

    def _handle_ambiguity(self, schema: RawIntentSchema) -> AgentResponse:
        """
        Show structured clarification when intent is ambiguous.
        Filters Mistral's internal reasoning from the user-facing message.
        """
        _INTERNAL_SIGNALS = (
            "not a firewall",
            "not a management",
            "is a query",
            "cannot be derived",
            "no structured intent",
            "is not an action",
            "is not a supported",
            "n'est pas",
            "pas une action",
            "rather than",
            "instead of",
            "suggests that",
        )

        raw_msg    = schema.ambiguity_msg or ""
        is_internal = any(sig in raw_msg.lower() for sig in _INTERNAL_SIGNALS)

        if is_internal or not raw_msg:
            self.ctx.ask_clarification(
                question="What operation did you want to perform?",
                expected_field="intent",
            )
            return AgentResponse(
                text=(
                    "I am not sure what you would like to do.\n\n"
                    "Some examples:\n"
                    "  list all policies\n"
                    "  add SSH to policy 4\n"
                    "  set policy 4 action to deny\n"
                    "  enable NAT in policy 4\n"
                    "  what does error -651 mean?\n\n"
                    "Type 'what can you do' for the full capability list."
                ),
                kind=ResponseKind.ANSWER,
            )

        if schema.candidates:
            lines = ["I need clarification:", ""]
            for i, c in enumerate(schema.candidates, 1):
                desc = (
                    c.get("description", str(c)) if isinstance(c, dict) else str(c)
                )
                lines.append(f"  {i}. {desc}")
            lines += ["", "Please rephrase to specify which you mean."]
            return AgentResponse(text="\n".join(lines), kind=ResponseKind.ANSWER)

        return AgentResponse(text=raw_msg, kind=ResponseKind.ANSWER)

    def _handle_incomplete(self, schema: RawIntentSchema) -> AgentResponse:
        """
        Show what was understood and ask only for the missing fields.
        Stores a PendingIncompleteIntent so the clarification reply
        can synthesise and complete the original request.
        """
        _FIELD_QUESTIONS: Dict[str, str] = {
            "policy_id":      "Which policy? (provide ID or name)",
            "name":           "What should the policy be named?",
            "srcintf":        "Which source interface? (e.g. port1, port2)",
            "dstintf":        "Which destination interface? (e.g. port1, port2)",
            "action":         "What action? (accept or deny)",
            "service":        "Which service(s)? (e.g. SSH, HTTPS, FTP)",
            "subnet":         "What subnet? (e.g. 192.168.1.0/24 or 10.0.0.1/32)",
            "address_name":   "What name for the address object?",
            "interface_name": "Which interface? (e.g. port1, port2)",
            "allowaccess":    "Which protocols to allow? (e.g. https ssh ping)",
            "neighbor_id":    "Which policy to move relative to?",
            "move_action":    "Before or after the reference policy?",
        }

        missing = [
            f for f in (schema.missing_fields or [])
            if f not in INTERNAL_SCHEMA_FIELDS
        ]

        lines: List[str] = []

        understood: List[str] = []
        if schema.policy_id:
            understood.append(f"  Policy ID: {schema.policy_id}")
        if schema.policy_name:
            understood.append(f"  Policy name: {schema.policy_name}")
        if schema.address_name:
            understood.append(f"  Address: {schema.address_name}")
        if schema.interface_name:
            understood.append(f"  Interface: {schema.interface_name}")
        if schema.ip_address:
            understood.append(f"  IP address: {schema.ip_address}")
        if schema.deltas:
            for d in schema.deltas:
                val = (
                    ", ".join(d.value) if isinstance(d.value, list) else str(d.value)
                )
                understood.append(f"  Change: {d.op} {d.field} = {val}")

        if understood:
            lines.append("I understood:")
            lines.extend(understood)
            lines.append("")

        if missing:
            lines.append("Still needed:")
            for f in missing:
                q = _FIELD_QUESTIONS.get(f, f"Please provide: {f}")
                lines.append(f"  {q}")

            # Store partial intent for synthesis-based completion
            collected: Dict[str, Any] = {}
            if schema.policy_id:    collected["policy_id"]    = schema.policy_id
            if schema.policy_name:  collected["policy_name"]  = schema.policy_name
            if schema.address_name: collected["address_name"] = schema.address_name
            if schema.ip_address:   collected["ip_address"]   = schema.ip_address
            if schema.deltas:       collected["deltas_count"] = len(schema.deltas)

            self.ctx.set_incomplete_intent(
                original_input=schema.raw_input,
                missing_fields=missing,
                collected=collected,
                intent_type=schema.intent.value,
                policy_id=schema.policy_id,
                policy_name=schema.policy_name,
            )

        else:
            lines.append(
                "I could not determine exactly what you want to do. "
                "Please be more specific."
            )

        return AgentResponse(text="\n".join(lines), kind=ResponseKind.ANSWER)

    def _start_update_confirmation(
        self,
        tool_args: dict,
        user_input: str,
        grounded: GroundedIntentSchema,
    ) -> AgentResponse:
        """Build the confirmation screen for policy update operations."""

        intent_obj: Optional[UpdateIntent] = tool_args.get("_update_intent")

        if not intent_obj:
            logger.error('"event":"start_update_confirmation_no_intent"')

            return AgentResponse(
                text=(
                    "Could not construct the update parameters.\n"
                    + _MISSING_HINTS.get("tool_update_policy", "")
                ),
                kind=ResponseKind.ANSWER,
            )

        sep = "=" * 55

        lines = [
            sep,
            "  CONFIRMATION REQUIRED",
            sep,
            f"  UPDATE {grounded.policy_display}:",
            "",
            intent_obj.describe(),
            "",
            "  Current state will be fetched before applying changes.",
            sep,
            "  Type 'yes' to confirm or 'no' to cancel.",
            sep,
        ]

        self._pending = ConfirmationState(
            tool_name="tool_update_policy",
            tool_args=tool_args,
            original_input=user_input,
        )

        return AgentResponse(
            text="\n".join(lines),
            kind=ResponseKind.CONFIRMATION,
            pending=True,
        )


    # ── Confirmation flow ──────────────────────────────────────────────────────

    def _handle_confirmation(self, user_input: str) -> AgentResponse:
        is_yes = user_input.strip().lower() in (
            "yes", "y", "ye", "yep", "yeah", "oui", "o",
        )

        if not is_yes:
            pc = self._pending
            log_action(
                "CANCELLED", pc.original_input, pc.tool_name,
                str(pc.tool_args), "User cancelled", "cancelled",
            )
            self._pending = None
            return AgentResponse(text="Action cancelled.", kind=ResponseKind.CANCELLED)

        pc = self._pending

        # Single-policy update
        if pc.tool_name == "tool_update_policy" and "_update_intent" in pc.tool_args:
            return self._execute_policy_update(pc)

        # NEW: Multi-policy batch update
        if pc.tool_name == "tool_batch_update_policy" and "_batch_intent" in pc.tool_args:
            return self._execute_batch_update(pc)

        # All other write operations
        if pc.is_first:
            validator = VALIDATORS.get(pc.tool_name)
            if validator:
                v = validator(pc.tool_args)
                if not v.valid:
                    self._pending = None
                    return AgentResponse(
                        text=v.format() + "\n\nAction blocked.",
                        kind=ResponseKind.BLOCKED,
                    )
                if v.has_warnings_only():
                    pc.advance_to_second(v.format())
                    return AgentResponse(
                        text=v.format(), kind=ResponseKind.WARNING, pending=True,
                    )

        # ── Snapshot capture before write ──────────────────────────────────────
        # Capture pre-operation state for rollback support.
        # This is deliberately placed AFTER validation to avoid capturing state
        # for operations that will be blocked.
        self._capture_pre_snapshot(pc)

        result       = _run_tool(pc.tool_name, pc.tool_args, pc.original_input)
        verification = _verify(pc.tool_name, pc.tool_args, result)
        answer       = _format_tool_result(
            self.llm_plain, self.conversation, result, pc.original_input
        )

        # Trust-boundary rule: verification string takes precedence over LLM response
        # for communicating whether the write was applied. The LLM formats prose;
        # the verifier supplies the ground truth.
        full_text = answer + ("\n" + verification if verification else "")
        self.ctx.record_write(pc.tool_name, str(pc.tool_args.get("policy_id", "")))
        self._record(pc.original_input, answer)
        self._pending = None
        return AgentResponse(
            text=full_text, tool_called=pc.tool_name, kind=ResponseKind.ANSWER
        )

    # ── Snapshot helpers ───────────────────────────────────────────────────────

    def _capture_pre_snapshot(self, pc: "ConfirmationState") -> None:
        """
        Capture pre-operation state into the snapshot store before a write.

        Only captures for tools that have a deterministic rollback procedure.
        Silently skips for tools without one (backup, block_ip, etc.).
        """
        tool = pc.tool_name
        args = pc.tool_args
        desc = pc.original_input[:80]

        try:
            if tool in ("tool_delete_policy", "tool_enable_disable_policy"):
                pid = args.get("policy_id")
                if pid:
                    capture_policy_snapshot(self.snapshots, int(pid), desc)

            elif tool == "tool_move_policy":
                pid = args.get("policy_id")
                if pid:
                    capture_policy_move_snapshot(self.snapshots, int(pid), desc)

            elif tool in ("tool_delete_route", "tool_create_route"):
                route_id = args.get("route_id")
                if route_id:
                    capture_route_snapshot(
                        self.snapshots, int(route_id), desc, tool_name=tool
                    )

            elif tool in ("tool_delete_service", "tool_create_service"):
                name = args.get("name", "")
                if name:
                    capture_service_snapshot(
                        self.snapshots, name, desc, tool_name=tool
                    )

            elif tool in ("tool_delete_user", "tool_create_user"):
                name = args.get("name", "")
                if name:
                    capture_user_snapshot(
                        self.snapshots, name, desc, tool_name=tool
                    )

        except Exception as exc:
            logger.warning(
                f'"event":"snapshot_capture_error","tool":"{tool}","error":"{exc}"'
            )

    # ── Rollback handler ───────────────────────────────────────────────────────

    def _handle_rollback(self, user_input: str) -> AgentResponse:
        """
        Process a rollback request.

        Supports:
            'rollback last'           → rolls back the most recent operation
            'rollback <OP_ID>'        → rolls back a specific operation by ID
            'show rollback history'   → lists available snapshots
        """
        lower = user_input.lower().strip()

        # List request
        if any(k in lower for k in ("history", "list", "show rollback", "available")):
            return AgentResponse(
                text=self.snapshots.format_list(), kind=ResponseKind.ANSWER
            )

        # Extract specific op_id if provided
        import re as _re
        op_id_match = _re.search(r'\b([0-9A-Fa-f]{8})\b', user_input)
        op_id = op_id_match.group(1).upper() if op_id_match else None

        logger.info(
            f'"event":"rollback_requested",'
            f'"op_id":"{op_id or "last"}",'
            f'"input":"{user_input[:80]}"'
        )

        result = execute_rollback(self.snapshots, op_id=op_id)

        if result.success:
            text = (
                f"Rollback completed successfully.\n"
                f"  Operation: [{result.op_id}]\n"
                f"  {result.message}\n"
                + (f"  {result.detail}" if result.detail else "")
            )
            log_action(
                "ROLLBACK", user_input, "rollback",
                f"op_id={result.op_id}", result.message, "success"
            )
        else:
            text = (
                f"Rollback failed.\n"
                f"  {result.message}\n"
                f"Use 'show rollback history' to see available rollback points."
            )
            log_action(
                "ROLLBACK", user_input, "rollback",
                f"op_id={result.op_id or 'last'}", result.message, "error"
            )

        self._record(user_input, text)
        return AgentResponse(
            text=text,
            kind=ResponseKind.ANSWER if result.success else ResponseKind.ERROR,
        )



    def _format_batch_results(
        self,
        batch:   "BatchUpdateIntent",
        results: "List[BatchUpdateResult]",
    ) -> str:
        """
        Format batch execution results into a clean per-policy report.
        Only claims success for policies where exec_result.success AND verified.
        """
        successes = [r for r in results if r.success and r.verified]
        failures  = [r for r in results if not r.success]
        partial   = [r for r in results if r.success and not r.verified]

        lines = [f"Batch update completed: {len(results)} policies processed.", ""]

        if successes:
            lines.append(f"  Succeeded and verified ({len(successes)}):")
            for r in successes:
                detail = ", ".join(r.verify_detail[:3])
                lines.append(f"    ✓ {r.policy_name} (ID:{r.policy_id}) — {detail}")
            lines.append("")

        if partial:
            lines.append(f"  Applied but verification inconclusive ({len(partial)}):")
            for r in partial:
                lines.append(f"    ⚠ {r.policy_name} (ID:{r.policy_id}) — {r.message}")
            lines.append("")

        if failures:
            lines.append(f"  Failed ({len(failures)}):")
            for r in failures:
                lines.append(f"    ✗ {r.policy_name} (ID:{r.policy_id}) — {r.message}")
            lines.append("")

        if not successes and not partial:
            lines.append("No policies were successfully updated.")

        return "\n".join(lines)


    def _execute_batch_update(self, pc: ConfirmationState) -> AgentResponse:
        """
        Execute a confirmed multi-policy batch update.

        Executes each UpdateIntent independently via PolicyUpdateExecutor.
        Verifies each independently. Reports per-policy results.

        Invariant I2: PolicyUpdateExecutor.execute() is called for every policy.
        Invariant I1: Response only claims success for policies where
                    exec_result.success AND vr.passed.
        """
        from modules.policies import get_policy, update_policy as _up_raw
        from intent_parser import BatchUpdateIntent, BatchUpdateResult

        batch: BatchUpdateIntent = pc.tool_args.get("_batch_intent")
        if not batch:
            self._pending = None
            return AgentResponse(
                text="Internal error: batch intent missing. Please retry.",
                kind=ResponseKind.ERROR,
            )

        executor    = PolicyUpdateExecutor(
            get_policy_fn=get_policy,
            update_policy_fn=_up_raw,
        )
        results: List[BatchUpdateResult] = []

        for intent in batch.intents:
            capture_policy_snapshot(self.snapshots, intent.policy_id, pc.original_input[:80])
            exec_result = executor.execute(intent)

            log_action(
                action="TOOL_BATCH_UPDATE_POLICY",
                user_input=pc.original_input,
                tool_called="tool_update_policy",
                tool_input=str([
                    (d.op.value, d.field_name, d.values or d.scalar)
                    for d in intent.deltas
                ]),
                result=f"policy_id={intent.policy_id}: {exec_result.message}",
                status="success" if exec_result.success else "error",
            )

            vr = verify_policy_update(
                policy_id=intent.policy_id,
                exec_result=exec_result,
                get_policy_fn=get_policy,
            )

            # Fetch name for display
            try:
                r   = get_policy(intent.policy_id)
                raw = r.get("results", {})
                p   = raw[0] if isinstance(raw, list) and raw else raw if isinstance(raw, dict) else {}
                policy_name = p.get("name", f"ID:{intent.policy_id}")
            except Exception:
                policy_name = f"ID:{intent.policy_id}"

            results.append(BatchUpdateResult(
                policy_id=intent.policy_id,
                policy_name=policy_name,
                success=exec_result.success,
                message=exec_result.message,
                verified=vr.passed,
                verify_detail=vr.fields_checked + vr.mismatches,
            ))

        # Build natural-language response
        answer = self._format_batch_results(batch, results)
        self._record(pc.original_input, answer)
        self._pending = None
        return AgentResponse(text=answer, kind=ResponseKind.ANSWER)



    def _execute_policy_update(self, pc: ConfirmationState) -> AgentResponse:
        """
        Execute a confirmed policy update via read-modify-write.

        Invariant I3: response generated only from post-write verified state.
        """

        from modules.policies import (
            get_policy,
            update_policy as _up_raw,
        )

        intent_obj: Optional[UpdateIntent] = pc.tool_args.get("_update_intent")

        if not intent_obj:
            self._pending = None

            logger.error('"event":"execute_policy_update_no_intent"')

            return AgentResponse(
                text="Internal error: update intent is missing. Please retry.",
                kind=ResponseKind.ERROR,
            )

        # Validation on first confirmation stage
        if pc.is_first:
            validator = VALIDATORS.get("tool_update_policy")

            if validator:
                v = validator({"policy_id": intent_obj.policy_id})

                if not v.valid:
                    self._pending = None

                    return AgentResponse(
                        text=v.format() + "\n\nAction blocked.",
                        kind=ResponseKind.BLOCKED,
                    )

                if v.has_warnings_only():
                    pc.advance_to_second(v.format())

                    return AgentResponse(
                        text=v.format(),
                        kind=ResponseKind.WARNING,
                        pending=True,
                    )

        # Execute read-modify-write
        executor = PolicyUpdateExecutor(
            get_policy_fn=get_policy,
            update_policy_fn=_up_raw,
        )

        capture_policy_snapshot(self.snapshots, intent_obj.policy_id, pc.original_input[:80])

        exec_result = executor.execute(intent_obj)

        log_action(
            action="TOOL_UPDATE_POLICY",
            user_input=pc.original_input,
            tool_called="tool_update_policy",
            tool_input=str([
                (d.op.value, d.field_name, d.values or d.scalar)
                for d in intent_obj.deltas
            ]),
            result=exec_result.message,
            status="success" if exec_result.success else "error",
        )

        # Verify field-by-field regardless of exec_result.success
        vr = verify_policy_update(
            policy_id=intent_obj.policy_id,
            exec_result=exec_result,
            get_policy_fn=get_policy,
        )

        # Response from verified state only — Invariant I3
        answer = _format_verified_update(
            self.llm_plain,
            self.conversation,
            intent_obj,
            exec_result,
            vr,
        )

        full_text = answer + "\n" + vr.format()

        self.ctx.record_write(
            "tool_update_policy",
            str(intent_obj.policy_id),
        )

        self._record(pc.original_input, answer)

        self._pending = None

        return AgentResponse(
            text=full_text,
            kind=ResponseKind.ANSWER,
        )


    # ── Session utilities ──────────────────────────────────────────────────────

    def _record(self, user_input: str, answer: str) -> None:
        """Append a Human/AI turn to conversation history. Invariant I4."""

        self.conversation.append(HumanMessage(content=user_input))
        self.conversation.append(AIMessage(content=answer))

        log_conversation(user_input, answer)


    def _get_recent_history(self) -> List[dict]:
        """Recent conversation turns for NLU context injection (last 3 turns)."""

        history: List[dict] = []

        for msg in self.conversation[-6:]:
            if isinstance(msg, HumanMessage):
                history.append({
                    "role": "user",
                    "content": msg.content[:200],
                })

            elif isinstance(msg, AIMessage):
                history.append({
                    "role": "assistant",
                    "content": msg.content[:200],
                })

        return history


    def _check_noop_enable_disable(
        self,
        tool_args: dict,
    ) -> Tuple[bool, str]:
        """
        Pre-flight: is enable/disable already in the requested state?

        Prevents a pointless confirm → execute → 'already set' cycle.
        Returns (should_skip, user_message).
        """

        pid = tool_args.get("policy_id")
        status = tool_args.get("status")

        if not pid or not status:
            return False, ""

        try:
            from modules.policies import get_policy as _gp

            r = _gp(int(pid))

            raw = r.get("results", {})

            p = (
                raw[0]
                if isinstance(raw, list) and raw
                else raw
                if isinstance(raw, dict)
                else {}
            )

            current = p.get("status")

            if current == status:
                verb = "enabled" if status == "enable" else "disabled"
                name = p.get("name", f"ID:{pid}")

                return (
                    True,
                    (
                        f"Policy '{name}' (ID:{pid}) is already "
                        f"{verb} on FortiGate. No change made."
                    ),
                )

        except Exception as exc:
            logger.debug(
                f'"event":"noop_check_fail","pid":{pid},"error":"{exc}"'
            )

        return False, ""