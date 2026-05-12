"""
nlu_grounder.py — Grounding validator.

Validates every field in RawIntentSchema against live FortiGate state.
This is the trust boundary — hallucinated or invalid values are blocked here.

Key design decisions:
  - current_state : ONLY live FortiGate API data
  - computed      : grounder-derived values (normalised IP, interface casing)
  - grounded_deltas : validated deltas — the ONLY source for execution bridge
  - Never mutates the input RawIntentSchema
  - API unavailability distinguished from entity-not-found
"""
from __future__ import annotations

import logging
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ── Path setup ────────────────────────────────────────────────────────────────
_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR  = os.path.dirname(_AGENT_DIR)
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from nlu_schema import NLUDelta, NLUIntentType, RawIntentSchema

logger = logging.getLogger("fortigate_agent")

# ══════════════════════════════════════════════════════════
#  Valid value registries
# ══════════════════════════════════════════════════════════

_VALID_ACTIONS    = {"accept", "deny"}
_VALID_NAT        = {"enable", "disable"}
_VALID_STATUS     = {"enable", "disable"}
_VALID_LOGTRAFFIC = {"all", "utm", "disable"}
_VALID_DIRECTION  = {"inbound", "outbound", "both"}

_KNOWN_SERVICES: Dict[str, str] = {
    "HTTP": "HTTP", "HTTPS": "HTTPS", "SSL": "HTTPS", "TLS": "HTTPS",
    "FTP": "FTP", "SFTP": "SFTP", "FTPS": "FTPS",
    "SSH": "SSH", "TELNET": "TELNET",
    "DNS": "DNS", "DOMAIN": "DNS",
    "SMTP": "SMTP", "SMTPS": "SMTPS", "MAIL": "SMTP", "EMAIL": "SMTP",
    "POP3": "POP3", "POP3S": "POP3S",
    "IMAP": "IMAP", "IMAPS": "IMAPS",
    "RDP": "RDP", "MSTSC": "RDP",
    "VNC": "VNC",
    "PING": "PING", "ICMP": "PING",
    "SNMP": "SNMP", "SYSLOG": "SYSLOG",
    "NTP": "NTP", "TFTP": "TFTP",
    "LDAP": "LDAP", "LDAPS": "LDAPS",
    "RADIUS": "RADIUS", "TACACS": "TACACS+", "TACACS+": "TACACS+",
    "SIP": "SIP", "H323": "H323",
    "ALL": "ALL", "ANY": "ALL",
}

LIST_FIELDS = {
    "service": {"item_key": "name"},
    "srcaddr": {"item_key": "name"},
    "dstaddr": {"item_key": "name"},
    "srcintf": {"item_key": "name"},
    "dstintf": {"item_key": "name"},
}

_SYSTEM_ADDRESS_EXACT = {
    "all", "none", "FABRIC_DEVICE", "FIREWALL_AUTH_PORTAL_ADDRESS",
}

_SYSTEM_ADDRESS_PREFIXES = (
    "FABRIC_", "FIREWALL_AUTH_PORTAL_", "SSLVPN_TUNNEL_ADDR",
)


def _normalize_service(name: str) -> Optional[str]:
    return _KNOWN_SERVICES.get(name.strip().upper())


def _is_api_error(exc: Exception) -> bool:
    s = str(exc).lower()
    return any(k in s for k in ("connection", "timeout", "refused", "unreachable", "network", "ssl"))


# ══════════════════════════════════════════════════════════
#  Schema types
# ══════════════════════════════════════════════════════════

@dataclass
class GroundingIssue:
    field:   str
    kind:    str   # "not_found" | "invalid_value" | "missing" | "api_unavailable" | "warning"
    message: str
    hint:    str = ""


@dataclass
class GroundedIntentSchema:
    """
    RawIntentSchema after grounding against live FortiGate state.

    current_state : ONLY live FortiGate policy/entity state (GET result).
    computed      : grounder-derived values not from FortiGate API directly
                    (e.g. normalised IP, canonical interface casing).
    grounded_deltas : validated deltas — sole source of truth for execution bridge.
    """
    raw:              RawIntentSchema
    policy_id:        Optional[int]         = None
    policy_display:   str                   = ""
    current_state:    dict                  = field(default_factory=dict)
    computed:         dict                  = field(default_factory=dict)
    grounded_deltas:  List[NLUDelta]        = field(default_factory=list)
    is_noop:          bool                  = False
    noop_message:     str                   = ""
    is_valid:         bool                  = False
    issues:           List[GroundingIssue]  = field(default_factory=list)

    def has_errors(self) -> bool:
        return any(
            i.kind in ("not_found", "invalid_value", "missing", "api_unavailable")
            for i in self.issues
        )

    def error_messages(self) -> List[str]:
        return [
            i.message + (f"\n  Hint: {i.hint}" if i.hint else "")
            for i in self.issues
            if i.kind in ("not_found", "invalid_value", "missing", "api_unavailable")
        ]

    def warning_messages(self) -> List[str]:
        return [i.message for i in self.issues if i.kind == "warning"]


@dataclass
class MultiPolicyGroundingResult:
    """
    Result of grounding a multi-policy intent.
    Each policy is grounded independently.
    """
    schema:           RawIntentSchema
    grounded_intents: List[GroundedIntentSchema]
    failed_policies:  List[str]
    shared_deltas:    List[NLUDelta]
    is_valid:         bool
    issues:           List[GroundingIssue] = field(default_factory=list)


# ══════════════════════════════════════════════════════════
#  Main grounder
# ══════════════════════════════════════════════════════════

def ground(schema: RawIntentSchema) -> GroundedIntentSchema:
    """
    Ground a RawIntentSchema against live FortiGate state.
    Never raises. Never mutates input schema.
    """
    result = GroundedIntentSchema(raw=schema)
    issues: List[GroundingIssue] = []
    intent = schema.intent

    logger.debug(
        f'"event":"grounding_start","intent":"{intent.value}",'
        f'"policy_id":{schema.policy_id},"deltas":{len(schema.deltas)}'
    )

    try:
        if intent in (
            NLUIntentType.UPDATE_POLICY,
            NLUIntentType.DELETE_POLICY,
            NLUIntentType.ENABLE_POLICY,
            NLUIntentType.DISABLE_POLICY,
            NLUIntentType.MOVE_POLICY,
        ):
            _ground_policy_ref(schema, result, issues)
            if not result.has_errors() and intent == NLUIntentType.UPDATE_POLICY:
                if not result.current_state:
                    issues.append(GroundingIssue(
                        field="current_state", kind="api_unavailable",
                        message="Could not fetch current policy state for delta validation.",
                    ))
                else:
                    _ground_update_deltas(schema, result, issues)
            if not result.has_errors() and intent == NLUIntentType.MOVE_POLICY:
                _ground_move_params(schema, result, issues)

        elif intent == NLUIntentType.CREATE_POLICY:
            _ground_create_policy(schema, result, issues)

        elif intent == NLUIntentType.CREATE_ADDRESS:
            _ground_create_address(schema, result, issues)

        elif intent == NLUIntentType.DELETE_ADDRESS:
            _ground_delete_address(schema, result, issues)

        elif intent == NLUIntentType.UPDATE_INTERFACE:
            _ground_interface(schema, result, issues)

        elif intent == NLUIntentType.BLOCK_IP:
            _ground_block_ip(schema, result, issues)

        elif intent == NLUIntentType.BACKUP_CONFIG:
            result.is_valid = True
            result.issues   = []
            return result

        elif intent in (NLUIntentType.AMBIGUOUS, NLUIntentType.INCOMPLETE):
            result.is_valid = False
            result.issues   = [GroundingIssue(
                field="intent", kind="missing",
                message="Intent is ambiguous or incomplete — requires clarification.",
            )]
            return result

        else:
            issues.append(GroundingIssue(
                field="intent", kind="invalid_value",
                message=f"Unknown intent type: {intent.value}",
            ))

    except Exception as exc:
        logger.error(
            f'"event":"grounding_crash","intent":"{intent.value}","error":"{exc}"',
            exc_info=True,
        )
        issues.append(GroundingIssue(
            field="system", kind="api_unavailable",
            message=f"Grounding failed unexpectedly: {exc}",
        ))

    result.issues   = issues
    result.is_valid = not result.has_errors()

    logger.debug(
        f'"event":"grounding_complete","is_valid":{result.is_valid},'
        f'"is_noop":{result.is_noop},"issues":{len(issues)},'
        f'"grounded_deltas":{len(result.grounded_deltas)}'
    )
    return result


def ground_multi(schema: RawIntentSchema) -> MultiPolicyGroundingResult:
    """
    Ground a multi-policy intent against live FortiGate state.

    Resolves all policy references to concrete IDs, then grounds each
    policy independently. Partial failures are collected without blocking
    the valid policies.
    """
    result = MultiPolicyGroundingResult(
        schema=schema,
        grounded_intents=[],
        failed_policies=[],
        shared_deltas=[],
        is_valid=False,
    )

    # ── Collect all target policy IDs ─────────────────────
    target_ids:   List[int] = list(schema.policy_ids)
    target_names: List[str] = list(schema.policy_names)

    if target_names:
        try:
            from modules.policies import list_policies
            r       = list_policies()
            results = r if isinstance(r, list) else r.get("results", [])
            name_map: Dict[str, int] = {
                p.get("name", "").lower(): p.get("policyid")
                for p in results
            }
            for name in target_names:
                pid = name_map.get(name.lower())
                if pid:
                    if pid not in target_ids:
                        target_ids.append(pid)
                else:
                    matches = [v for k, v in name_map.items() if name.lower() in k]
                    if len(matches) == 1:
                        if matches[0] not in target_ids:
                            target_ids.append(matches[0])
                    else:
                        result.failed_policies.append(f"'{name}' (not found)")
        except Exception as exc:
            result.issues.append(GroundingIssue(
                field="policy_names", kind="api_unavailable",
                message=f"Could not resolve policy names: {exc}",
            ))

    if not target_ids:
        result.issues.append(GroundingIssue(
            field="policy_ids", kind="missing",
            message="No specific policies identified. Please specify policy IDs or names.",
            hint="Example: enable nat in policy 3 and policy 4",
        ))
        return result

    # ── Ground each policy independently ──────────────────
    first_valid: Optional[GroundedIntentSchema] = None

    for pid in target_ids:
        single_schema = RawIntentSchema(
            intent=schema.intent,
            confidence=schema.confidence,
            policy_id=pid,
            deltas=list(schema.deltas),
            raw_input=schema.raw_input,
        )
        grounded = ground(single_schema)

        if grounded.is_valid:
            result.grounded_intents.append(grounded)
            if first_valid is None:
                first_valid         = grounded
                result.shared_deltas = grounded.grounded_deltas
        else:
            result.failed_policies.append(str(pid))
            result.issues.extend(grounded.issues)

    result.is_valid = len(result.grounded_intents) > 0
    return result


# ══════════════════════════════════════════════════════════
#  Per-intent grounders
# ══════════════════════════════════════════════════════════

def _ground_policy_ref(
    schema: RawIntentSchema,
    result: GroundedIntentSchema,
    issues: List[GroundingIssue],
) -> None:
    from modules.policies import list_policies, get_policy

    pid = schema.policy_id

    if not pid and schema.policy_name:
        try:
            r       = list_policies()
            results = r if isinstance(r, list) else r.get("results", [])
            name_l  = schema.policy_name.lower()
            for p in results:
                if p.get("name", "").lower() == name_l:
                    pid = p.get("policyid")
                    break
            if not pid:
                matches = [p for p in results if name_l in p.get("name", "").lower()]
                if len(matches) == 1:
                    pid = matches[0].get("policyid")
                elif len(matches) > 1:
                    names = ", ".join(
                        f"{m.get('name')} (ID:{m.get('policyid')})" for m in matches
                    )
                    issues.append(GroundingIssue(
                        field="policy_name", kind="not_found",
                        message=f"Multiple policies match '{schema.policy_name}': {names}",
                        hint="Please specify the exact policy ID.",
                    ))
                    return
        except Exception as exc:
            kind = "api_unavailable" if _is_api_error(exc) else "not_found"
            issues.append(GroundingIssue(
                field="policy_name", kind=kind,
                message=(
                    "Could not reach FortiGate to search for policy."
                    if kind == "api_unavailable" else
                    f"Could not search for policy '{schema.policy_name}': {exc}"
                ),
            ))
            return

    if not pid:
        issues.append(GroundingIssue(
            field="policy_id", kind="missing",
            message="No policy specified.",
            hint="Provide the policy ID or name. Use 'list all policies' to see options.",
        ))
        return

    try:
        r   = get_policy(int(pid))
        raw = r.get("results", {})
        p   = (
            raw[0] if isinstance(raw, list) and raw else
            raw if isinstance(raw, dict) and raw else None
        )
        if not p:
            issues.append(GroundingIssue(
                field="policy_id", kind="not_found",
                message=f"Policy ID {pid} does not exist on this FortiGate.",
                hint="Use 'list all policies' to see available policies.",
            ))
            return

        result.policy_id      = int(pid)
        result.policy_display = f"{p.get('name', '?')} (ID: {pid})"
        result.current_state  = dict(p)
        logger.debug(f'"event":"policy_ref_resolved","id":{pid},"name":"{p.get("name")}"')

    except Exception as exc:
        kind = "api_unavailable" if _is_api_error(exc) else "not_found"
        issues.append(GroundingIssue(
            field="policy_id", kind=kind,
            message=(
                "Could not reach FortiGate to verify the policy. Please check the connection."
                if kind == "api_unavailable" else
                f"Could not verify policy ID {pid}: {exc}"
            ),
        ))


def _ground_update_deltas(
    schema: RawIntentSchema,
    result: GroundedIntentSchema,
    issues: List[GroundingIssue],
) -> None:
    current         = result.current_state
    noop_messages:  List[str]    = []
    valid_deltas:   List[NLUDelta] = []

    for delta in schema.deltas:
        f  = delta.field
        op = delta.op
        v  = delta.value

        if f == "action":
            if str(v).lower() not in _VALID_ACTIONS:
                issues.append(GroundingIssue(
                    field="action", kind="invalid_value",
                    message=f"'{v}' is not valid for action.",
                    hint="Valid values: accept or deny",
                ))
                continue
            if str(current.get("action", "")).lower() == str(v).lower():
                noop_messages.append(f"action is already '{v}'")
                continue
            valid_deltas.append(delta)

        elif f == "nat":
            if str(v).lower() not in _VALID_NAT:
                issues.append(GroundingIssue(
                    field="nat", kind="invalid_value",
                    message=f"'{v}' is not valid for nat.",
                    hint="Valid values: enable or disable",
                ))
                continue
            if str(current.get("nat", "disable")).lower() == str(v).lower():
                noop_messages.append(f"nat is already '{v}'")
                continue
            valid_deltas.append(delta)

        elif f == "status":
            if str(v).lower() not in _VALID_STATUS:
                issues.append(GroundingIssue(
                    field="status", kind="invalid_value",
                    message=f"'{v}' is not valid for status.",
                    hint="Valid values: enable or disable",
                ))
                continue
            if str(current.get("status", "enable")).lower() == str(v).lower():
                noop_messages.append(f"status is already '{v}'")
                continue
            valid_deltas.append(delta)

        elif f == "logtraffic":
            if str(v).lower() not in _VALID_LOGTRAFFIC:
                issues.append(GroundingIssue(
                    field="logtraffic", kind="invalid_value",
                    message=f"'{v}' is not valid for logtraffic.",
                    hint="Valid values: all, utm, disable",
                ))
                continue
            if str(current.get("logtraffic", "utm")).lower() == str(v).lower():
                noop_messages.append(f"logtraffic is already '{v}'")
                continue
            valid_deltas.append(delta)

        elif f == "service":
            raw_values = [v] if isinstance(v, str) else list(v)
            normalized: List[str] = []
            for sv in raw_values:
                n = _normalize_service(str(sv))
                if n is None:
                    issues.append(GroundingIssue(
                        field="service", kind="invalid_value",
                        message=f"'{sv}' is not a recognized service name.",
                        hint="Known: SSH, HTTPS, HTTP, FTP, DNS, RDP, PING, SMTP, ALL",
                    ))
                else:
                    normalized.append(n)
            if not normalized:
                continue
            item_key    = LIST_FIELDS["service"]["item_key"]
            current_svc = {
                str(item.get(item_key, "")).upper()
                for item in current.get("service", [])
            }
            delta_set = {s.upper() for s in normalized}
            noop = False
            if op == "add" and delta_set.issubset(current_svc):
                noop_messages.append(
                    f"{', '.join(sorted(normalized))} already in services "
                    f"(current: {', '.join(sorted(current_svc))})"
                )
                noop = True
            elif op == "remove" and not delta_set.intersection(current_svc):
                noop_messages.append(
                    f"{', '.join(sorted(normalized))} not found in services "
                    f"(current: {', '.join(sorted(current_svc))})"
                )
                noop = True
            elif op == "replace" and delta_set == current_svc:
                noop_messages.append(f"services already set to {', '.join(sorted(delta_set))}")
                noop = True
            if not noop:
                valid_deltas.append(NLUDelta(
                    field=f, op=op, value=normalized, confidence=delta.confidence,
                ))
        else:
            issues.append(GroundingIssue(
                field=f, kind="invalid_value",
                message=f"'{f}' is not a recognized policy field.",
                hint="Valid fields: action, nat, status, logtraffic, service",
            ))

    result.grounded_deltas = valid_deltas
    if noop_messages and not valid_deltas and not issues:
        result.is_noop      = True
        result.noop_message = (
            f"No changes needed for policy {result.policy_display}:\n"
            + "\n".join(f"  {m}" for m in noop_messages)
        )


def _ground_move_params(
    schema: RawIntentSchema,
    result: GroundedIntentSchema,
    issues: List[GroundingIssue],
) -> None:
    from modules.policies import get_policy as _gp

    if not schema.move_action or schema.move_action not in ("before", "after"):
        issues.append(GroundingIssue(
            field="move_action", kind="missing",
            message="Please specify 'before' or 'after'.",
        ))

    if not schema.neighbor_id:
        issues.append(GroundingIssue(
            field="neighbor_id", kind="missing",
            message="Please specify which policy to move relative to.",
            hint="Example: move policy 4 before policy 3",
        ))
        return

    try:
        r   = _gp(int(schema.neighbor_id))
        raw = r.get("results", {})
        p   = (
            raw[0] if isinstance(raw, list) and raw else
            raw if isinstance(raw, dict) and raw else None
        )
        if not p:
            issues.append(GroundingIssue(
                field="neighbor_id", kind="not_found",
                message=f"Reference policy ID {schema.neighbor_id} does not exist.",
            ))
    except Exception as exc:
        kind = "api_unavailable" if _is_api_error(exc) else "not_found"
        issues.append(GroundingIssue(
            field="neighbor_id", kind=kind,
            message=(
                "Could not reach FortiGate to verify the reference policy."
                if kind == "api_unavailable" else
                f"Could not verify reference policy ID {schema.neighbor_id}: {exc}"
            ),
        ))


def _ground_create_policy(
    schema: RawIntentSchema,
    result: GroundedIntentSchema,
    issues: List[GroundingIssue],
) -> None:
    from modules.interfaces import list_interfaces

    cp = schema.create_params or {}
    for f in ("name", "srcintf", "dstintf"):
        if not cp.get(f):
            issues.append(GroundingIssue(
                field=f, kind="missing",
                message=f"Policy '{f}' is required for creation.",
            ))

    if cp.get("action") and cp["action"].lower() not in _VALID_ACTIONS:
        issues.append(GroundingIssue(
            field="action", kind="invalid_value",
            message=f"'{cp['action']}' is not valid. Use 'accept' or 'deny'.",
        ))

    try:
        r       = list_interfaces()
        results = r if isinstance(r, list) else r.get("results", [])
        ifaces_ci = {i.get("name", "").lower(): i.get("name", "") for i in results}

        for f in ("srcintf", "dstintf"):
            val = cp.get(f, "")
            if not val:
                continue
            val_l = val.lower()
            if val_l in ifaces_ci:
                cp[f] = ifaces_ci[val_l]
            elif val.lower() not in ("any", "all"):
                issues.append(GroundingIssue(
                    field=f, kind="not_found",
                    message=f"Interface '{val}' not found on this FortiGate.",
                    hint="Available: " + ", ".join(list(ifaces_ci.values())[:6]),
                ))
    except Exception as exc:
        if _is_api_error(exc):
            issues.append(GroundingIssue(
                field="srcintf", kind="api_unavailable",
                message="Could not reach FortiGate to validate interfaces.",
            ))
        else:
            logger.warning(f'"event":"interface_validation_fail","error":"{exc}"')

    result.is_valid = not result.has_errors()


def _ground_create_address(
    schema: RawIntentSchema,
    result: GroundedIntentSchema,
    issues: List[GroundingIssue],
) -> None:
    if not schema.address_name:
        issues.append(GroundingIssue(
            field="address_name", kind="missing",
            message="Address object name is required.",
            hint="Example: create address WebServer 192.168.10.50/32",
        ))
    subnet = (schema.create_params or {}).get("subnet", "")
    if not subnet:
        issues.append(GroundingIssue(
            field="subnet", kind="missing",
            message="Subnet is required in CIDR notation.",
            hint="Example: 192.168.1.0/24 or 10.0.0.1/32",
        ))
    elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", subnet):
        issues.append(GroundingIssue(
            field="subnet", kind="invalid_value",
            message=f"'{subnet}' is not valid CIDR notation.",
            hint="Use format like 192.168.1.0/24 or 10.0.0.1/32",
        ))
    result.is_valid = not result.has_errors()


def _ground_delete_address(
    schema: RawIntentSchema,
    result: GroundedIntentSchema,
    issues: List[GroundingIssue],
) -> None:
    from modules.addresses import list_addresses

    if not schema.address_name:
        issues.append(GroundingIssue(
            field="address_name", kind="missing",
            message="Please specify the address object name to delete.",
        ))
        return

    # System object protection
    if (
        schema.address_name in _SYSTEM_ADDRESS_EXACT
        or any(schema.address_name.startswith(p) for p in _SYSTEM_ADDRESS_PREFIXES)
    ):
        issues.append(GroundingIssue(
            field="address_name", kind="invalid_value",
            message=f"'{schema.address_name}' is a system-managed object and cannot be deleted.",
            hint="Only user-created address objects can be deleted.",
        ))
        result.is_valid = False
        return

    try:
        r       = list_addresses()
        results = r if isinstance(r, list) else r.get("results", [])
        names   = {a.get("name", "").lower(): a.get("name", "") for a in results}
        if schema.address_name.lower() not in names:
            close = [n for n in names.values() if schema.address_name.lower() in n.lower()]
            hint  = f"Did you mean: {', '.join(close[:3])}?" if close else ""
            issues.append(GroundingIssue(
                field="address_name", kind="not_found",
                message=f"Address object '{schema.address_name}' does not exist.",
                hint=hint,
            ))
    except Exception as exc:
        kind = "api_unavailable" if _is_api_error(exc) else "not_found"
        issues.append(GroundingIssue(
            field="address_name", kind=kind,
            message=(
                "Could not reach FortiGate to verify the address object."
                if kind == "api_unavailable" else
                f"Could not verify address '{schema.address_name}': {exc}"
            ),
        ))

    result.is_valid = not result.has_errors()


def _ground_interface(
    schema: RawIntentSchema,
    result: GroundedIntentSchema,
    issues: List[GroundingIssue],
) -> None:
    from modules.interfaces import list_interfaces

    if not schema.interface_name:
        issues.append(GroundingIssue(
            field="interface_name", kind="missing",
            message="Please specify the interface name.",
            hint="Example: disable HTTP and TELNET on port2",
        ))
        return

    try:
        r       = list_interfaces()
        results = r if isinstance(r, list) else r.get("results", [])
        ifaces_ci = {i.get("name", "").lower(): i.get("name", "") for i in results}
        if schema.interface_name.lower() in ifaces_ci:
            result.computed["canonical_interface"] = ifaces_ci[schema.interface_name.lower()]
        else:
            issues.append(GroundingIssue(
                field="interface_name", kind="not_found",
                message=f"Interface '{schema.interface_name}' not found on this FortiGate.",
                hint="Available: " + ", ".join(list(ifaces_ci.values())[:6]),
            ))
    except Exception as exc:
        kind = "api_unavailable" if _is_api_error(exc) else "not_found"
        issues.append(GroundingIssue(
            field="interface_name", kind=kind,
            message=(
                "Could not reach FortiGate to validate the interface."
                if kind == "api_unavailable" else
                f"Could not verify interface '{schema.interface_name}': {exc}"
            ),
        ))

    if not (schema.create_params or {}).get("allowaccess", ""):
        issues.append(GroundingIssue(
            field="allowaccess", kind="missing",
            message="Please specify which protocols to allow.",
            hint="Example: https ssh ping",
        ))
    result.is_valid = not result.has_errors()


def _ground_block_ip(
    schema: RawIntentSchema,
    result: GroundedIntentSchema,
    issues: List[GroundingIssue],
) -> None:
    if not schema.ip_address:
        issues.append(GroundingIssue(
            field="ip_address", kind="missing",
            message="Please provide the IP address to block.",
            hint="Example: block ip 192.168.1.55",
        ))
        return

    ip = schema.ip_address.strip()
    if "/" not in ip:
        ip = ip + "/32"
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", ip):
        issues.append(GroundingIssue(
            field="ip_address", kind="invalid_value",
            message=f"'{schema.ip_address}' is not a valid IP address.",
        ))
        return

    direction = schema.direction or "both"
    if direction not in _VALID_DIRECTION:
        direction = "both"

    # Store in computed (NOT current_state which holds live FortiGate data)
    result.computed["grounded_ip"]        = ip
    result.computed["grounded_direction"] = direction
    result.is_valid = True