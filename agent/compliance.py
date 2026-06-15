"""
compliance.py

Deterministic compliance and security posture engine.

ARCHITECTURE:
    - Zero LLM involvement — all findings are deterministic rule evaluations
    - Structured findings with rule_id, severity, resource, finding, risk, remediation
    - Rules are additive — new rules can be added without modifying existing ones
    - Results are always reproducible given the same FortiGate state

SEVERITY LEVELS:
    CRITICAL  — immediate exploitation risk or management lockout risk
    HIGH      — significant security weakness requiring prompt attention
    MEDIUM    — security best-practice violation
    LOW       — configuration hygiene issue
    INFO      — informational observation, no action required

RULE CATALOGUE:
    Policy rules:
        POL-001  ANY → ANY ACCEPT with ALL services (permissive default)
        POL-002  TELNET service in accept policy
        POL-003  Logging disabled on accept policy
        POL-004  Disabled policy (review for cleanup)
        POL-005  Shadowed policy (later deny after earlier accept of same path)
        POL-006  ACCEPT from 0.0.0.0/any on remote-access services (RDP/SSH/TELNET)

    Interface rules:
        INTF-001  HTTP or TELNET in allowaccess (cleartext management)

    Route rules:
        ROUTE-001  Multiple default routes (potential routing ambiguity)

    User rules:
        USER-001  User account with status=disable (orphaned account)
"""
import logging
from dataclasses import dataclass, field as dc_field
from typing import List, Dict, Any, Optional

logger = logging.getLogger("fortigate_agent")


# ══════════════════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class ComplianceFinding:
    rule_id:     str   # e.g. "POL-001"
    severity:    str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    resource:    str   # human-readable resource (e.g. "Policy 4 (test1)")
    finding:     str   # what was found
    risk:        str   # what the risk is
    remediation: str   # what to do about it


@dataclass
class ComplianceReport:
    findings:  List[ComplianceFinding] = dc_field(default_factory=list)
    errors:    List[str]               = dc_field(default_factory=list)

    def add(self, finding: ComplianceFinding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> List[ComplianceFinding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule_id)
        )

    def counts_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def format(self) -> str:
        if not self.findings and not self.errors:
            return (
                "Compliance check passed — no findings.\n"
                "All evaluated rules returned no violations."
            )

        lines = []

        counts = self.counts_by_severity()
        summary_parts = [
            f"{counts[s]} {s}" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            if counts.get(s)
        ]
        lines.append(f"Compliance Report: {len(self.findings)} finding(s) — {', '.join(summary_parts)}")
        lines.append("=" * 70)
        lines.append("")

        for f in self.sorted_findings():
            lines.append(f"[{f.severity:<8}] [{f.rule_id}] {f.resource}")
            lines.append(f"  Finding    : {f.finding}")
            lines.append(f"  Risk       : {f.risk}")
            lines.append(f"  Remediation: {f.remediation}")
            lines.append("")

        if self.errors:
            lines.append("─" * 70)
            lines.append("Evaluation errors (partial results):")
            for e in self.errors:
                lines.append(f"  [WARN] {e}")

        return "\n".join(lines).rstrip()


# ══════════════════════════════════════════════════════════════════════════════
#  Data loaders
# ══════════════════════════════════════════════════════════════════════════════

def _load_policies() -> tuple:
    """Returns (policies_list, error_msg_or_None)."""
    try:
        from modules.policies import list_policies
        r = list_policies()
        return (r if isinstance(r, list) else r.get("results", [])), None
    except Exception as exc:
        return [], f"Could not load policies: {exc}"


def _load_interfaces() -> tuple:
    try:
        from modules.interfaces import list_interfaces
        r = list_interfaces()
        return (r if isinstance(r, list) else r.get("results", [])), None
    except Exception as exc:
        return [], f"Could not load interfaces: {exc}"


def _load_routes() -> tuple:
    try:
        from modules.routing import list_routes
        r = list_routes()
        return (r if isinstance(r, list) else r.get("results", [])), None
    except Exception as exc:
        return [], f"Could not load routes: {exc}"


def _load_users() -> tuple:
    try:
        from modules.users import list_users
        r = list_users()
        return (r if isinstance(r, list) else r.get("results", [])), None
    except Exception as exc:
        return [], f"Could not load users: {exc}"


# ══════════════════════════════════════════════════════════════════════════════
#  Policy rules
# ══════════════════════════════════════════════════════════════════════════════

_REMOTE_ACCESS_SERVICES = {"SSH", "RDP", "TELNET", "VNC"}


def _p_resource(p: dict) -> str:
    pid  = p.get("policyid", "?")
    name = p.get("name",     "?")
    return f"Policy {pid} ({name})"


def _svc_names(p: dict) -> set:
    return {s.get("name", "").upper() for s in (p.get("service") or [])}


def _addr_names(p: dict, field: str) -> set:
    return {a.get("name", "").lower() for a in (p.get(field) or [])}


def _intf_names(p: dict, field: str) -> set:
    return {i.get("name", "").lower() for i in (p.get(field) or [])}


def _check_pol001(p: dict) -> Optional[ComplianceFinding]:
    """POL-001: Fully permissive ACCEPT — ANY → ANY on ALL services."""
    if p.get("action") != "accept":
        return None
    svcs  = _svc_names(p)
    srcs  = _addr_names(p, "srcaddr")
    dsts  = _addr_names(p, "dstaddr")
    if "ALL" in svcs and "all" in srcs and "all" in dsts:
        return ComplianceFinding(
            rule_id="POL-001", severity="CRITICAL",
            resource=_p_resource(p),
            finding="Action=ACCEPT with service=ALL, srcaddr=all, dstaddr=all.",
            risk="Any host can reach any destination on any protocol. Equivalent to no firewall.",
            remediation=(
                "Replace 'all' srcaddr with a specific address object. "
                "Replace 'ALL' service with only required services. "
                "Replace 'all' dstaddr with specific destination objects."
            ),
        )
    return None


def _check_pol002(p: dict) -> Optional[ComplianceFinding]:
    """POL-002: TELNET allowed in an ACCEPT policy."""
    if p.get("action") != "accept":
        return None
    if "TELNET" in _svc_names(p):
        return ComplianceFinding(
            rule_id="POL-002", severity="HIGH",
            resource=_p_resource(p),
            finding="Service TELNET is allowed in an ACCEPT policy.",
            risk="TELNET transmits all data including credentials in cleartext over the network.",
            remediation="Replace TELNET with SSH. If TELNET is required, restrict srcaddr to trusted management hosts only.",
        )
    return None


def _check_pol003(p: dict) -> Optional[ComplianceFinding]:
    """POL-003: Logging disabled on non-deny policy."""
    if p.get("action") == "deny":
        return None
    if p.get("logtraffic", "all") == "disable":
        return ComplianceFinding(
            rule_id="POL-003", severity="MEDIUM",
            resource=_p_resource(p),
            finding="logtraffic=disable — no traffic is being logged for this policy.",
            risk="Accepted traffic leaves no audit trail. Impossible to detect data exfiltration or lateral movement.",
            remediation="Set logtraffic to 'all' or at minimum 'utm' to retain visibility.",
        )
    return None


def _check_pol004(p: dict) -> Optional[ComplianceFinding]:
    """POL-004: Policy is disabled (review for cleanup)."""
    if p.get("status") == "disable":
        return ComplianceFinding(
            rule_id="POL-004", severity="LOW",
            resource=_p_resource(p),
            finding="Policy is disabled and not being evaluated.",
            risk="Disabled policies accumulate over time, adding complexity and confusion to the ruleset.",
            remediation="Review this policy. If it is no longer needed, delete it to keep the ruleset clean.",
        )
    return None


def _check_pol005(policies: list) -> List[ComplianceFinding]:
    """POL-005: Shadowed policy — a deny rule after a broader accept for the same path."""
    findings = []
    for i, p in enumerate(policies):
        if p.get("action") != "deny":
            continue
        p_srcs  = _addr_names(p, "srcaddr")
        p_dsts  = _addr_names(p, "dstaddr")
        p_svcs  = _svc_names(p)
        p_sints = _intf_names(p, "srcintf")
        p_dints = _intf_names(p, "dstintf")
        # Check if any earlier policy fully covers this deny
        for earlier in policies[:i]:
            if earlier.get("action") != "accept":
                continue
            if earlier.get("status") == "disable":
                continue
            e_srcs  = _addr_names(earlier, "srcaddr")
            e_dsts  = _addr_names(earlier, "dstaddr")
            e_svcs  = _svc_names(earlier)
            e_sints = _intf_names(earlier, "srcintf")
            e_dints = _intf_names(earlier, "dstintf")
            same_path = (
                (p_sints <= e_sints or "any" in e_sints) and
                (p_dints <= e_dints or "any" in e_dints) and
                ("all" in e_srcs or p_srcs <= e_srcs) and
                ("all" in e_dsts or p_dsts <= e_dsts) and
                ("ALL" in e_svcs or p_svcs <= e_svcs)
            )
            if same_path:
                findings.append(ComplianceFinding(
                    rule_id="POL-005", severity="HIGH",
                    resource=_p_resource(p),
                    finding=(
                        f"This DENY policy is shadowed by earlier ACCEPT policy "
                        f"{earlier.get('policyid', '?')} ({earlier.get('name', '?')}). "
                        f"FortiGate matches top-down — this deny is never reached."
                    ),
                    risk="The deny rule has no effect. Traffic you believe is blocked is actually permitted.",
                    remediation=(
                        f"Move this DENY policy above policy ID {earlier.get('policyid', '?')}, "
                        f"or restrict the overlapping ACCEPT policy."
                    ),
                ))
                break  # one finding per shadowed policy is enough
    return findings


def _check_pol006(p: dict) -> Optional[ComplianceFinding]:
    """POL-006: Remote-access service (SSH/RDP/TELNET) from any source."""
    if p.get("action") != "accept":
        return None
    svcs = _svc_names(p)
    srcs = _addr_names(p, "srcaddr")
    remote_matches = svcs & _REMOTE_ACCESS_SERVICES
    if remote_matches and "all" in srcs:
        svc_str = ", ".join(sorted(remote_matches))
        return ComplianceFinding(
            rule_id="POL-006", severity="HIGH",
            resource=_p_resource(p),
            finding=f"Remote-access service(s) {svc_str} are allowed from ANY source address.",
            risk="Exposes remote access protocols to the entire internet. High risk of brute-force or exploitation.",
            remediation=(
                "Create an address object containing only trusted admin IPs and use it as srcaddr. "
                "Never expose SSH/RDP/TELNET to 0.0.0.0/any."
            ),
        )
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  Interface rules
# ══════════════════════════════════════════════════════════════════════════════

def _check_intf001(iface: dict) -> Optional[ComplianceFinding]:
    """INTF-001: HTTP or TELNET in interface management allowaccess."""
    access   = str(iface.get("allowaccess", "")).lower()
    insecure = []
    if "http"   in access.split(): insecure.append("HTTP")
    if "telnet" in access.split(): insecure.append("TELNET")
    if insecure:
        name = iface.get("name", "?")
        return ComplianceFinding(
            rule_id="INTF-001", severity="HIGH",
            resource=f"Interface {name}",
            finding=f"Management protocols {', '.join(insecure)} are enabled on this interface.",
            risk=f"{', '.join(insecure)} transmit credentials in cleartext. An attacker on the network can capture admin passwords.",
            remediation=f"Disable {', '.join(insecure)} management access. Use HTTPS and SSH only.",
        )
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  Route rules
# ══════════════════════════════════════════════════════════════════════════════

def _check_route001(routes: list) -> Optional[ComplianceFinding]:
    """ROUTE-001: Multiple default routes (0.0.0.0)."""
    defaults = [
        r for r in routes
        if str(r.get("dst", "")).startswith("0.0.0.0")
    ]
    if len(defaults) > 1:
        gateways = [r.get("gateway", "?") for r in defaults]
        return ComplianceFinding(
            rule_id="ROUTE-001", severity="MEDIUM",
            resource="Routing Table",
            finding=f"Multiple default routes detected ({len(defaults)}): gateways {gateways}.",
            risk="Asymmetric routing or unpredictable failover. Traffic may exit from an unexpected interface.",
            remediation="Use a single default route with appropriate distance/priority values for failover.",
        )
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  User rules
# ══════════════════════════════════════════════════════════════════════════════

def _check_user001(user: dict) -> Optional[ComplianceFinding]:
    """USER-001: Disabled user account (orphaned)."""
    if user.get("status") == "disable":
        name = user.get("name", "?")
        return ComplianceFinding(
            rule_id="USER-001", severity="LOW",
            resource=f"User account '{name}'",
            finding="User account is disabled.",
            risk="Disabled accounts accumulate and create confusion. They may be re-enabled accidentally.",
            remediation="If this account is permanently decommissioned, delete it.",
        )
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  Main compliance runner
# ══════════════════════════════════════════════════════════════════════════════

def run_compliance_check(scope: str = "full") -> ComplianceReport:
    """
    Execute all compliance rules and return a structured ComplianceReport.

    scope:
        "full"       — all resource types
        "policies"   — policies only
        "interfaces" — interfaces only
        "routes"     — routes only
        "users"      — users only
    """
    report = ComplianceReport()

    # ── Policies ──────────────────────────────────────────────────────────────
    if scope in ("full", "policies"):
        policies, err = _load_policies()
        if err:
            report.errors.append(err)
        else:
            for p in policies:
                for check_fn in [_check_pol001, _check_pol002, _check_pol003,
                                  _check_pol004, _check_pol006]:
                    finding = check_fn(p)
                    if finding:
                        report.add(finding)
            # Batch rule (needs full policy list)
            for finding in _check_pol005(policies):
                report.add(finding)

    # ── Interfaces ────────────────────────────────────────────────────────────
    if scope in ("full", "interfaces"):
        interfaces, err = _load_interfaces()
        if err:
            report.errors.append(err)
        else:
            for iface in interfaces:
                finding = _check_intf001(iface)
                if finding:
                    report.add(finding)

    # ── Routes ────────────────────────────────────────────────────────────────
    if scope in ("full", "routes"):
        routes, err = _load_routes()
        if err:
            report.errors.append(err)
        else:
            finding = _check_route001(routes)
            if finding:
                report.add(finding)

    # ── Users ─────────────────────────────────────────────────────────────────
    if scope in ("full", "users"):
        users, err = _load_users()
        if err:
            report.errors.append(err)
        else:
            for user in users:
                finding = _check_user001(user)
                if finding:
                    report.add(finding)

    logger.info(
        f'"event":"compliance_check_complete",'
        f'"scope":"{scope}",'
        f'"findings":{len(report.findings)},'
        f'"errors":{len(report.errors)}'
    )
    return report

