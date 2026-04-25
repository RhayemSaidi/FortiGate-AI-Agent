import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.policies import list_policies
from modules.addresses import list_addresses
from modules.interfaces import list_interfaces
from modules.monitor import get_cpu_usage, get_memory_usage
from modules.system import get_system_status


class SecurityInsight:
    """Represents a single security finding."""

    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH     = "HIGH"
    SEVERITY_MEDIUM   = "MEDIUM"
    SEVERITY_LOW      = "LOW"
    SEVERITY_INFO     = "INFO"

    def __init__(self, severity: str, category: str,
                 title: str, description: str, recommendation: str,
                 affected_object: str = ""):
        self.severity = severity
        self.category = category
        self.title = title
        self.description = description
        self.recommendation = recommendation
        self.affected_object = affected_object

    def format(self) -> str:
        severity_labels = {
            "CRITICAL": "[CRITICAL]",
            "HIGH":     "[HIGH]    ",
            "MEDIUM":   "[MEDIUM]  ",
            "LOW":      "[LOW]     ",
            "INFO":     "[INFO]    ",
        }
        label = severity_labels.get(self.severity, "[UNKNOWN] ")
        lines = [
            f"{label} {self.title}",
            f"           Category   : {self.category}",
            f"           Object     : {self.affected_object}" if self.affected_object else "",
            f"           Issue      : {self.description}",
            f"           Fix        : {self.recommendation}",
        ]
        return "\n".join(l for l in lines if l)


class FirewallAnalyzer:
    """
    Analyzes FortiGate configuration for security issues,
    misconfigurations, conflicts, and best practice violations.
    """

    def __init__(self):
        self.insights = []
        self.policies = []
        self.addresses = []
        self.interfaces = []
        self.errors = []

    def _load_data(self):
        """Load all required data from FortiGate."""
        try:
            r = list_policies()
            self.policies = r if isinstance(r, list) else r.get("results", [])
        except Exception as e:
            self.errors.append(f"Could not load policies: {e}")

        try:
            r = list_addresses()
            self.addresses = r if isinstance(r, list) else r.get("results", [])
        except Exception as e:
            self.errors.append(f"Could not load addresses: {e}")

        try:
            r = list_interfaces()
            self.interfaces = r if isinstance(r, list) else r.get("results", [])
        except Exception as e:
            self.errors.append(f"Could not load interfaces: {e}")

    def _add(self, severity, category, title,
             description, recommendation, affected=""):
        self.insights.append(SecurityInsight(
            severity, category, title,
            description, recommendation, affected
        ))

    # ── Policy analysis ───────────────────────────────────

    def _analyze_overly_permissive_policies(self):
        """Detect policies that allow too much traffic."""
        for p in self.policies:
            name = p.get("name", "?")
            pid = p.get("policyid", "?")
            action = p.get("action", "")
            services = [s.get("name") for s in p.get("service", [])]
            srcaddrs = [a.get("name") for a in p.get("srcaddr", [])]
            dstaddrs = [a.get("name") for a in p.get("dstaddr", [])]
            logtraffic = p.get("logtraffic", "disable")

            if action != "accept":
                continue

            # ALL service + all addresses = extremely dangerous
            if ("ALL" in services and
                    "all" in srcaddrs and
                    "all" in dstaddrs):
                self._add(
                    SecurityInsight.SEVERITY_CRITICAL,
                    "Overly Permissive Policy",
                    f"Policy allows ALL traffic from ALL to ALL",
                    f"Policy '{name}' (ID:{pid}) permits every service "
                    f"from any source to any destination. "
                    f"This completely bypasses firewall protection.",
                    "Restrict to specific source/destination addresses "
                    "and only required services.",
                    f"Policy '{name}' (ID:{pid})"
                )

            # ALL service but specific addresses
            elif "ALL" in services:
                self._add(
                    SecurityInsight.SEVERITY_HIGH,
                    "Overly Permissive Policy",
                    f"Policy allows ALL services",
                    f"Policy '{name}' (ID:{pid}) permits all services. "
                    f"Only the required services should be allowed.",
                    "Replace 'ALL' with a list of only the services "
                    "this policy needs to permit.",
                    f"Policy '{name}' (ID:{pid})"
                )

            # SSH/RDP/Telnet from any source
            risky_services = {"SSH", "RDP", "TELNET", "HTTP"}
            matching = risky_services.intersection(set(services))
            if matching and "all" in srcaddrs:
                self._add(
                    SecurityInsight.SEVERITY_HIGH,
                    "Exposed Remote Access",
                    f"Remote access service exposed to all sources",
                    f"Policy '{name}' (ID:{pid}) allows "
                    f"{', '.join(matching)} from any source address. "
                    f"This exposes remote access services to the entire network.",
                    "Restrict source address to known admin workstation IPs only.",
                    f"Policy '{name}' (ID:{pid})"
                )

            # No logging
            if logtraffic in ("disable", "utm"):
                self._add(
                    SecurityInsight.SEVERITY_MEDIUM,
                    "Logging Disabled",
                    f"Policy has logging disabled",
                    f"Policy '{name}' (ID:{pid}) does not log traffic. "
                    f"This prevents detection of security incidents "
                    f"and compliance violations.",
                    "Set logtraffic to 'all' to enable full logging.",
                    f"Policy '{name}' (ID:{pid})"
                )

    def _analyze_policy_conflicts(self):
        """Detect policies that conflict with or shadow each other."""
        for i, p1 in enumerate(self.policies):
            for j, p2 in enumerate(self.policies):
                if i >= j:
                    continue

                name1 = p1.get("name", "?")
                name2 = p2.get("name", "?")
                id1 = p1.get("policyid", "?")
                id2 = p2.get("policyid", "?")

                src1 = {i.get("name") for i in p1.get("srcintf", [])}
                src2 = {i.get("name") for i in p2.get("srcintf", [])}
                dst1 = {i.get("name") for i in p1.get("dstintf", [])}
                dst2 = {i.get("name") for i in p2.get("dstintf", [])}
                svc1 = {s.get("name") for s in p1.get("service", [])}
                svc2 = {s.get("name") for s in p2.get("service", [])}
                act1 = p1.get("action", "")
                act2 = p2.get("action", "")

                # Check for interface overlap
                src_overlap = src1 & src2
                dst_overlap = dst1 & dst2
                svc_overlap = (svc1 & svc2) or "ALL" in svc1 or "ALL" in svc2

                if src_overlap and dst_overlap and svc_overlap:
                    if act1 != act2:
                        # Conflicting actions on same traffic
                        self._add(
                            SecurityInsight.SEVERITY_HIGH,
                            "Policy Conflict",
                            f"Conflicting policies on same traffic path",
                            f"Policies '{name1}' (ID:{id1}, {act1}) and "
                            f"'{name2}' (ID:{id2}, {act2}) cover the same "
                            f"traffic path with opposite actions. "
                            f"FortiGate applies top-down — "
                            f"only the first match takes effect.",
                            f"Review policy order. The policy with lower ID "
                            f"will take precedence over the other.",
                            f"Policies ID:{id1} vs ID:{id2}"
                        )
                    elif act1 == act2:
                        # Redundant policies
                        self._add(
                            SecurityInsight.SEVERITY_LOW,
                            "Redundant Policy",
                            f"Duplicate or redundant policies",
                            f"Policies '{name1}' (ID:{id1}) and "
                            f"'{name2}' (ID:{id2}) cover the same traffic "
                            f"with the same action ({act1}). "
                            f"One of them may be redundant.",
                            "Review both policies and remove the redundant one "
                            "to simplify the policy table.",
                            f"Policies ID:{id1} and ID:{id2}"
                        )

    def _analyze_disabled_policies(self):
        """Find disabled policies that may be stale."""
        for p in self.policies:
            if p.get("status") == "disable":
                name = p.get("name", "?")
                pid = p.get("policyid", "?")
                self._add(
                    SecurityInsight.SEVERITY_LOW,
                    "Disabled Policy",
                    f"Disabled policy found",
                    f"Policy '{name}' (ID:{pid}) is disabled. "
                    f"Disabled policies accumulate over time and "
                    f"make the policy table harder to audit.",
                    "If no longer needed, delete the policy. "
                    "If temporarily disabled, document the reason.",
                    f"Policy '{name}' (ID:{pid})"
                )

    # ── Interface analysis ────────────────────────────────

    def _analyze_interfaces(self):
        """Detect interface security issues."""
        for iface in self.interfaces:
            name = iface.get("name", "?")
            allowaccess = iface.get("allowaccess", "")
            ip = iface.get("ip", "")
            iface_type = iface.get("type", "")

            # Skip virtual/internal interfaces
            if iface_type in ("loopback", "aggregate", "redundant"):
                continue
            if name in ("ssl.root", "fortilink", "l2t.root",
                        "naf.root", "default-mesh"):
                continue

            # Management services on all interfaces
            if allowaccess:
                services = allowaccess.split()
                dangerous = {"http", "telnet"}
                found = dangerous.intersection(set(services))
                if found:
                    self._add(
                        SecurityInsight.SEVERITY_HIGH,
                        "Insecure Management Access",
                        f"Insecure management protocol enabled",
                        f"Interface '{name}' has {', '.join(found).upper()} "
                        f"management access enabled. "
                        f"These protocols transmit credentials in cleartext.",
                        f"Disable {', '.join(found).upper()} and use HTTPS "
                        f"and SSH only for management access.",
                        f"Interface '{name}'"
                    )

                # HTTPS/SSH on WAN — warn
                wan_keywords = ["wan", "port1", "internet"]
                is_wan = any(k in name.lower() for k in wan_keywords)
                mgmt_services = {"https", "ssh", "ping"}
                found_mgmt = mgmt_services.intersection(set(services))
                if is_wan and found_mgmt:
                    self._add(
                        SecurityInsight.SEVERITY_MEDIUM,
                        "Management Exposed on WAN",
                        f"Management access enabled on WAN interface",
                        f"Interface '{name}' has {', '.join(found_mgmt).upper()} "
                        f"enabled. Exposing management to WAN risks "
                        f"brute force attacks from the internet.",
                        "Restrict management access to a dedicated "
                        "management VLAN or specific trusted IP addresses.",
                        f"Interface '{name}'"
                    )

    # ── Address object analysis ───────────────────────────

    def _analyze_address_objects(self):
        """Detect unused or risky address objects."""
        # Build set of addresses used in policies
        used_addresses = set()
        for p in self.policies:
            for a in p.get("srcaddr", []):
                used_addresses.add(a.get("name"))
            for a in p.get("dstaddr", []):
                used_addresses.add(a.get("name"))

        # Built-in FortiGate addresses to skip
        builtin = {
            "all", "none", "FABRIC_DEVICE",
            "FIREWALL_AUTH_PORTAL_ADDRESS",
            "SSLVPN_TUNNEL_ADDR1",
            "EMS_ALL_UNKNOWN_CLIENTS",
            "EMS_ALL_UNMANAGEABLE_CLIENTS"
        }

        for addr in self.addresses:
            name = addr.get("name", "")
            subnet = addr.get("subnet", "")

            if name in builtin:
                continue

            # Unused address objects
            if name not in used_addresses:
                self._add(
                    SecurityInsight.SEVERITY_INFO,
                    "Unused Address Object",
                    f"Address object not used in any policy",
                    f"Address object '{name}' ({subnet}) exists but "
                    f"is not referenced by any firewall policy.",
                    "Remove unused address objects to keep the "
                    "configuration clean and auditable.",
                    f"Address '{name}'"
                )

            # Overly broad address objects
            if subnet and "/" in subnet:
                try:
                    prefix = int(subnet.split("/")[1])
                    if prefix < 8:
                        self._add(
                            SecurityInsight.SEVERITY_MEDIUM,
                            "Overly Broad Address",
                            f"Very broad address object detected",
                            f"Address '{name}' covers a /{prefix} subnet "
                            f"which includes millions of IP addresses.",
                            "Verify this is intentional and restrict "
                            "to the smallest necessary subnet.",
                            f"Address '{name}' ({subnet})"
                        )
                except Exception:
                    pass

    # ── Resource analysis ─────────────────────────────────

    def _analyze_resources(self):
        """Check system resource usage for health issues."""
        try:
            cpu_data = get_cpu_usage()
            mem_data = get_memory_usage()
            cpu = cpu_data["results"]["cpu"][0]["current"]
            mem = mem_data["results"]["mem"][0]["current"]
            cpu_peak = cpu_data["results"]["cpu"][0]["historical"]["1-min"]["max"]

            if cpu_peak > 90:
                self._add(
                    SecurityInsight.SEVERITY_CRITICAL,
                    "Resource Health",
                    f"CPU usage critically high",
                    f"CPU peaked at {cpu_peak}% in the last minute. "
                    f"This may indicate a DoS attack or "
                    f"resource exhaustion.",
                    "Investigate running processes and active sessions. "
                    "Consider enabling DoS protection policies.",
                    f"CPU peak: {cpu_peak}%"
                )
            elif cpu_peak > 70:
                self._add(
                    SecurityInsight.SEVERITY_HIGH,
                    "Resource Health",
                    f"CPU usage elevated",
                    f"CPU peaked at {cpu_peak}% recently. "
                    f"Monitor for sustained high usage.",
                    "Review active sessions and traffic patterns.",
                    f"CPU peak: {cpu_peak}%"
                )

            if mem > 90:
                self._add(
                    SecurityInsight.SEVERITY_CRITICAL,
                    "Resource Health",
                    f"Memory usage critically high",
                    f"Memory usage is at {mem}%. "
                    f"Risk of process crashes and instability.",
                    "Review active sessions, reduce UTM features "
                    "if not needed, consider hardware upgrade.",
                    f"Memory: {mem}%"
                )
            elif mem > 75:
                self._add(
                    SecurityInsight.SEVERITY_MEDIUM,
                    "Resource Health",
                    f"Memory usage elevated",
                    f"Memory usage is at {mem}%. Monitor closely.",
                    "Review memory usage trend and active sessions.",
                    f"Memory: {mem}%"
                )

        except Exception as e:
            self.errors.append(f"Could not analyze resources: {e}")

    # ── General policy table health ───────────────────────

    def _analyze_policy_table_health(self):
        """Check overall policy table quality."""
        if not self.policies:
            return

        total = len(self.policies)

        # Check for default naming (Policy1, Policy2 etc)
        poorly_named = []
        for p in self.policies:
            name = p.get("name", "")
            if (name.lower().startswith("policy") or
                    name.lower().startswith("rule") or
                    name == str(p.get("policyid"))):
                poorly_named.append(name)

        if poorly_named:
            self._add(
                SecurityInsight.SEVERITY_LOW,
                "Policy Naming",
                f"Policies with generic names found",
                f"Policies with generic names make auditing difficult: "
                f"{', '.join(poorly_named)}",
                "Use descriptive names like "
                "'LAN-to-WAN-HTTPS' or 'BlockSSH-FromInternet'.",
                f"{len(poorly_named)} poorly named policies"
            )

        # No deny-all at end
        last_policy = self.policies[-1] if self.policies else None
        if last_policy:
            last_action = last_policy.get("action", "")
            if last_action != "deny":
                self._add(
                    SecurityInsight.SEVERITY_INFO,
                    "Policy Best Practice",
                    f"No explicit deny-all rule at end of policy table",
                    f"Best practice is to have an explicit deny-all "
                    f"rule at the bottom of the policy table for clarity. "
                    f"FortiGate implicitly denies but an explicit rule "
                    f"makes the intent clear in audits.",
                    "Add a deny-all rule at the bottom of the policy "
                    "table as a best practice.",
                    f"Last policy: '{last_policy.get('name')}'"
                )

    # ── Main analysis runner ──────────────────────────────

    def analyze(self) -> dict:
        """
        Run the full analysis and return structured results.
        """
        self._load_data()

        # Run all checks
        self._analyze_overly_permissive_policies()
        self._analyze_policy_conflicts()
        self._analyze_disabled_policies()
        self._analyze_interfaces()
        self._analyze_address_objects()
        self._analyze_resources()
        self._analyze_policy_table_health()

        # Sort by severity
        severity_order = {
            "CRITICAL": 0, "HIGH": 1,
            "MEDIUM": 2, "LOW": 3, "INFO": 4
        }
        self.insights.sort(
            key=lambda x: severity_order.get(x.severity, 5)
        )

        # Count by severity
        counts = {
            "CRITICAL": 0, "HIGH": 0,
            "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        for insight in self.insights:
            counts[insight.severity] = counts.get(insight.severity, 0) + 1

        return {
            "insights": self.insights,
            "counts": counts,
            "total": len(self.insights),
            "errors": self.errors,
            "policies_analyzed": len(self.policies),
            "addresses_analyzed": len(self.addresses),
            "interfaces_analyzed": len(self.interfaces),
        }


def format_analysis_report(results: dict) -> str:
    """
    Format the full analysis as a readable report.
    """
    counts = results["counts"]
    total = results["total"]
    insights = results["insights"]

    lines = []
    lines.append("=" * 60)
    lines.append("  FORTIGATE SECURITY ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append(f"\n  Objects analyzed:")
    lines.append(f"    Policies   : {results['policies_analyzed']}")
    lines.append(f"    Addresses  : {results['addresses_analyzed']}")
    lines.append(f"    Interfaces : {results['interfaces_analyzed']}")

    lines.append(f"\n  Findings summary:")
    lines.append(f"    CRITICAL : {counts.get('CRITICAL', 0)}")
    lines.append(f"    HIGH     : {counts.get('HIGH', 0)}")
    lines.append(f"    MEDIUM   : {counts.get('MEDIUM', 0)}")
    lines.append(f"    LOW      : {counts.get('LOW', 0)}")
    lines.append(f"    INFO     : {counts.get('INFO', 0)}")
    lines.append(f"    TOTAL    : {total}")

    if total == 0:
        lines.append("\n  No security issues found. Configuration looks clean.")
        lines.append("=" * 60)
        return "\n".join(lines)

    # Group by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        group = [i for i in insights if i.severity == severity]
        if not group:
            continue

        lines.append(f"\n  {'─'*56}")
        lines.append(f"  {severity} FINDINGS ({len(group)})")
        lines.append(f"  {'─'*56}")

        for insight in group:
            lines.append(f"\n  {insight.format()}")

    if results["errors"]:
        lines.append(f"\n  {'─'*56}")
        lines.append("  ANALYSIS ERRORS")
        lines.append(f"  {'─'*56}")
        for e in results["errors"]:
            lines.append(f"  [ERROR] {e}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def run_analysis() -> str:
    """
    Entry point — run full analysis and return formatted report.
    Called by the agent tool.
    """
    analyzer = FirewallAnalyzer()
    results = analyzer.analyze()
    return format_analysis_report(results)