import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.policies   import list_policies
from modules.addresses  import list_addresses
from modules.interfaces import list_interfaces
from modules.monitor    import get_cpu_usage, get_memory_usage
from modules.system     import get_system_status


class SecurityInsight:
    """Represents a single security finding."""

    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH     = "HIGH"
    SEVERITY_MEDIUM   = "MEDIUM"
    SEVERITY_LOW      = "LOW"
    SEVERITY_INFO     = "INFO"

    def __init__(self, severity: str, category: str,
                 title: str, description: str,
                 recommendation: str, affected_object: str = ""):
        self.severity        = severity
        self.category        = category
        self.title           = title
        self.description     = description
        self.recommendation  = recommendation
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
            (f"           Object     : {self.affected_object}"
             if self.affected_object else ""),
            f"           Issue      : {self.description}",
            f"           Fix        : {self.recommendation}",
        ]
        return "\n".join(l for l in lines if l)


# ── Virtual / internal interface types and names to skip ──
# Using the type field is more reliable than a hardcoded name list
# because different FortiGate models use different internal names.
_SKIP_INTERFACE_TYPES = {
    "loopback", "aggregate", "redundant",
    "tunnel", "vdom-link", "vap", "wl-mesh",
}
_SKIP_INTERFACE_NAMES = {
    "ssl.root", "fortilink", "l2t.root",
    "naf.root", "default-mesh", "fortilink0",
}


class FirewallAnalyzer:
    """
    Analyzes FortiGate configuration for security issues,
    misconfigurations, conflicts, and best-practice violations.
    """

    def __init__(self):
        self.insights   : list = []
        self.policies   : list = []
        self.addresses  : list = []
        self.interfaces : list = []
        self.errors     : list = []

    def _load_data(self):
        """Load all required data from the FortiGate."""
        try:
            r = list_policies()
            self.policies = r if isinstance(r, list) else r.get("results", [])
        except Exception as exc:
            self.errors.append(f"Could not load policies: {exc}")

        try:
            r = list_addresses()
            self.addresses = r if isinstance(r, list) else r.get("results", [])
        except Exception as exc:
            self.errors.append(f"Could not load addresses: {exc}")

        try:
            r = list_interfaces()
            self.interfaces = r if isinstance(r, list) else r.get("results", [])
        except Exception as exc:
            self.errors.append(f"Could not load interfaces: {exc}")

    def _add(self, severity, category, title,
             description, recommendation, affected=""):
        self.insights.append(SecurityInsight(
            severity, category, title,
            description, recommendation, affected,
        ))

    # ── Policy analysis ───────────────────────────────────

    def _analyze_overly_permissive_policies(self):
        """Detect policies that allow too much traffic."""
        for p in self.policies:
            name      = p.get("name", "?")
            pid       = p.get("policyid", "?")
            action    = p.get("action", "")
            services  = [s.get("name") for s in p.get("service",  [])]
            srcaddrs  = [a.get("name") for a in p.get("srcaddr",  [])]
            dstaddrs  = [a.get("name") for a in p.get("dstaddr",  [])]
            logtraffic = p.get("logtraffic", "disable")

            if action != "accept":
                continue

            # ALL service + all source + all destination — extremely dangerous
            if "ALL" in services and "all" in srcaddrs and "all" in dstaddrs:
                self._add(
                    SecurityInsight.SEVERITY_CRITICAL,
                    "Overly Permissive Policy",
                    "Policy allows ALL traffic from ALL to ALL",
                    f"Policy '{name}' (ID:{pid}) permits every service "
                    f"from any source to any destination. "
                    f"This completely bypasses firewall protection.",
                    "Restrict to specific source/destination addresses "
                    "and only required services.",
                    f"Policy '{name}' (ID:{pid})",
                )

            # ALL service but with specific addresses
            elif "ALL" in services:
                self._add(
                    SecurityInsight.SEVERITY_HIGH,
                    "Overly Permissive Policy",
                    "Policy allows ALL services",
                    f"Policy '{name}' (ID:{pid}) permits all services. "
                    f"Only the strictly required services should be allowed.",
                    "Replace 'ALL' with a specific list of required services.",
                    f"Policy '{name}' (ID:{pid})",
                )

            # Sensitive remote-access services from any source
            risky = {"SSH", "RDP", "TELNET", "HTTP"}
            exposed = risky.intersection(set(services))
            if exposed and "all" in srcaddrs:
                self._add(
                    SecurityInsight.SEVERITY_HIGH,
                    "Exposed Remote Access",
                    "Remote access service exposed to all sources",
                    f"Policy '{name}' (ID:{pid}) allows "
                    f"{', '.join(exposed)} from any source address. "
                    f"This exposes remote access to the entire network.",
                    "Restrict source address to known admin workstation IPs only.",
                    f"Policy '{name}' (ID:{pid})",
                )

            # Logging disabled
            if logtraffic in ("disable", "utm"):
                self._add(
                    SecurityInsight.SEVERITY_MEDIUM,
                    "Logging Disabled",
                    "Policy has logging disabled",
                    f"Policy '{name}' (ID:{pid}) does not log traffic. "
                    f"This prevents detection of security incidents "
                    f"and compliance violations.",
                    "Set logtraffic to 'all' to enable full logging.",
                    f"Policy '{name}' (ID:{pid})",
                )

    def _analyze_policy_conflicts(self):
        """Detect policies that conflict with or shadow each other."""
        for i, p1 in enumerate(self.policies):
            for j, p2 in enumerate(self.policies):
                if i >= j:
                    continue

                name1 = p1.get("name", "?")
                name2 = p2.get("name", "?")
                id1   = p1.get("policyid", "?")
                id2   = p2.get("policyid", "?")

                src1 = {x.get("name") for x in p1.get("srcintf", [])}
                src2 = {x.get("name") for x in p2.get("srcintf", [])}
                dst1 = {x.get("name") for x in p1.get("dstintf", [])}
                dst2 = {x.get("name") for x in p2.get("dstintf", [])}
                svc1 = {s.get("name") for s in p1.get("service",  [])}
                svc2 = {s.get("name") for s in p2.get("service",  [])}
                act1 = p1.get("action", "")
                act2 = p2.get("action", "")

                src_overlap = bool(src1 & src2)
                dst_overlap = bool(dst1 & dst2)
                # FIX: explicit bool — svc1 & svc2 returns a set (falsy when empty),
                # the 'or' clauses return bools. Using bool() everywhere keeps the
                # type consistent and the logic unambiguous.
                svc_overlap = bool(svc1 & svc2) or "ALL" in svc1 or "ALL" in svc2

                if src_overlap and dst_overlap and svc_overlap:
                    if act1 != act2:
                        self._add(
                            SecurityInsight.SEVERITY_HIGH,
                            "Policy Conflict",
                            "Conflicting policies on same traffic path",
                            f"Policies '{name1}' (ID:{id1}, {act1}) and "
                            f"'{name2}' (ID:{id2}, {act2}) cover the same "
                            f"traffic path with opposite actions. "
                            f"FortiGate applies top-down — "
                            f"only the first match takes effect.",
                            f"Review policy order. Lower ID takes precedence.",
                            f"Policies ID:{id1} vs ID:{id2}",
                        )
                    else:
                        self._add(
                            SecurityInsight.SEVERITY_LOW,
                            "Redundant Policy",
                            "Duplicate or redundant policies",
                            f"Policies '{name1}' (ID:{id1}) and "
                            f"'{name2}' (ID:{id2}) cover the same traffic "
                            f"with the same action ({act1}). "
                            f"One may be redundant.",
                            "Review both policies and remove the redundant one.",
                            f"Policies ID:{id1} and ID:{id2}",
                        )

    def _analyze_disabled_policies(self):
        """Find disabled policies that may be stale."""
        for p in self.policies:
            if p.get("status") == "disable":
                name = p.get("name", "?")
                pid  = p.get("policyid", "?")
                self._add(
                    SecurityInsight.SEVERITY_LOW,
                    "Disabled Policy",
                    "Disabled policy found",
                    f"Policy '{name}' (ID:{pid}) is disabled. "
                    f"Accumulating disabled policies makes the table "
                    f"harder to audit over time.",
                    "Delete it if no longer needed, or document the reason "
                    "if it is temporarily disabled.",
                    f"Policy '{name}' (ID:{pid})",
                )

    # ── Interface analysis ────────────────────────────────

    def _analyze_interfaces(self):
        """Detect interface-level security issues."""
        for iface in self.interfaces:
            name        = iface.get("name", "?")
            allowaccess = iface.get("allowaccess", "")
            iface_type  = iface.get("type", "")

            if iface_type in _SKIP_INTERFACE_TYPES:
                continue
            if name in _SKIP_INTERFACE_NAMES:
                continue

            if not allowaccess:
                continue

            services = set(allowaccess.lower().split())

            # Insecure cleartext management protocols
            found_insecure = services.intersection({"http", "telnet"})
            if found_insecure:
                self._add(
                    SecurityInsight.SEVERITY_HIGH,
                    "Insecure Management Access",
                    "Insecure management protocol enabled",
                    f"Interface '{name}' has "
                    f"{', '.join(found_insecure).upper()} management enabled. "
                    f"These protocols transmit credentials in cleartext.",
                    f"Disable {', '.join(found_insecure).upper()} and "
                    f"use only HTTPS and SSH for management.",
                    f"Interface '{name}'",
                )

            # Management services exposed on a WAN-facing interface
            wan_keywords = {"wan", "internet", "outside", "untrust"}
            is_wan = any(k in name.lower() for k in wan_keywords)
            # port1 is commonly the WAN port on many FortiGate models
            is_wan = is_wan or name.lower() == "port1"

            found_mgmt = services.intersection({"https", "ssh", "ping"})
            if is_wan and found_mgmt:
                self._add(
                    SecurityInsight.SEVERITY_MEDIUM,
                    "Management Exposed on WAN",
                    "Management access enabled on WAN interface",
                    f"Interface '{name}' has "
                    f"{', '.join(found_mgmt).upper()} enabled. "
                    f"Exposing management to the internet risks "
                    f"brute-force attacks.",
                    "Restrict management access to a dedicated management "
                    "VLAN or specific trusted IP addresses using a "
                    "trusted-host list on the admin account.",
                    f"Interface '{name}'",
                )

    # ── Address object analysis ───────────────────────────

    def _analyze_address_objects(self):
        """Detect unused or risky address objects."""
        used_addresses: set = set()
        for p in self.policies:
            for a in p.get("srcaddr", []):
                used_addresses.add(a.get("name"))
            for a in p.get("dstaddr", []):
                used_addresses.add(a.get("name"))

        # Built-in FortiGate address objects — skip these
        builtin = {
            "all", "none", "FABRIC_DEVICE",
            "FIREWALL_AUTH_PORTAL_ADDRESS",
            "SSLVPN_TUNNEL_ADDR1",
            "EMS_ALL_UNKNOWN_CLIENTS",
            "EMS_ALL_UNMANAGEABLE_CLIENTS",
        }

        for addr in self.addresses:
            name   = addr.get("name", "")
            subnet = addr.get("subnet", "")

            if name in builtin:
                continue

            if name not in used_addresses:
                self._add(
                    SecurityInsight.SEVERITY_INFO,
                    "Unused Address Object",
                    "Address object not used in any policy",
                    f"Address object '{name}' ({subnet}) exists but "
                    f"is not referenced by any firewall policy.",
                    "Remove unused address objects to keep the "
                    "configuration clean and auditable.",
                    f"Address '{name}'",
                )

            if subnet and "/" in subnet:
                try:
                    prefix = int(subnet.split("/")[1])
                    if prefix < 8:
                        self._add(
                            SecurityInsight.SEVERITY_MEDIUM,
                            "Overly Broad Address",
                            "Very broad address object detected",
                            f"Address '{name}' covers a /{prefix} subnet "
                            f"which includes millions of IP addresses.",
                            "Verify this is intentional and restrict "
                            "to the smallest necessary subnet.",
                            f"Address '{name}' ({subnet})",
                        )
                except (ValueError, IndexError):
                    pass

    # ── Resource analysis ─────────────────────────────────

    def _analyze_resources(self):
        """Check system resource usage for health issues."""
        try:
            cpu_data = get_cpu_usage()
            mem_data = get_memory_usage()

            # FIX: safe chained .get() access — never raises KeyError/IndexError
            # regardless of the FortiOS version or API response structure.
            cpu_results   = cpu_data.get("results", {})
            cpu_list      = cpu_results.get("cpu", [{}])
            cpu_entry     = cpu_list[0] if cpu_list else {}
            cpu_current   = cpu_entry.get("current", 0)
            historical    = cpu_entry.get("historical", {})
            one_min       = historical.get("1-min", {})
            cpu_peak      = one_min.get("max", cpu_current)

            mem_results   = mem_data.get("results", {})
            mem_list      = mem_results.get("mem", [{}])
            mem_entry     = mem_list[0] if mem_list else {}
            mem_current   = mem_entry.get("current", 0)

        except (TypeError, AttributeError) as exc:
            self.errors.append(f"Could not parse resource monitoring data: {exc}")
            return
        except Exception as exc:
            self.errors.append(f"Could not analyze resources: {exc}")
            return

        if cpu_peak > 90:
            self._add(
                SecurityInsight.SEVERITY_CRITICAL,
                "Resource Health",
                "CPU usage critically high",
                f"CPU peaked at {cpu_peak}% in the last minute. "
                f"This may indicate a DoS attack or resource exhaustion.",
                "Investigate running processes and active sessions. "
                "Consider enabling DoS protection policies.",
                f"CPU peak: {cpu_peak}%",
            )
        elif cpu_peak > 70:
            self._add(
                SecurityInsight.SEVERITY_HIGH,
                "Resource Health",
                "CPU usage elevated",
                f"CPU peaked at {cpu_peak}% recently. "
                f"Monitor for sustained high usage.",
                "Review active sessions and traffic patterns.",
                f"CPU peak: {cpu_peak}%",
            )

        if mem_current > 90:
            self._add(
                SecurityInsight.SEVERITY_CRITICAL,
                "Resource Health",
                "Memory usage critically high",
                f"Memory is at {mem_current}%. "
                f"Risk of process crashes and instability.",
                "Review active sessions, reduce UTM features if not needed, "
                "or consider a hardware upgrade.",
                f"Memory: {mem_current}%",
            )
        elif mem_current > 75:
            self._add(
                SecurityInsight.SEVERITY_MEDIUM,
                "Resource Health",
                "Memory usage elevated",
                f"Memory is at {mem_current}%. Monitor closely.",
                "Review memory usage trend and active sessions.",
                f"Memory: {mem_current}%",
            )

    # ── Policy table health ───────────────────────────────

    def _analyze_policy_table_health(self):
        """Check overall policy table naming and structure."""
        if not self.policies:
            return

        # Generic policy names make auditing difficult
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
                "Policies with generic names found",
                f"Generic names make auditing difficult: "
                f"{', '.join(poorly_named)}",
                "Use descriptive names like 'LAN-to-WAN-HTTPS' "
                "or 'Block-SSH-from-Internet'.",
                f"{len(poorly_named)} poorly named policies",
            )

        # FIX: FortiGate always has an implicit deny-all — this is not a
        # vulnerability. We note it as INFO-level (best practice only) and
        # acknowledge the implicit behaviour so analysts are not confused.
        last_policy = self.policies[-1] if self.policies else None
        if last_policy and last_policy.get("action", "") != "deny":
            self._add(
                SecurityInsight.SEVERITY_INFO,
                "Policy Best Practice",
                "No explicit deny-all rule at end of policy table",
                "FortiGate implicitly denies all unmatched traffic — "
                "this is NOT a vulnerability. However, adding an explicit "
                "deny-all rule at the bottom makes auditor intent clearer "
                "and is required by some compliance frameworks.",
                "Consider adding an explicit deny-all rule at the bottom "
                "for audit clarity and compliance. This is optional.",
                f"Last policy: '{last_policy.get('name')}'",
            )

    # ── Main analysis runner ──────────────────────────────

    def analyze(self) -> dict:
        """Run the full analysis and return structured results."""
        self._load_data()

        self._analyze_overly_permissive_policies()
        self._analyze_policy_conflicts()
        self._analyze_disabled_policies()
        self._analyze_interfaces()
        self._analyze_address_objects()
        self._analyze_resources()
        self._analyze_policy_table_health()

        severity_order = {
            "CRITICAL": 0, "HIGH": 1,
            "MEDIUM": 2, "LOW": 3, "INFO": 4,
        }
        self.insights.sort(
            key=lambda x: severity_order.get(x.severity, 5)
        )

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for insight in self.insights:
            counts[insight.severity] = counts.get(insight.severity, 0) + 1

        return {
            "insights":            self.insights,
            "counts":              counts,
            "total":               len(self.insights),
            "errors":              self.errors,
            "policies_analyzed":   len(self.policies),
            "addresses_analyzed":  len(self.addresses),
            "interfaces_analyzed": len(self.interfaces),
        }


def format_analysis_report(results: dict) -> str:
    """Format the full analysis as a readable report."""
    counts   = results["counts"]
    total    = results["total"]
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

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = [i for i in insights if i.severity == severity]
        if not group:
            continue
        lines.append(f"\n  {'─' * 56}")
        lines.append(f"  {severity} FINDINGS ({len(group)})")
        lines.append(f"  {'─' * 56}")
        for insight in group:
            lines.append(f"\n  {insight.format()}")

    if results["errors"]:
        lines.append(f"\n  {'─' * 56}")
        lines.append("  ANALYSIS ERRORS")
        lines.append(f"  {'─' * 56}")
        for e in results["errors"]:
            lines.append(f"  [ERROR] {e}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def run_analysis() -> str:
    """Entry point — run full analysis and return formatted report."""
    analyzer = FirewallAnalyzer()
    results  = analyzer.analyze()
    return format_analysis_report(results)