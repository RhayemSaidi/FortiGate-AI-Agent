import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.policies   import list_policies
from modules.addresses  import list_addresses
from modules.interfaces import list_interfaces
from modules.monitor    import get_cpu_usage, get_memory_usage


class SecurityInsight:
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    def __init__(self, severity, category, title,
                 description, recommendation, affected=""):
        self.severity       = severity
        self.category       = category
        self.title          = title
        self.description    = description
        self.recommendation = recommendation
        self.affected       = affected

    def format(self) -> str:
        labels = {
            "CRITICAL": "[CRITICAL]",
            "HIGH":     "[HIGH]    ",
            "MEDIUM":   "[MEDIUM]  ",
            "LOW":      "[LOW]     ",
            "INFO":     "[INFO]    ",
        }
        label = labels.get(self.severity, "[UNKNOWN] ")
        lines = [f"{label} {self.title}"]
        if self.affected:
            lines.append(f"           Object  : {self.affected}")
        lines.append(f"           Issue   : {self.description}")
        lines.append(f"           Fix     : {self.recommendation}")
        return "\n".join(lines)


class FirewallAnalyzer:
    def __init__(self):
        self.insights    = []
        self.policies    = []
        self.addresses   = []
        self.interfaces  = []
        self.errors      = []

    def _load_data(self):
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

    def _add(self, severity, category, title, description, recommendation, affected=""):
        self.insights.append(SecurityInsight(
            severity, category, title, description, recommendation, affected
        ))

    def _analyze_overly_permissive_policies(self):
        for p in self.policies:
            name     = p.get("name", "?")
            pid      = p.get("policyid", "?")
            action   = p.get("action", "")
            services = [s.get("name") for s in p.get("service", [])]
            srcaddrs = [a.get("name") for a in p.get("srcaddr", [])]
            dstaddrs = [a.get("name") for a in p.get("dstaddr", [])]
            logtraffic = p.get("logtraffic", "disable")

            if action != "accept":
                continue

            if "ALL" in services and "all" in srcaddrs and "all" in dstaddrs:
                self._add(
                    SecurityInsight.CRITICAL,
                    "Overly Permissive Policy",
                    "Policy allows ALL traffic from ALL to ALL",
                    f"Policy '{name}' (ID:{pid}) permits every service from any source "
                    f"to any destination — completely bypasses firewall protection.",
                    "Restrict to specific source/destination addresses and required services.",
                    f"Policy '{name}' (ID:{pid})"
                )
            elif "ALL" in services:
                self._add(
                    SecurityInsight.HIGH,
                    "Overly Permissive Policy",
                    "Policy allows ALL services",
                    f"Policy '{name}' (ID:{pid}) permits all services.",
                    "Replace 'ALL' with only the services this policy requires.",
                    f"Policy '{name}' (ID:{pid})"
                )

            risky = {"SSH", "RDP", "TELNET", "HTTP"}
            found = risky.intersection(set(services))
            if found and "all" in srcaddrs:
                self._add(
                    SecurityInsight.HIGH,
                    "Exposed Remote Access",
                    "Remote access service exposed to all sources",
                    f"Policy '{name}' (ID:{pid}) allows {', '.join(found)} "
                    f"from any source — exposes remote access to entire network.",
                    "Restrict source address to known admin workstation IPs only.",
                    f"Policy '{name}' (ID:{pid})"
                )

            if logtraffic in ("disable", "utm"):
                self._add(
                    SecurityInsight.MEDIUM,
                    "Logging Disabled",
                    "Policy has logging disabled",
                    f"Policy '{name}' (ID:{pid}) does not log traffic. "
                    f"Security incidents and compliance violations cannot be detected.",
                    "Set logtraffic to 'all' to enable full traffic logging.",
                    f"Policy '{name}' (ID:{pid})"
                )

    def _analyze_policy_conflicts(self):
        for i, p1 in enumerate(self.policies):
            for j, p2 in enumerate(self.policies):
                if i >= j:
                    continue

                name1 = p1.get("name", "?"); id1 = p1.get("policyid", "?")
                name2 = p2.get("name", "?"); id2 = p2.get("policyid", "?")

                src1 = {x.get("name") for x in p1.get("srcintf", [])}
                src2 = {x.get("name") for x in p2.get("srcintf", [])}
                dst1 = {x.get("name") for x in p1.get("dstintf", [])}
                dst2 = {x.get("name") for x in p2.get("dstintf", [])}
                svc1 = {s.get("name") for s in p1.get("service", [])}
                svc2 = {s.get("name") for s in p2.get("service", [])}
                act1 = p1.get("action", ""); act2 = p2.get("action", "")

                src_ok = bool(src1 & src2)
                dst_ok = bool(dst1 & dst2)
                svc_ok = bool(svc1 & svc2) or "ALL" in svc1 or "ALL" in svc2

                if src_ok and dst_ok and svc_ok:
                    if act1 != act2:
                        self._add(
                            SecurityInsight.HIGH,
                            "Policy Conflict",
                            "Conflicting policies on same traffic path",
                            f"Policies '{name1}' (ID:{id1}, {act1}) and "
                            f"'{name2}' (ID:{id2}, {act2}) cover the same path "
                            f"with opposite actions. Lower ID takes precedence.",
                            f"Review order. Use tool_move_policy to ensure the "
                            f"correct rule takes priority.",
                            f"Policies ID:{id1} vs ID:{id2}"
                        )
                    else:
                        self._add(
                            SecurityInsight.LOW,
                            "Redundant Policy",
                            "Duplicate policies detected",
                            f"Policies '{name1}' (ID:{id1}) and '{name2}' (ID:{id2}) "
                            f"cover the same traffic with the same action ({act1}).",
                            "Remove the redundant policy to simplify the policy table.",
                            f"Policies ID:{id1} and ID:{id2}"
                        )

    def _analyze_disabled_policies(self):
        for p in self.policies:
            if p.get("status") == "disable":
                name = p.get("name", "?"); pid = p.get("policyid", "?")
                self._add(
                    SecurityInsight.LOW,
                    "Disabled Policy",
                    "Disabled policy found",
                    f"Policy '{name}' (ID:{pid}) is disabled and accumulates clutter.",
                    "Delete if no longer needed, or document why it is kept disabled.",
                    f"Policy '{name}' (ID:{pid})"
                )

    def _analyze_interfaces(self):
        """
        FIX: allowaccess can be a space-separated string OR a list
        depending on FortiOS version. Handle both formats.
        """
        skip_names = {"ssl.root", "fortilink", "l2t.root", "naf.root", "default-mesh"}
        skip_types = {"loopback", "aggregate", "redundant"}

        for iface in self.interfaces:
            name       = iface.get("name", "?")
            iface_type = iface.get("type", "")

            if name in skip_names or iface_type in skip_types:
                continue

            # FIX: handle both string and list for allowaccess
            allowaccess_raw = iface.get("allowaccess", "")
            if isinstance(allowaccess_raw, list):
                services = [s.lower() for s in allowaccess_raw]
            else:
                services = allowaccess_raw.lower().split() if allowaccess_raw else []

            if not services:
                continue

            dangerous = {"http", "telnet"}
            found_dangerous = dangerous.intersection(set(services))
            if found_dangerous:
                self._add(
                    SecurityInsight.HIGH,
                    "Insecure Management Access",
                    "Insecure management protocol enabled",
                    f"Interface '{name}' has {', '.join(found_dangerous).upper()} enabled. "
                    f"These protocols transmit credentials in cleartext.",
                    f"Disable {', '.join(found_dangerous).upper()} and use only HTTPS and SSH.",
                    f"Interface '{name}'"
                )

            wan_keywords = ["wan", "internet"]
            is_wan = any(k in name.lower() for k in wan_keywords)
            if not is_wan and name.lower() in ("port1",):
                is_wan = True

            mgmt_services = {"https", "ssh", "ping"}
            found_mgmt = mgmt_services.intersection(set(services))
            if is_wan and found_mgmt:
                self._add(
                    SecurityInsight.MEDIUM,
                    "Management Exposed on WAN",
                    "Management access enabled on WAN interface",
                    f"Interface '{name}' has {', '.join(found_mgmt).upper()} enabled. "
                    f"Exposes management to brute-force attacks from internet.",
                    "Restrict management to a dedicated management VLAN or trusted IPs.",
                    f"Interface '{name}'"
                )

    def _analyze_address_objects(self):
        used_addresses: set = set()
        for p in self.policies:
            for a in p.get("srcaddr", []):
                used_addresses.add(a.get("name"))
            for a in p.get("dstaddr", []):
                used_addresses.add(a.get("name"))

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
                    SecurityInsight.INFO,
                    "Unused Address Object",
                    "Address object not referenced by any policy",
                    f"Address '{name}' ({subnet}) exists but is not used in any rule.",
                    "Remove unused objects to keep configuration clean and auditable.",
                    f"Address '{name}'"
                )

            if subnet and "/" in subnet:
                try:
                    prefix = int(subnet.split("/")[1])
                    if prefix < 8:
                        self._add(
                            SecurityInsight.MEDIUM,
                            "Overly Broad Address",
                            "Very broad address object detected",
                            f"Address '{name}' covers a /{prefix} subnet "
                            f"— millions of IP addresses.",
                            "Verify this is intentional and restrict if possible.",
                            f"Address '{name}' ({subnet})"
                        )
                except Exception:
                    pass

    def _analyze_resources(self):
        try:
            cpu_data = get_cpu_usage()
            mem_data = get_memory_usage()
            cpu      = cpu_data["results"]["cpu"][0]["current"]
            mem      = mem_data["results"]["mem"][0]["current"]
            cpu_peak = cpu_data["results"]["cpu"][0]["historical"]["1-min"]["max"]

            if cpu_peak > 90:
                self._add(
                    SecurityInsight.CRITICAL, "Resource Health",
                    "CPU critically high",
                    f"CPU peaked at {cpu_peak}% — possible DoS or resource exhaustion.",
                    "Investigate active sessions and processes.",
                    f"CPU peak: {cpu_peak}%"
                )
            elif cpu_peak > 70:
                self._add(
                    SecurityInsight.HIGH, "Resource Health",
                    "CPU usage elevated",
                    f"CPU peaked at {cpu_peak}%.",
                    "Monitor traffic patterns and active sessions.",
                    f"CPU peak: {cpu_peak}%"
                )

            if mem > 90:
                self._add(
                    SecurityInsight.CRITICAL, "Resource Health",
                    "Memory critically high",
                    f"Memory at {mem}% — risk of process crashes.",
                    "Review active sessions and UTM features.",
                    f"Memory: {mem}%"
                )
            elif mem > 75:
                self._add(
                    SecurityInsight.MEDIUM, "Resource Health",
                    "Memory usage elevated",
                    f"Memory at {mem}%.",
                    "Monitor memory trend.",
                    f"Memory: {mem}%"
                )
        except Exception as exc:
            self.errors.append(f"Resource analysis error: {exc}")

    def _analyze_policy_table_health(self):
        if not self.policies:
            return

        poorly_named = []
        for p in self.policies:
            name = p.get("name", "")
            if (name.lower().startswith("policy") or
                    name.lower().startswith("rule") or
                    name == str(p.get("policyid"))):
                poorly_named.append(name)

        if poorly_named:
            self._add(
                SecurityInsight.LOW,
                "Policy Naming",
                "Policies with generic names found",
                f"Generic names make auditing difficult: {', '.join(poorly_named)}",
                "Use descriptive names like 'LAN-to-WAN-HTTPS' or 'Block-SSH-WAN'.",
                f"{len(poorly_named)} poorly named policies"
            )

        if self.policies:
            last = self.policies[-1]
            if last.get("action") != "deny":
                self._add(
                    SecurityInsight.INFO,
                    "Policy Best Practice",
                    "No explicit deny-all rule at end of policy table",
                    "Best practice is an explicit deny-all at the bottom for audit clarity.",
                    "Add a deny-all rule at the bottom of the policy table.",
                    f"Last policy: '{last.get('name')}'"
                )

    def analyze(self) -> dict:
        self._load_data()
        self._analyze_overly_permissive_policies()
        self._analyze_policy_conflicts()
        self._analyze_disabled_policies()
        self._analyze_interfaces()
        self._analyze_address_objects()
        self._analyze_resources()
        self._analyze_policy_table_health()

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.insights.sort(key=lambda x: order.get(x.severity, 5))

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for ins in self.insights:
            counts[ins.severity] = counts.get(ins.severity, 0) + 1

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
    counts   = results["counts"]
    insights = results["insights"]

    lines = ["=" * 60, "  FORTIGATE SECURITY ANALYSIS REPORT", "=" * 60]
    lines.append(f"\n  Objects analyzed:")
    lines.append(f"    Policies   : {results['policies_analyzed']}")
    lines.append(f"    Addresses  : {results['addresses_analyzed']}")
    lines.append(f"    Interfaces : {results['interfaces_analyzed']}")
    lines.append(f"\n  Findings:")
    lines.append(f"    CRITICAL : {counts.get('CRITICAL', 0)}")
    lines.append(f"    HIGH     : {counts.get('HIGH', 0)}")
    lines.append(f"    MEDIUM   : {counts.get('MEDIUM', 0)}")
    lines.append(f"    LOW      : {counts.get('LOW', 0)}")
    lines.append(f"    INFO     : {counts.get('INFO', 0)}")
    lines.append(f"    TOTAL    : {results['total']}")

    if results["total"] == 0:
        lines.append("\n  No security issues found.")
        lines.append("=" * 60)
        return "\n".join(lines)

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        group = [i for i in insights if i.severity == severity]
        if not group:
            continue
        lines.append(f"\n  {'─'*56}")
        lines.append(f"  {severity} ({len(group)})")
        lines.append(f"  {'─'*56}")
        for ins in group:
            lines.append(f"\n  {ins.format()}")

    if results["errors"]:
        lines.append(f"\n  {'─'*56}")
        lines.append("  ANALYSIS ERRORS")
        for e in results["errors"]:
            lines.append(f"  [ERROR] {e}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def run_analysis() -> str:
    analyzer = FirewallAnalyzer()
    results  = analyzer.analyze()
    return format_analysis_report(results)