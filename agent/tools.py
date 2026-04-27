import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_core.tools import tool

from modules.system     import get_system_status
from modules.monitor    import get_cpu_usage, get_memory_usage, get_active_sessions
from modules.policies   import (
    list_policies, get_policy, get_policy_id_by_name,
    create_policy, update_policy, delete_policy, move_policy,
)
from modules.addresses  import list_addresses, create_address, delete_address
from modules.interfaces import list_interfaces, update_interface_allowaccess
from modules.routing    import list_routes
from modules.users      import list_users
from modules.vpn        import get_vpn_status
from modules.backup     import backup_config

from rag.retriever import search, search_errors
from insights      import run_analysis


# ══════════════════════════════════════════════════════════
#  SYSTEM HEALTH TOOLS
# ══════════════════════════════════════════════════════════

@tool
def tool_get_system_status(input: str = "") -> str:
    """Get FortiGate hostname, hardware model, firmware version, and serial number."""
    try:
        r   = get_system_status()
        res = r.get("results", {})
        return (
            f"Hostname : {res.get('hostname',   'N/A')}\n"
            f"Model    : {res.get('model_name', 'N/A')}\n"
            f"Version  : {r.get('version',      'N/A')}\n"
            f"Serial   : {r.get('serial',       'N/A')}"
        )
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_get_cpu_memory(input: str = "") -> str:
    """Get current CPU and memory usage. Also reports 1-minute CPU peak."""
    try:
        cpu_data  = get_cpu_usage()
        mem_data  = get_memory_usage()
        cpu_list  = cpu_data.get("results", {}).get("cpu", [{}])
        cpu_entry = cpu_list[0] if cpu_list else {}
        mem_list  = mem_data.get("results", {}).get("mem", [{}])
        mem_entry = mem_list[0] if mem_list else {}
        return (
            f"CPU usage    : {cpu_entry.get('current', 'N/A')}%  "
            f"(1-min peak: {cpu_entry.get('historical', {}).get('1-min', {}).get('max', 'N/A')}%)\n"
            f"Memory usage : {mem_entry.get('current', 'N/A')}%"
        )
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_get_active_sessions(input: str = "") -> str:
    """
    Get the current number of active firewall sessions.
    High counts may indicate a DoS attack or connection leak.
    """
    try:
        r       = get_active_sessions()
        results = r.get("results", {})
        if isinstance(results, dict):
            count = (results.get("session_count") or
                     results.get("total") or
                     results.get("filt_count"))
            if count is not None:
                return f"Active firewall sessions: {count:,}"
            summary = ", ".join(f"{k}: {v}" for k, v in results.items()
                                if isinstance(v, (int, float, str)))
            return f"Session data: {summary}" if summary else "Session data unavailable."
        if isinstance(results, (int, float)):
            return f"Active firewall sessions: {int(results):,}"
        if isinstance(results, list):
            return f"Active firewall sessions: {len(results):,}"
        return "Could not determine active session count."
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_get_vpn_status(input: str = "") -> str:
    """Get live status of all IPsec VPN tunnels: name, UP/DOWN, remote gateway, traffic."""
    try:
        r       = get_vpn_status()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No IPsec VPN tunnels configured."
        def _fmt(b):
            return f"{b/1024:.1f} KB" if b >= 1024 else f"{b} B"
        lines = [
            f"  {t.get('name','?'):<30} "
            f"status: {t.get('status','?').upper():<12} "
            f"remote: {t.get('rgwy','?'):<18} "
            f"in: {_fmt(t.get('incoming_bytes',0))}  "
            f"out: {_fmt(t.get('outgoing_bytes',0))}"
            for t in results
        ]
        return "IPsec VPN Tunnels:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════
#  CONFIGURATION READ TOOLS
# ══════════════════════════════════════════════════════════

@tool
def tool_list_policies(input: str = "") -> str:
    """
    List all firewall policies: ID, name, action, and traffic direction.
    Use this before making any policy changes to get current IDs.
    """
    try:
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No firewall policies found."
        lines = []
        for p in results:
            src = (p.get("srcintf") or [{}])[0].get("name", "?")
            dst = (p.get("dstintf") or [{}])[0].get("name", "?")
            lines.append(
                f"  ID {p.get('policyid','?'):>3} | "
                f"{p.get('name','unnamed'):<30} | "
                f"{p.get('action','?'):>6} | "
                f"{src} -> {dst}"
            )
        return "Firewall Policies:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_get_policy_details(policy_id: int) -> str:
    """
    Get complete details of a single policy by its numeric ID.
    Returns interfaces, addresses, services, action, schedule, and logging.
    Use this before updating or deleting a policy to confirm you have the right rule.
    """
    try:
        r = get_policy(policy_id)
        # FIX: FortiOS returns results as dict for single-object queries
        # but some versions return a list — handle both
        raw = r.get("results", {})
        if isinstance(raw, list):
            p = raw[0] if raw else {}
        elif isinstance(raw, dict):
            p = raw
        else:
            p = {}

        if not p:
            return f"[ERROR] Policy ID {policy_id} not found."

        return (
            f"Policy ID    : {p.get('policyid', '?')}\n"
            f"Name         : {p.get('name', '?')}\n"
            f"Status       : {p.get('status', '?')}\n"
            f"Action       : {p.get('action', '?')}\n"
            f"Src Interface: {', '.join(i.get('name','?') for i in p.get('srcintf',[]))}\n"
            f"Dst Interface: {', '.join(i.get('name','?') for i in p.get('dstintf',[]))}\n"
            f"Src Address  : {', '.join(a.get('name','?') for a in p.get('srcaddr',[]))}\n"
            f"Dst Address  : {', '.join(a.get('name','?') for a in p.get('dstaddr',[]))}\n"
            f"Services     : {', '.join(s.get('name','?') for s in p.get('service',[]))}\n"
            f"Schedule     : {p.get('schedule', '?')}\n"
            f"Log Traffic  : {p.get('logtraffic', '?')}\n"
            f"NAT          : {p.get('nat', '?')}"
        )
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_list_addresses(input: str = "") -> str:
    """
    List all address objects: name and subnet/FQDN.
    Use this to find objects before creating policies or to check for
    existing objects (including BLOCKED- prefixed blocked IPs).
    """
    try:
        r       = list_addresses()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No address objects found."
        lines = []
        for a in results[:20]:
            subnet = a.get("subnet") or a.get("fqdn") or "N/A"
            lines.append(f"  {a.get('name','?'):<35} {subnet}")
        if len(results) > 20:
            lines.append(f"  ... and {len(results) - 20} more")
        return "Address Objects:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_list_interfaces(input: str = "") -> str:
    """List all network interfaces with IP address and status."""
    try:
        r       = list_interfaces()
        results = r if isinstance(r, list) else r.get("results", [])
        lines   = [
            f"  {i.get('name','?'):<20} "
            f"{i.get('ip','0.0.0.0 0.0.0.0'):<25} "
            f"status: {i.get('status','?')}"
            for i in results[:12]
        ]
        return "Network Interfaces:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_list_users(input: str = "") -> str:
    """List all local user accounts with their status."""
    try:
        r       = list_users()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No local users found."
        lines = [
            f"  {u.get('name','?'):<25} status: {u.get('status','?')}"
            for u in results
        ]
        return "Local Users:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_list_routes(input: str = "") -> str:
    """List all static routes: destination, gateway, and interface."""
    try:
        r       = list_routes()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No static routes configured."
        lines = [
            f"  {rt.get('dst','?'):<25} "
            f"via {rt.get('gateway','?'):<18} "
            f"on {rt.get('device','?')}"
            for rt in results
        ]
        return "Static Routes:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════
#  POLICY WRITE TOOLS
# ══════════════════════════════════════════════════════════

@tool
def tool_create_policy(name: str, srcintf: str, dstintf: str,
                       srcaddr: str = "all", dstaddr: str = "all",
                       service: str = "ALL", action: str = "accept") -> str:
    """
    Create a new firewall policy. FortiGate assigns the ID automatically.
    The actual assigned ID is verified and returned after creation.
    Parameters:
    - name     : unique policy name, no spaces (use hyphens)
    - srcintf  : source interface (e.g. port1, wan1)
    - dstintf  : destination interface (e.g. port2, lan)
    - srcaddr  : source address object name (default: all)
    - dstaddr  : destination address object name (default: all)
    - service  : ALL, HTTP, HTTPS, SSH, FTP, DNS, SMTP, RDP, PING
    - action   : accept or deny
    """
    try:
        if not name or not srcintf or not dstintf:
            return "[ERROR] name, srcintf, and dstintf are all required."
        r = create_policy(
            name=name, srcintf=srcintf, dstintf=dstintf,
            srcaddr=srcaddr, dstaddr=dstaddr,
            service=service, action=action,
        )
        if r.get("status") == "success":
            # FIX: verify the actual assigned ID from FortiGate
            actual_id = get_policy_id_by_name(name)
            id_str = f"ID #{actual_id}" if actual_id else "ID assigned by FortiGate"
            return (
                f"[SUCCESS] Policy '{name}' created ({id_str}).\n"
                f"   {srcintf} -> {dstintf} | service: {service} | action: {action}\n"
                f"   Note: FortiGate assigns IDs automatically. "
                f"Use tool_move_policy to reorder if needed."
            )
        # FIX: handle error -4 explicitly
        cli_errors = r.get("cli_error", [])
        if r.get("error") == -4 or any("-4" in str(e) for e in cli_errors):
            return (
                "[ERROR] Policy limit reached (error -4). "
                "Your FortiGate VM has a maximum number of allowed policies. "
                "Delete unused policies to free space."
            )
        return f"[ERROR] {cli_errors}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_update_policy(policy_id: int, action: str = "",
                       srcaddr: str = "", dstaddr: str = "",
                       service: str = "", status: str = "",
                       name: str = "") -> str:
    """
    Modify an existing firewall policy. Only provided fields are changed.
    Use tool_get_policy_details first to see current values.
    Parameters:
    - policy_id : numeric ID (required)
    - action    : change to 'accept' or 'deny'
    - srcaddr   : new source address object name
    - dstaddr   : new destination address object name
    - service   : new service (ALL, HTTP, HTTPS, SSH, etc.)
    - status    : 'enable' or 'disable'
    - name      : rename the policy
    """
    try:
        if not policy_id:
            return "[ERROR] policy_id is required."
        data = {}
        if name:   data["name"]   = name
        if status: data["status"] = status
        if action:
            if action not in ("accept", "deny"):
                return "[ERROR] action must be 'accept' or 'deny'."
            data["action"] = action
        if srcaddr: data["srcaddr"] = [{"name": srcaddr}]
        if dstaddr: data["dstaddr"] = [{"name": dstaddr}]
        if service: data["service"] = [{"name": service}]
        if not data:
            return "[ERROR] No fields to update were provided."
        r = update_policy(policy_id, data)
        if r.get("status") == "success":
            return f"[SUCCESS] Policy ID {policy_id} updated successfully."
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_enable_disable_policy(policy_id: int, status: str) -> str:
    """
    Enable or disable a specific firewall policy without deleting it.
    Disabled policies stay in the table but are not evaluated.
    Parameters:
    - policy_id : numeric ID of the policy
    - status    : 'enable' to activate, 'disable' to deactivate
    """
    try:
        if not policy_id:
            return "[ERROR] policy_id is required."
        if status not in ("enable", "disable"):
            return "[ERROR] status must be 'enable' or 'disable'."
        r = update_policy(policy_id, {"status": status})
        if r.get("status") == "success":
            verb = "enabled" if status == "enable" else "disabled"
            return f"[SUCCESS] Policy ID {policy_id} {verb} successfully."
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_delete_policy(policy_id: int) -> str:
    """
    Permanently delete a firewall policy by its numeric ID.
    Always use tool_list_policies first to confirm the correct ID.
    This action cannot be undone.
    """
    try:
        if not policy_id:
            return "[ERROR] policy_id is required."
        r = delete_policy(policy_id)
        if r.get("status") == "success":
            return f"[SUCCESS] Policy ID {policy_id} deleted successfully."
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_move_policy(policy_id: int, move_action: str,
                     neighbor_id: int) -> str:
    """
    Move a firewall policy before or after another policy.
    FortiGate evaluates policies top-down — the first match wins.
    Use this to fix conflicts where a deny rule is shadowed by an accept rule.
    Parameters:
    - policy_id   : ID of the policy to move
    - move_action : 'before' or 'after'
    - neighbor_id : ID of the reference policy
    Example: move policy 3 before policy 2 ensures deny takes priority.
    """
    try:
        if move_action not in ("before", "after"):
            return "[ERROR] move_action must be 'before' or 'after'."
        r = move_policy(policy_id, move_action, neighbor_id)
        if r.get("status") == "success":
            return (
                f"[SUCCESS] Policy ID {policy_id} moved "
                f"{move_action} policy ID {neighbor_id}."
            )
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════
#  ADDRESS WRITE TOOLS
# ══════════════════════════════════════════════════════════

@tool
def tool_create_address(name: str, subnet: str) -> str:
    """
    Create a new address object for use in firewall policies.
    Parameters:
    - name   : unique name, no spaces (e.g. WebServer, AdminPC)
    - subnet : CIDR notation (192.168.1.10/32 for host, 192.168.1.0/24 for subnet)
    """
    try:
        if not name or not subnet:
            return "[ERROR] Both name and subnet are required."
        r = create_address(name, subnet)
        if r.get("status") == "success":
            return f"[SUCCESS] Address object '{name}' ({subnet}) created."
        return f"[ERROR] {r}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_delete_address(name: str) -> str:
    """
    Delete an address object by its exact name.
    Will fail if the object is referenced by any firewall policy.
    Use tool_list_addresses to find the exact name.
    """
    try:
        if not name:
            return "[ERROR] Address name is required."
        r = delete_address(name.strip())
        if r.get("status") == "success":
            return f"[SUCCESS] Address object '{name}' deleted."
        return f"[ERROR] {r}"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════
#  INTERFACE WRITE TOOLS
# ══════════════════════════════════════════════════════════

@tool
def tool_update_interface_access(name: str, allowaccess: str) -> str:
    """
    Update which management protocols are allowed on an interface.
    All protocols not listed will be disabled.
    Parameters:
    - name        : interface name (e.g. port1, port2, wan1)
    - allowaccess : space-separated list of protocols to ALLOW
                    Safe: https ssh ping
                    Insecure (cleartext): http telnet
                    Example to harden: "https ssh ping"
    """
    try:
        if not name or not allowaccess:
            return "[ERROR] Both interface name and allowaccess are required."
        valid = {"https", "http", "ssh", "telnet", "ping", "snmp"}
        requested = set(allowaccess.lower().strip().split())
        invalid = requested - valid
        if invalid:
            return f"[ERROR] Invalid protocols: {invalid}. Valid: {valid}"
        r = update_interface_allowaccess(name, allowaccess.lower().strip())
        if r.get("status") == "success":
            return (
                f"[SUCCESS] Interface '{name}' management access updated.\n"
                f"   Allowed: {allowaccess.lower().strip()}"
            )
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════
#  INCIDENT RESPONSE
# ══════════════════════════════════════════════════════════

@tool
def tool_block_ip(ip_address: str, direction: str = "both",
                  srcintf: str = "port1", dstintf: str = "port2") -> str:
    """
    Block all traffic from or to a specific IP address immediately.
    Creates an address object and deny policy(ies) for incident response.
    Parameters:
    - ip_address : IP to block (e.g. 192.168.1.55 or 192.168.1.55/32)
    - direction  : 'inbound', 'outbound', or 'both' (default)
    - srcintf    : source interface (default: port1)
    - dstintf    : destination interface (default: port2)
    """
    try:
        import re as _re
        ip = ip_address.strip()
        if "/" not in ip:
            ip = ip + "/32"

        # FIX: more robust name sanitization with fixed max length
        ip_clean  = _re.sub(r'[^a-zA-Z0-9]', '-', ip)
        safe_name = f"BLOCKED-{ip_clean}"
        # Enforce 35-char FortiGate limit cleanly
        if len(safe_name) > 35:
            safe_name = safe_name[:35]

        # Create address object — handle duplicate gracefully
        addr_result = create_address(safe_name, ip)
        addr_ok = addr_result.get("status") == "success"

        if not addr_ok:
            error_code = addr_result.get("error", 0)
            cli_errors = str(addr_result.get("cli_error", ""))
            # FIX: check error -5 and -651 both indicate duplicate
            already_exists = (
                error_code in (-651, -5)
                or "already used" in cli_errors.lower()
                or "duplicate" in cli_errors.lower()
            )
            if not already_exists:
                return (
                    f"[ERROR] Could not create address object '{safe_name}': "
                    f"error {error_code}. "
                    f"Try a different IP or check for an existing object with this name."
                )
            # Address exists from previous attempt — continue with policy creation

        results = []

        if direction in ("inbound", "both"):
            policy_name = f"BLOCK-IN-{ip_clean}"[:35]
            r = create_policy(
                name=policy_name, srcintf=srcintf, dstintf=dstintf,
                srcaddr=safe_name, dstaddr="all", service="ALL", action="deny",
            )
            if r.get("status") == "success":
                results.append(f"Inbound deny policy created: '{policy_name}'")
            else:
                err = r.get("error", 0)
                if err == -4:
                    results.append("Inbound rule FAILED: policy limit reached (error -4)")
                else:
                    results.append(f"Inbound rule error: {r.get('cli_error', r)}")

        if direction in ("outbound", "both"):
            policy_name = f"BLOCK-OUT-{ip_clean}"[:35]
            r = create_policy(
                name=policy_name, srcintf=dstintf, dstintf=srcintf,
                srcaddr="all", dstaddr=safe_name, service="ALL", action="deny",
            )
            if r.get("status") == "success":
                results.append(f"Outbound deny policy created: '{policy_name}'")
            else:
                err = r.get("error", 0)
                if err == -4:
                    results.append("Outbound rule FAILED: policy limit reached (error -4)")
                else:
                    results.append(f"Outbound rule error: {r.get('cli_error', r)}")

        summary = "\n   ".join(results)
        return (
            f"[SUCCESS] IP {ip} block attempt complete.\n"
            f"   Address object: '{safe_name}'\n"
            f"   {summary}"
        )
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════
#  MAINTENANCE
# ══════════════════════════════════════════════════════════

@tool
def tool_backup_config(input: str = "") -> str:
    """
    Backup the current FortiGate configuration to a local timestamped file.
    Always do this before making significant configuration changes.
    """
    try:
        return backup_config()
    except Exception as exc:
        return f"[ERROR] Backup failed: {exc}"


# ══════════════════════════════════════════════════════════
#  INTELLIGENCE
# ══════════════════════════════════════════════════════════

@tool
def tool_search_knowledge(query: str) -> str:
    """
    Search 24,000+ chunks of official FortiGate documentation.
    Use this for ANY question: configuration, CLI commands, error codes,
    best practices, troubleshooting, feature explanations.
    This is the authoritative source — always prefer this over memory.
    Examples: 'error -651', 'how to create VLAN', 'IPsec phase1 settings'
    """
    try:
        if not query:
            return "Please provide a search query."
        import re
        if re.search(r'-?\d{1,4}', query) and "error" in query.lower():
            code = re.search(r'-?\d+', query).group()
            result = search_errors(code)
            if result:
                return result
        result = search(query, k=4)
        if not result:
            result = search(" ".join(query.split()[:4]), k=4)
        if not result:
            return "No documentation found. Please check docs.fortinet.com"
        return result
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_analyze_security(input: str = "") -> str:
    """
    Run a comprehensive security analysis of the entire FortiGate configuration.
    Detects: overly permissive policies, policy conflicts, shadowed rules,
    insecure interface management, unused address objects, resource issues.
    Returns findings by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO.
    Use when asked to analyze, audit, check security, scan, or find risks.
    """
    try:
        return run_analysis()
    except Exception as exc:
        return f"[ERROR] Security analysis failed: {exc}"


# ══════════════════════════════════════════════════════════
#  MASTER TOOL LIST
# ══════════════════════════════════════════════════════════

ALL_TOOLS = [
    # System health
    tool_get_system_status,
    tool_get_cpu_memory,
    tool_get_active_sessions,
    tool_get_vpn_status,
    # Read configuration
    tool_list_policies,
    tool_get_policy_details,
    tool_list_addresses,
    tool_list_interfaces,
    tool_list_users,
    tool_list_routes,
    # Write — policies
    tool_create_policy,
    tool_update_policy,
    tool_enable_disable_policy,
    tool_delete_policy,
    tool_move_policy,
    # Write — addresses
    tool_create_address,
    tool_delete_address,
    # Write — interfaces
    tool_update_interface_access,
    # Write — incident response
    tool_block_ip,
    # Write — maintenance
    tool_backup_config,
    # Intelligence
    tool_search_knowledge,
    tool_analyze_security,
]

# Exported for use by agent.py and test suite
TOOL_MAP = {t.name: t for t in ALL_TOOLS}