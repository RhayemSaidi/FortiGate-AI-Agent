import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_core.tools import tool

from modules.system     import get_system_status
from modules.monitor    import get_cpu_usage, get_memory_usage, get_active_sessions
from modules.policies   import (
    list_policies, get_policy,
    create_policy, update_policy,
    delete_policy, move_policy,
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
#  READ TOOLS — System health
# ══════════════════════════════════════════════════════════

@tool
def tool_get_system_status(input: str = "") -> str:
    """
    Get the FortiGate system status: hostname, hardware model,
    firmware version, and serial number.
    Use this when the user asks about the device, firmware,
    or 'what FortiGate is this'.
    """
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
    """
    Get the current CPU and memory usage percentages of the FortiGate.
    Also reports the 1-minute CPU peak.
    Use this when the user asks about performance, resource usage,
    CPU, memory, or RAM.
    """
    try:
        cpu_data  = get_cpu_usage()
        mem_data  = get_memory_usage()

        cpu_list  = cpu_data.get("results", {}).get("cpu", [{}])
        cpu_entry = cpu_list[0] if cpu_list else {}
        cpu_val   = cpu_entry.get("current", "N/A")
        cpu_max   = cpu_entry.get("historical", {}).get("1-min", {}).get("max", "N/A")

        mem_list  = mem_data.get("results", {}).get("mem", [{}])
        mem_entry = mem_list[0] if mem_list else {}
        mem_val   = mem_entry.get("current", "N/A")

        return (
            f"CPU usage    : {cpu_val}%  (1-min peak: {cpu_max}%)\n"
            f"Memory usage : {mem_val}%"
        )
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_get_active_sessions(input: str = "") -> str:
    """
    Get the current number of active firewall sessions on the FortiGate.
    High session counts may indicate a DoS attack or connection leak.
    Use this when the user asks about active connections or session count.
    """
    try:
        r       = get_active_sessions()
        results = r.get("results", {})

        if isinstance(results, dict):
            count = (results.get("session_count")
                     or results.get("total")
                     or results.get("filt_count"))
            if count is not None:
                return f"Active firewall sessions: {count:,}"
            summary = ", ".join(
                f"{k}: {v}" for k, v in results.items()
                if isinstance(v, (int, float, str))
            )
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
    """
    Get the live status of all IPsec VPN tunnels on the FortiGate.
    Shows tunnel name, UP/DOWN status, remote gateway, and traffic volume.
    Use this when the user asks about VPN tunnels, IPsec, or VPN connectivity.
    """
    try:
        r       = get_vpn_status()
        results = r if isinstance(r, list) else r.get("results", [])

        if not results:
            return "No IPsec VPN tunnels configured."

        def _fmt(b: int) -> str:
            return f"{b / 1024:.1f} KB" if b >= 1024 else f"{b} B"

        lines = []
        for tunnel in results:
            lines.append(
                f"  {tunnel.get('name', '?'):<30} "
                f"status: {tunnel.get('status', '?').upper():<12} "
                f"remote: {tunnel.get('rgwy', '?'):<18} "
                f"in: {_fmt(tunnel.get('incoming_bytes', 0))}  "
                f"out: {_fmt(tunnel.get('outgoing_bytes', 0))}"
            )
        return "IPsec VPN Tunnels:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════
#  READ TOOLS — Configuration
# ══════════════════════════════════════════════════════════

@tool
def tool_list_policies(input: str = "") -> str:
    """
    List all firewall policies currently configured on the FortiGate.
    Shows ID, name, action (accept/deny), and traffic direction.
    Use this to get an overview of all rules before making changes.
    """
    try:
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No firewall policies found."

        lines = []
        for p in results:
            src_list = p.get("srcintf") or [{}]
            dst_list = p.get("dstintf") or [{}]
            src_name = src_list[0].get("name", "?") if src_list else "?"
            dst_name = dst_list[0].get("name", "?") if dst_list else "?"
            lines.append(
                f"  ID {p.get('policyid', '?'):>3} | "
                f"{p.get('name', 'unnamed'):<30} | "
                f"{p.get('action', '?'):>6} | "
                f"{src_name} -> {dst_name}"
            )
        return "Firewall Policies:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_get_policy_details(policy_id: int) -> str:
    """
    Get the complete details of a single firewall policy by its numeric ID.
    Returns all fields: interfaces, addresses, services, action, schedule,
    logging, and status. Use this before updating or deleting a policy
    to confirm you have the right rule.
    Parameter:
    - policy_id : the numeric policy ID from tool_list_policies
    """
    try:
        r = get_policy(policy_id)
        results = r.get("results", {})
        # FortiOS returns a list for single-object queries in some versions
        p = results[0] if isinstance(results, list) and results else results
        if not p:
            return f"[ERROR] Policy ID {policy_id} not found."

        src_intfs = [i.get("name") for i in p.get("srcintf", [])]
        dst_intfs = [i.get("name") for i in p.get("dstintf", [])]
        src_addrs = [a.get("name") for a in p.get("srcaddr", [])]
        dst_addrs = [a.get("name") for a in p.get("dstaddr", [])]
        services  = [s.get("name") for s in p.get("service",  [])]

        return (
            f"Policy ID    : {p.get('policyid', '?')}\n"
            f"Name         : {p.get('name', '?')}\n"
            f"Status       : {p.get('status', '?')}\n"
            f"Action       : {p.get('action', '?')}\n"
            f"Src Interface: {', '.join(src_intfs)}\n"
            f"Dst Interface: {', '.join(dst_intfs)}\n"
            f"Src Address  : {', '.join(src_addrs)}\n"
            f"Dst Address  : {', '.join(dst_addrs)}\n"
            f"Services     : {', '.join(services)}\n"
            f"Schedule     : {p.get('schedule', '?')}\n"
            f"Log Traffic  : {p.get('logtraffic', '?')}\n"
            f"NAT          : {p.get('nat', '?')}"
        )
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_list_addresses(input: str = "") -> str:
    """
    List all address objects configured on the FortiGate.
    Shows name and subnet/FQDN for the first 15 objects.
    Use this to find address objects before creating policies or
    to check if an object already exists.
    """
    try:
        r       = list_addresses()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No address objects found."
        lines = []
        for a in results[:15]:
            subnet = a.get("subnet") or a.get("fqdn") or "N/A"
            lines.append(f"  {a.get('name', '?'):<35} {subnet}")
        if len(results) > 15:
            lines.append(f"  ... and {len(results) - 15} more")
        return "Address Objects:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_list_interfaces(input: str = "") -> str:
    """
    List all network interfaces on the FortiGate with IP address and status.
    Use this to verify interface names before creating policies,
    or to check which interfaces are UP/DOWN.
    """
    try:
        r       = list_interfaces()
        results = r if isinstance(r, list) else r.get("results", [])
        lines   = []
        for iface in results[:10]:
            lines.append(
                f"  {iface.get('name', '?'):<20} "
                f"{iface.get('ip', '0.0.0.0 0.0.0.0'):<25} "
                f"status: {iface.get('status', '?')}"
            )
        return "Network Interfaces:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_list_users(input: str = "") -> str:
    """
    List all local user accounts configured on the FortiGate.
    Shows username and account status (enable/disable).
    """
    try:
        r       = list_users()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No local users found."
        lines = [
            f"  {u.get('name', '?'):<25} status: {u.get('status', '?')}"
            for u in results
        ]
        return "Local Users:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_list_routes(input: str = "") -> str:
    """
    List all static routes configured on the FortiGate.
    Shows destination, gateway, and interface for each route.
    """
    try:
        r       = list_routes()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No static routes configured."
        lines = [
            f"  {route.get('dst', '?'):<25} "
            f"via {route.get('gateway', '?'):<18} "
            f"on {route.get('device', '?')}"
            for route in results
        ]
        return "Static Routes:\n" + "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════
#  WRITE TOOLS — Policy management
# ══════════════════════════════════════════════════════════

@tool
def tool_create_policy(name: str, srcintf: str, dstintf: str,
                       srcaddr: str = "all", dstaddr: str = "all",
                       service: str = "ALL", action: str = "accept") -> str:
    """
    Create a new firewall policy on the FortiGate.
    All traffic is logged automatically. Schedule defaults to 'always'.
    Parameters:
    - name     : unique policy name, no spaces (use hyphens)
    - srcintf  : source interface name (e.g. port1, wan1)
    - dstintf  : destination interface name (e.g. port2, lan)
    - srcaddr  : source address object name (default: all)
    - dstaddr  : destination address object name (default: all)
    - service  : service name — ALL, HTTP, HTTPS, SSH, FTP, DNS, SMTP, RDP, PING
    - action   : accept (allow) or deny (block)
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
            return (
                f"[SUCCESS] Policy '{name}' created successfully.\n"
                f"   {srcintf} -> {dstintf} | service: {service} | action: {action}"
            )
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_update_policy(policy_id: int, action: str = "",
                       srcaddr: str = "", dstaddr: str = "",
                       service: str = "", status: str = "",
                       name: str = "") -> str:
    """
    Modify an existing firewall policy on the FortiGate.
    Only the fields you provide are changed — all others remain unchanged.
    Use tool_get_policy_details first to see current values.
    Parameters:
    - policy_id : numeric ID of the policy to update (required)
    - action    : change to 'accept' or 'deny' (optional)
    - srcaddr   : new source address object name (optional)
    - dstaddr   : new destination address object name (optional)
    - service   : new service (ALL, HTTP, HTTPS, SSH, etc.) (optional)
    - status    : 'enable' to activate, 'disable' to deactivate (optional)
    - name      : rename the policy (optional)
    """
    try:
        if not policy_id:
            return "[ERROR] policy_id is required."

        data = {}
        if name:    data["name"]    = name
        if status:  data["status"]  = status
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
            changed = ", ".join(
                f"{k}={v}" for k, v in data.items()
                if k not in ("srcaddr", "dstaddr", "service")
            )
            return (
                f"[SUCCESS] Policy ID {policy_id} updated.\n"
                f"   Changes applied: {changed or 'address/service fields'}"
            )
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_delete_policy(policy_id: int) -> str:
    """
    Permanently delete a firewall policy from the FortiGate by its numeric ID.
    This removes the rule from the policy table. The action cannot be undone.
    IMPORTANT: Always use tool_list_policies first to confirm the correct policy ID
    before calling this tool.
    Parameter:
    - policy_id : numeric ID of the policy to delete
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
    Move a firewall policy before or after another policy in the table.
    FortiGate evaluates policies top-down — the first matching rule wins.
    Use this to fix conflicts where a deny rule is shadowed by an accept rule
    with higher priority (lower ID). Moving the deny rule before the accept
    rule ensures it takes effect.
    Parameters:
    - policy_id   : ID of the policy you want to move
    - move_action : 'before' or 'after'
    - neighbor_id : ID of the reference policy
    Example: move policy 3 before policy 2 fixes a conflict where 2 shadows 3.
    """
    try:
        if move_action not in ("before", "after"):
            return "[ERROR] move_action must be 'before' or 'after'."
        r = move_policy(policy_id, move_action, neighbor_id)
        if r.get("status") == "success":
            return (
                f"[SUCCESS] Policy ID {policy_id} moved "
                f"{move_action} policy ID {neighbor_id}. "
                f"Rule order updated."
            )
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════
#  WRITE TOOLS — Address objects
# ══════════════════════════════════════════════════════════

@tool
def tool_create_address(name: str, subnet: str) -> str:
    """
    Create a new address object on the FortiGate.
    Address objects are used in firewall policies as source/destination.
    Parameters:
    - name   : unique name, no spaces (e.g. WebServer, AdminPC)
    - subnet : IP in CIDR notation (e.g. 192.168.1.10/32 for host,
               192.168.1.0/24 for subnet, or 0.0.0.0/0 for any)
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
    Delete an address object from the FortiGate by its exact name.
    NOTE: If the object is referenced by a firewall policy, deletion will fail.
    Use tool_list_addresses to find the exact name.
    Parameter:
    - name : exact name of the address object to delete
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
#  WRITE TOOLS — Interfaces
# ══════════════════════════════════════════════════════════

@tool
def tool_update_interface_access(name: str, allowaccess: str) -> str:
    """
    Update which management protocols are allowed on a network interface.
    Use this to harden security by disabling HTTP/TELNET and keeping
    only HTTPS and SSH, or to fix insecure management access findings.
    Parameters:
    - name        : interface name (e.g. port1, port2, wan1)
    - allowaccess : space-separated list of protocols to ALLOW.
                    All others will be disabled.
                    Safe values  : https ssh ping snmp
                    Insecure     : http telnet (credentials in cleartext)
                    Example (secure): "https ssh ping"
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
#  WRITE TOOLS — Incident response
# ══════════════════════════════════════════════════════════

@tool
def tool_block_ip(ip_address: str, direction: str = "both",
                  srcintf: str = "port1", dstintf: str = "port2") -> str:
    """
    Block all traffic from or to a specific IP address by creating
    an address object and a deny policy. Use this for incident response
    when you need to immediately block a suspicious or malicious IP.
    Parameters:
    - ip_address : the IP to block in CIDR notation (e.g. 192.168.1.55/32)
    - direction  : 'inbound' (block incoming), 'outbound' (block outgoing),
                   or 'both' (block in both directions, default)
    - srcintf    : source interface (default: port1)
    - dstintf    : destination interface (default: port2)
    """
    try:
        import re as _re
        # Normalize IP
        ip = ip_address.strip()
        if "/" not in ip:
            ip = ip + "/32"

        # Sanitize for use as an object name
        safe_name = "BLOCKED-" + _re.sub(r'[^a-zA-Z0-9]', '-', ip)[:25]

        # Create address object
        addr_result = create_address(safe_name, ip)
        if addr_result.get("status") != "success":
            # Address may already exist — continue anyway
            if "already used" not in str(addr_result):
                return f"[ERROR] Could not create address object: {addr_result}"

        results = []

        if direction in ("inbound", "both"):
            policy_name = f"BLOCK-IN-{safe_name}"[:35]
            r = create_policy(
                name=policy_name,
                srcintf=srcintf,
                dstintf=dstintf,
                srcaddr=safe_name,
                dstaddr="all",
                service="ALL",
                action="deny",
            )
            if r.get("status") == "success":
                results.append(f"Inbound deny rule created: '{policy_name}'")
            else:
                results.append(f"Inbound rule error: {r.get('cli_error', r)}")

        if direction in ("outbound", "both"):
            policy_name = f"BLOCK-OUT-{safe_name}"[:35]
            r = create_policy(
                name=policy_name,
                srcintf=dstintf,
                dstintf=srcintf,
                srcaddr="all",
                dstaddr=safe_name,
                service="ALL",
                action="deny",
            )
            if r.get("status") == "success":
                results.append(f"Outbound deny rule created: '{policy_name}'")
            else:
                results.append(f"Outbound rule error: {r.get('cli_error', r)}")

        summary = "\n   ".join(results)
        return (
            f"[SUCCESS] IP {ip_address} blocked.\n"
            f"   Address object: '{safe_name}'\n"
            f"   {summary}"
        )
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════
#  WRITE TOOLS — Maintenance
# ══════════════════════════════════════════════════════════

@tool
def tool_backup_config(input: str = "") -> str:
    """
    Download and save the current FortiGate configuration to a local file.
    The backup file is saved in the project directory with a timestamp.
    Use this before making any significant configuration changes.
    """
    try:
        return backup_config()
    except Exception as exc:
        return f"[ERROR] Backup failed: {exc}"


# ══════════════════════════════════════════════════════════
#  INTELLIGENCE TOOLS
# ══════════════════════════════════════════════════════════

@tool
def tool_search_knowledge(query: str) -> str:
    """
    Search the FortiGate official documentation knowledge base.
    Use this for ANY question about FortiGate — configuration steps,
    error codes, CLI commands, best practices, troubleshooting,
    feature explanations, or security recommendations.
    This tool searches 24,000+ chunks of official Fortinet documentation.
    Parameters:
    - query : the question or topic (be specific for better results)
    Examples: 'what does error -651 mean', 'how to create a VLAN',
              'IPsec phase1 configuration', 'FortiOS logging best practices'
    """
    try:
        if not query:
            return "Please provide a search query."

        import re
        if re.search(r'-?\d{1,4}', query) and "error" in query.lower():
            error_code = re.search(r'-?\d+', query).group()
            result = search_errors(error_code)
            if result:
                return result

        result = search(query, k=4)
        if not result:
            simplified = " ".join(query.split()[:4])
            result = search(simplified, k=4)

        if not result:
            return (
                "No specific documentation found for this query. "
                "Please consult docs.fortinet.com for the latest information."
            )
        return result
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_analyze_security(input: str = "") -> str:
    """
    Run a comprehensive security analysis of the entire FortiGate configuration.
    Detects: overly permissive policies, policy conflicts, shadowed rules,
    insecure interface management, unused address objects, and resource issues.
    Returns findings grouped by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO.
    Use this when the user asks to 'analyze', 'audit', 'check security',
    'find risks', 'scan', or 'review the firewall'.
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