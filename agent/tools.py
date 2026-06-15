import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re
from langchain_core.tools import tool
from langchain.tools import tool as lc_tool

from modules.system     import get_system_status, reboot_system
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


#  SYSTEM HEALTH TOOLS

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


#  CONFIGURATION READ TOOLS

# ── Policy search and analysis tools ─────────────────────────────────────────

@tool
def tool_search_policies(
    action:  str = "",
    status:  str = "",
    service: str = "",
    srcintf: str = "",
    dstintf: str = "",
    name:    str = "",
    nat:     str = "",
) -> str:
    """
    Search and filter firewall policies by field values.
    Returns only policies that match ALL specified criteria.
    All parameters are optional — provide at least one filter.

    Parameters:
        action  : Filter by action: 'accept' or 'deny'
        status  : Filter by status: 'enable' or 'disable'
        service : Filter by service name e.g. 'HTTP', 'SSH', 'HTTPS', 'FTP'
        srcintf : Filter by source interface e.g. 'port1', 'wan1'
        dstintf : Filter by destination interface
        name    : Filter by policy name (partial match)
        nat     : Filter by NAT status: 'enable' or 'disable'
    """
    from modules.policies import search_policies

    filters = {}
    if action:  filters["action"]  = action.lower()
    if status:  filters["status"]  = status.lower()
    if service: filters["service"] = service.upper()
    if srcintf: filters["srcintf"] = srcintf.lower()
    if dstintf: filters["dstintf"] = dstintf.lower()
    if name:    filters["name"]    = name
    if nat:     filters["nat"]     = nat.lower()

    if not filters:
        return "[ERROR] At least one filter must be provided."

    result = search_policies(filters)

    if "error" in result:
        return f"[ERROR] {result['error']}"

    policies = result.get("results", [])
    count    = result.get("count", 0)
    total    = result.get("total_policies", 0)
    applied  = result.get("filters_applied", filters)

    if count == 0:
        filter_desc = ", ".join(f"{k}={v}" for k, v in applied.items())
        return (
            f"[SUCCESS] No policies found matching: {filter_desc}. "
            f"({total} total policies on this FortiGate)"
        )

    filter_desc = ", ".join(f"{k}={v}" for k, v in applied.items())
    lines = [
        f"[SUCCESS] Found {count} of {total} policies matching: {filter_desc}\n",
        f"| {'ID':>3} | {'Name':<25} | {'Action':<12} | {'Status':<8} | {'Src Intf':<10} | {'Dst Intf':<10} | {'Services':<20} |",
        f"|{'---':>4}-|{'-'*26}-|{'-'*13}-|{'-'*9}-|{'-'*11}-|{'-'*11}-|{'-'*21}-|"
    ]

    for p in policies:
        src    = (p.get("srcintf") or [{}])[0].get("name", "?")
        dst    = (p.get("dstintf") or [{}])[0].get("name", "?")
        svcs   = ", ".join(s.get("name", "?") for s in (p.get("service") or [])) or "—"
        flag   = " (off)" if p.get("status") == "disable" else ""
        pid    = p.get("policyid", "?")
        pname  = p.get("name", "?")
        action = p.get("action", "?")
        status = p.get("status", "enable")

        lines.append(
            f"| {pid:>3} | {pname:<25} | {action+flag:<12} | {status:<8} | {src:<10} | {dst:<10} | {svcs:<20} |"
        )

    return "\n".join(lines)


@tool
def tool_get_address_usage(address_name: str) -> str:
    """
    Find all firewall policies that reference a specific address object.
    Use this before deleting an address to check if it is still in use.

    Parameters:
        address_name : Exact name of the address object to check
    """
    from modules.policies import get_address_usage

    if not address_name or not address_name.strip():
        return "[ERROR] address_name is required."

    result = get_address_usage(address_name.strip())

    if "error" in result:
        return f"[ERROR] {result['error']}"

    count    = result.get("used_by_count", 0)
    policies = result.get("used_by", [])

    if count == 0:
        return (
            f"[SUCCESS] Address '{address_name}' is not referenced by any "
            f"firewall policy. It is safe to delete."
        )

    lines = [
        f"[SUCCESS] Address '{address_name}' is referenced by {count} policy/policies:",
        "",
        f"| {'ID':>3} | {'Name':<25} | {'Action':<12} | {'Status':<8} | {'Used as':<20} |",
        f"|{'---':>4}-|{'-'*26}-|{'-'*13}-|{'-'*9}-|{'-'*21}-|"
    ]
    for p in policies:
        roles = " + ".join(p.get("roles", []))
        lines.append(
            f"| {p['policyid']:>3} | {p['name']:<25} | {p['action']:<12} | {p.get('status','enable'):<8} | {roles:<20} |"
        )

    lines += [
        "",
        f"WARNING: Deleting '{address_name}' will break the {count} "
        f"policies listed above. Remove it from those policies first.",
    ]
    return "\n".join(lines)


@tool
def tool_get_service_usage(service_name: str) -> str:
    """
    Find all firewall policies that use a specific service object.
    Use this before deleting a custom service to check if it is still in use.

    Parameters:
        service_name : Name of the service object to check (e.g. 'SSH', 'HTTP')
    """
    from modules.policies import get_service_usage

    if not service_name or not service_name.strip():
        return "[ERROR] service_name is required."

    result = get_service_usage(service_name.strip())

    if "error" in result:
        return f"[ERROR] {result['error']}"

    count    = result.get("used_by_count", 0)
    policies = result.get("used_by", [])

    if count == 0:
        return (
            f"[SUCCESS] Service '{service_name}' is not used by any policy "
            f"(excluding policies with action=ALL)."
        )

    lines = [
        f"[SUCCESS] Service '{service_name}' is used by {count} policy/policies:",
        "",
        f"  {'ID':>3} | {'Name':<25} | {'Action':>6} | Status",
        "  " + "-" * 55,
    ]
    for p in policies:
        lines.append(
            f"  {p['policyid']:>3} | {p['name']:<25} | "
            f"{p['action']:>6} | {p.get('status','enable')}"
        )
    return "\n".join(lines)

@lc_tool
def tool_list_services() -> str:
    """
    List all service objects defined on this FortiGate.
    Includes built-in and custom services.
    """
    try:
        from api.client import get
        r = get("/cmdb/firewall.service/custom")
        results = r if isinstance(r, list) else r.get("results", [])
        
        if not results:
            return "[SUCCESS] No custom service objects found. Only built-in services available."
        
        lines = [f"[SUCCESS] Custom service objects ({len(results)}):"]
        for s in results:
            proto = s.get("protocol", "?")
            port  = s.get("tcp-portrange", s.get("udp-portrange", ""))
            lines.append(
                f"  {s.get('name','?'):<30} protocol={proto} port={port}"
            )
        return "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] Could not fetch services: {exc}"

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
        lines = [
            f"| {'ID':>3} | {'Name':<25} | {'Action':<12} | {'Status':<8} | {'Src Intf':<10} | {'Dst Intf':<10} | {'Services':<20} |",
            f"|{'---':>4}-|{'-'*26}-|{'-'*13}-|{'-'*9}-|{'-'*11}-|{'-'*11}-|{'-'*21}-|"
        ]
        for p in results:
            src    = (p.get("srcintf") or [{}])[0].get("name", "?")
            dst    = (p.get("dstintf") or [{}])[0].get("name", "?")
            svcs   = ", ".join(s.get("name", "?") for s in (p.get("service") or [])) or "—"
            flag   = " (off)" if p.get("status") == "disable" else ""
            pid    = p.get("policyid", "?")
            pname  = p.get("name", "?")
            action = p.get("action", "?")
            status = p.get("status", "enable")
            
            lines.append(
                f"| {pid:>3} | {pname:<25} | {action+flag:<12} | {status:<8} | {src:<10} | {dst:<10} | {svcs:<20} |"
            )
        return "Firewall Policies:\n\n" + "\n".join(lines)
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

        src_intf  = ', '.join(i.get('name','?') for i in p.get('srcintf',[]))
        dst_intf  = ', '.join(i.get('name','?') for i in p.get('dstintf',[]))
        src_addr  = ', '.join(a.get('name','?') for a in p.get('srcaddr',[]))
        dst_addr  = ', '.join(a.get('name','?') for a in p.get('dstaddr',[]))
        services  = ', '.join(s.get('name','?') for s in p.get('service',[]))

        lines = [
            f"| {'Field':<15} | {'Value':<50} |",
            f"|{'-'*17}-|{'-'*52}-|",
            f"| {'Policy ID':<15} | {str(p.get('policyid', '?')):<50} |",
            f"| {'Name':<15} | {p.get('name', '?'):<50} |",
            f"| {'Status':<15} | {p.get('status', '?'):<50} |",
            f"| {'Action':<15} | {p.get('action', '?'):<50} |",
            f"| {'Src Interface':<15} | {src_intf:<50} |",
            f"| {'Dst Interface':<15} | {dst_intf:<50} |",
            f"| {'Src Address':<15} | {src_addr:<50} |",
            f"| {'Dst Address':<15} | {dst_addr:<50} |",
            f"| {'Services':<15} | {services:<50} |",
            f"| {'Schedule':<15} | {p.get('schedule', '?'):<50} |",
            f"| {'Log Traffic':<15} | {p.get('logtraffic', '?'):<50} |",
            f"| {'NAT':<15} | {p.get('nat', '?'):<50} |"
        ]
        return "\n".join(lines)
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


#  POLICY WRITE TOOLS

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
    For service, you can specify multiple services comma-separated: "SSH,HTTPS"
    Parameters:
    - policy_id : numeric ID (required)
    - action    : 'accept' or 'deny'
    - srcaddr   : source address object name
    - dstaddr   : destination address object name
    - service   : service name(s) — single (SSH) or multiple (SSH,HTTPS)
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
        if service:
            # FIX: parse comma/space separated services into list of dicts
            parts = [s.strip() for s in re.split(r'[,\s]+', service) if s.strip()]
            data["service"] = [{"name": p} for p in parts]
        if not data:
            return "[ERROR] No fields to update were provided."
        r = update_policy(policy_id, data)
        if r.get("status") == "success":
            svc_display = service if service else "unchanged"
            return f"[SUCCESS] Policy ID {policy_id} updated. Services: {svc_display}"
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


#  ADDRESS WRITE TOOLS

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


#  INTERFACE WRITE TOOLS

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


#  INCIDENT RESPONSE

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


#  MAINTENANCE

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


#  INTELLIGENCE

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


# ══════════════════════════════════════════════════════════════════════════════
#  OBSERVABILITY TOOLS — Log analysis
# ══════════════════════════════════════════════════════════════════════════════

@tool
def tool_get_traffic_logs(input: str = "") -> str:
    """
    Retrieve the 50 most recent firewall traffic log entries.
    Shows source/destination IPs, ports, policy matched, and allow/deny action.
    Use when asked about recent traffic, connection history, or what traffic passed.
    """
    try:
        from modules.logs import get_traffic_logs
        r = get_traffic_logs()
        logs = r if isinstance(r, list) else r.get("results", [])
        if not logs:
            return "[SUCCESS] No traffic log entries found."
        lines = ["Recent Traffic Logs (last 50):", ""]
        for e in logs[:50]:
            src  = e.get("srcip", e.get("src", "?"))
            dst  = e.get("dstip", e.get("dst", "?"))
            port = e.get("dstport", "?")
            act  = e.get("action", "?").upper()
            pol  = e.get("policyid", e.get("policy", "?"))
            svc  = e.get("service", e.get("proto", "?"))
            ts   = e.get("date", "") + " " + e.get("time", "")
            lines.append(
                f"  {ts:<20} {src:<18} → {dst:<18}:{port:<6} "
                f"svc={svc:<10} policy={pol:<4} {act}"
            )
        return "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_get_threat_logs(input: str = "") -> str:
    """
    Retrieve the 50 most recent IPS/threat detection log entries.
    Shows attacker IP, victim IP, attack name, severity, and action taken.
    Use when asked about intrusion attempts, threats, attacks, or IPS alerts.
    """
    try:
        from modules.logs import get_threat_logs
        r = get_threat_logs()
        logs = r if isinstance(r, list) else r.get("results", [])
        if not logs:
            return "[SUCCESS] No threat log entries found."
        lines = ["Recent Threat Logs (last 50):", ""]
        for e in logs[:50]:
            src      = e.get("srcip",    "?")
            dst      = e.get("dstip",    "?")
            attack   = e.get("attack",   e.get("msg", "?"))
            severity = e.get("severity", "?").upper()
            action   = e.get("action",   "?").upper()
            ts       = e.get("date", "") + " " + e.get("time", "")
            lines.append(
                f"  {ts:<20} [{severity:<8}] {src:<18} → {dst:<18} "
                f"{attack:<40} action={action}"
            )
        return "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_get_event_logs(input: str = "") -> str:
    """
    Retrieve the 50 most recent system event log entries.
    Shows admin logins, configuration changes, system events, and failures.
    Use when asked about admin activity, config changes, or system events.
    """
    try:
        from modules.logs import get_event_logs
        r = get_event_logs()
        logs = r if isinstance(r, list) else r.get("results", [])
        if not logs:
            return "[SUCCESS] No event log entries found."
        lines = ["Recent Event Logs (last 50):", ""]
        for e in logs[:50]:
            user  = e.get("user",    e.get("admin", "system"))
            msg   = e.get("msg",     e.get("logdesc", "?"))
            level = e.get("level",   "?").upper()
            ts    = e.get("date", "") + " " + e.get("time", "")
            lines.append(f"  {ts:<20} [{level:<8}] user={user:<15} {msg}")
        return "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════════════════════════
#  MONITORING TOOLS — Network performance
# ══════════════════════════════════════════════════════════════════════════════

@tool
def tool_get_bandwidth_usage(input: str = "") -> str:
    """
    Get real-time bandwidth utilisation per interface (TX and RX in Mbps/Kbps).
    Use when asked about network throughput, bandwidth, traffic load, or interface speed.
    """
    try:
        from modules.monitor import get_bandwidth
        r       = get_bandwidth()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "[SUCCESS] No bandwidth data available."
        lines = ["Interface Bandwidth Usage:", ""]
        for iface in results:
            name = iface.get("id", iface.get("name", "?"))
            tx   = iface.get("tx_bytes", iface.get("tx_byte", 0))
            rx   = iface.get("rx_bytes", iface.get("rx_byte", 0))
            def _fmt(b):
                b = int(b) if b else 0
                if b >= 1_000_000:
                    return f"{b/1_000_000:.1f} MB/s"
                elif b >= 1_000:
                    return f"{b/1_000:.1f} KB/s"
                return f"{b} B/s"
            lines.append(f"  {name:<20} TX: {_fmt(tx):<15} RX: {_fmt(rx)}")
        return "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTE WRITE TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@tool
def tool_create_route(dst: str, gateway: str, device: str, netmask: str = "255.255.255.0") -> str:
    """
    Add a static route to the FortiGate routing table.
    Parameters:
    - dst     : destination network in dotted-decimal (e.g. 10.20.0.0)
    - gateway : next-hop IP address (e.g. 192.168.1.1)
    - device  : outbound interface name (e.g. wan1, port2)
    - netmask : subnet mask in dotted-decimal (default 255.255.255.0)
    Example: add route to 10.20.0.0/24 via 192.168.1.1 on wan1
    """
    try:
        if not dst or not gateway or not device:
            return "[ERROR] dst, gateway, and device are all required."
        from modules.routing import create_route
        r = create_route(dst, gateway, device, netmask)
        if r.get("status") == "success":
            return (
                f"[SUCCESS] Static route added: {dst}/{netmask} "
                f"via {gateway} on {device}."
            )
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_delete_route(route_id: int) -> str:
    """
    Delete a static route by its numeric ID.
    Use tool_list_routes first to identify the correct route ID.
    This action cannot be undone — removing an active route may disrupt connectivity.
    Parameters:
    - route_id : numeric ID of the static route to delete
    """
    try:
        if not route_id:
            return "[ERROR] route_id is required."
        from modules.routing import delete_route
        r = delete_route(route_id)
        if r.get("status") == "success":
            return f"[SUCCESS] Static route ID {route_id} deleted."
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════════════════════════
#  CUSTOM SERVICE WRITE TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@tool
def tool_create_service(name: str, protocol: str = "TCP", port_range: str = "8080") -> str:
    """
    Create a custom service object for use in firewall policies.
    Parameters:
    - name       : unique name for the service (e.g. MyApp, CustomHTTPS)
    - protocol   : TCP or UDP (default: TCP)
    - port_range : single port or range (e.g. 8080, 8000-8080)
    Example: create service MyApp TCP port 8443
    """
    try:
        if not name:
            return "[ERROR] Service name is required."
        protocol = protocol.upper()
        if protocol not in ("TCP", "UDP", "ICMP", "IP"):
            return "[ERROR] protocol must be TCP, UDP, ICMP, or IP."
        from modules.services import create_service
        r = create_service(name.strip(), protocol, port_range)
        if r.get("status") == "success":
            return (
                f"[SUCCESS] Custom service '{name}' created "
                f"({protocol}/{port_range})."
            )
        cli = r.get("cli_error", "")
        if r.get("error") in (-651, -5) or "already used" in str(cli).lower():
            return f"[ERROR] Service '{name}' already exists."
        return f"[ERROR] {cli or r}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_delete_service(name: str) -> str:
    """
    Delete a custom service object by its exact name.
    Will fail if the service is still referenced by active firewall policies.
    Use tool_get_service_usage first to check if the service is in use.
    Parameters:
    - name : exact name of the service object to delete
    """
    try:
        if not name:
            return "[ERROR] Service name is required."
        from modules.services import delete_service
        r = delete_service(name.strip())
        if r.get("status") == "success":
            return f"[SUCCESS] Custom service '{name}' deleted."
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════════════════════════
#  INTERFACE WRITE TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@tool
def tool_set_interface_status(name: str, status: str) -> str:
    """
    Bring a network interface administratively up or down.
    WARNING: Bringing down an in-use interface will drop active connections.
    Always verify traffic is not dependent on this interface before disabling.
    Parameters:
    - name   : interface name (e.g. port1, port2, wan1)
    - status : 'up' to enable, 'down' to disable
    """
    try:
        if not name or not status:
            return "[ERROR] Both interface name and status are required."
        status = status.lower()
        if status not in ("up", "down"):
            return "[ERROR] status must be 'up' or 'down'."
        from modules.interfaces import set_interface_status
        r = set_interface_status(name.strip(), status)
        if r.get("status") == "success":
            verb = "enabled" if status == "up" else "disabled"
            return f"[SUCCESS] Interface '{name}' is now {verb}."
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════════════════════════
#  USER MANAGEMENT WRITE TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@tool
def tool_create_user(name: str, password: str, status: str = "enable") -> str:
    """
    Create a new local user account on the FortiGate.
    The user can be added to user groups for policy-based authentication.
    Parameters:
    - name     : unique username (no spaces)
    - password : initial password (minimum 8 characters recommended)
    - status   : 'enable' (default) or 'disable'
    """
    try:
        if not name or not password:
            return "[ERROR] Both username and password are required."
        if len(password) < 6:
            return "[ERROR] Password must be at least 6 characters."
        status = status.lower()
        if status not in ("enable", "disable"):
            return "[ERROR] status must be 'enable' or 'disable'."
        from modules.users import create_user
        r = create_user(name.strip(), password, status)
        if r.get("status") == "success":
            return f"[SUCCESS] Local user '{name}' created (status: {status})."
        cli = r.get("cli_error", "")
        if r.get("error") in (-651, -5) or "already used" in str(cli).lower():
            return f"[ERROR] User '{name}' already exists."
        return f"[ERROR] {cli or r}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@tool
def tool_delete_user(name: str) -> str:
    """
    Delete a local user account by name.
    This permanently removes the account and any associated authentication state.
    Parameters:
    - name : exact username to delete
    """
    try:
        if not name:
            return "[ERROR] Username is required."
        from modules.users import delete_user
        r = delete_user(name.strip())
        if r.get("status") == "success":
            return f"[SUCCESS] Local user '{name}' deleted."
        return f"[ERROR] {r.get('cli_error', r)}"
    except Exception as exc:
        return f"[ERROR] {exc}"


#  SYSTEM CONTROL
# ══════════════════════════════════════════════════════════════════════════════

@tool
def tool_reboot_system(input: str = "") -> str:
    """
    Reboot the FortiGate firewall appliance.
    This is a destructive action that severs all network connections and the management session.
    """
    try:
        r = reboot_system()
        if isinstance(r, dict) and r.get("status") == "success":
            return "[SUCCESS] Firewall is rebooting. Expect connection loss."
        return f"[ERROR] Reboot failed: {r}"
    except Exception as exc:
        if "timeout" in str(exc).lower() or "connection" in str(exc).lower() or "refused" in str(exc).lower():
            return "[SUCCESS] Firewall is rebooting (connection dropped as expected)."
        return f"[ERROR] Reboot failed: {exc}"


#  MASTER TOOL LIST

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
    tool_get_address_usage,
    tool_search_policies,
    tool_get_service_usage,
    tool_list_services,
    # Observability — logs
    tool_get_traffic_logs,
    tool_get_threat_logs,
    tool_get_event_logs,
    # Monitoring — network
    tool_get_bandwidth_usage,
    # Write — policies
    tool_create_policy,
    tool_update_policy,
    tool_enable_disable_policy,
    tool_delete_policy,
    tool_move_policy,
    # Write — addresses
    tool_create_address,
    tool_delete_address,
    # Write — routes
    tool_create_route,
    tool_delete_route,
    # Write — services
    tool_create_service,
    tool_delete_service,
    # Write — interfaces
    tool_update_interface_access,
    tool_set_interface_status,
    # Write — users
    tool_create_user,
    tool_delete_user,
    # Write — incident response
    tool_block_ip,
    # Write — maintenance
    tool_backup_config,
    tool_reboot_system,
    # Intelligence
    tool_search_knowledge,
    tool_analyze_security,
]

# Exported for use by agent.py and test suite
TOOL_MAP = {t.name: t for t in ALL_TOOLS}

WRITE_TOOLS = {
    "tool_create_policy",
    "tool_update_policy",
    "tool_enable_disable_policy",
    "tool_delete_policy",
    "tool_move_policy",
    "tool_create_address",
    "tool_delete_address",
    "tool_create_route",
    "tool_delete_route",
    "tool_create_service",
    "tool_delete_service",
    "tool_update_interface_access",
    "tool_set_interface_status",
    "tool_create_user",
    "tool_delete_user",
    "tool_block_ip",
    "tool_backup_config",
    "tool_reboot_system",
}
