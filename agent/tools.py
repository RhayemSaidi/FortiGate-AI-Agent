import json
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_core.tools import tool
from modules.system import get_system_status
from modules.monitor import get_cpu_usage, get_memory_usage
from modules.policies import list_policies, create_policy
from modules.addresses import list_addresses, create_address, delete_address
from modules.interfaces import list_interfaces
from modules.routing import list_routes
from modules.users import list_users
from modules.backup import backup_config
from modules.interfaces import list_interfaces, get_interface, update_interface_allowaccess
from rag.retriever import search, search_errors
from insights import run_analysis


def _parse_input(input_data) -> dict:
    """
    Safely parse tool input regardless of format.
    Handles: dict, JSON string, empty string, None.
    This fixes the core reliability issue with qwen2.5:3b.
    """
    if isinstance(input_data, dict):
        return input_data
    if isinstance(input_data, str):
        input_data = input_data.strip()
        if not input_data:
            return {}
        try:
            return json.loads(input_data)
        except json.JSONDecodeError:
            return {"raw": input_data}
    return {}


# ── READ TOOLS ────────────────────────────────────────────

@tool
def tool_update_interface_access(name: str, allowaccess: str) -> str:
    """
    Update the management access protocols on a FortiGate network interface.
    Use this to enable or disable HTTP, HTTPS, SSH, TELNET, PING on an interface.
    Parameters:
    - name        : interface name (e.g. port1, port2)
    - allowaccess : space-separated list of allowed protocols
                    Valid values: https http ssh telnet ping snmp
                    Example to allow only HTTPS and SSH: "https ssh ping"
                    Example to remove HTTP and TELNET: "https ssh ping"
    """
    try:
        if not name or not allowaccess:
            return "[ERROR] Both interface name and allowaccess are required."

        # Validate allowed protocols
        valid_protocols = {"https", "http", "ssh", "telnet", "ping", "snmp"}
        requested = set(allowaccess.lower().strip().split())
        invalid = requested - valid_protocols
        if invalid:
            return f"[ERROR] Invalid protocols: {invalid}. Valid: {valid_protocols}"

        r = update_interface_allowaccess(name, allowaccess.lower().strip())
        if r.get("status") == "success":
            return (
                f"[SUCCESS] Interface '{name}' management access updated.\n"
                f"   Allowed protocols: {allowaccess.lower().strip()}"
            )
        return f"[ERROR] Failed to update interface: {r.get('cli_error', r)}"
    except Exception as e:
        return f"[ERROR] Exception updating interface: {str(e)}"

@tool
def tool_get_system_status(input: str = "") -> str:
    """Get the FortiGate system status including hostname, model and firmware version."""
    try:
        r = get_system_status()
        res = r.get("results", {})
        return (
            f"Hostname : {res.get('hostname', 'N/A')}\n"
            f"Model    : {res.get('model_name', 'N/A')}\n"
            f"Version  : {r.get('version', 'N/A')}\n"
            f"Serial   : {r.get('serial', 'N/A')}"
        )
    except Exception as e:
        return f"Error getting system status: {str(e)}"


@tool
def tool_get_cpu_memory(input: str = "") -> str:
    """Get current CPU and memory usage percentages of the FortiGate."""
    try:
        cpu = get_cpu_usage()
        mem = get_memory_usage()
        cpu_val = cpu["results"]["cpu"][0]["current"]
        mem_val = mem["results"]["mem"][0]["current"]
        cpu_max = cpu["results"]["cpu"][0]["historical"]["1-min"]["max"]
        return (
            f"CPU usage    : {cpu_val}% (1-min peak: {cpu_max}%)\n"
            f"Memory usage : {mem_val}%"
        )
    except Exception as e:
        return f"Error getting resource usage: {str(e)}"


@tool
def tool_list_policies(input: str = "") -> str:
    """List all firewall policies currently configured on the FortiGate."""
    try:
        r = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No firewall policies found."
        lines = []
        for p in results:
            lines.append(
                f"  ID {p.get('policyid'):>3} | {p.get('name', 'unnamed'):<30} "
                f"| {p.get('action', '?'):>6} "
                f"| {p.get('srcintf', [{}])[0].get('name', '?')} -> "
                f"{p.get('dstintf', [{}])[0].get('name', '?')}"
            )
        return "Firewall Policies:\n" + "\n".join(lines)
    except Exception as e:
        return f"Error listing policies: {str(e)}"


@tool
def tool_list_addresses(input: str = "") -> str:
    """List all address objects configured on the FortiGate."""
    try:
        r = list_addresses()
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
    except Exception as e:
        return f"Error listing addresses: {str(e)}"


@tool
def tool_list_interfaces(input: str = "") -> str:
    """List all network interfaces on the FortiGate with their IP and status."""
    try:
        r = list_interfaces()
        results = r if isinstance(r, list) else r.get("results", [])
        lines = []
        for i in results[:10]:
            lines.append(
                f"  {i.get('name', '?'):<20} "
                f"{i.get('ip', '0.0.0.0 0.0.0.0'):<25} "
                f"status: {i.get('status', '?')}"
            )
        return "Network Interfaces:\n" + "\n".join(lines)
    except Exception as e:
        return f"Error listing interfaces: {str(e)}"


@tool
def tool_list_users(input: str = "") -> str:
    """List all local users configured on the FortiGate."""
    try:
        r = list_users()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No local users found."
        lines = [
            f"  {u.get('name', '?'):<25} status: {u.get('status', '?')}"
            for u in results
        ]
        return "Local Users:\n" + "\n".join(lines)
    except Exception as e:
        return f"Error listing users: {str(e)}"


@tool
def tool_list_routes(input: str = "") -> str:
    """List all static routes configured on the FortiGate."""
    try:
        r = list_routes()
        results = r if isinstance(r, list) else r.get("results", [])
        if not results:
            return "No static routes configured."
        lines = [
            f"  {r.get('dst', '?'):<25} via {r.get('gateway', '?'):<18} "
            f"on {r.get('device', '?')}"
            for r in results
        ]
        return "Static Routes:\n" + "\n".join(lines)
    except Exception as e:
        return f"Error listing routes: {str(e)}"


# ── WRITE TOOLS ───────────────────────────────────────────

@tool
def tool_create_policy(name: str, srcintf: str, dstintf: str,
                       srcaddr: str = "all", dstaddr: str = "all",
                       service: str = "ALL", action: str = "accept") -> str:
    """
    Create a new firewall policy on the FortiGate.
    Parameters:
    - name     : unique policy name
    - srcintf  : source interface (e.g. port1)
    - dstintf  : destination interface (e.g. port2)
    - srcaddr  : source address object name (default: all)
    - dstaddr  : destination address object name (default: all)
    - service  : service name (e.g. HTTP, SSH, ALL)
    - action   : accept or deny
    """
    try:
        if not name or not srcintf or not dstintf:
            return "Error: name, srcintf and dstintf are all required."
        r = create_policy(
            name=name,
            srcintf=srcintf,
            dstintf=dstintf,
            srcaddr=srcaddr,
            dstaddr=dstaddr,
            service=service,
            action=action
        )
        if r.get("status") == "success":
            return (
                f"[SUCCESS] Policy '{name}' created successfully.\n"
                f"   {srcintf} -> {dstintf} | service: {service} | action: {action}"
            )
        cli_errors = r.get("cli_error", [])
        return f"[ERROR] Error creating policy: {cli_errors}"
    except Exception as e:
        return f"[ERROR] Exception creating policy: {str(e)}"


@tool
def tool_create_address(name: str, subnet: str) -> str:
    """
    Create a new address object on the FortiGate.
    Parameters:
    - name   : unique name for the address object
    - subnet : IP address with mask in CIDR or dotted notation
               Examples: 192.168.1.10/32  or  10.0.0.0/24
    """
    try:
        if not name or not subnet:
            return "Error: both name and subnet are required."
        r = create_address(name, subnet)
        if r.get("status") == "success":
            return f"[SUCCESS] Address object '{name}' ({subnet}) created successfully."
        return f"[ERROR] Error creating address: {r}"
    except Exception as e:
        return f"[ERROR] Exception creating address: {str(e)}"


@tool
def tool_delete_address(name: str) -> str:
    """
    Delete an address object from the FortiGate by its exact name.
    Parameter:
    - name : the exact name of the address object to delete
    """
    try:
        if not name:
            return "Error: address name is required."
        r = delete_address(name.strip())
        if r.get("status") == "success":
            return f"[SUCCESS] Address object '{name}' deleted successfully."
        return f"[ERROR] Error deleting address: {r}"
    except Exception as e:
        return f"[ERROR] Exception deleting address: {str(e)}"


@tool
def tool_backup_config(input: str = "") -> str:
    """Backup the current FortiGate configuration to a local file."""
    try:
        result = backup_config()
        return f"[SUCCESS] {result}"
    except Exception as e:
        return f"[ERROR] Backup failed: {str(e)}"


# ── RAG KNOWLEDGE TOOL ────────────────────────────────────

@tool
def tool_search_knowledge(query: str) -> str:
    """
    Search the FortiGate documentation knowledge base to answer
    questions about configuration, troubleshooting, best practices,
    error codes, and security recommendations.
    Use this for any question that asks 'what', 'how', 'why', or 'explain'.
    Parameter:
    - query : the question or topic to search for
    """
    try:
        if not query:
            return "Please provide a search query."

        import re
        # Error code lookup
        if re.search(r'-?\d{1,4}', query) and 'error' in query.lower():
            error_code = re.search(r'-?\d+', query).group()
            result = search_errors(error_code)
            if result:
                return result

        # Try primary search
        result = search(query, k=4)

        # If empty, try a simplified version of the query
        if not result:
            simplified = ' '.join(query.split()[:4])
            result = search(simplified, k=4)

        if not result:
            return (
                "No specific documentation found for this query. "
                "This topic may not be covered in the indexed documentation. "
                "Please consult the official FortiGate documentation at docs.fortinet.com"
            )

        return result

    except Exception as e:
        return f"Error searching knowledge base: {str(e)}"

@tool
def tool_analyze_security(input: str = "") -> str:
    """
    Run a comprehensive security analysis of the FortiGate configuration.
    Detects overly permissive policies, policy conflicts, disabled policies,
    insecure interface settings, unused address objects, and resource issues.
    Use this when the user asks to analyze, audit, or check the firewall security.
    """
    try:
        return run_analysis()
    except Exception as e:
        return f"[ERROR] Security analysis failed: {str(e)}"

# ── MASTER TOOL LIST ──────────────────────────────────────

ALL_TOOLS = [
    tool_get_system_status,
    tool_get_cpu_memory,
    tool_list_policies,
    tool_list_addresses,
    tool_list_interfaces,
    tool_list_users,
    tool_list_routes,
    tool_create_policy,
    tool_create_address,
    tool_delete_address,
    tool_backup_config,
    tool_search_knowledge,
    tool_analyze_security,
    tool_update_interface_access,
]