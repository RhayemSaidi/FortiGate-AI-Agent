from langchain.tools import tool
from modules.system import get_system_status
from modules.monitor import get_cpu_usage, get_memory_usage
from modules.policies import list_policies, create_policy
from modules.addresses import list_addresses, create_address, delete_address
from modules.interfaces import list_interfaces
from modules.routing import list_routes
from modules.users import list_users
from modules.backup import backup_config

@tool
def tool_get_system_status(input: str = "") -> str:
    """Get the FortiGate system status including hostname, model and firmware version."""
    r = get_system_status()
    res = r.get("results", {})
    return f"Hostname: {res.get('hostname')}, Model: {res.get('model_name')}, Version: {r.get('version')}"

@tool
def tool_get_cpu_memory(input: str = "") -> str:
    """Get current CPU and memory usage percentages of the FortiGate."""
    cpu = get_cpu_usage()
    mem = get_memory_usage()
    cpu_val = cpu["results"]["cpu"][0]["current"]
    mem_val = mem["results"]["mem"][0]["current"]
    return f"CPU: {cpu_val}%, Memory: {mem_val}%"

@tool
def tool_list_policies(input: str = "") -> str:
    """List all firewall policies on the FortiGate."""
    r = list_policies()
    results = r if isinstance(r, list) else r.get("results", [])
    if not results:
        return "No firewall policies found."
    lines = [f"[{p.get('policyid')}] {p.get('name')} — action: {p.get('action')}" for p in results]
    return "\n".join(lines)

@tool
def tool_create_policy(input: str) -> str:
    """
    Create a firewall policy. 
    Input must be a JSON string with keys: name, srcintf, dstintf, srcaddr, dstaddr, service, action.
    Example: {"name":"BlockHTTP","srcintf":"port1","dstintf":"port1","srcaddr":"all","dstaddr":"all","service":"HTTP","action":"deny"}
    """
    import json
    try:
        params = json.loads(input)
        r = create_policy(
            name=params["name"],
            srcintf=params.get("srcintf", "port1"),
            dstintf=params.get("dstintf", "port1"),
            srcaddr=params.get("srcaddr", "all"),
            dstaddr=params.get("dstaddr", "all"),
            service=params.get("service", "ALL"),
            action=params.get("action", "accept")
        )
        if r.get("status") == "success":
            return f"Policy '{params['name']}' created successfully."
        return f"Error creating policy: {r.get('cli_error', r)}"
    except Exception as e:
        return f"Failed to create policy: {str(e)}"

@tool
def tool_list_addresses(input: str = "") -> str:
    """List all address objects on the FortiGate."""
    r = list_addresses()
    results = r if isinstance(r, list) else r.get("results", [])
    if not results:
        return "No address objects found."
    lines = [f"{a.get('name')} — {a.get('subnet') or a.get('fqdn') or 'N/A'}" for a in results[:10]]
    return "\n".join(lines)

@tool
def tool_create_address(input: str) -> str:
    """
    Create an address object.
    Input must be a JSON string with keys: name, subnet.
    Example: {"name":"WebServer","subnet":"192.168.1.10/32"}
    """
    import json
    try:
        params = json.loads(input)
        r = create_address(params["name"], params["subnet"])
        if r.get("status") == "success":
            return f"Address '{params['name']}' created successfully."
        return f"Error: {r}"
    except Exception as e:
        return f"Failed: {str(e)}"

@tool
def tool_delete_address(input: str) -> str:
    """
    Delete an address object by name.
    Input: the exact name of the address object to delete.
    Example: WebServer
    """
    r = delete_address(input.strip())
    if r.get("status") == "success":
        return f"Address '{input.strip()}' deleted successfully."
    return f"Error deleting address: {r}"

@tool
def tool_list_interfaces(input: str = "") -> str:
    """List all network interfaces on the FortiGate."""
    r = list_interfaces()
    results = r if isinstance(r, list) else r.get("results", [])
    lines = [f"{i.get('name')} — {i.get('ip')} — {i.get('status')}" for i in results[:10]]
    return "\n".join(lines)

@tool
def tool_list_users(input: str = "") -> str:
    """List all local users on the FortiGate."""
    r = list_users()
    results = r if isinstance(r, list) else r.get("results", [])
    if not results:
        return "No local users found."
    lines = [f"{u.get('name')} — status: {u.get('status')}" for u in results]
    return "\n".join(lines)

@tool
def tool_backup_config(input: str = "") -> str:
    """Backup the FortiGate configuration to a local file."""
    result = backup_config()
    return result

# Master list of all tools — imported by agent.py
ALL_TOOLS = [
    tool_get_system_status,
    tool_get_cpu_memory,
    tool_list_policies,
    tool_create_policy,
    tool_list_addresses,
    tool_create_address,
    tool_delete_address,
    tool_list_interfaces,
    tool_list_users,
    tool_backup_config,
]