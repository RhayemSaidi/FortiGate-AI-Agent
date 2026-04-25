from api.client import get, put

def list_interfaces():
    """List all network interfaces"""
    return get("/cmdb/system/interface")

def get_interface(name):
    """Get details of a specific interface"""
    return get(f"/cmdb/system/interface/{name}")

def update_interface_ip(name, ip, netmask):
    """Update the IP address of an interface"""
    data = {
        "ip": f"{ip} {netmask}"
    }
    return put(f"/cmdb/system/interface/{name}", data)

def set_interface_status(name, status="up"):
    """Enable or disable an interface (status: 'up' or 'down')"""
    data = {
        "status": status
    }
    return put(f"/cmdb/system/interface/{name}", data)

def update_interface_allowaccess(name: str, allowaccess: str):
    """
    Update the management access protocols on an interface.
    allowaccess is a space-separated string of protocols.
    Example: "https ssh ping"
    Valid options: https http ssh telnet ping snmp
    """
    data = {
        "allowaccess": allowaccess
    }
    return put(f"/cmdb/system/interface/{name}", data)