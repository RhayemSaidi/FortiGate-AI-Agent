from api.client import get, post, put, delete

def list_services():
    """List all custom service objects"""
    return get("/cmdb/firewall.service/custom")

def get_service(name):
    """Get a specific service by name"""
    return get(f"/cmdb/firewall.service/custom/{name}")

def create_service(name, protocol="TCP", port_range="80"):
    """Create a custom service object"""
    data = {
        "name": name,
        "protocol": protocol,
        "tcp-portrange": port_range
    }
    return post("/cmdb/firewall.service/custom", data)

def delete_service(name):
    """Delete a custom service by name"""
    return delete(f"/cmdb/firewall.service/custom/{name}")