from api.client import get, post, put, delete

def list_addresses():
    """List all address objects"""
    return get("/cmdb/firewall/address")

def get_address(name):
    """Get a specific address object by name"""
    return get(f"/cmdb/firewall/address/{name}")

def create_address(name, subnet):
    """Create a new address object (e.g. name='WebServer', subnet='192.168.1.10/32')"""
    data = {
        "name": name,
        "type": "ipmask",
        "subnet": subnet
    }
    return post("/cmdb/firewall/address", data)

def update_address(name, subnet):
    """Update an existing address object"""
    data = {
        "subnet": subnet
    }
    return put(f"/cmdb/firewall/address/{name}", data)

def delete_address(name):
    """Delete an address object by name"""
    return delete(f"/cmdb/firewall/address/{name}")