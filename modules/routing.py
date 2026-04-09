from api.client import get, post, delete

def list_routes():
    """List all static routes"""
    return get("/cmdb/router/static")

def create_route(dst, gateway, device, netmask="255.255.255.0"):
    """Add a static route"""
    data = {
        "dst": f"{dst} {netmask}",
        "gateway": gateway,
        "device": device
    }
    return post("/cmdb/router/static", data)

def delete_route(route_id):
    """Delete a static route by ID"""
    return delete(f"/cmdb/router/static/{route_id}")