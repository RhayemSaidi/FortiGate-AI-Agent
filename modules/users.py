from api.client import get, post, put, delete

def list_users():
    """List all local users"""
    return get("/cmdb/user/local")

def get_user(name):
    """Get a specific user by name"""
    return get(f"/cmdb/user/local/{name}")

def create_user(name, password, status="enable"):
    """Create a local user"""
    data = {
        "name": name,
        "passwd": password,
        "status": status
    }
    return post("/cmdb/user/local", data)

def delete_user(name):
    """Delete a local user"""
    return delete(f"/cmdb/user/local/{name}")

def list_groups():
    """List all user groups"""
    return get("/cmdb/user/group")

def create_group(name, members=[]):
    """Create a user group with optional members"""
    data = {
        "name": name,
        "member": [{"name": m} for m in members]
    }
    return post("/cmdb/user/group", data)