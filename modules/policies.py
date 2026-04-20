from api.client import get, post, put, delete


def list_policies():
    """Get all firewall policies"""
    return get("/cmdb/firewall/policy")


def get_policy(policy_id):
    """Get a specific firewall policy by ID"""
    return get(f"/cmdb/firewall/policy/{policy_id}")


def create_policy(name, srcintf, dstintf, srcaddr="all",
                  dstaddr="all", service="ALL", action="accept",
                  schedule="always"):
    """Create a new firewall policy"""
    data = {
        "name": name,
        "srcintf": [{"name": srcintf}],
        "dstintf": [{"name": dstintf}],
        "srcaddr": [{"name": srcaddr}],
        "dstaddr": [{"name": dstaddr}],
        "service": [{"name": service}],
        "action": action,
        "schedule": schedule,
        "status": "enable",
        "logtraffic": "all"
    }
    return post("/cmdb/firewall/policy", data)


def update_policy(policy_id, data):
    """Update an existing firewall policy by ID"""
    return put(f"/cmdb/firewall/policy/{policy_id}", data)


def delete_policy(policy_id):
    """Delete a firewall policy by ID"""
    return delete(f"/cmdb/firewall/policy/{policy_id}")