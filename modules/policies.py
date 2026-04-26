from api.client import get, post, put, delete


def list_policies():
    """Get all firewall policies."""
    return get("/cmdb/firewall/policy")


def get_policy(policy_id: int):
    """Get a specific firewall policy by its numeric ID."""
    return get(f"/cmdb/firewall/policy/{policy_id}")


def create_policy(name, srcintf, dstintf, srcaddr="all",
                  dstaddr="all", service="ALL", action="accept",
                  schedule="always"):
    """Create a new firewall policy."""
    data = {
        "name":     name,
        "srcintf":  [{"name": srcintf}],
        "dstintf":  [{"name": dstintf}],
        "srcaddr":  [{"name": srcaddr}],
        "dstaddr":  [{"name": dstaddr}],
        "service":  [{"name": service}],
        "action":   action,
        "schedule": schedule,
        "status":   "enable",
        "logtraffic": "all",
    }
    return post("/cmdb/firewall/policy", data)


def update_policy(policy_id: int, data: dict):
    """Update an existing firewall policy by its numeric ID."""
    return put(f"/cmdb/firewall/policy/{policy_id}", data)


def delete_policy(policy_id: int):
    """Permanently delete a firewall policy by its numeric ID."""
    return delete(f"/cmdb/firewall/policy/{policy_id}")


def move_policy(policy_id: int, move_action: str, neighbor_id: int):
    """
    Move a policy before or after another policy in the table.
    move_action: 'before' or 'after'
    neighbor_id: the policy ID to move relative to
    FortiGate evaluates policies top-down — order determines match priority.
    """
    endpoint = (
        f"/cmdb/firewall/policy/{policy_id}"
        f"?action=move&{move_action}={neighbor_id}"
    )
    return post(endpoint, {})