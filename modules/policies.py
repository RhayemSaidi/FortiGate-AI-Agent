from api.client import get, post

POLICY_ENDPOINT = "/cmdb/firewall/policy"

def list_policies():
    return get("/cmdb/firewall/policy")

def get_policy(policy_id):
    return get(f"{POLICY_ENDPOINT}/{policy_id}")

def create_policy(name, srcintf, dstintf, action="accept"):
    data = {
        "name": name,
        "srcintf": [{"name": srcintf}],
        "dstintf": [{"name": dstintf}],
        "srcaddr": [{"name": "all"}],
        "dstaddr": [{"name": "all"}],
        "action": action,
        "schedule": "always",
        "service": [{"name": "ALL"}],
        "logtraffic": "all"
    }

    return post(POLICY_ENDPOINT, data)