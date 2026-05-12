from api.client import get, post, put, delete


def list_policies():
    return get("/cmdb/firewall/policy")


def get_policy(policy_id: int):
    return get(f"/cmdb/firewall/policy/{policy_id}")


def get_policy_id_by_name(name: str):
    r       = list_policies()
    results = r if isinstance(r, list) else r.get("results", [])
    for p in results:
        if p.get("name", "").lower() == name.lower():
            return p.get("policyid")
    return None


def create_policy(name, srcintf, dstintf, srcaddr="all",
                  dstaddr="all", service="ALL", action="accept",
                  schedule="always"):
    data = {
        "name":       name,
        "srcintf":    [{"name": srcintf}],
        "dstintf":    [{"name": dstintf}],
        "srcaddr":    [{"name": srcaddr}],
        "dstaddr":    [{"name": dstaddr}],
        "service":    [{"name": s.strip()} for s in service.split(",") if s.strip()],
        "action":     action,
        "schedule":   schedule,
        "status":     "enable",
        "logtraffic": "all",
    }
    return post("/cmdb/firewall/policy", data)


def update_policy(policy_id: int, data: dict):
    """
    PUT the complete policy payload to FortiGate.
    FIX: Handles all field types correctly.
    Service field accepts both string (comma-separated) and list of dicts.
    """
    import re as _re

    # Normalize service field if present
    if "service" in data:
        svc = data["service"]
        if isinstance(svc, str):
            # Comma or space separated string → list of name dicts
            parts = [s.strip() for s in _re.split(r'[,\s]+', svc) if s.strip()]
            data["service"] = [{"name": p} for p in parts]
        elif isinstance(svc, list):
            normalized = []
            for item in svc:
                if isinstance(item, str):
                    normalized.append({"name": item.strip()})
                elif isinstance(item, dict) and "name" in item:
                    normalized.append(item)
            data["service"] = normalized

    # Normalize all other list fields (srcaddr, dstaddr, etc.)
    for field_name in ("srcaddr", "dstaddr", "srcintf", "dstintf"):
        if field_name in data:
            items = data[field_name]
            if isinstance(items, str):
                data[field_name] = [{"name": items.strip()}]
            elif isinstance(items, list):
                normalized = []
                for item in items:
                    if isinstance(item, str):
                        normalized.append({"name": item.strip()})
                    elif isinstance(item, dict):
                        normalized.append(item)
                data[field_name] = normalized

    return put(f"/cmdb/firewall/policy/{policy_id}", data)

def delete_policy(policy_id: int):
    return delete(f"/cmdb/firewall/policy/{policy_id}")


def move_policy(policy_id: int, move_action: str, neighbor_id: int):
    endpoint = (
        f"/cmdb/firewall/policy/{policy_id}"
        f"?action=move&{move_action}={neighbor_id}"
    )
    return put(endpoint, {})

# agent/modules/policies.py — add these functions

def search_policies(filters: dict) -> dict:
    """
    Filter policies by field values.
    
    Supported filters:
        action   : "accept" | "deny"
        status   : "enable" | "disable"
        service  : service name, case-insensitive (e.g. "HTTP", "SSH")
        srcintf  : source interface name, case-insensitive
        dstintf  : destination interface name, case-insensitive
        name     : partial policy name match, case-insensitive
        nat      : "enable" | "disable"
    
    Returns {"results": [...], "count": N, "filters_applied": {...}}
    """
    try:
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
    except Exception as exc:
        return {"error": str(exc), "results": [], "count": 0}

    filtered = []
    for p in results:
        match = True
        for field, value in filters.items():
            if not value:
                continue

            val_l = str(value).lower()

            if field == "service":
                svcs = [
                    s.get("name", "").upper()
                    for s in (p.get("service") or [])
                ]
                # Match exact service name OR "ALL" (which covers everything)
                if val_l.upper() not in svcs and "ALL" not in svcs:
                    match = False
                    break

            elif field == "status":
                if p.get("status", "enable").lower() != val_l:
                    match = False
                    break

            elif field == "action":
                if p.get("action", "").lower() != val_l:
                    match = False
                    break

            elif field == "nat":
                if str(p.get("nat", "disable")).lower() != val_l:
                    match = False
                    break

            elif field == "srcintf":
                intf_names = [
                    i.get("name", "").lower()
                    for i in (p.get("srcintf") or [])
                ]
                if val_l not in intf_names and "any" not in intf_names:
                    match = False
                    break

            elif field == "dstintf":
                intf_names = [
                    i.get("name", "").lower()
                    for i in (p.get("dstintf") or [])
                ]
                if val_l not in intf_names and "any" not in intf_names:
                    match = False
                    break

            elif field == "name":
                if val_l not in p.get("name", "").lower():
                    match = False
                    break

        if match:
            filtered.append(p)

    return {
        "results":         filtered,
        "count":           len(filtered),
        "filters_applied": {k: v for k, v in filters.items() if v},
        "total_policies":  len(results),
    }

def get_policy_by_name(name: str) -> dict:
    """
    Fetch a policy by name (case-insensitive, partial match supported).
    Returns the policy dict or {"error": ..., "results": []}.
    """
    try:
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        name_l  = name.lower()
        
        # Exact match first
        for p in results:
            if p.get("name", "").lower() == name_l:
                return {"results": p, "match": "exact"}
        
        # Partial match
        matches = [p for p in results if name_l in p.get("name", "").lower()]
        if len(matches) == 1:
            return {"results": matches[0], "match": "partial"}
        if len(matches) > 1:
            return {
                "results": matches,
                "match": "multiple",
                "message": f"Found {len(matches)} policies matching '{name}'"
            }
        
        return {
            "error": f"No policy found with name '{name}'",
            "results": []
        }
    except Exception as exc:
        return {"error": str(exc), "results": []}


def get_address_usage(address_name: str) -> dict:
    """
    Find all policies that reference a specific address object.
    Critical safety check before deleting an address object.
    
    Returns {"address_name": ..., "used_by_count": N, "used_by": [...]}
    """
    try:
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
    except Exception as exc:
        return {"error": str(exc), "used_by": [], "used_by_count": 0}

    name_l        = address_name.lower()
    using_policies = []

    for p in results:
        src_names = [a.get("name", "").lower() for a in (p.get("srcaddr") or [])]
        dst_names = [a.get("name", "").lower() for a in (p.get("dstaddr") or [])]

        roles = []
        if name_l in src_names:
            roles.append("srcaddr")
        if name_l in dst_names:
            roles.append("dstaddr")

        if roles:
            using_policies.append({
                "policyid": p.get("policyid"),
                "name":     p.get("name"),
                "action":   p.get("action"),
                "status":   p.get("status", "enable"),
                "roles":    roles,
            })

    return {
        "address_name": address_name,
        "used_by_count": len(using_policies),
        "used_by":       using_policies,
    }

def get_service_usage(service_name: str) -> dict:
    """
    Find all policies that use a specific service object.
    Critical safety check before deleting a custom service.
    
    Returns {"service_name": ..., "used_by_count": N, "used_by": [...]}
    """
    try:
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
    except Exception as exc:
        return {"error": str(exc), "used_by": [], "used_by_count": 0}

    name_u        = service_name.upper()
    using_policies = []

    for p in results:
        svc_names = [s.get("name", "").upper() for s in (p.get("service") or [])]
        if name_u in svc_names or "ALL" in svc_names:
            using_policies.append({
                "policyid": p.get("policyid"),
                "name":     p.get("name"),
                "action":   p.get("action"),
                "status":   p.get("status", "enable"),
            })

    return {
        "service_name":  service_name,
        "used_by_count": len(using_policies),
        "used_by":       using_policies,
    }

import re