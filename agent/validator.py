import re
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.interfaces import list_interfaces
from modules.addresses  import list_addresses
from modules.policies   import list_policies


class ValidationResult:
    def __init__(self):
        self.valid       = True
        self.errors      = []
        self.warnings    = []
        self.suggestions = []

    def add_error(self, msg: str):
        self.valid = False
        self.errors.append(msg)

    def add_warning(self, msg: str):
        self.warnings.append(msg)

    def add_suggestion(self, msg: str):
        self.suggestions.append(msg)

    def format(self) -> str:
        lines = []
        if self.errors:
            lines += ["\n" + "="*55, "  VALIDATION FAILED", "="*55]
            for e in self.errors:
                lines.append(f"  [ERROR]   {e}")
        if self.warnings:
            if not self.errors:
                lines += ["\n" + "="*55, "  VALIDATION WARNING", "="*55]
            for w in self.warnings:
                lines.append(f"  [WARNING] {w}")
        if self.suggestions:
            lines.append("  " + "-"*51)
            for s in self.suggestions:
                lines.append(f"  [HINT]    {s}")
        if not self.valid:
            lines += ["="*55, "  Action blocked. Fix the errors above.", "="*55]
        elif self.warnings:
            lines += ["="*55, "  Type 'yes' to proceed anyway or 'no' to cancel.", "="*55]
        else:
            lines += ["\n"+"="*55, "  VALIDATION PASSED", "="*55,
                      "  All checks passed. Safe to proceed.", "="*55]
        return "\n".join(lines)

    def is_clean(self) -> bool:
        return self.valid and not self.warnings

    def has_warnings_only(self) -> bool:
        return self.valid and bool(self.warnings)


# ── Cache ─────────────────────────────────────────────────
_cache: dict = {}


def clear_cache():
    """Clear all cached data. Call before every write validation."""
    _cache.clear()


def _get_interfaces() -> list:
    if "interfaces" not in _cache:
        r = list_interfaces()
        results = r if isinstance(r, list) else r.get("results", [])
        _cache["interfaces"] = [i.get("name", "") for i in results]
    return _cache["interfaces"]


def _get_address_names() -> list:
    if "addresses" not in _cache:
        r = list_addresses()
        results = r if isinstance(r, list) else r.get("results", [])
        _cache["addresses"] = [a.get("name", "") for a in results]
    return _cache["addresses"]


def _load_policies() -> None:
    if "policies_full" not in _cache:
        r = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        _cache["policies_full"] = results
        _cache["policies_by_name"] = {
            p.get("name", ""): p.get("policyid") for p in results
        }
        _cache["policies_by_id"] = {
            str(p.get("policyid", "")): p.get("name", "") for p in results
        }


def _get_policy_names() -> dict:
    _load_policies()
    return _cache["policies_by_name"]


def _get_policy_ids() -> dict:
    _load_policies()
    return _cache["policies_by_id"]


def _get_existing_policies_full() -> list:
    _load_policies()
    return _cache["policies_full"]


# ── Format validators ─────────────────────────────────────

def validate_ip_cidr(value: str) -> bool:
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$', value):
        return False
    ip, prefix = value.rsplit("/", 1)
    if any(int(o) > 255 for o in ip.split(".")):
        return False
    return 0 <= int(prefix) <= 32


def validate_ip_mask(value: str) -> bool:
    parts = value.strip().split()
    if len(parts) != 2:
        return False
    return all(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', p) for p in parts)


def validate_object_name(name: str) -> tuple:
    if not name:
        return False, "Name cannot be empty."
    if len(name) > 35:
        return False, f"Name '{name}' is too long (max 35 chars)."
    if re.search(r'\s', name):
        return False, f"Name '{name}' cannot contain spaces. Use hyphens."
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_\-]*$', name):
        return False, f"Name '{name}' has invalid characters. Use letters, numbers, hyphens, underscores."
    return True, ""


# ── Policy validators ─────────────────────────────────────

def validate_create_policy(params: dict) -> ValidationResult:
    result = ValidationResult()
    clear_cache()

    name    = params.get("name",    "").strip()
    srcintf = params.get("srcintf", "").strip()
    dstintf = params.get("dstintf", "").strip()
    srcaddr = params.get("srcaddr", "all").strip()
    dstaddr = params.get("dstaddr", "all").strip()
    service = params.get("service", "ALL").strip()
    action  = params.get("action",  "accept").strip().lower()

    if not name:    result.add_error("Policy name is required.")
    if not srcintf: result.add_error("Source interface is required.")
    if not dstintf: result.add_error("Destination interface is required.")
    if not result.valid:
        return result

    name_valid, name_error = validate_object_name(name)
    if not name_valid:
        result.add_error(name_error)
    if action not in ("accept", "deny"):
        result.add_error(f"Action must be 'accept' or 'deny'.")
    if not result.valid:
        return result

    try:
        ifaces = _get_interfaces()
        for intf, label in [(srcintf, "Source"), (dstintf, "Destination")]:
            if intf not in ifaces:
                similar = [i for i in ifaces if intf.lower() in i.lower()]
                msg = f"{label} interface '{intf}' does not exist."
                msg += (f" Did you mean: {', '.join(similar)}?" if similar
                        else f" Available: {', '.join(ifaces[:8])}")
                result.add_error(msg)
    except Exception as exc:
        result.add_warning(f"Could not verify interfaces: {exc}")

    if srcintf and dstintf and srcintf == dstintf:
        result.add_warning(f"Source and destination are the same interface ('{srcintf}'). Verify this is intentional.")

    try:
        addrs = _get_address_names()
        for addr, label in [(srcaddr, "Source"), (dstaddr, "Destination")]:
            if addr != "all" and addr not in addrs:
                result.add_error(f"{label} address '{addr}' does not exist. Create it first.")
    except Exception as exc:
        result.add_warning(f"Could not verify address objects: {exc}")

    try:
        if name in _get_policy_names():
            result.add_error(
                f"Policy '{name}' already exists (ID:{_get_policy_names()[name]}). "
                f"Choose a different name."
            )
    except Exception as exc:
        result.add_warning(f"Could not verify name uniqueness: {exc}")

    if not result.valid:
        return result

    try:
        for existing in _get_existing_policies_full():
            e_src  = [i.get("name") for i in existing.get("srcintf", [])]
            e_dst  = [i.get("name") for i in existing.get("dstintf", [])]
            e_svc  = [s.get("name") for s in existing.get("service",  [])]
            e_act  = existing.get("action", "")
            e_name = existing.get("name", "")
            e_id   = existing.get("policyid", "")
            same   = (srcintf in e_src and dstintf in e_dst and
                      (service in e_svc or "ALL" in e_svc))
            if same and e_act != action:
                result.add_warning(
                    f"Conflict with '{e_name}' (ID:{e_id}): same path, opposite action ({e_act}). "
                    f"FortiGate applies top-down — check rule order."
                )
            elif same and e_act == action:
                result.add_warning(f"'{e_name}' (ID:{e_id}) already covers this traffic. May be redundant.")
    except Exception as exc:
        result.add_warning(f"Conflict detection error: {exc}")

    if action == "accept":
        if srcaddr == "all" and dstaddr == "all" and service == "ALL":
            result.add_warning("SECURITY RISK: Allows ALL traffic from ALL sources to ALL destinations.")
            result.add_suggestion("Specify exact addresses and restrict to required services.")
        elif srcaddr == "all" and service == "ALL":
            result.add_warning("SECURITY RISK: Allows all traffic from any source on all services.")
        if service in ("SSH", "RDP", "TELNET") and srcaddr == "all":
            result.add_warning(f"SECURITY RISK: {service} allowed from any source. Exposes remote access.")
            result.add_suggestion(f"Create an address object for your admin workstation and use it as source.")

    if action == "deny" and service in ("SSH", "HTTPS", "HTTP", "TELNET"):
        result.add_suggestion(f"Blocking {service}. Ensure management access via another interface.")

    return result


def validate_delete_policy(params: dict) -> ValidationResult:
    result = ValidationResult()
    clear_cache()

    policy_id = params.get("policy_id")
    if not policy_id:
        result.add_error("policy_id is required.")
        return result

    try:
        ids = _get_policy_ids()
        if str(policy_id) not in ids:
            result.add_error(
                f"Policy ID {policy_id} does not exist. "
                f"Use tool_list_policies to see available IDs."
            )
            return result
        name = ids[str(policy_id)]
        result.add_warning(
            f"PERMANENTLY DELETE policy '{name}' (ID:{policy_id}). "
            f"This cannot be undone. Traffic this rule handled will be affected immediately."
        )
    except Exception as exc:
        result.add_warning(f"Could not verify policy: {exc}")

    return result


def validate_update_policy(params: dict) -> ValidationResult:
    result = ValidationResult()
    clear_cache()

    policy_id = params.get("policy_id")
    action    = params.get("action", "")
    status    = params.get("status", "")
    srcaddr   = params.get("srcaddr", "")
    dstaddr   = params.get("dstaddr", "")

    if not policy_id:
        result.add_error("policy_id is required.")
        return result

    try:
        ids = _get_policy_ids()
        if str(policy_id) not in ids:
            result.add_error(f"Policy ID {policy_id} does not exist.")
            return result
    except Exception as exc:
        result.add_warning(f"Could not verify policy: {exc}")

    if action and action not in ("accept", "deny"):
        result.add_error("action must be 'accept' or 'deny'.")
    if status and status not in ("enable", "disable"):
        result.add_error("status must be 'enable' or 'disable'.")
    if not result.valid:
        return result

    try:
        addrs = _get_address_names()
        if srcaddr and srcaddr != "all" and srcaddr not in addrs:
            result.add_error(f"Source address '{srcaddr}' does not exist.")
        if dstaddr and dstaddr != "all" and dstaddr not in addrs:
            result.add_error(f"Destination address '{dstaddr}' does not exist.")
    except Exception as exc:
        result.add_warning(f"Could not verify addresses: {exc}")

    if action == "accept":
        result.add_warning("Changing action to ACCEPT. Verify source/destination scope is appropriately restricted.")
    if status == "disable":
        result.add_warning("Disabling this policy. Traffic it was handling will no longer match this rule.")

    return result


def validate_enable_disable_policy(params: dict) -> ValidationResult:
    result = ValidationResult()
    clear_cache()

    policy_id = params.get("policy_id")
    status    = params.get("status", "")

    if not policy_id:
        result.add_error("policy_id is required.")
        return result
    if status not in ("enable", "disable"):
        result.add_error("status must be 'enable' or 'disable'.")
        return result

    try:
        ids = _get_policy_ids()
        if str(policy_id) not in ids:
            result.add_error(f"Policy ID {policy_id} does not exist.")
            return result
        name = ids[str(policy_id)]
        if status == "disable":
            result.add_warning(
                f"Disabling policy '{name}' (ID:{policy_id}). "
                f"Traffic this rule was handling will no longer be matched."
            )
    except Exception as exc:
        result.add_warning(f"Could not verify policy: {exc}")

    return result


def validate_move_policy(params: dict) -> ValidationResult:
    result = ValidationResult()
    clear_cache()

    policy_id   = params.get("policy_id")
    move_action = params.get("move_action", "")
    neighbor_id = params.get("neighbor_id")

    if not policy_id:   result.add_error("policy_id is required.")
    if not neighbor_id: result.add_error("neighbor_id is required.")
    if move_action not in ("before", "after"):
        result.add_error("move_action must be 'before' or 'after'.")
    if not result.valid:
        return result

    try:
        ids = _get_policy_ids()
        if str(policy_id) not in ids:
            result.add_error(f"Policy ID {policy_id} does not exist.")
        if str(neighbor_id) not in ids:
            result.add_error(f"Reference policy ID {neighbor_id} does not exist.")
        if result.valid:
            p_name = ids[str(policy_id)]
            n_name = ids[str(neighbor_id)]
            result.add_warning(
                f"Moving '{p_name}' (ID:{policy_id}) {move_action} "
                f"'{n_name}' (ID:{neighbor_id}). "
                f"This changes which rule takes precedence for overlapping traffic."
            )
    except Exception as exc:
        result.add_warning(f"Could not verify policies: {exc}")

    return result


def validate_block_ip(params: dict) -> ValidationResult:
    result = ValidationResult()

    ip_address = params.get("ip_address", "").strip()
    direction  = params.get("direction", "both")

    if not ip_address:
        result.add_error("ip_address is required.")
        return result

    check = ip_address if "/" in ip_address else ip_address + "/32"
    if not validate_ip_cidr(check):
        result.add_error(f"Invalid IP format: '{ip_address}'. Use 192.168.1.55 or 192.168.1.55/32.")
        return result

    if direction not in ("inbound", "outbound", "both"):
        result.add_error("direction must be 'inbound', 'outbound', or 'both'.")
        return result

    if (ip_address.startswith("192.168.") or
            ip_address.startswith("10.") or
            ip_address.startswith("172.")):
        result.add_warning(
            f"Blocking private/internal IP ({ip_address}). "
            f"Ensure this is not your own workstation or a critical server."
        )

    result.add_suggestion(
        "Blocking creates deny policies. Note the policy IDs assigned "
        "so you can delete them to reverse this block."
    )
    return result


def validate_create_address(params: dict) -> ValidationResult:
    result = ValidationResult()
    clear_cache()

    name   = params.get("name",   "").strip()
    subnet = params.get("subnet", "").strip()

    if not name:   result.add_error("Address name is required.")
    if not subnet: result.add_error("Subnet is required.")
    if not result.valid:
        return result

    name_valid, name_error = validate_object_name(name)
    if not name_valid:
        result.add_error(name_error)

    if not validate_ip_cidr(subnet) and not validate_ip_mask(subnet):
        result.add_error(
            f"Invalid subnet '{subnet}'. "
            f"Use CIDR (192.168.1.0/24) or dotted mask (192.168.1.0 255.255.255.0)."
        )
    if not result.valid:
        return result

    try:
        if name in _get_address_names():
            result.add_error(f"Address object '{name}' already exists. Choose a different name.")
    except Exception as exc:
        result.add_warning(f"Could not verify name uniqueness: {exc}")

    if subnet in ("0.0.0.0/0", "0.0.0.0 0.0.0.0"):
        result.add_warning("This covers ALL IP addresses — may create overly permissive rules.")
    if subnet.startswith("127."):
        result.add_warning("Loopback range — typically not used in firewall policies.")
    if "/" in subnet:
        try:
            prefix = int(subnet.split("/")[1])
            if prefix < 8:
                result.add_warning(f"/{prefix} covers millions of addresses. Confirm intentional.")
        except (ValueError, IndexError):
            pass

    return result


def validate_delete_address(params: dict) -> ValidationResult:
    result = ValidationResult()
    clear_cache()

    name = params.get("name", "").strip()
    if not name:
        result.add_error("Address name is required.")
        return result

    try:
        if name not in _get_address_names():
            result.add_error(f"Address object '{name}' does not exist.")
            return result
    except Exception as exc:
        result.add_warning(f"Could not verify address: {exc}")

    try:
        used_in = []
        for p in _get_existing_policies_full():
            src = [a.get("name") for a in p.get("srcaddr", [])]
            dst = [a.get("name") for a in p.get("dstaddr", [])]
            if name in src or name in dst:
                used_in.append(f"'{p.get('name')}' (ID:{p.get('policyid')})")
        if used_in:
            result.add_warning(
                f"'{name}' is used in {len(used_in)} policy(ies): {', '.join(used_in)}. "
                f"Deleting it may break these policies."
            )
    except Exception as exc:
        result.add_warning(f"Could not check policy usage: {exc}")

    return result


def validate_update_interface_access(params: dict) -> ValidationResult:
    result = ValidationResult()

    name        = params.get("name",        "").strip()
    allowaccess = params.get("allowaccess", "").strip()

    if not name:
        result.add_error("Interface name is required.")
        return result

    if not allowaccess:
        result.add_error("allowaccess cannot be empty — would lock you out of the firewall.")
        return result

    protocols = set(allowaccess.lower().split())

    if not protocols.intersection({"https", "ssh"}):
        result.add_error(
            "LOCKOUT PREVENTION: At least HTTPS or SSH must remain enabled. "
            "Removing both will lock you out."
        )
        return result

    insecure = protocols.intersection({"http", "telnet"})
    if insecure:
        result.add_warning(
            f"Enabling insecure protocols: {', '.join(insecure).upper()}. "
            f"These transmit credentials in cleartext."
        )

    try:
        ifaces = _get_interfaces()
        if name not in ifaces:
            similar = [i for i in ifaces if name.lower() in i.lower()]
            msg = f"Interface '{name}' does not exist."
            if similar:
                msg += f" Did you mean: {', '.join(similar)}?"
            result.add_error(msg)
    except Exception as exc:
        result.add_warning(f"Could not verify interface: {exc}")

    return result