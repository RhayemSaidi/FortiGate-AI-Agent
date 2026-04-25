import re
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.interfaces import list_interfaces
from modules.addresses import list_addresses
from modules.policies import list_policies
from modules.services import list_services


# ── Validation Result Object ──────────────────────────────

class ValidationResult:
    """
    Represents the outcome of a validation check.
    Contains status, errors, warnings, and suggestions.
    """
    def __init__(self):
        self.valid = True
        self.errors = []       # Hard failures — block execution
        self.warnings = []     # Soft issues — warn but allow with confirmation
        self.suggestions = []  # Helpful hints shown to the user

    def add_error(self, message: str):
        self.valid = False
        self.errors.append(message)

    def add_warning(self, message: str):
        self.warnings.append(message)

    def add_suggestion(self, message: str):
        self.suggestions.append(message)

    def format(self) -> str:
        """Format the full validation report as a readable string."""
        lines = []

        if self.errors:
            lines.append("\n" + "="*55)
            lines.append("  VALIDATION FAILED")
            lines.append("="*55)
            for e in self.errors:
                lines.append(f"  [ERROR]   {e}")

        if self.warnings:
            if not self.errors:
                lines.append("\n" + "="*55)
                lines.append("  VALIDATION WARNING")
                lines.append("="*55)
            for w in self.warnings:
                lines.append(f"  [WARNING] {w}")

        if self.suggestions:
            lines.append("  " + "-"*51)
            for s in self.suggestions:
                lines.append(f"  [HINT]    {s}")

        if not self.valid:
            lines.append("="*55)
            lines.append("  Action blocked. Please fix the errors above.")
            lines.append("="*55)
        elif self.warnings:
            lines.append("="*55)
            lines.append("  Type 'yes' to proceed anyway or 'no' to cancel.")
            lines.append("="*55)
        else:
            # Clean pass — no errors, no warnings
            lines.append("\n" + "="*55)
            lines.append("  VALIDATION PASSED")
            lines.append("="*55)
            lines.append("  All checks passed. Safe to proceed.")
            lines.append("="*55)

        return "\n".join(lines)

    def is_clean(self) -> bool:
        """True if no errors and no warnings."""
        return self.valid and not self.warnings

    def has_warnings_only(self) -> bool:
        """True if valid but has warnings that need acknowledgment."""
        return self.valid and bool(self.warnings)


# ── Live data fetchers with caching ──────────────────────
# We cache for the duration of a single validation call
# to avoid hammering the FortiGate API

_cache = {}


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


def _get_policy_names() -> dict:
    """Returns dict of {name: policyid} for all existing policies."""
    if "policies" not in _cache:
        r = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        _cache["policies"] = {
            p.get("name", ""): p.get("policyid")
            for p in results
        }
    return _cache["policies"]


def _get_existing_policies_full() -> list:
    """Returns full policy objects for conflict detection."""
    if "policies_full" not in _cache:
        r = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        _cache["policies_full"] = results
    return _cache["policies_full"]


def clear_cache():
    """Call this after a write operation to force fresh data."""
    _cache.clear()


# ── Format validators ─────────────────────────────────────

def validate_ip_cidr(value: str) -> bool:
    """
    Validate an IP address in CIDR notation.
    Accepts: 192.168.1.0/24, 10.0.0.1/32, 0.0.0.0/0
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$'
    if not re.match(pattern, value):
        return False
    parts = value.split('/')
    octets = parts[0].split('.')
    for octet in octets:
        if int(octet) > 255:
            return False
    prefix = int(parts[1])
    if prefix < 0 or prefix > 32:
        return False
    return True


def validate_ip_mask(value: str) -> bool:
    """
    Validate IP with dotted subnet mask.
    Accepts: 192.168.1.0 255.255.255.0
    """
    parts = value.strip().split()
    if len(parts) != 2:
        return False
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return (re.match(ip_pattern, parts[0]) and
            re.match(ip_pattern, parts[1]))


def validate_object_name(name: str) -> tuple:
    """
    Validate a FortiGate object name.
    Returns (is_valid, error_message).
    Rules: 1-35 chars, alphanumeric + hyphens + underscores,
    no spaces, not starting with a number.
    """
    if not name:
        return False, "Name cannot be empty."
    if len(name) > 35:
        return False, f"Name '{name}' is too long (max 35 characters)."
    if re.search(r'\s', name):
        return False, f"Name '{name}' cannot contain spaces. Use hyphens instead."
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_\-]*$', name):
        return False, (
            f"Name '{name}' contains invalid characters. "
            f"Use only letters, numbers, hyphens and underscores."
        )
    return True, ""


# ── Policy validators ─────────────────────────────────────

def validate_create_policy(params: dict) -> ValidationResult:
    """
    Full validation pipeline for firewall policy creation.
    Checks parameters, existence, conflicts, and security.
    """
    result = ValidationResult()
    clear_cache()  # Always use fresh data for write operations

    name = params.get("name", "").strip()
    srcintf = params.get("srcintf", "").strip()
    dstintf = params.get("dstintf", "").strip()
    srcaddr = params.get("srcaddr", "all").strip()
    dstaddr = params.get("dstaddr", "all").strip()
    service = params.get("service", "ALL").strip()
    action = params.get("action", "accept").strip().lower()

    # ── 1. Parameter completeness ─────────────────────────
    if not name:
        result.add_error("Policy name is required.")
    if not srcintf:
        result.add_error("Source interface is required.")
    if not dstintf:
        result.add_error("Destination interface is required.")

    if not result.valid:
        return result

    # ── 2. Format validation ──────────────────────────────
    name_valid, name_error = validate_object_name(name)
    if not name_valid:
        result.add_error(name_error)

    if action not in ("accept", "deny"):
        result.add_error(
            f"Action must be 'accept' or 'deny', got '{action}'."
        )

    if not result.valid:
        return result

    # ── 3. Existence checks (live API) ────────────────────
    try:
        existing_interfaces = _get_interfaces()

        # Check source interface
        if srcintf not in existing_interfaces:
            similar = [i for i in existing_interfaces
                      if srcintf.lower() in i.lower()]
            error_msg = f"Source interface '{srcintf}' does not exist on this FortiGate."
            if similar:
                error_msg += f" Did you mean: {', '.join(similar)}?"
            else:
                error_msg += f" Available interfaces: {', '.join(existing_interfaces[:8])}"
            result.add_error(error_msg)

        # Check destination interface
        if dstintf not in existing_interfaces:
            similar = [i for i in existing_interfaces
                      if dstintf.lower() in i.lower()]
            error_msg = f"Destination interface '{dstintf}' does not exist on this FortiGate."
            if similar:
                error_msg += f" Did you mean: {', '.join(similar)}?"
            else:
                error_msg += f" Available interfaces: {', '.join(existing_interfaces[:8])}"
            result.add_error(error_msg)

    except Exception as e:
        result.add_warning(
            f"Could not verify interfaces against FortiGate: {str(e)}. "
            f"Proceeding without interface validation."
        )

    # Check source interface == destination interface
    if srcintf == dstintf and srcintf:
        result.add_warning(
            f"Source and destination interfaces are both '{srcintf}'. "
            f"This is unusual — are you sure this is intentional?"
        )

    # Check address objects exist (skip if "all")
    try:
        existing_addresses = _get_address_names()

        if srcaddr != "all" and srcaddr not in existing_addresses:
            result.add_error(
                f"Source address object '{srcaddr}' does not exist. "
                f"Create it first or use 'all'."
            )
        if dstaddr != "all" and dstaddr not in existing_addresses:
            result.add_error(
                f"Destination address object '{dstaddr}' does not exist. "
                f"Create it first or use 'all'."
            )
    except Exception as e:
        result.add_warning(f"Could not verify address objects: {str(e)}")

    # Check policy name uniqueness
    try:
        existing_policies = _get_policy_names()
        if name in existing_policies:
            existing_id = existing_policies[name]
            result.add_error(
                f"A policy named '{name}' already exists (ID: {existing_id}). "
                f"Choose a different name."
            )
    except Exception as e:
        result.add_warning(f"Could not verify policy name uniqueness: {str(e)}")

    if not result.valid:
        return result

    # ── 4. Conflict detection ─────────────────────────────
    try:
        existing_policies_full = _get_existing_policies_full()
        for existing in existing_policies_full:
            e_srcintf = [i.get("name") for i in existing.get("srcintf", [])]
            e_dstintf = [i.get("name") for i in existing.get("dstintf", [])]
            e_service = [s.get("name") for s in existing.get("service", [])]
            e_action = existing.get("action", "")
            e_name = existing.get("name", "")
            e_id = existing.get("policyid", "")

            # Same interfaces and service but different action
            if (srcintf in e_srcintf and
                    dstintf in e_dstintf and
                    (service in e_service or "ALL" in e_service) and
                    e_action != action):
                result.add_warning(
                    f"Conflict detected with policy '{e_name}' (ID: {e_id}): "
                    f"Same traffic path ({srcintf} -> {dstintf}, {service}) "
                    f"but opposite action ({e_action}). "
                    f"FortiGate applies policies top-down — check rule order."
                )

            # Exact duplicate check
            if (srcintf in e_srcintf and
                    dstintf in e_dstintf and
                    (service in e_service or "ALL" in e_service) and
                    e_action == action):
                result.add_warning(
                    f"Policy '{e_name}' (ID: {e_id}) already covers this traffic "
                    f"({srcintf} -> {dstintf}, {service}, {action}). "
                    f"This new policy may be redundant."
                )

    except Exception as e:
        result.add_warning(f"Could not run conflict detection: {str(e)}")

    # ── 5. Security risk assessment ───────────────────────
    if action == "accept":
        # Overly permissive rule
        if srcaddr == "all" and dstaddr == "all" and service == "ALL":
            result.add_warning(
                "SECURITY RISK: This policy allows ALL traffic from ALL sources "
                "to ALL destinations on ALL services. This is extremely permissive "
                "and violates the principle of least privilege. "
                "Consider restricting the scope."
            )
            result.add_suggestion(
                "Best practice: Specify exact source/destination addresses "
                "and only the services that are strictly required."
            )

        # Allow all from any to internet
        if srcaddr == "all" and service == "ALL":
            result.add_warning(
                "SECURITY RISK: This policy allows all traffic from any source "
                "on all services. Consider restricting the service list."
            )

        # SSH/RDP accept rules from any source
        if service in ("SSH", "RDP", "TELNET") and srcaddr == "all":
            result.add_warning(
                f"SECURITY RISK: Allowing {service} from any source address. "
                f"This exposes remote access to the entire network. "
                f"Consider restricting the source address to known admin IPs."
            )
            result.add_suggestion(
                f"Create a specific address object for your admin workstation "
                f"and use it as the source address for {service} policies."
            )

    # Deny rule on management protocols — good practice acknowledgment
    if action == "deny" and service in ("SSH", "HTTPS", "HTTP", "TELNET"):
        result.add_suggestion(
            f"Good security practice: blocking {service} access. "
            f"Make sure you still have management access via another interface."
        )

    return result


# ── Address object validators ─────────────────────────────

def validate_create_address(params: dict) -> ValidationResult:
    """
    Full validation for address object creation.
    """
    result = ValidationResult()
    clear_cache()

    name = params.get("name", "").strip()
    subnet = params.get("subnet", "").strip()

    # ── 1. Parameter completeness ─────────────────────────
    if not name:
        result.add_error("Address object name is required.")
    if not subnet:
        result.add_error("Subnet is required.")

    if not result.valid:
        return result

    # ── 2. Format validation ──────────────────────────────
    name_valid, name_error = validate_object_name(name)
    if not name_valid:
        result.add_error(name_error)

    # Validate subnet format (CIDR or dotted mask)
    subnet_valid = validate_ip_cidr(subnet) or validate_ip_mask(subnet)
    if not subnet_valid:
        result.add_error(
            f"Invalid subnet format '{subnet}'. "
            f"Use CIDR notation (e.g. 192.168.1.0/24) "
            f"or dotted mask (e.g. 192.168.1.0 255.255.255.0)."
        )

    if not result.valid:
        return result

    # ── 3. Existence check ────────────────────────────────
    try:
        existing_addresses = _get_address_names()
        if name in existing_addresses:
            result.add_error(
                f"An address object named '{name}' already exists. "
                f"Choose a different name or delete the existing one first."
            )
    except Exception as e:
        result.add_warning(f"Could not verify address name uniqueness: {str(e)}")

    # ── 4. Security checks ────────────────────────────────
    # Warn about overly broad subnets
    if subnet in ("0.0.0.0/0", "0.0.0.0 0.0.0.0"):
        result.add_warning(
            "This address object covers ALL IP addresses (0.0.0.0/0). "
            "Using this in firewall policies may create overly permissive rules."
        )

    # Check for loopback range
    if subnet.startswith("127."):
        result.add_warning(
            "This address is in the loopback range (127.x.x.x). "
            "This is typically not used in firewall policies."
        )

    # /8 or very broad subnet warning
    if "/" in subnet:
        prefix = int(subnet.split("/")[1])
        if prefix < 8:
            result.add_warning(
                f"This subnet (/{prefix}) is very broad and covers "
                f"millions of IP addresses. Confirm this is intentional."
            )

    return result


def validate_delete_address(params: dict) -> ValidationResult:
    """
    Validation for address object deletion.
    Checks existence and warns if used in policies.
    """
    result = ValidationResult()
    clear_cache()

    name = params.get("name", "").strip()

    if not name:
        result.add_error("Address object name is required.")
        return result

    # Check it exists
    try:
        existing_addresses = _get_address_names()
        if name not in existing_addresses:
            result.add_error(
                f"Address object '{name}' does not exist on this FortiGate."
            )
            return result
    except Exception as e:
        result.add_warning(f"Could not verify address existence: {str(e)}")

    # Check if used in any policy
    try:
        existing_policies = _get_existing_policies_full()
        used_in = []
        for policy in existing_policies:
            src_addrs = [a.get("name") for a in policy.get("srcaddr", [])]
            dst_addrs = [a.get("name") for a in policy.get("dstaddr", [])]
            if name in src_addrs or name in dst_addrs:
                used_in.append(
                    f"'{policy.get('name')}' (ID: {policy.get('policyid')})"
                )

        if used_in:
            result.add_warning(
                f"Address object '{name}' is currently used in "
                f"{len(used_in)} firewall policy(ies): {', '.join(used_in)}. "
                f"Deleting it may break these policies."
            )
    except Exception as e:
        result.add_warning(f"Could not check policy usage: {str(e)}")

    return result

def validate_update_interface_access(params: dict) -> ValidationResult:
    """
    Validate interface management access update.
    Prevents accidental lockout.
    """
    result = ValidationResult()

    name = params.get("name", "").strip()
    allowaccess = params.get("allowaccess", "").strip()

    if not name:
        result.add_error("Interface name is required.")
        return result

    if not allowaccess:
        result.add_error(
            "allowaccess cannot be empty. This would disable ALL "
            "management access and lock you out of the firewall."
        )
        return result

    protocols = set(allowaccess.lower().split())

    # Lockout prevention — must have at least one management protocol
    mgmt_protocols = {"https", "ssh"}
    if not protocols.intersection(mgmt_protocols):
        result.add_error(
            "LOCKOUT PREVENTION: You must keep at least HTTPS or SSH enabled. "
            "Removing all management protocols will lock you out of the firewall."
        )
        return result

    # Warn about insecure protocols being added
    insecure = {"http", "telnet"}
    found_insecure = protocols.intersection(insecure)
    if found_insecure:
        result.add_warning(
            f"You are enabling insecure protocols: "
            f"{', '.join(found_insecure).upper()}. "
            f"These transmit credentials in cleartext."
        )

    # Verify interface exists
    try:
        existing = _get_interfaces()
        if name not in existing:
            similar = [i for i in existing if name.lower() in i.lower()]
            msg = f"Interface '{name}' does not exist."
            if similar:
                msg += f" Did you mean: {', '.join(similar)}?"
            result.add_error(msg)
    except Exception as e:
        result.add_warning(f"Could not verify interface: {e}")

    return result