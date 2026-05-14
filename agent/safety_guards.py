"""
safety_guards.py

Deterministic pre-execution safety checks for dangerous write operations.

This module enforces trust-boundary safety BEFORE confirmation is presented
to the user. It is purely deterministic — no LLM reasoning is involved.

Each guard function returns a ValidationResult following the same contract
as validator.py. Guards are registered in core.py's VALIDATORS dict.

Danger tiers:
    BLOCK  — operation would clearly cause management lockout or data loss.
    WARN   — operation is dangerous but may be intentional (secondary confirm).
    ALLOW  — operation is safe to proceed.

Guards implemented:
    - tool_set_interface_status : management lockout prevention
    - tool_delete_route         : default-route and management-subnet protection
    - tool_create_route         : format and sanity validation
    - tool_delete_service       : in-use reference check (blocks deletion)
    - tool_create_service       : name format and port validation
    - tool_create_user          : name format validation
    - tool_delete_user          : last-admin protection (best-effort)
"""
import re
import logging
from typing import Optional

logger = logging.getLogger("fortigate_agent")


# ── Import the shared ValidationResult ────────────────────────────────────────
# We re-use the existing ValidationResult from validator.py for API consistency.
from validator import ValidationResult, validate_object_name


# ══════════════════════════════════════════════════════════════════════════════
#  Internal helpers
# ══════════════════════════════════════════════════════════════════════════════

def _validate_ip(ip: str) -> bool:
    """Return True if ip is a valid dotted-decimal IPv4 address."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _validate_netmask(mask: str) -> bool:
    """Return True if mask is a valid dotted-decimal subnet mask."""
    return _validate_ip(mask)


def _get_management_interface() -> Optional[str]:
    """
    Best-effort detection of the FortiGate management interface.
    Returns interface name string or None if undeterminable.
    Checks: allowaccess on each interface for https/ssh.
    """
    try:
        from modules.interfaces import list_interfaces
        r       = list_interfaces()
        results = r if isinstance(r, list) else r.get("results", [])
        for iface in results:
            access = str(iface.get("allowaccess", "")).lower()
            if "https" in access or "ssh" in access:
                return iface.get("name")
    except Exception as exc:
        logger.debug(f'"event":"guard_mgmt_lookup_fail","error":"{exc}"')
    return None


def _get_routes() -> list:
    """Return current static route list."""
    try:
        from modules.routing import list_routes
        r = list_routes()
        return r if isinstance(r, list) else r.get("results", [])
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  Interface safety guard
# ══════════════════════════════════════════════════════════════════════════════

def validate_set_interface_status(params: dict) -> ValidationResult:
    """
    Guard: bringing an interface down.

    BLOCKS if:
    - status='down' and the interface appears to be the management interface
      (has HTTPS or SSH in its allowaccess).

    WARNS if:
    - status='down' on any named interface (connectivity impact).
    """
    result = ValidationResult()

    name   = str(params.get("name", "")).strip()
    status = str(params.get("status", "")).lower().strip()

    if not name:
        result.add_error("Interface name is required.")
        return result
    if status not in ("up", "down"):
        result.add_error("status must be 'up' or 'down'.")
        return result

    # Existence check
    try:
        from modules.interfaces import list_interfaces
        r       = list_interfaces()
        results = r if isinstance(r, list) else r.get("results", [])
        iface_map = {i.get("name", ""): i for i in results}

        if name not in iface_map:
            similar = [n for n in iface_map if name.lower() in n.lower()]
            msg = f"Interface '{name}' does not exist."
            if similar:
                msg += f" Did you mean: {', '.join(similar)}?"
            result.add_error(msg)
            return result

        if status == "down":
            iface_data = iface_map[name]
            access     = str(iface_data.get("allowaccess", "")).lower()

            # Management lockout prevention
            if "https" in access or "ssh" in access:
                result.add_error(
                    f"MANAGEMENT LOCKOUT PREVENTION: Interface '{name}' has "
                    f"{'HTTPS' if 'https' in access else ''} "
                    f"{'SSH' if 'ssh' in access else ''} management access enabled. "
                    f"Bringing it down will disconnect you from the FortiGate. "
                    f"This operation has been BLOCKED."
                )
                return result

            # General connectivity warning
            result.add_warning(
                f"Bringing interface '{name}' DOWN will immediately drop all "
                f"traffic passing through it. Ensure no critical services depend on it."
            )

    except Exception as exc:
        result.add_warning(f"Could not verify interface safety: {exc}. Proceed with caution.")

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  Route safety guards
# ══════════════════════════════════════════════════════════════════════════════

def validate_create_route(params: dict) -> ValidationResult:
    """
    Guard: adding a static route.

    Validates:
    - dst, gateway, device are present and correctly formatted
    - gateway is a valid IP
    - netmask is a valid dotted-decimal mask
    - Warns if adding a default route (0.0.0.0)
    """
    result = ValidationResult()

    dst     = str(params.get("dst",     "")).strip()
    gateway = str(params.get("gateway", "")).strip()
    device  = str(params.get("device",  "")).strip()
    netmask = str(params.get("netmask", "255.255.255.0")).strip()

    if not dst:
        result.add_error("Destination network (dst) is required.")
    if not gateway:
        result.add_error("Gateway IP is required.")
    if not device:
        result.add_error("Outbound interface (device) is required.")
    if not result.valid:
        return result

    if not _validate_ip(dst):
        result.add_error(f"Invalid destination IP: '{dst}'. Use dotted-decimal (e.g. 10.20.0.0).")
    if not _validate_ip(gateway):
        result.add_error(f"Invalid gateway IP: '{gateway}'.")
    if not _validate_netmask(netmask):
        result.add_error(f"Invalid netmask: '{netmask}'. Use dotted-decimal (e.g. 255.255.255.0).")
    if not result.valid:
        return result

    # Verify interface exists
    try:
        from modules.interfaces import list_interfaces
        r       = list_interfaces()
        results = r if isinstance(r, list) else r.get("results", [])
        ifaces  = [i.get("name", "") for i in results]
        if device not in ifaces:
            similar = [i for i in ifaces if device.lower() in i.lower()]
            msg = f"Interface '{device}' does not exist."
            if similar:
                msg += f" Did you mean: {', '.join(similar)}?"
            result.add_error(msg)
            return result
    except Exception as exc:
        result.add_warning(f"Could not verify interface '{device}': {exc}")

    if dst == "0.0.0.0":
        result.add_warning(
            "Adding a DEFAULT ROUTE (0.0.0.0). This will affect ALL unmatched traffic. "
            "A misconfigured default route can black-hole management access."
        )

    return result


def validate_delete_route(params: dict) -> ValidationResult:
    """
    Guard: deleting a static route.

    BLOCKS if the route being deleted is the default route (0.0.0.0 dst).
    WARNS for all route deletions (connectivity impact).
    """
    result  = ValidationResult()
    route_id = params.get("route_id")

    if not route_id:
        result.add_error("route_id is required. Use 'list routes' to find the ID.")
        return result

    try:
        routes = _get_routes()
        route_map = {str(r.get("seq-num", r.get("id", ""))): r for r in routes}

        if str(route_id) not in route_map:
            result.add_error(
                f"Route ID {route_id} does not exist. "
                f"Use 'list routes' to see available IDs."
            )
            return result

        route = route_map[str(route_id)]
        dst   = str(route.get("dst", "")).split()[0] if route.get("dst") else "?"
        gw    = route.get("gateway", "?")
        dev   = route.get("device", "?")

        if dst in ("0.0.0.0", ""):
            result.add_error(
                f"SAFETY BLOCK: Route ID {route_id} is the DEFAULT ROUTE "
                f"(dst=0.0.0.0 via {gw} on {dev}). "
                f"Deleting it will black-hole all outbound traffic and "
                f"likely disconnect management access. This operation has been BLOCKED."
            )
            return result

        result.add_warning(
            f"Deleting static route ID {route_id}: {dst} via {gw} on {dev}. "
            f"Traffic destined for {dst} will lose its route immediately."
        )

    except Exception as exc:
        result.add_warning(f"Could not verify route {route_id}: {exc}. Proceed with caution.")

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  Service object safety guards
# ══════════════════════════════════════════════════════════════════════════════

def validate_create_service(params: dict) -> ValidationResult:
    """
    Guard: creating a custom service object.

    Validates:
    - Name format (35 char, no spaces)
    - Protocol is valid
    - Port range is reasonable
    """
    result = ValidationResult()

    name       = str(params.get("name",       "")).strip()
    protocol   = str(params.get("protocol",   "TCP")).upper().strip()
    port_range = str(params.get("port_range", "")).strip()

    if not name:
        result.add_error("Service name is required.")
        return result

    name_valid, name_error = validate_object_name(name)
    if not name_valid:
        result.add_error(name_error)
        return result

    if protocol not in ("TCP", "UDP", "ICMP", "IP"):
        result.add_error(f"Protocol must be TCP, UDP, ICMP, or IP. Got: '{protocol}'.")
        return result

    if protocol in ("TCP", "UDP") and port_range:
        # Validate port range format: "8080" or "8000-8080"
        port_pattern = re.compile(r'^\d+(-\d+)?$')
        for part in port_range.split():
            if not port_pattern.match(part):
                result.add_error(
                    f"Invalid port range '{part}'. "
                    f"Use a single port (e.g. 8080) or range (e.g. 8000-8080)."
                )
                return result
        # Check for privileged port warning
        try:
            ports = [int(p) for p in re.findall(r'\d+', port_range)]
            if any(p < 1024 for p in ports):
                result.add_warning(
                    f"Port {min(p for p in ports if p < 1024)} is a well-known privileged port. "
                    f"Ensure this doesn't conflict with existing built-in services."
                )
        except ValueError:
            pass

    # Check for name collision with existing services
    try:
        from modules.services import list_services
        r       = list_services()
        results = r if isinstance(r, list) else r.get("results", [])
        existing = {s.get("name", "").lower() for s in results}
        if name.lower() in existing:
            result.add_error(f"Custom service '{name}' already exists.")
            return result
    except Exception as exc:
        result.add_warning(f"Could not verify service name uniqueness: {exc}")

    return result


def validate_delete_service(params: dict) -> ValidationResult:
    """
    Guard: deleting a custom service object.

    BLOCKS if the service is currently referenced by any firewall policy.
    This prevents creating orphaned policy references.
    """
    result = ValidationResult()
    name   = str(params.get("name", "")).strip()

    if not name:
        result.add_error("Service name is required.")
        return result

    # Check existence
    try:
        from modules.services import list_services
        r       = list_services()
        results = r if isinstance(r, list) else r.get("results", [])
        names   = {s.get("name", "") for s in results}
        if name not in names:
            result.add_error(f"Custom service '{name}' does not exist.")
            return result
    except Exception as exc:
        result.add_warning(f"Could not verify service existence: {exc}")

    # Reference check — block if in use
    try:
        from modules.policies import list_policies
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        using   = []
        for p in results:
            svc_names = [s.get("name", "").upper() for s in (p.get("service") or [])]
            if name.upper() in svc_names:
                using.append(f"{p.get('name', '?')} (ID:{p.get('policyid', '?')})")

        if using:
            policy_list = ", ".join(using[:5])
            suffix      = f" (and {len(using) - 5} more)" if len(using) > 5 else ""
            result.add_error(
                f"Cannot delete service '{name}' — it is referenced by "
                f"{len(using)} policy/policies: {policy_list}{suffix}. "
                f"Remove it from those policies first."
            )
            return result
    except Exception as exc:
        result.add_warning(
            f"Could not verify policy references for '{name}': {exc}. "
            f"Deletion may break active policies."
        )

    result.add_warning(
        f"PERMANENTLY DELETE custom service '{name}'. "
        f"This cannot be undone."
    )
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  User management safety guards
# ══════════════════════════════════════════════════════════════════════════════

def validate_create_user(params: dict) -> ValidationResult:
    """
    Guard: creating a local user.

    Validates:
    - Name format
    - Password minimum length
    - Name uniqueness
    """
    result   = ValidationResult()
    name     = str(params.get("name",     "")).strip()
    password = str(params.get("password", ""))
    status   = str(params.get("status",   "enable")).lower()

    if not name:
        result.add_error("Username is required.")
        return result
    if not password:
        result.add_error("Password is required.")
        return result

    name_valid, name_error = validate_object_name(name)
    if not name_valid:
        result.add_error(name_error)
        return result

    if len(password) < 8:
        result.add_warning(
            f"Password is only {len(password)} characters. "
            f"FortiGate recommends minimum 8 characters for security."
        )

    if status not in ("enable", "disable"):
        result.add_error("status must be 'enable' or 'disable'.")
        return result

    try:
        from modules.users import list_users
        r       = list_users()
        results = r if isinstance(r, list) else r.get("results", [])
        names   = {u.get("name", "").lower() for u in results}
        if name.lower() in names:
            result.add_error(f"User '{name}' already exists.")
            return result
    except Exception as exc:
        result.add_warning(f"Could not verify user name uniqueness: {exc}")

    return result


def validate_delete_user(params: dict) -> ValidationResult:
    """
    Guard: deleting a local user.

    BLOCKS if the user is the last admin account (best-effort).
    WARNS for all user deletions.
    """
    result = ValidationResult()
    name   = str(params.get("name", "")).strip()

    if not name:
        result.add_error("Username is required.")
        return result

    try:
        from modules.users import list_users
        r       = list_users()
        results = r if isinstance(r, list) else r.get("results", [])
        names   = {u.get("name", "") for u in results}

        if name not in names:
            result.add_error(f"User '{name}' does not exist.")
            return result

        # Last-admin protection (best-effort)
        enabled_users = [u for u in results if u.get("status", "enable") == "enable"]
        if len(enabled_users) <= 1 and enabled_users[0].get("name") == name:
            result.add_error(
                f"LOCKOUT PREVENTION: '{name}' appears to be the only active local user. "
                f"Deleting it may lock you out of the system. "
                f"Create another admin account first."
            )
            return result

    except Exception as exc:
        result.add_warning(f"Could not verify user '{name}': {exc}")

    result.add_warning(
        f"PERMANENTLY DELETE user account '{name}'. "
        f"This cannot be undone. Any active sessions for this user will be terminated."
    )
    return result
