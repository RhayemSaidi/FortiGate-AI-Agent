"""
snapshot.py

Lightweight operation snapshot and rollback engine.

ARCHITECTURE:
    - Pure in-process state (no disk I/O, no database)
    - Max 10 snapshots per session (FIFO eviction)
    - Each snapshot captures: resource key, pre-op state, metadata
    - Rollback is deterministic — no LLM involvement
    - Trust boundary preserved: rollback only restores known pre-state

SNAPSHOT LIFECYCLE:
    1. Before confirmed write → snapshot.capture(tool_name, resource, pre_state, desc)
    2. After user asks → snapshot.rollback_last() or snapshot.rollback(op_id)
    3. Audit log records all captures and rollbacks

ROLLBACK CONTRACTS:
    - Only policies, routes, services, users, and addresses can be rolled back
    - Interface status rollback is NOT supported (network disruption risk)
    - Rollback uses the SAME API path as normal writes (not a special bypass)
    - Rollback produces a ConfirmationState for re-confirmation

ROLLBACK IS NOT AUTOMATIC:
    The user must explicitly request a rollback.
    This prevents accidental restoration.
"""
import logging
import uuid
from collections import deque
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

logger = logging.getLogger("fortigate_agent")

_MAX_SNAPSHOTS = 10


# ══════════════════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class OperationSnapshot:
    """
    Immutable record of pre-operation state for a single write operation.

    op_id        : Short 8-char hex operation identifier (globally unique)
    timestamp    : ISO8601 UTC string
    tool_name    : The tool that performed the write (e.g. 'tool_create_route')
    resource_key : Dotted resource identifier (e.g. 'policy:4', 'route:2', 'user:alice')
    pre_state    : Full resource state BEFORE the write was applied
    description  : Human-readable description (e.g. 'enable NAT in policy 4')
    rollback_fn  : Name of rollback function to call (determines restoration logic)
    """
    op_id:        str
    timestamp:    str
    tool_name:    str
    resource_key: str
    pre_state:    Dict[str, Any]
    description:  str
    rollback_fn:  str      = ""   # e.g. 'restore_policy', 'restore_route'
    rolled_back:  bool     = False


@dataclass
class RollbackResult:
    success:  bool
    op_id:    str
    message:  str
    detail:   str = ""


# ══════════════════════════════════════════════════════════════════════════════
#  Snapshot store (session-scoped singleton pattern)
# ══════════════════════════════════════════════════════════════════════════════

import os
import json

_SNAPSHOT_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "snapshots.json")

class SnapshotStore:
    """
    Persistent store for operation snapshots. One instance per AgentSession.
    State is saved to disk to survive container/process restarts.
    """

    def __init__(self):
        self._snapshots: deque[OperationSnapshot] = deque(maxlen=_MAX_SNAPSHOTS)
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        if not os.path.exists(_SNAPSHOT_FILE):
            return
        try:
            with open(_SNAPSHOT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    # Ignore corrupted entries safely
                    if isinstance(item, dict):
                        self._snapshots.append(OperationSnapshot(**item))
        except Exception as exc:
            logger.error(f'"event":"snapshot_load_failed","error":"{exc}"')

    def _save_to_disk(self) -> None:
        try:
            os.makedirs(os.path.dirname(_SNAPSHOT_FILE), exist_ok=True)
            with open(_SNAPSHOT_FILE, "w", encoding="utf-8") as f:
                json.dump([s.__dict__ for s in self._snapshots], f, indent=2)
        except Exception as exc:
            logger.error(f'"event":"snapshot_save_failed","error":"{exc}"')

    def capture(
        self,
        tool_name:    str,
        resource_key: str,
        pre_state:    Dict[str, Any],
        description:  str,
        rollback_fn:  str = "",
    ) -> str:
        """
        Capture a pre-operation snapshot and persist to disk.
        """
        op_id = uuid.uuid4().hex[:8].upper()
        ts    = datetime.now(timezone.utc).isoformat()

        snap = OperationSnapshot(
            op_id=op_id,
            timestamp=ts,
            tool_name=tool_name,
            resource_key=resource_key,
            pre_state=dict(pre_state),   # shallow copy — safe for flat dicts
            description=description,
            rollback_fn=rollback_fn,
        )
        self._snapshots.append(snap)
        self._save_to_disk()

        logger.debug(
            f'"event":"snapshot_captured",'
            f'"op_id":"{op_id}",'
            f'"tool":"{tool_name}",'
            f'"resource":"{resource_key}",'
            f'"description":"{description[:80]}"'
        )
        return op_id

    def list(self) -> List[OperationSnapshot]:
        """Return snapshots newest-first (most recent at index 0)."""
        return list(reversed(self._snapshots))

    def get(self, op_id: str) -> Optional[OperationSnapshot]:
        """Find a snapshot by op_id."""
        for snap in self._snapshots:
            if snap.op_id.upper() == op_id.upper():
                return snap
        return None

    def mark_rolled_back(self, op_id: str) -> None:
        for snap in self._snapshots:
            if snap.op_id.upper() == op_id.upper():
                snap.rolled_back = True
                self._save_to_disk()
                break

    def format_list(self) -> str:
        """Format snapshot list for display to user."""
        snaps = self.list()
        if not snaps:
            return "No rollback snapshots available in this session."
        lines = ["Available rollback points:", ""]
        for s in snaps:
            status = " [ROLLED BACK]" if s.rolled_back else ""
            lines.append(
                f"  [{s.op_id}] {s.timestamp[:19]}Z  "
                f"{s.tool_name:<30} {s.description[:50]}{status}"
            )
        lines.append("")
        lines.append(
            "To rollback: type 'rollback last' or 'rollback <OP_ID>'"
        )
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  Pre-capture helpers — fetch pre-state before write
# ══════════════════════════════════════════════════════════════════════════════

def capture_policy_snapshot(
    store:       SnapshotStore,
    policy_id:   int,
    description: str,
) -> Optional[str]:
    """Capture pre-state of a policy before modification."""
    try:
        from modules.policies import get_policy
        r   = get_policy(policy_id)
        raw = r.get("results", {})
        pre = raw[0] if isinstance(raw, list) and raw else raw if isinstance(raw, dict) else {}
        if not pre:
            return None
        return store.capture(
            tool_name="tool_update_policy",
            resource_key=f"policy:{policy_id}",
            pre_state=pre,
            description=description,
            rollback_fn="restore_policy",
        )
    except Exception as exc:
        logger.warning(f'"event":"snapshot_capture_fail","resource":"policy:{policy_id}","error":"{exc}"')
        return None

def capture_policy_move_snapshot(
    store:       SnapshotStore,
    policy_id:   int,
    description: str,
) -> Optional[str]:
    """Capture the positional state of a policy before moving it."""
    try:
        from modules.policies import list_policies
        r = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        
        idx = -1
        for i, p in enumerate(results):
            if p.get("policyid") == policy_id:
                idx = i
                break
                
        if idx == -1:
            return None
            
        if idx == 0 and len(results) > 1:
            pre_state = {"move_action": "before", "neighbor_id": results[1].get("policyid")}
        elif idx > 0:
            pre_state = {"move_action": "after", "neighbor_id": results[idx - 1].get("policyid")}
        else:
            return None
            
        return store.capture(
            tool_name="tool_move_policy",
            resource_key=f"policy_move:{policy_id}",
            pre_state=pre_state,
            description=description,
            rollback_fn="restore_policy_move",
        )
    except Exception as exc:
        logger.warning(f'"event":"snapshot_capture_fail","resource":"policy_move:{policy_id}","error":"{exc}"')
        return None


def capture_route_snapshot(
    store:       SnapshotStore,
    route_id:    int,
    description: str,
    tool_name:   str = "tool_delete_route",
) -> Optional[str]:
    """Capture pre-state of a route before deletion."""
    try:
        from modules.routing import list_routes
        r      = list_routes()
        routes = r if isinstance(r, list) else r.get("results", [])
        for route in routes:
            rid = str(route.get("seq-num", route.get("id", "")))
            if rid == str(route_id):
                return store.capture(
                    tool_name=tool_name,
                    resource_key=f"route:{route_id}",
                    pre_state=route,
                    description=description,
                    rollback_fn="restore_route",
                )
    except Exception as exc:
        logger.warning(f'"event":"snapshot_capture_fail","resource":"route:{route_id}","error":"{exc}"')
    return None


def capture_user_snapshot(
    store:       SnapshotStore,
    username:    str,
    description: str,
    tool_name:   str = "tool_delete_user",
) -> Optional[str]:
    """Capture pre-state of a user before deletion."""
    try:
        from modules.users import list_users
        r       = list_users()
        results = r if isinstance(r, list) else r.get("results", [])
        for u in results:
            if u.get("name", "") == username:
                # IMPORTANT: never log passwords. Sanitise pre_state.
                safe_state = {k: v for k, v in u.items() if k != "passwd"}
                return store.capture(
                    tool_name=tool_name,
                    resource_key=f"user:{username}",
                    pre_state=safe_state,
                    description=description,
                    rollback_fn="restore_user",
                )
    except Exception as exc:
        logger.warning(f'"event":"snapshot_capture_fail","resource":"user:{username}","error":"{exc}"')
    return None


def capture_service_snapshot(
    store:       SnapshotStore,
    service_name: str,
    description:  str,
    tool_name:    str = "tool_delete_service",
) -> Optional[str]:
    """Capture pre-state of a custom service before deletion."""
    try:
        from modules.services import list_services
        r       = list_services()
        results = r if isinstance(r, list) else r.get("results", [])
        for svc in results:
            if svc.get("name", "") == service_name:
                return store.capture(
                    tool_name=tool_name,
                    resource_key=f"service:{service_name}",
                    pre_state=svc,
                    description=description,
                    rollback_fn="restore_service",
                )
    except Exception as exc:
        logger.warning(f'"event":"snapshot_capture_fail","resource":"service:{service_name}","error":"{exc}"')
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  Rollback executors — deterministic, no LLM
# ══════════════════════════════════════════════════════════════════════════════

def _rollback_policy(snap: OperationSnapshot) -> RollbackResult:
    """Restore a policy to its pre-operation state using a full PUT."""
    try:
        from modules.policies import update_policy
        policy_id = int(snap.resource_key.split(":")[1])
        # Strip read-only fields before PUT
        readonly = {"policyid", "q_origin_key", "uuid", "type", "implied",
                    "vdom", "ippool", "poolname", "global-label", "send-deny-packet"}
        payload  = {k: v for k, v in snap.pre_state.items() if k not in readonly}
        r = update_policy(policy_id, payload)
        if r.get("status") == "success":
            return RollbackResult(
                success=True, op_id=snap.op_id,
                message=f"Policy ID {policy_id} restored to pre-operation state.",
                detail=f"Snapshot: {snap.description}",
            )
        return RollbackResult(
            success=False, op_id=snap.op_id,
            message=f"FortiGate rejected rollback for policy {policy_id}: {r.get('cli_error', r)}",
        )
    except Exception as exc:
        return RollbackResult(
            success=False, op_id=snap.op_id,
            message=f"Rollback failed: {exc}",
        )

def _rollback_policy_move(snap: OperationSnapshot) -> RollbackResult:
    """Restore a policy to its pre-operation position."""
    try:
        from modules.policies import move_policy
        policy_id = int(snap.resource_key.split(":")[1])
        action = snap.pre_state.get("move_action")
        neighbor = snap.pre_state.get("neighbor_id")
        
        r = move_policy(policy_id, action, neighbor)
        if r.get("status") == "success":
            return RollbackResult(
                success=True, op_id=snap.op_id,
                message=f"Policy ID {policy_id} moved back {action} policy {neighbor}.",
                detail=f"Snapshot: {snap.description}",
            )
        return RollbackResult(
            success=False, op_id=snap.op_id,
            message=f"FortiGate rejected rollback for policy move {policy_id}: {r.get('cli_error', r)}",
        )
    except Exception as exc:
        return RollbackResult(
            success=False, op_id=snap.op_id,
            message=f"Rollback failed: {exc}",
        )


def _rollback_route(snap: OperationSnapshot) -> RollbackResult:
    """Re-create a deleted route from its pre-operation state."""
    try:
        from modules.routing import create_route
        dst     = snap.pre_state.get("dst", "")
        gateway = snap.pre_state.get("gateway", "")
        device  = snap.pre_state.get("device", "")
        # dst may be stored as "10.20.0.0 255.255.255.0"
        parts   = str(dst).split()
        dst_ip  = parts[0] if parts else dst
        netmask = parts[1] if len(parts) > 1 else "255.255.255.0"
        r = create_route(dst_ip, gateway, device, netmask)
        if r.get("status") == "success":
            return RollbackResult(
                success=True, op_id=snap.op_id,
                message=f"Route to {dst_ip} via {gateway} on {device} restored.",
                detail=f"Snapshot: {snap.description}",
            )
        return RollbackResult(
            success=False, op_id=snap.op_id,
            message=f"FortiGate rejected route restoration: {r.get('cli_error', r)}",
        )
    except Exception as exc:
        return RollbackResult(success=False, op_id=snap.op_id, message=f"Route rollback failed: {exc}")


def _rollback_service(snap: OperationSnapshot) -> RollbackResult:
    """Re-create a deleted custom service from its pre-operation state."""
    try:
        from modules.services import create_service
        name       = snap.pre_state.get("name", "")
        protocol   = snap.pre_state.get("protocol", "TCP")
        port_range = snap.pre_state.get("tcp-portrange", snap.pre_state.get("udp-portrange", ""))
        r = create_service(name, protocol, port_range)
        if r.get("status") == "success":
            return RollbackResult(
                success=True, op_id=snap.op_id,
                message=f"Custom service '{name}' restored.",
                detail=f"Snapshot: {snap.description}",
            )
        return RollbackResult(
            success=False, op_id=snap.op_id,
            message=f"Service restoration failed: {r.get('cli_error', r)}",
        )
    except Exception as exc:
        return RollbackResult(success=False, op_id=snap.op_id, message=f"Service rollback failed: {exc}")


def _rollback_user(snap: OperationSnapshot) -> RollbackResult:
    """
    Re-create a deleted user.
    NOTE: Password cannot be restored from snapshot (never stored).
    A placeholder password is set — user must reset it.
    """
    try:
        from modules.users import create_user
        name   = snap.pre_state.get("name", "")
        status = snap.pre_state.get("status", "enable")
        # We never store the password — use a placeholder that must be changed
        placeholder_pw = "ChangeMe123!"
        r = create_user(name, placeholder_pw, status)
        if r.get("status") == "success":
            return RollbackResult(
                success=True, op_id=snap.op_id,
                message=(
                    f"User '{name}' re-created with status={status}. "
                    f"PASSWORD NOT RESTORED — set a new password immediately."
                ),
                detail=f"Snapshot: {snap.description}",
            )
        return RollbackResult(
            success=False, op_id=snap.op_id,
            message=f"User restoration failed: {r.get('cli_error', r)}",
        )
    except Exception as exc:
        return RollbackResult(success=False, op_id=snap.op_id, message=f"User rollback failed: {exc}")


# Rollback dispatch table — deterministic, no LLM
_ROLLBACK_FN_MAP = {
    "restore_policy":  _rollback_policy,
    "restore_policy_move": _rollback_policy_move,
    "restore_route":   _rollback_route,
    "restore_service": _rollback_service,
    "restore_user":    _rollback_user,
}


# ══════════════════════════════════════════════════════════════════════════════
#  Public rollback API
# ══════════════════════════════════════════════════════════════════════════════

def execute_rollback(store: SnapshotStore, op_id: Optional[str] = None) -> RollbackResult:
    """
    Execute a rollback.

    If op_id is None → rolls back the most recent non-rolled-back snapshot.
    If op_id is provided → rolls back that specific operation.

    Returns RollbackResult. Caller is responsible for displaying the result
    and logging the audit event.
    """
    if op_id:
        snap = store.get(op_id)
        if not snap:
            return RollbackResult(
                success=False, op_id=op_id or "",
                message=f"No snapshot found with ID '{op_id}'. Use 'show rollback history' to list available snapshots.",
            )
    else:
        # Most recent non-rolled-back
        candidates = [s for s in store.list() if not s.rolled_back]
        if not candidates:
            return RollbackResult(
                success=False, op_id="",
                message="No rollback snapshots available in this session.",
            )
        snap = candidates[0]

    if snap.rolled_back:
        return RollbackResult(
            success=False, op_id=snap.op_id,
            message=f"Snapshot [{snap.op_id}] has already been rolled back.",
        )

    if not snap.rollback_fn or snap.rollback_fn not in _ROLLBACK_FN_MAP:
        return RollbackResult(
            success=False, op_id=snap.op_id,
            message=f"No rollback procedure available for '{snap.tool_name}'. Manual restoration required.",
        )

    logger.info(
        f'"event":"rollback_start",'
        f'"op_id":"{snap.op_id}",'
        f'"tool":"{snap.tool_name}",'
        f'"resource":"{snap.resource_key}"'
    )

    result = _ROLLBACK_FN_MAP[snap.rollback_fn](snap)

    if result.success:
        store.mark_rolled_back(snap.op_id)
        logger.info(
            f'"event":"rollback_success",'
            f'"op_id":"{snap.op_id}",'
            f'"resource":"{snap.resource_key}"'
        )
    else:
        logger.warning(
            f'"event":"rollback_failed",'
            f'"op_id":"{snap.op_id}",'
            f'"resource":"{snap.resource_key}",'
            f'"reason":"{result.message[:100]}"'
        )

    return result

