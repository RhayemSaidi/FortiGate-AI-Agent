"""
executor.py

Read-modify-write execution engine for all policy update operations.

Contract:
  1. Fetch complete current state
  2. Apply each FieldDelta to produce target state
  3. Send the COMPLETE target state as a PUT
  4. Return the expected state for verification

Never trusts API success response alone.
Never sends partial updates.
"""
import logging
from dataclasses import dataclass, field as dc_field
from typing import Optional, List, Dict, Any

from intent_parser import UpdateIntent, FieldDelta, FieldOp, LIST_FIELDS, SCALAR_FIELDS

logger = logging.getLogger("fortigate_agent")


@dataclass
class ExecutionResult:
    success:         bool
    message:         str
    expected_state:  Optional[Dict] = None
    applied_deltas:  List[FieldDelta] = dc_field(default_factory=list)
    pre_state:       Optional[Dict] = None  # State before execution — for audit


class PolicyUpdateExecutor:
    """
    Executes policy updates with read-modify-write semantics.
    Handles all field types: service lists, scalars (action, nat, status).
    """

    # Fields FortiGate manages internally — never include in PUT payload
    _READONLY_FIELDS = frozenset({
        "policyid", "q_origin_key", "uuid", "type",
        "implied", "vdom", "ippool", "poolname",
        "global-label", "send-deny-packet",
    })

    def __init__(self, get_policy_fn, update_policy_fn):
        self._get    = get_policy_fn   # (policy_id: int) -> dict
        self._update = update_policy_fn  # (policy_id: int, data: dict) -> dict

    def execute(self, intent: UpdateIntent) -> ExecutionResult:
        # Step 1: Read current state
        current = self._fetch(intent.policy_id)
        if current is None:
            return ExecutionResult(
                success=False,
                message=f"Policy ID {intent.policy_id} not found on FortiGate.",
            )

        pre_state = dict(current)

        # Step 2: Pre-flight no-op detection
        # Done here (not before showing confirmation) so the user always sees
        # the confirmation screen for transparency. No-op is reported after
        # confirmation if the state already matches.
        noop_messages = self._check_noops(current, intent.deltas)
        if noop_messages and len(noop_messages) == len(intent.deltas):
            # All deltas are no-ops — report cleanly without making an API call
            return ExecutionResult(
                success=True,
                message="No changes needed — " + "; ".join(noop_messages),
                expected_state=current,
                pre_state=pre_state,
            )

        # Step 3: Apply deltas to produce target state
        target, errors = self._apply_deltas(dict(current), intent.deltas)
        if errors:
            return ExecutionResult(
                success=False,
                message="Cannot apply requested changes: " + "; ".join(errors),
                pre_state=pre_state,
            )

        # Step 4: Build complete PUT payload
        payload = self._build_payload(target)

        # Step 5: Execute
        r = self._update(intent.policy_id, payload)
        if r.get("status") != "success":
            cli_err = r.get("cli_error", [str(r)])
            return ExecutionResult(
                success=False,
                message=f"FortiGate rejected update: {cli_err}",
                expected_state=target,
                pre_state=pre_state,
            )

        return ExecutionResult(
            success=True,
            message=f"Policy ID {intent.policy_id} updated.",
            expected_state=target,
            applied_deltas=intent.deltas,
            pre_state=pre_state,
        )

    def _fetch(self, policy_id: int) -> Optional[dict]:
        try:
            r   = self._get(policy_id)
            raw = r.get("results", {})
            if isinstance(raw, list) and raw:
                return raw[0]
            if isinstance(raw, dict) and raw:
                return raw
        except Exception as exc:
            logger.error(
                f'"event":"executor_fetch_fail",'
                f'"policy_id":{policy_id},"error":"{exc}"'
            )
        return None

    def _check_noops(self, current: dict, deltas: List[FieldDelta]) -> List[str]:
        """
        Identify which deltas are no-ops given the current state.
        Returns human-readable descriptions of no-op deltas.
        """
        noops = []
        for delta in deltas:
            field = delta.field_name

            if delta.op == FieldOp.SET:
                current_val = str(current.get(field, "")).lower()
                requested   = delta.scalar.lower()
                if current_val == requested:
                    noops.append(f"{field} is already '{delta.scalar}'")

            elif field in LIST_FIELDS:
                item_key     = LIST_FIELDS[field]["item_key"]
                current_set  = {
                    item.get(item_key, "").upper()
                    for item in current.get(field, [])
                }
                delta_set = {v.upper() for v in delta.values}

                if delta.op == FieldOp.ADD and delta_set.issubset(current_set):
                    noops.append(
                        f"{', '.join(delta.values)} already in {field}"
                    )
                elif delta.op == FieldOp.REMOVE and not delta_set.intersection(current_set):
                    noops.append(
                        f"{', '.join(delta.values)} not found in {field}"
                    )
                elif delta.op == FieldOp.REPLACE and delta_set == current_set:
                    noops.append(f"{field} already set to {', '.join(delta.values)}")

        return noops

    def _apply_deltas(self, target: dict,
                      deltas: List[FieldDelta]) -> tuple:
        errors = []

        for delta in deltas:
            field = delta.field_name

            if delta.op == FieldOp.SET:
                if field not in SCALAR_FIELDS:
                    errors.append(f"'{field}' is not a settable scalar field.")
                    continue
                allowed = SCALAR_FIELDS[field]["values"]
                if allowed and delta.scalar.lower() not in {v.lower() for v in allowed}:
                    errors.append(
                        f"'{delta.scalar}' is not a valid value for '{field}'. "
                        f"Allowed: {', '.join(allowed)}"
                    )
                    continue
                # Apply: FortiGate uses string values for all scalar fields
                target[field] = delta.scalar

            elif field in LIST_FIELDS:
                item_key     = LIST_FIELDS[field]["item_key"]
                current_items = list(target.get(field, []))
                current_set   = {
                    item.get(item_key, "").upper(): item.get(item_key, "")
                    for item in current_items
                }
                delta_set = {v.upper(): v for v in delta.values}

                if delta.op == FieldOp.ADD:
                    # Preserve existing items, add new ones
                    merged = dict(current_set)   # upper → original_case
                    merged.update(delta_set)     # new ones overwrite (dedup)
                    new_items = sorted(merged.values())

                elif delta.op == FieldOp.REMOVE:
                    remaining = {
                        k: v for k, v in current_set.items()
                        if k not in delta_set
                    }
                    if not remaining:
                        errors.append(
                            f"Removing {delta.values} from '{field}' would leave it empty. "
                            f"A policy must have at least one entry in '{field}'."
                        )
                        continue
                    new_items = sorted(remaining.values())

                elif delta.op == FieldOp.REPLACE:
                    new_items = sorted(delta_set.values())

                else:
                    errors.append(f"Unknown operation '{delta.op}' for field '{field}'")
                    continue

                target[field] = [{item_key: name} for name in new_items]

            else:
                errors.append(
                    f"Field '{field}' is not recognized. "
                    f"List fields: {list(LIST_FIELDS.keys())}. "
                    f"Scalar fields: {list(SCALAR_FIELDS.keys())}."
                )

        return target, errors

    def _build_payload(self, target: dict) -> dict:
        """Build the complete PUT payload, excluding read-only fields."""
        return {
            k: v for k, v in target.items()
            if k not in self._READONLY_FIELDS
        }