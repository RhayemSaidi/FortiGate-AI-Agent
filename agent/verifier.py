"""
verifier.py

Field-level verification after policy write operations.
Fetches actual FortiGate state and compares it to the expected state.
Never trusts the API success response alone.
"""
from typing import Optional, List, Dict
from intent_parser import LIST_FIELDS, FieldDelta, FieldOp
from executor import ExecutionResult


class VerificationResult:
    def __init__(self, passed: bool, fields_checked: List[str],
                 mismatches: List[str]):
        self.passed         = passed
        self.fields_checked = fields_checked
        self.mismatches     = mismatches

    def format(self) -> str:
        if self.passed:
            lines = ["[Verified on FortiGate:]"]
            for f in self.fields_checked:
                lines.append(f"  {f}")
            return "\n".join(lines)
        else:
            lines = ["[WARNING: Verification failed — state may not match:]"]
            for m in self.mismatches:
                lines.append(f"  MISMATCH: {m}")
            for f in [f for f in self.fields_checked if not any(f.startswith(m.split(':')[0]) for m in self.mismatches)]:
                lines.append(f"  OK: {f}")
            return "\n".join(lines)


def verify_policy_update(policy_id: int, exec_result: ExecutionResult,
                          get_policy_fn) -> VerificationResult:
    """
    Compare actual FortiGate state to the expected state after execution.
    Performs field-level set comparison for list fields.
    Returns a clean VerificationResult for display.
    """
    if not exec_result.success:
        return VerificationResult(
            passed=False,
            fields_checked=[],
            mismatches=[f"Execution failed: {exec_result.message}"]
        )

    if not exec_result.applied_deltas or exec_result.expected_state is None:
        # No-op or no deltas to verify
        return VerificationResult(passed=True, fields_checked=[], mismatches=[])

    # Fetch actual state
    try:
        r   = get_policy_fn(policy_id)
        raw = r.get("results", {})
        actual = (
            raw[0] if isinstance(raw, list) and raw else
            raw if isinstance(raw, dict) and raw else
            None
        )
    except Exception as exc:
        return VerificationResult(
            passed=False, fields_checked=[],
            mismatches=[f"Could not fetch post-execution state: {exc}"]
        )

    if actual is None:
        return VerificationResult(
            passed=False, fields_checked=[],
            mismatches=[f"Policy ID {policy_id} not found after execution"]
        )

    fields_checked = []
    mismatches     = []

    for delta in exec_result.applied_deltas:
        field    = delta.field_name
        expected = exec_result.expected_state.get(field)
        got      = actual.get(field)

        if field in LIST_FIELDS:
            item_key      = LIST_FIELDS[field]["item_key"]
            expected_set  = {
                i.get(item_key, "").upper() for i in (expected or [])
            }
            actual_set    = {
                i.get(item_key, "").upper() for i in (got or [])
            }

            if expected_set == actual_set:
                fields_checked.append(
                    f"{field} = [{', '.join(sorted(actual_set))}]"
                )
            else:
                missing = expected_set - actual_set
                extra   = actual_set - expected_set
                desc = []
                if missing: desc.append(f"expected but missing: {sorted(missing)}")
                if extra:   desc.append(f"present but unexpected: {sorted(extra)}")
                mismatches.append(f"{field}: {'; '.join(desc)}")

        else:
            # Scalar field
            exp_str = str(expected).lower() if expected is not None else ""
            act_str = str(got).lower() if got is not None else ""

            if exp_str == act_str:
                fields_checked.append(f"{field} = {act_str}")
            else:
                mismatches.append(
                    f"{field}: expected '{exp_str}', got '{act_str}'"
                )

    passed = len(mismatches) == 0
    return VerificationResult(
        passed=passed,
        fields_checked=fields_checked,
        mismatches=mismatches,
    )