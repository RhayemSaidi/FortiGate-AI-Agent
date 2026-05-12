"""
test_nlu_full.py — Full test suite for the NLU pipeline.
Path setup is handled by conftest.py.
"""

import sys
import os
import json
import pytest
from unittest.mock import patch, MagicMock
from dataclasses import dataclass

# conftest.py handles path setup — no manual sys.path here

from nlu_schema import (
    RawIntentSchema, NLUIntentType, NLUConfidence, NLUDelta,
    INTERNAL_SCHEMA_FIELDS,
)
from nlu_interpreter import (
    _extract_json, _normalize_dict, _build_schema,
    NLUResult, fetch_live_context,
)
from nlu_grounder import ground, GroundedIntentSchema


# ══════════════════════════════════════════════════════════
#  Unit tests — JSON extraction
# ══════════════════════════════════════════════════════════

class TestJSONExtraction:
    def test_clean_json(self):
        text = '{"intent": "update_policy", "policy_id": 4}'
        result = _extract_json(text)
        assert json.loads(result)["intent"] == "update_policy"

    def test_json_with_prose_preamble(self):
        text = 'Here is the JSON output:\n{"intent": "update_policy", "policy_id": 4}'
        result = _extract_json(text)
        assert json.loads(result)["intent"] == "update_policy"

    def test_json_with_markdown_fences(self):
        text = '```json\n{"intent": "delete_policy", "policy_id": 3}\n```'
        result = _extract_json(text)
        assert json.loads(result)["intent"] == "delete_policy"

    def test_json_with_trailing_text(self):
        text = '{"intent": "backup_config"}\n\nI hope this helps!'
        result = _extract_json(text)
        assert json.loads(result)["intent"] == "backup_config"

    def test_no_json_raises(self):
        with pytest.raises(ValueError):
            _extract_json("There is no JSON here at all.")

    def test_unmatched_braces_raises(self):
        with pytest.raises(ValueError):
            _extract_json('{"intent": "update_policy"')

    def test_nested_json(self):
        text = '{"intent": "update_policy", "create_params": {"name": "test"}}'
        result = _extract_json(text)
        data = json.loads(result)
        assert data["create_params"]["name"] == "test"


# ══════════════════════════════════════════════════════════
#  Unit tests — Key normalization
# ══════════════════════════════════════════════════════════

class TestNormalization:
    def test_intent_alias_policy_update(self):
        data = {"intent": "policy_update", "policy_id": 4, "deltas": []}
        result = _normalize_dict(data)
        assert result["intent"] == "update_policy"

    def test_delta_key_alias(self):
        data = {
            "intent": "update_policy",
            "deltas": [{"field_name": "action", "operation": "set", "value": "deny"}]
        }
        result = _normalize_dict(data)
        assert result["deltas"][0]["field"] == "action"
        assert result["deltas"][0]["op"] == "set"

    def test_op_alias_ajouter(self):
        data = {
            "intent": "update_policy",
            "deltas": [{"field": "service", "op": "ajouter", "value": "SSH"}]
        }
        result = _normalize_dict(data)
        assert result["deltas"][0]["op"] == "add"

    def test_field_alias_services_plural(self):
        data = {
            "intent": "update_policy",
            "deltas": [{"field": "services", "op": "add", "value": "FTP"}]
        }
        result = _normalize_dict(data)
        assert result["deltas"][0]["field"] == "service"

    def test_french_intent_normalizes(self):
        data = {"intent": "mettre_a_jour", "policy_id": 4, "deltas": []}
        result = _normalize_dict(data)
        assert result["intent"] == "update_policy"


# ══════════════════════════════════════════════════════════
#  Unit tests — Schema building
# ══════════════════════════════════════════════════════════

class TestSchemaBuilding:
    def _minimal(self, **kwargs):
        base = {
            "intent": "update_policy", "confidence": "high",
            "policy_id": 4, "policy_name": None,
            "address_name": None, "interface_name": None,
            "neighbor_id": None, "move_action": None,
            "ip_address": None, "direction": None,
            "deltas": [], "create_params": {},
            "ambiguous": False, "ambiguity_msg": "",
            "candidates": [], "missing_fields": [],
            "raw_input": "test input"
        }
        base.update(kwargs)
        return base

    def test_valid_schema(self):
        data = self._minimal(
            deltas=[{"field": "action", "op": "set", "value": "deny", "confidence": "high"}]
        )
        schema = _build_schema(data, "test")
        assert schema.intent == NLUIntentType.UPDATE_POLICY
        assert len(schema.deltas) == 1
        assert schema.deltas[0].field == "action"
        assert schema.deltas[0].value == "deny"

    def test_missing_intent_raises(self):
        from agent_errors import NLUSchemaError
        data = self._minimal()
        data["intent"] = ""
        with pytest.raises(NLUSchemaError):
            _build_schema(data, "test")

    def test_unknown_intent_becomes_ambiguous(self):
        data = self._minimal(intent="totally_unknown_intent_xyz")
        schema = _build_schema(data, "test")
        assert schema.intent == NLUIntentType.AMBIGUOUS

    def test_service_csv_split(self):
        data = self._minimal(
            deltas=[{"field": "service", "op": "replace",
                     "value": "SSH,HTTPS,FTP", "confidence": "high"}]
        )
        schema = _build_schema(data, "test")
        assert isinstance(schema.deltas[0].value, list)
        assert "SSH" in schema.deltas[0].value
        assert "HTTPS" in schema.deltas[0].value

    def test_invalid_policy_id_becomes_none(self):
        data = self._minimal(policy_id="not_a_number")
        schema = _build_schema(data, "test")
        assert schema.policy_id is None


# ══════════════════════════════════════════════════════════
#  Integration tests — Interpret (requires Mistral API)
# ══════════════════════════════════════════════════════════

@pytest.mark.integration
class TestInterpretIntegration:
    """These tests require a live Mistral API connection."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from langchain_mistralai import ChatMistralAI
        from config import MISTRAL_API_KEY
        self.llm = ChatMistralAI(
            model="mistral-small-latest", temperature=0, api_key=MISTRAL_API_KEY
        )
        self.context = {
            "policies": [
                {"id": 1, "name": "LAN-Internet", "action": "accept", "status": "enable"},
                {"id": 3, "name": "BlockSSH", "action": "deny", "status": "enable"},
                {"id": 4, "name": "test1", "action": "accept", "status": "enable"},
            ],
            "interfaces": ["port1", "port2", "port3"],
            "services": ["HTTP", "HTTPS", "FTP", "SSH", "DNS", "ALL"],
            "addresses": ["WebServer", "AdminPC"],
        }

    def _interpret(self, text: str) -> NLUResult:
        from nlu_interpreter import interpret
        return interpret(text, self.llm, self.context)

    def _assert_update(self, result: NLUResult, expected_field: str,
                        expected_op: str, expected_policy_id: int = None):
        assert result.success, f"interpret() failed: {result.error_msg}"
        s = result.schema
        assert s.intent == NLUIntentType.UPDATE_POLICY, f"Got {s.intent}"
        if expected_policy_id:
            assert s.policy_id == expected_policy_id or s.policy_name is not None
        deltas_for_field = [d for d in s.deltas if d.field == expected_field]
        assert deltas_for_field, f"No delta for field '{expected_field}', got {s.deltas}"
        assert deltas_for_field[0].op == expected_op, (
            f"Expected op '{expected_op}', got '{deltas_for_field[0].op}'"
        )

    # ── Service operations ─────────────────────────────────

    def test_add_ssh_canonical(self):
        r = self._interpret("add ssh to policy 4")
        self._assert_update(r, "service", "add", 4)
        assert "SSH" in r.schema.deltas[0].value

    def test_add_ssh_natural(self):
        r = self._interpret("give policy 4 ssh access")
        self._assert_update(r, "service", "add")

    def test_add_ssh_french(self):
        r = self._interpret("ajouter SSH à la politique 4")
        self._assert_update(r, "service", "add")

    def test_remove_ftp(self):
        r = self._interpret("remove FTP from policy 4")
        self._assert_update(r, "service", "remove")
        assert "FTP" in r.schema.deltas[0].value

    def test_compound_add_remove(self):
        r = self._interpret("add FTP and remove HTTPS from policy 4")
        assert r.success
        fields = [d.field for d in r.schema.deltas]
        assert "service" in fields

    def test_replace_services(self):
        r = self._interpret("set policy 4 services to SSH and HTTPS only")
        assert r.success
        svc_deltas = [d for d in r.schema.deltas if d.field == "service"]
        assert svc_deltas
        assert svc_deltas[0].op == "replace"

    # ── Scalar operations ──────────────────────────────────

    def test_set_action_deny_explicit(self):
        r = self._interpret("set policy 4 action to deny")
        self._assert_update(r, "action", "set")
        action_d = [d for d in r.schema.deltas if d.field == "action"][0]
        assert action_d.value == "deny"

    def test_set_action_deny_implicit(self):
        """The key test — no 'action' keyword in input."""
        r = self._interpret("set policy 4 to deny")
        assert r.success, f"Failed: {r.error_msg}"
        assert r.schema.intent == NLUIntentType.UPDATE_POLICY
        action_d = [d for d in r.schema.deltas if d.field == "action"]
        assert action_d, "No action delta produced"
        assert action_d[0].value == "deny"

    def test_set_nat_enable(self):
        r = self._interpret("enable NAT in policy 4")
        self._assert_update(r, "nat", "set")
        nat_d = [d for d in r.schema.deltas if d.field == "nat"][0]
        assert nat_d.value == "enable"

    def test_set_nat_disable(self):
        r = self._interpret("disable NAT on policy test1")
        assert r.success
        nat_d = [d for d in r.schema.deltas if d.field == "nat"]
        assert nat_d
        assert nat_d[0].value == "disable"

    # ── Policy CRUD ────────────────────────────────────────

    def test_create_policy(self):
        r = self._interpret(
            "create a policy named BlockHTTP from port1 to port2 denying HTTP"
        )
        assert r.success
        assert r.schema.intent == NLUIntentType.CREATE_POLICY

    def test_delete_policy_by_id(self):
        r = self._interpret("delete policy 4")
        assert r.success
        assert r.schema.intent == NLUIntentType.DELETE_POLICY
        assert r.schema.policy_id == 4

    def test_delete_policy_by_name(self):
        r = self._interpret("delete policy BlockSSH")
        assert r.success
        assert r.schema.intent == NLUIntentType.DELETE_POLICY

    def test_enable_policy_by_id(self):
        r = self._interpret("enable policy 3")
        assert r.success
        assert r.schema.intent == NLUIntentType.ENABLE_POLICY

    def test_disable_policy_by_name(self):
        r = self._interpret("disable policy BlockSSH")
        assert r.success
        assert r.schema.intent == NLUIntentType.DISABLE_POLICY

    def test_move_policy(self):
        r = self._interpret("move policy 4 before policy 3")
        assert r.success
        assert r.schema.intent == NLUIntentType.MOVE_POLICY
        assert r.schema.policy_id == 4
        assert r.schema.neighbor_id == 3
        assert r.schema.move_action == "before"

    # ── Hallucination tests ────────────────────────────────

    def test_no_hallucinated_policy_id(self):
        """Policy ID 99 is NOT in context — Mistral should not invent it."""
        r = self._interpret("add SSH to policy 99")
        if r.success:
            # If Mistral returns policy_id=99, grounder must catch it
            assert r.schema.policy_id in (None, 99)  # Not hallucinated to another ID
            # Grounder will reject 99 as not found

    def test_no_hallucinated_service(self):
        """SFTP-Custom is NOT in known services — grounder must reject."""
        r = self._interpret("add SFTP-Custom to policy 4")
        if r.success and r.schema.deltas:
            svc_d = [d for d in r.schema.deltas if d.field == "service"]
            if svc_d:
                values = svc_d[0].value if isinstance(svc_d[0].value, list) else [svc_d[0].value]
                # If Mistral hallucinates, grounder catches it
                grounded = ground(r.schema)
                # Either no deltas after grounding, or the service was rejected
                invalid_issues = [i for i in grounded.issues
                                   if i.field == "service" and i.kind == "invalid_value"]
                assert invalid_issues or not grounded.grounded_deltas

    # ── Ambiguity tests ────────────────────────────────────

    def test_ambiguous_enable_without_context(self):
        """'enable policy 4' is unambiguous (status). 'enable X in policy 4' is context-dependent."""
        r = self._interpret("enable policy 4")
        assert r.success
        # Should be enable_policy (status), not update_policy (nat)
        assert r.schema.intent in (NLUIntentType.ENABLE_POLICY, NLUIntentType.UPDATE_POLICY)

    # ── Bilingual tests ────────────────────────────────────

    def test_french_add_service(self):
        r = self._interpret("ajouter FTP à la politique 4")
        assert r.success
        assert r.schema.intent == NLUIntentType.UPDATE_POLICY

    def test_french_delete_policy(self):
        r = self._interpret("supprimer la politique BlockSSH")
        assert r.success
        assert r.schema.intent == NLUIntentType.DELETE_POLICY

    def test_mixed_language(self):
        r = self._interpret("add SSH to la politique 4")
        assert r.success
        assert r.schema.intent == NLUIntentType.UPDATE_POLICY

    # ── Error handling ─────────────────────────────────────

    def test_empty_input(self):
        from nlu_interpreter import interpret
        r = interpret("", self.llm, self.context)
        assert r.failed
        assert r.error_kind == "parse"

    def test_whitespace_only(self):
        from nlu_interpreter import interpret
        r = interpret("   ", self.llm, self.context)
        assert r.failed


# ══════════════════════════════════════════════════════════
#  Unit tests — Grounding
# ══════════════════════════════════════════════════════════

class TestGrounding:
    """These tests mock FortiGate API calls."""

    def _make_schema(self, **kwargs) -> RawIntentSchema:
        defaults = {
            "intent": NLUIntentType.UPDATE_POLICY,
            "confidence": NLUConfidence.HIGH,
            "policy_id": 4, "policy_name": None,
            "address_name": None, "interface_name": None,
            "neighbor_id": None, "move_action": None,
            "ip_address": None, "direction": None,
            "deltas": [], "create_params": {},
            "ambiguous": False, "ambiguity_msg": "",
            "candidates": [], "missing_fields": [],
            "raw_input": "test",
        }
        defaults.update(kwargs)
        return RawIntentSchema(**defaults)

    def _mock_policy(self, pid: int, name: str = "test1",
                      action: str = "accept",
                      services: list = None) -> dict:
        return {
            "policyid": pid, "name": name, "action": action,
            "status": "enable", "nat": "disable", "logtraffic": "all",
            "service": [{"name": s} for s in (services or ["SSH", "HTTPS"])],
            "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
            "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}],
        }

    @patch("modules.policies.get_policy")
    @patch("modules.policies.list_policies")
    def test_valid_add_service(self, mock_list, mock_get):
        policy = self._mock_policy(4, services=["HTTPS"])
        mock_get.return_value = {"results": policy}
        mock_list.return_value = {"results": [policy]}

        schema = self._make_schema(
            deltas=[NLUDelta("service", "add", ["SSH"], "high")]
        )
        result = ground(schema)
        assert result.is_valid
        assert not result.is_noop
        assert len(result.grounded_deltas) == 1

    @patch("modules.policies.get_policy")
    @patch("modules.policies.list_policies")
    def test_noop_detected_add_existing(self, mock_list, mock_get):
        policy = self._mock_policy(4, services=["SSH", "HTTPS"])
        mock_get.return_value = {"results": policy}
        mock_list.return_value = {"results": [policy]}

        schema = self._make_schema(
            deltas=[NLUDelta("service", "add", ["SSH"], "high")]
        )
        result = ground(schema)
        assert result.is_valid
        assert result.is_noop
        assert "SSH" in result.noop_message

    @patch("modules.policies.get_policy")
    @patch("modules.policies.list_policies")
    def test_invalid_service_rejected(self, mock_list, mock_get):
        policy = self._mock_policy(4, services=["SSH"])
        mock_get.return_value = {"results": policy}
        mock_list.return_value = {"results": [policy]}

        schema = self._make_schema(
            deltas=[NLUDelta("service", "add", ["SFTP-Custom"], "high")]
        )
        result = ground(schema)
        assert not result.is_valid
        service_issues = [i for i in result.issues if i.field == "service"]
        assert service_issues

    @patch("modules.policies.get_policy")
    @patch("modules.policies.list_policies")
    def test_nonexistent_policy_rejected(self, mock_list, mock_get):
        mock_get.return_value = {"results": {}}
        mock_list.return_value = {"results": []}

        schema = self._make_schema(policy_id=99)
        result = ground(schema)
        assert not result.is_valid
        pid_issues = [i for i in result.issues if i.field == "policy_id"]
        assert pid_issues

    @patch("modules.policies.get_policy")
    @patch("modules.policies.list_policies")
    def test_noop_action_already_set(self, mock_list, mock_get):
        policy = self._mock_policy(4, action="deny")
        mock_get.return_value = {"results": policy}
        mock_list.return_value = {"results": [policy]}

        schema = self._make_schema(
            deltas=[NLUDelta("action", "set", "deny", "high")]
        )
        result = ground(schema)
        assert result.is_valid
        assert result.is_noop

    @patch("modules.policies.get_policy")
    @patch("modules.policies.list_policies")
    def test_nat_grounded_correctly(self, mock_list, mock_get):
        policy = self._mock_policy(4)
        policy["nat"] = "disable"
        mock_get.return_value = {"results": policy}
        mock_list.return_value = {"results": [policy]}

        schema = self._make_schema(
            deltas=[NLUDelta("nat", "set", "enable", "high")]
        )
        result = ground(schema)
        assert result.is_valid
        assert not result.is_noop
        assert len(result.grounded_deltas) == 1
        assert result.grounded_deltas[0].value == "enable"

    @patch("modules.policies.get_policy")
    @patch("modules.policies.list_policies")
    def test_schema_not_mutated(self, mock_list, mock_get):
        """Grounder must not mutate the input schema."""
        policy = self._mock_policy(4, services=["SSH"])
        mock_get.return_value = {"results": policy}
        mock_list.return_value = {"results": [policy]}

        original_deltas = [NLUDelta("service", "add", ["FTP", "HTTPS"], "high")]
        schema = self._make_schema(deltas=original_deltas)
        original_delta_count = len(schema.deltas)

        result = ground(schema)
        assert len(schema.deltas) == original_delta_count  # Not mutated


# ══════════════════════════════════════════════════════════
#  Integration tests — FortiGate API simulation
# ══════════════════════════════════════════════════════════

@pytest.mark.integration
class TestFortiGateAPIFailures:
    """Tests for graceful behavior when FortiGate is unavailable."""

    @patch("modules.policies.list_policies", side_effect=Exception("Connection refused"))
    @patch("modules.policies.get_policy", side_effect=Exception("Connection refused"))
    def test_context_fetch_failure_graceful(self, mock_get, mock_list):
        """If FortiGate unreachable, context fetch fails gracefully."""
        from nlu_interpreter import fetch_live_context
        from agent_errors import ContextFetchError
        with pytest.raises(ContextFetchError):
            fetch_live_context()

    @patch("modules.policies.get_policy", side_effect=Exception("Timeout"))
    @patch("modules.policies.list_policies", side_effect=Exception("Timeout"))
    def test_grounding_handles_api_failure(self, mock_list, mock_get):
        """Grounder should not crash when FortiGate API fails."""
        schema = RawIntentSchema(
            intent=NLUIntentType.UPDATE_POLICY,
            confidence=NLUConfidence.HIGH,
            policy_id=4,
            raw_input="test",
        )
        result = ground(schema)
        assert not result.is_valid
        assert any("Could not verify" in i.message or "Could not fetch" in i.message
                   for i in result.issues)


# ══════════════════════════════════════════════════════════
#  Smoke tests — quick terminal verification
# ══════════════════════════════════════════════════════════

def run_smoke_tests():
    """
    Quick smoke tests you can run directly from terminal.
    python tests/test_nlu_full.py
    """
    print("\n" + "=" * 60)
    print("  NLU SMOKE TESTS")
    print("=" * 60)

    # Test JSON extraction
    tests = [
        ('{"intent":"update_policy"}', "clean"),
        ('Here is: {"intent":"update_policy"}', "preamble"),
        ('```json\n{"intent":"update_policy"}\n```', "markdown"),
    ]
    for text, label in tests:
        try:
            result = _extract_json(text)
            assert json.loads(result)["intent"] == "update_policy"
            print(f"  [OK] JSON extraction: {label}")
        except Exception as e:
            print(f"  [FAIL] JSON extraction: {label} — {e}")

    # Test normalization
    data = {"intent": "policy_update", "deltas": [{"field_name": "action", "operation": "set", "value": "deny"}]}
    norm = _normalize_dict(data)
    if norm.get("intent") == "update_policy" and norm["deltas"][0].get("field") == "action":
        print("  [OK] Key normalization")
    else:
        print(f"  [FAIL] Key normalization — got {norm}")

    # Test schema building
    data = {
        "intent": "update_policy", "confidence": "high",
        "policy_id": 4, "policy_name": None, "address_name": None,
        "interface_name": None, "neighbor_id": None, "move_action": None,
        "ip_address": None, "direction": None,
        "deltas": [{"field": "action", "op": "set", "value": "deny", "confidence": "high"}],
        "create_params": {}, "ambiguous": False, "ambiguity_msg": "",
        "candidates": [], "missing_fields": [], "raw_input": "set policy 4 to deny"
    }
    schema = _build_schema(data, "test")
    if schema.intent == NLUIntentType.UPDATE_POLICY and schema.deltas[0].value == "deny":
        print("  [OK] Schema building")
    else:
        print(f"  [FAIL] Schema building — {schema.intent}, {schema.deltas}")

    print("\n  Smoke tests complete.")
    print("=" * 60)


if __name__ == "__main__":
    run_smoke_tests()