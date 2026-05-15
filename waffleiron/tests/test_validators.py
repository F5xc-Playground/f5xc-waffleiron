"""Tests for the output validator (validators.py)."""

import pytest

from waffleiron.validators import ValidationError, ValidationResult, validate


# ---------------------------------------------------------------------------
# Helpers to build minimal valid dicts
# ---------------------------------------------------------------------------

def minimal_app_firewall(name="my-fw", namespace="default") -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"blocking": {}},
    }


def minimal_exclusion_policy(name="my-excl", namespace="default") -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"waf_exclusion_rules": []},
    }


# ---------------------------------------------------------------------------
# TestValidOutput
# ---------------------------------------------------------------------------

class TestValidOutput:
    def test_valid_app_firewall(self):
        obj = minimal_app_firewall()
        result = validate(obj, "app_firewall")
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.errors == []

    def test_valid_exclusion_policy(self):
        obj = minimal_exclusion_policy()
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is True
        assert result.errors == []

    def test_valid_app_firewall_with_bot_protection(self):
        obj = minimal_app_firewall()
        obj["spec"]["bot_protection_setting"] = {
            "malicious_bot_action": "BLOCK",
            "suspicious_bot_action": "REPORT",
            "good_bot_action": "IGNORE",
        }
        result = validate(obj, "app_firewall")
        assert result.is_valid is True

    def test_valid_app_firewall_with_blocking_page(self):
        obj = minimal_app_firewall()
        obj["spec"]["blocking_page"] = {"blocking_page": "x" * 100}
        result = validate(obj, "app_firewall")
        assert result.is_valid is True

    def test_valid_app_firewall_with_anonymization(self):
        obj = minimal_app_firewall()
        obj["spec"]["custom_anonymization"] = {
            "anonymization_config": [{"http_header": {"header_name": f"h{i}"}} for i in range(5)]
        }
        result = validate(obj, "app_firewall")
        assert result.is_valid is True

    def test_valid_app_firewall_with_response_codes(self):
        obj = minimal_app_firewall()
        obj["spec"]["allowed_response_codes"] = {"response_codes": list(range(200, 210))}
        result = validate(obj, "app_firewall")
        assert result.is_valid is True

    def test_valid_exclusion_policy_with_rules(self):
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "metadata": {"name": f"rule-{i}"},
                "any_domain": {},
                "any_path": {},
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 200000001, "context": "CONTEXT_ANY"}
                    ]
                },
            }
            for i in range(5)
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is True

    def test_valid_signature_id_zero(self):
        """Signature ID 0 means 'all signatures' and is valid."""
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 0, "context": "CONTEXT_ANY"}
                    ]
                }
            }
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is True

    def test_valid_attack_types_in_app_firewall(self):
        obj = minimal_app_firewall()
        obj["spec"]["detection_settings"] = {
            "attack_type_settings": {
                "disabled_attack_types": [
                    "ATTACK_TYPE_SQL_INJECTION",
                    "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
                ]
            }
        }
        result = validate(obj, "app_firewall")
        assert result.is_valid is True


# ---------------------------------------------------------------------------
# TestMissingRequired
# ---------------------------------------------------------------------------

class TestMissingRequired:
    def test_app_firewall_missing_metadata(self):
        obj = {"spec": {"blocking": {}}}
        result = validate(obj, "app_firewall")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "metadata" in paths

    def test_app_firewall_missing_namespace(self):
        obj = {"metadata": {"name": "fw"}, "spec": {"blocking": {}}}
        result = validate(obj, "app_firewall")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "metadata.namespace" in paths

    def test_app_firewall_missing_name(self):
        obj = {"metadata": {"namespace": "ns"}, "spec": {"blocking": {}}}
        result = validate(obj, "app_firewall")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "metadata.name" in paths

    def test_app_firewall_missing_spec(self):
        obj = {"metadata": {"name": "fw", "namespace": "ns"}}
        result = validate(obj, "app_firewall")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "spec" in paths

    def test_exclusion_policy_missing_metadata(self):
        obj = {"spec": {"waf_exclusion_rules": []}}
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "metadata" in paths

    def test_exclusion_policy_missing_namespace(self):
        obj = {"metadata": {"name": "ep"}, "spec": {"waf_exclusion_rules": []}}
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "metadata.namespace" in paths

    def test_exclusion_policy_missing_spec(self):
        obj = {"metadata": {"name": "ep", "namespace": "ns"}}
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "spec" in paths


# ---------------------------------------------------------------------------
# TestInvalidOutput
# ---------------------------------------------------------------------------

class TestInvalidOutput:
    def test_name_too_long(self):
        obj = minimal_app_firewall(name="a" * 65)
        result = validate(obj, "app_firewall")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "metadata.name" in paths

    def test_name_exactly_64_chars_is_valid(self):
        obj = minimal_app_firewall(name="a" * 64)
        result = validate(obj, "app_firewall")
        assert result.is_valid is True

    def test_blocking_page_too_large(self):
        obj = minimal_app_firewall()
        obj["spec"]["blocking_page"] = {"blocking_page": "x" * 5000}
        result = validate(obj, "app_firewall")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "spec.blocking_page.blocking_page" in paths

    def test_blocking_page_exactly_4096_is_valid(self):
        obj = minimal_app_firewall()
        obj["spec"]["blocking_page"] = {"blocking_page": "x" * 4096}
        result = validate(obj, "app_firewall")
        assert result.is_valid is True

    def test_too_many_anonymization_items(self):
        obj = minimal_app_firewall()
        obj["spec"]["custom_anonymization"] = {
            "anonymization_config": [{"http_header": {"header_name": f"h{i}"}} for i in range(70)]
        }
        result = validate(obj, "app_firewall")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "spec.custom_anonymization.anonymization_config" in paths

    def test_anonymization_exactly_64_is_valid(self):
        obj = minimal_app_firewall()
        obj["spec"]["custom_anonymization"] = {
            "anonymization_config": [{"http_header": {"header_name": f"h{i}"}} for i in range(64)]
        }
        result = validate(obj, "app_firewall")
        assert result.is_valid is True

    def test_too_many_response_codes(self):
        obj = minimal_app_firewall()
        obj["spec"]["allowed_response_codes"] = {"response_codes": list(range(200, 250))}
        result = validate(obj, "app_firewall")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "spec.allowed_response_codes.response_codes" in paths

    def test_response_codes_exactly_48_is_valid(self):
        obj = minimal_app_firewall()
        obj["spec"]["allowed_response_codes"] = {"response_codes": list(range(200, 248))}
        result = validate(obj, "app_firewall")
        assert result.is_valid is True

    def test_invalid_bot_action(self):
        """CHALLENGE is not a valid XC bot action."""
        obj = minimal_app_firewall()
        obj["spec"]["bot_protection_setting"] = {
            "malicious_bot_action": "CHALLENGE",
            "suspicious_bot_action": "REPORT",
            "good_bot_action": "IGNORE",
        }
        result = validate(obj, "app_firewall")
        assert result.is_valid is False
        # Should report the field path
        error_paths = [e.path for e in result.errors]
        assert any("bot_protection_setting" in p for p in error_paths)

    def test_invalid_attack_type(self):
        obj = minimal_app_firewall()
        obj["spec"]["detection_settings"] = {
            "attack_type_settings": {
                "disabled_attack_types": ["ATTACK_TYPE_SQL_INJECTION", "ATTACK_TYPE_NONEXISTENT"]
            }
        }
        result = validate(obj, "app_firewall")
        assert result.is_valid is False
        error_paths = [e.path for e in result.errors]
        assert any("disabled_attack_types" in p for p in error_paths)

    def test_too_many_exclusion_rules(self):
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {"metadata": {"name": f"rule-{i}"}} for i in range(300)
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is False
        paths = [e.path for e in result.errors]
        assert "spec.waf_exclusion_rules" in paths

    def test_exclusion_rules_exactly_256_is_valid(self):
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {"metadata": {"name": f"rule-{i}"}} for i in range(256)
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is True

    def test_too_many_signature_contexts(self):
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 200000001, "context": "CONTEXT_ANY"}
                        for _ in range(1025)
                    ]
                }
            }
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is False
        error_paths = [e.path for e in result.errors]
        assert any("exclude_signature_contexts" in p for p in error_paths)

    def test_signature_contexts_exactly_1024_is_valid(self):
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 200000001, "context": "CONTEXT_ANY"}
                        for _ in range(1024)
                    ]
                }
            }
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is True

    def test_invalid_signature_id(self):
        """Signature ID 999 is out of range and not 0."""
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 999, "context": "CONTEXT_ANY"}
                    ]
                }
            }
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is False
        error_msgs = [e.message for e in result.errors]
        assert any("999" in m for m in error_msgs)

    def test_invalid_signature_id_boundary_low(self):
        """200000000 is one below the valid range."""
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 200000000, "context": "CONTEXT_ANY"}
                    ]
                }
            }
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is False

    def test_valid_signature_id_boundary_low(self):
        """200000001 is the minimum valid ID (non-zero)."""
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 200000001, "context": "CONTEXT_ANY"}
                    ]
                }
            }
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is True

    def test_valid_signature_id_boundary_high(self):
        """299999999 is the maximum valid ID."""
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 299999999, "context": "CONTEXT_ANY"}
                    ]
                }
            }
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is True

    def test_invalid_signature_id_boundary_high(self):
        """300000000 is one above the valid range."""
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 300000000, "context": "CONTEXT_ANY"}
                    ]
                }
            }
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is False

    def test_invalid_context_value(self):
        """CONTEXT_QUERY_PARAM is not a valid context."""
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 200000001, "context": "CONTEXT_QUERY_PARAM"}
                    ]
                }
            }
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is False
        error_msgs = [e.message for e in result.errors]
        assert any("CONTEXT_QUERY_PARAM" in m for m in error_msgs)

    def test_all_valid_context_values(self):
        """Every valid context value should pass."""
        valid_contexts = [
            "CONTEXT_ANY", "CONTEXT_BODY", "CONTEXT_REQUEST", "CONTEXT_RESPONSE",
            "CONTEXT_PARAMETER", "CONTEXT_HEADER", "CONTEXT_COOKIE", "CONTEXT_URL", "CONTEXT_URI",
        ]
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = [
            {
                "app_firewall_detection_control": {
                    "exclude_signature_contexts": [
                        {"signature_id": 200000001, "context": ctx}
                        for ctx in valid_contexts
                    ]
                }
            }
        ]
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is True


# ---------------------------------------------------------------------------
# TestWarnings
# ---------------------------------------------------------------------------

class TestWarnings:
    def test_empty_exclusion_rules_list_warns(self):
        """An empty exclusion rules list is valid but worth a warning."""
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = []
        result = validate(obj, "waf_exclusion_policy")
        assert result.is_valid is True
        assert len(result.warnings) > 0
        warning_paths = [w.path for w in result.warnings]
        assert "spec.waf_exclusion_rules" in warning_paths

    def test_warning_severity_field(self):
        obj = minimal_exclusion_policy()
        obj["spec"]["waf_exclusion_rules"] = []
        result = validate(obj, "waf_exclusion_policy")
        for w in result.warnings:
            assert w.severity == "warning"

    def test_error_severity_field(self):
        obj = minimal_app_firewall(name="a" * 65)
        result = validate(obj, "app_firewall")
        for e in result.errors:
            assert e.severity == "error"


# ---------------------------------------------------------------------------
# TestValidationErrorDataclass
# ---------------------------------------------------------------------------

class TestValidationErrorDataclass:
    def test_validation_error_fields(self):
        err = ValidationError(path="spec.foo", message="bad value", severity="error")
        assert err.path == "spec.foo"
        assert err.message == "bad value"
        assert err.severity == "error"

    def test_validation_result_fields(self):
        result = ValidationResult(is_valid=True, errors=[], warnings=[])
        assert result.is_valid is True
        assert result.errors == []
        assert result.warnings == []


# ---------------------------------------------------------------------------
# TestUnknownObjectType
# ---------------------------------------------------------------------------

class TestUnknownObjectType:
    def test_unknown_type_raises(self):
        obj = {"metadata": {"name": "x", "namespace": "ns"}, "spec": {}}
        with pytest.raises((ValueError, KeyError, NotImplementedError)):
            validate(obj, "unknown_type")
