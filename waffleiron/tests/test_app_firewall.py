"""Tests for the AppFirewallTranslator."""

import pytest

from waffleiron.translators.app_firewall import AppFirewallTranslator
from waffleiron.model import EnforcementMode, AccuracyLevel

from conftest import make_policy_with_disabled_sig_set, make_policy_with_disabled_violation, make_minimal_policy


class TestMetadata:
    def test_name_and_namespace(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="my-ns")
        assert result["metadata"]["name"] == "test-policy"
        assert result["metadata"]["namespace"] == "my-ns"

    def test_name_sanitized_to_lowercase(self, minimal_policy):
        minimal_policy.name = "My_Policy NAME"
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        name = result["metadata"]["name"]
        assert name == name.lower()
        assert " " not in name
        assert "_" not in name

    def test_name_max_64_chars(self, minimal_policy):
        minimal_policy.name = "a" * 100
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        assert len(result["metadata"]["name"]) <= 64

    def test_name_no_trailing_hyphen_after_truncation(self, minimal_policy):
        minimal_policy.name = "a" * 63 + "-b"
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        name = result["metadata"]["name"]
        assert not name.endswith("-")

    def test_name_empty_raises(self, minimal_policy):
        minimal_policy.name = "___"
        with pytest.raises(ValueError, match="empty XC resource name"):
            AppFirewallTranslator.translate(minimal_policy, namespace="ns")


class TestEnforcementMode:
    def test_blocking_mode(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="test-ns")
        assert result["spec"]["blocking"] == {}

    def test_transparent_mode(self, minimal_policy):
        minimal_policy.enforcement_mode = EnforcementMode.TRANSPARENT
        result = AppFirewallTranslator.translate(minimal_policy, namespace="test-ns")
        assert result["spec"]["monitoring"] == {}

    def test_blocking_excludes_monitoring(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        assert "monitoring" not in result["spec"]

    def test_transparent_excludes_blocking(self, minimal_policy):
        minimal_policy.enforcement_mode = EnforcementMode.TRANSPARENT
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        assert "blocking" not in result["spec"]


class TestSignatureSettings:
    def test_high_accuracy(self, minimal_policy):
        minimal_policy.signatures.accuracy_level = AccuracyLevel.HIGH
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        assert "only_high_accuracy_signatures" in detection["signature_selection_setting"]

    def test_high_medium_accuracy(self, minimal_policy):
        minimal_policy.signatures.accuracy_level = AccuracyLevel.HIGH_MEDIUM
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        sig_sel = detection["signature_selection_setting"]
        assert "high_medium_accuracy_signatures" in sig_sel

    def test_all_accuracy(self, minimal_policy):
        minimal_policy.signatures.accuracy_level = AccuracyLevel.ALL
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        assert "high_medium_low_accuracy_signatures" in detection["signature_selection_setting"]

    def test_staging_enabled(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        assert "stage_new_and_updated_signatures" in detection

    def test_staging_period_value(self, minimal_policy):
        minimal_policy.signatures.staging_period = 14
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        assert detection["stage_new_and_updated_signatures"]["staging_period"] == 14

    def test_staging_disabled(self, minimal_policy):
        minimal_policy.signatures.staging_enabled = False
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        assert "disable_staging" in detection

    def test_default_attack_type_settings_when_no_disabled_sets(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        sig_sel = result["spec"]["detection_settings"]["signature_selection_setting"]
        assert "default_attack_type_settings" in sig_sel

    def test_disabled_attack_types(self):
        policy = make_policy_with_disabled_sig_set("SQL Injection Signatures")
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        sig_sel = result["spec"]["detection_settings"]["signature_selection_setting"]
        disabled = sig_sel["attack_type_settings"]["disabled_attack_types"]
        assert "ATTACK_TYPE_SQL_INJECTION" in disabled

    def test_disabled_attack_types_xss(self):
        policy = make_policy_with_disabled_sig_set("Cross-Site Scripting Signatures")
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        sig_sel = result["spec"]["detection_settings"]["signature_selection_setting"]
        disabled = sig_sel["attack_type_settings"]["disabled_attack_types"]
        assert "ATTACK_TYPE_CROSS_SITE_SCRIPTING" in disabled

    def test_unknown_disabled_sig_set_is_skipped(self):
        policy = make_policy_with_disabled_sig_set("Some Unknown Set")
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        sig_sel = result["spec"]["detection_settings"]["signature_selection_setting"]
        # Should fall back to default since unknown set doesn't map to an XC type
        assert "default_attack_type_settings" in sig_sel

    def test_enabled_sig_set_not_disabled(self):
        from waffleiron.model import SignatureSet
        policy = make_minimal_policy(
            signature_sets=[SignatureSet(name="SQL Injection Signatures", enabled=True)],
        )
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        sig_sel = result["spec"]["detection_settings"]["signature_selection_setting"]
        assert "default_attack_type_settings" in sig_sel


class TestViolationSettings:
    def test_default_violation_settings_when_no_disabled_violations(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        assert "default_violation_settings" in detection

    def test_disabled_violations(self):
        policy = make_policy_with_disabled_violation("VIOL_ENCODING")
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        disabled = detection["disabled_violation_types"]
        assert "VIOL_ENCODING" in disabled

    def test_alarm_only_violation_not_disabled(self, mature_policy):
        # mature_policy has VIOL_COOKIE_MODIFIED as alarm=True, block=False — NOT disabled
        result = AppFirewallTranslator.translate(mature_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        # Should be default since no violations are fully disabled (alarm=False, block=False)
        assert "default_violation_settings" in detection

    def test_evasion_split(self):
        policy = make_policy_with_disabled_violation("VIOL_EVASION")
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        disabled = detection["disabled_violation_types"]
        evasion_subtypes = [v for v in disabled if v.startswith("VIOL_EVASION_")]
        assert len(evasion_subtypes) == 8

    def test_http_protocol_split(self):
        policy = make_policy_with_disabled_violation("VIOL_HTTP_PROTOCOL")
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        disabled = detection["disabled_violation_types"]
        http_subtypes = [v for v in disabled if v.startswith("VIOL_HTTP_PROTOCOL_")]
        assert len(http_subtypes) == 10

    def test_violation_xml_format_remapped(self):
        policy = make_policy_with_disabled_violation("VIOL_XML_FORMAT")
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        disabled = detection["disabled_violation_types"]
        assert "VIOL_XML_MALFORMED" in disabled


class TestThreatCampaigns:
    def test_enabled(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        assert "enable_threat_campaigns" in detection

    def test_disabled(self, minimal_policy):
        minimal_policy.signatures.threat_campaigns_enabled = False
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        assert "disable_threat_campaigns" in detection


class TestFalsePositiveSuppression:
    def test_always_enabled(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        assert "enable_suppression" in detection


class TestBotProtection:
    def test_default_bot_setting_when_no_bot_defense(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        assert "default_bot_setting" in result["spec"]

    def test_bot_actions(self, mature_policy):
        result = AppFirewallTranslator.translate(mature_policy, namespace="ns")
        bot = result["spec"]["bot_protection_setting"]
        assert bot["malicious_bot_action"] == "BLOCK"
        assert bot["good_bot_action"] == "REPORT"

    def test_untranslatable_bot_action_defaults_to_block(self, mature_policy):
        # unknown-bot has action "challenge" which is untranslatable → defaults to BLOCK
        result = AppFirewallTranslator.translate(mature_policy, namespace="ns")
        bot = result["spec"]["bot_protection_setting"]
        assert bot["suspicious_bot_action"] == "BLOCK"

    def test_bot_ignore_action(self, mature_policy):
        mature_policy.bot_defense.categories[1].action = "ignore"
        result = AppFirewallTranslator.translate(mature_policy, namespace="ns")
        bot = result["spec"]["bot_protection_setting"]
        assert bot["good_bot_action"] == "IGNORE"


class TestBlockingPage:
    def test_default_blocking_page_when_not_enabled(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        assert "use_default_blocking_page" in result["spec"]

    def test_custom_page_variable_translated(self, mature_policy):
        result = AppFirewallTranslator.translate(mature_policy, namespace="ns")
        page = result["spec"]["blocking_page"]
        assert "{{request_id}}" in page["blocking_page_body"]
        assert "<%TS.request.ID()%>" not in page["blocking_page_body"]

    def test_custom_page_response_code(self, mature_policy):
        result = AppFirewallTranslator.translate(mature_policy, namespace="ns")
        page = result["spec"]["blocking_page"]
        assert page["response_code"] == "Forbidden"


class TestAnonymization:
    def test_default_anonymization_when_no_sensitive_params(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        assert "default_anonymization" in result["spec"]

    def test_sensitive_parameters(self, mature_policy):
        result = AppFirewallTranslator.translate(mature_policy, namespace="ns")
        anon = result["spec"]["custom_anonymization"]["anonymization_config"]
        names = [
            a.get("query_parameter", {}).get("query_param_name")
            for a in anon
            if "query_parameter" in a
        ]
        assert "session_id" in names

    def test_sensitive_cookies(self):
        from waffleiron.model import CookieEntity, EntityCollection
        policy = make_minimal_policy(
            entities=EntityCollection(
                cookies=[CookieEntity(name="auth_token", attack_signatures_check=True)],
            ),
        )
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        assert "default_anonymization" in result["spec"]

    def test_sensitive_headers(self):
        from waffleiron.model import HeaderEntity, EntityCollection
        policy = make_minimal_policy(
            entities=EntityCollection(
                headers=[HeaderEntity(name="Authorization")],
            ),
        )
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        assert "default_anonymization" in result["spec"]


class TestResponseCodes:
    def test_allow_all_when_empty(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        assert "allow_all_response_codes" in result["spec"]

    def test_allowed_response_codes(self, minimal_policy):
        minimal_policy.allowed_response_codes = [200, 301, 404]
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        codes = result["spec"]["allowed_response_codes"]["response_code"]
        assert 200 in codes
        assert 301 in codes
        assert 404 in codes


class TestTopLevelStructure:
    def test_result_has_metadata_and_spec(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        assert "metadata" in result
        assert "spec" in result

    def test_spec_has_detection_settings(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        assert "detection_settings" in result["spec"]
