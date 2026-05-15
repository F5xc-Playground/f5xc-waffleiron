"""Tests for the XML policy parser."""

from pathlib import Path

import pytest

from waffleiron.parsers.xml_parser import XmlPolicyParser
from waffleiron.model import EnforcementMode, AccuracyLevel


class TestRealExportFormat:
    """Tests against a real ``tmsh save asm policy`` export (v11.6 format)."""

    def test_policy_name(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert policy.name == "linux-high"

    def test_enforcement_mode(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert policy.enforcement_mode == EnforcementMode.BLOCKING

    def test_encoding(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert policy.encoding == "utf-8"

    def test_signature_overrides(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert len(policy.signatures.global_overrides) == 5
        sig_ids = {s.sig_id for s in policy.signatures.global_overrides}
        assert 200002444 in sig_ids

    def test_signature_sets(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert len(policy.signature_sets) >= 1

    def test_staging_disabled(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert policy.signatures.staging_enabled is False

    def test_violations(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert len(policy.violations) >= 30
        names = {v.name for v in policy.violations}
        assert "CSRF attack detected" in names or "CSRF" in names

    def test_alarm_only_violations(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        alarm_only = [v for v in policy.violations if v.alarm and not v.block]
        assert len(alarm_only) >= 5

    def test_urls(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert len(policy.entities.urls) == 1
        assert policy.entities.urls[0].name == "*"
        assert policy.entities.urls[0].type == "wildcard"

    def test_parameters(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert len(policy.entities.parameters) == 1
        assert policy.entities.parameters[0].name == "*"

    def test_file_types(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert len(policy.entities.file_types) == 1
        assert policy.entities.file_types[0].name == "*"

    def test_headers(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert len(policy.entities.headers) >= 3
        names = {h.name for h in policy.entities.headers}
        assert "*" in names

    def test_methods(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert len(policy.entities.methods) == 3
        names = {m.name for m in policy.entities.methods}
        assert "GET" in names
        assert "POST" in names

    def test_response_codes(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert len(policy.allowed_response_codes) == 6
        assert 400 in policy.allowed_response_codes
        assert 503 in policy.allowed_response_codes

    def test_csrf_disabled(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert policy.csrf.enabled is False

    def test_data_guard(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "real_export_linux_high.xml")
        assert policy.data_guard.enabled is False
        assert policy.data_guard.credit_cards is False
        assert policy.data_guard.ssn is False


class TestRealExportPublicPolicies:
    """Smoke tests parsing the full set of public F5 ASM policy exports.

    These run only when the downloaded policies are present at /tmp/asm-test-policies/xml/.
    """

    POLICY_DIR = Path("/tmp/asm-test-policies/xml")

    @pytest.fixture(autouse=True)
    def _skip_if_missing(self):
        if not self.POLICY_DIR.exists():
            pytest.skip("Public ASM policies not downloaded to /tmp/asm-test-policies/xml/")

    def _all_xml_files(self):
        return sorted(self.POLICY_DIR.glob("*.xml"))

    def test_all_parse_without_error(self):
        failures = []
        for xml_file in self._all_xml_files():
            try:
                XmlPolicyParser.parse(xml_file)
            except Exception as e:
                failures.append(f"{xml_file.name}: {e}")
        assert not failures, f"Parse failures:\n" + "\n".join(failures)

    def test_all_have_names(self):
        for xml_file in self._all_xml_files():
            policy = XmlPolicyParser.parse(xml_file)
            assert policy.name, f"{xml_file.name} has empty name"

    def test_all_have_violations(self):
        for xml_file in self._all_xml_files():
            policy = XmlPolicyParser.parse(xml_file)
            assert len(policy.violations) > 0, f"{xml_file.name} has no violations"

    def test_all_have_signatures(self):
        for xml_file in self._all_xml_files():
            policy = XmlPolicyParser.parse(xml_file)
            assert len(policy.signatures.global_overrides) > 0, f"{xml_file.name} has no sig overrides"


class TestMinimalPolicy:
    def test_parse_enforcement_mode(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "minimal_blocking.xml")
        assert policy.enforcement_mode == EnforcementMode.BLOCKING
        assert policy.name == "test-policy"
        assert policy.encoding == "utf-8"

    def test_parse_signatures(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "minimal_blocking.xml")
        assert policy.signatures.accuracy_level == AccuracyLevel.HIGH_MEDIUM
        assert policy.signatures.staging_enabled is True
        assert len(policy.signatures.global_overrides) == 1


class TestRapidDeploymentPolicy:
    def test_policy_name(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "rapid_deployment.xml")
        assert policy.name == "rapid-deployment"

    def test_signature_sets(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "rapid_deployment.xml")
        assert len(policy.signature_sets) == 2
        names = {s.name for s in policy.signature_sets}
        assert "Generic Detection Signatures" in names
        assert "High Accuracy Signatures" in names

    def test_violations(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "rapid_deployment.xml")
        assert len(policy.violations) == 5
        sig_viol = next(v for v in policy.violations if v.name == "VIOL_ATTACK_SIGNATURE")
        assert sig_viol.alarm is True
        assert sig_viol.block is True

    def test_no_custom_entities(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "rapid_deployment.xml")
        assert len(policy.entities.urls) == 0
        assert len(policy.whitelist_ips) == 0
        assert len(policy.geolocation.disallowed) == 0


class TestMatureTunedPolicy:
    def test_alarm_only_signatures(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        alarm_only = [s for s in policy.signatures.global_overrides if s.alarm and not s.block]
        assert len(alarm_only) == 1
        assert alarm_only[0].sig_id == 200001001

    def test_disabled_signatures(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        disabled = [s for s in policy.signatures.global_overrides if not s.enabled]
        assert len(disabled) == 1
        assert disabled[0].sig_id == 200001002

    def test_url_entities(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        assert len(policy.entities.urls) == 2
        api_url = next(u for u in policy.entities.urls if u.name == "/api/v1/data")
        assert api_url.attack_signatures_check is False

    def test_per_url_signature_overrides(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        login_url = next(u for u in policy.entities.urls if u.name == "/login")
        assert len(login_url.signature_overrides) == 1
        assert login_url.signature_overrides[0].sig_id == 200001004

    def test_sensitive_parameter(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        session = next(p for p in policy.entities.parameters if p.name == "session_id")
        assert session.sensitive is True

    def test_parameter_no_sig_check(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        query = next(p for p in policy.entities.parameters if p.name == "query")
        assert query.attack_signatures_check is False

    def test_cookie_no_sig_check(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        tracking = next(c for c in policy.entities.cookies if c.name == "tracking")
        assert tracking.attack_signatures_check is False

    def test_alarm_only_violations(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        alarm_only = [v for v in policy.violations if v.alarm and not v.block]
        assert len(alarm_only) == 2

    def test_ip_whitelist(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        assert len(policy.whitelist_ips) == 1
        assert policy.whitelist_ips[0].ip == "10.0.0.0"

    def test_geolocation(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        assert "North Korea" in policy.geolocation.disallowed
        assert "Iran" in policy.geolocation.disallowed

    def test_bot_defense(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        assert policy.bot_defense.enabled is True
        malicious = next(c for c in policy.bot_defense.categories if c.name == "malicious-bot")
        assert malicious.action == "block"

    def test_custom_blocking_page(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        assert policy.blocking_page.enabled is True
        assert "<%TS.request.ID()%>" in policy.blocking_page.custom_html


class TestPositiveSecurityPolicy:
    def test_url_entity_counts(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "positive_security.xml")
        explicit = [u for u in policy.entities.urls if u.type == "explicit"]
        wildcard = [u for u in policy.entities.urls if u.type == "wildcard"]
        assert len(explicit) == 3
        assert len(wildcard) == 2

    def test_parameter_value_types(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "positive_security.xml")
        value_types = {p.value_type for p in policy.entities.parameters if p.value_type}
        assert "alpha" in value_types
        assert "numeric" in value_types

    def test_custom_signatures(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "positive_security.xml")
        assert len(policy.custom_signatures) == 2
        assert all(sig.pattern for sig in policy.custom_signatures)

    def test_file_types(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "positive_security.xml")
        assert len(policy.entities.file_types) == 3

    def test_mandatory_header(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "positive_security.xml")
        mandatory = [h for h in policy.entities.headers if h.mandatory]
        assert len(mandatory) == 1
