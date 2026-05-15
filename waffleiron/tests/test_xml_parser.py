"""Tests for the XML policy parser."""

from waffleiron.parsers.xml_parser import XmlPolicyParser
from waffleiron.model import EnforcementMode, AccuracyLevel


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
