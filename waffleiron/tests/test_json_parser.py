"""Tests for the JSON policy parser and auto-detection dispatch."""

from waffleiron.parsers.json_parser import JsonPolicyParser
from waffleiron.parsers.xml_parser import XmlPolicyParser
from waffleiron.model import EnforcementMode, AccuracyLevel


class TestJsonParserMinimal:
    def test_parse_enforcement_mode(self, fixtures_path):
        policy = JsonPolicyParser.parse(fixtures_path / "minimal_blocking.json")
        assert policy.enforcement_mode == EnforcementMode.BLOCKING
        assert policy.name == "test-policy"

    def test_parse_encoding(self, fixtures_path):
        policy = JsonPolicyParser.parse(fixtures_path / "minimal_blocking.json")
        assert policy.encoding == "utf-8"

    def test_parse_signatures(self, fixtures_path):
        policy = JsonPolicyParser.parse(fixtures_path / "minimal_blocking.json")
        assert len(policy.signatures.global_overrides) == 1
        assert policy.signatures.global_overrides[0].sig_id == 200001001

    def test_parse_violations(self, fixtures_path):
        policy = JsonPolicyParser.parse(fixtures_path / "minimal_blocking.json")
        assert len(policy.violations) == 1
        assert policy.violations[0].name == "VIOL_ATTACK_SIGNATURE"


class TestJsonXmlConsistency:
    def test_minimal_policy_matches(self, fixtures_path):
        xml_policy = XmlPolicyParser.parse(fixtures_path / "minimal_blocking.xml")
        json_policy = JsonPolicyParser.parse(fixtures_path / "minimal_blocking.json")
        assert xml_policy.enforcement_mode == json_policy.enforcement_mode
        assert xml_policy.name == json_policy.name
        assert xml_policy.encoding == json_policy.encoding
        assert xml_policy.signatures.accuracy_level == json_policy.signatures.accuracy_level
        assert len(xml_policy.violations) == len(json_policy.violations)
        assert len(xml_policy.signatures.global_overrides) == len(json_policy.signatures.global_overrides)


class TestAutoDetectParse:
    def test_parse_xml_auto(self, fixtures_path):
        from waffleiron.parsers import parse
        policy = parse(fixtures_path / "minimal_blocking.xml")
        assert policy.name == "test-policy"

    def test_parse_json_auto(self, fixtures_path):
        from waffleiron.parsers import parse
        policy = parse(fixtures_path / "minimal_blocking.json")
        assert policy.name == "test-policy"
