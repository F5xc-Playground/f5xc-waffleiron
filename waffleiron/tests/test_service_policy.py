"""Tests for ServicePolicyTranslator."""

from __future__ import annotations

import pytest

from waffleiron.model import (
    GeolocationConfig,
    IpIntelCategory,
    IpIntelligenceConfig,
    IpWhitelistEntry,
)
from waffleiron.translators.service_policy import ServicePolicyTranslator

# Import conftest helpers (available in test scope via conftest.py)
from conftest import make_minimal_policy, make_policy_with_ip_intelligence


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_policy():
    return make_minimal_policy()


@pytest.fixture
def mature_policy():
    """Policy with whitelist IPs and geolocation disallowed countries."""
    return make_minimal_policy(
        name="mature-tuned",
        whitelist_ips=[IpWhitelistEntry(ip="10.0.0.0", mask="255.0.0.0", block_requests="never")],
        geolocation=GeolocationConfig(disallowed=["North Korea", "Iran"]),
    )


# ---------------------------------------------------------------------------
# TestNoServicePolicy
# ---------------------------------------------------------------------------


class TestNoServicePolicy:
    def test_returns_none_when_not_needed(self, minimal_policy):
        result = ServicePolicyTranslator.translate(minimal_policy, namespace="ns")
        assert result is None

    def test_returns_none_for_empty_whitelist_and_no_geo(self):
        policy = make_minimal_policy(
            whitelist_ips=[],
            geolocation=GeolocationConfig(disallowed=[]),
            ip_intelligence=IpIntelligenceConfig(categories=[]),
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is None


# ---------------------------------------------------------------------------
# TestIpWhitelist
# ---------------------------------------------------------------------------


class TestIpWhitelist:
    def test_creates_allow_rule(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        allow_rules = [r for r in rules if r.get("spec", {}).get("action") == "ALLOW"]
        assert len(allow_rules) >= 1

    def test_ip_prefix(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        allow_rules = [r for r in rules if r.get("spec", {}).get("action") == "ALLOW"]
        prefixes = allow_rules[0]["spec"]["ip_prefix_list"]["ip_prefixes"]
        assert "10.0.0.0/8" in prefixes

    def test_multiple_whitelist_ips_produce_multiple_allow_rules(self):
        policy = make_minimal_policy(
            whitelist_ips=[
                IpWhitelistEntry(ip="10.0.0.0", mask="255.0.0.0"),
                IpWhitelistEntry(ip="192.168.1.0", mask="255.255.255.0"),
                IpWhitelistEntry(ip="172.16.0.0", mask="255.255.0.0"),
            ]
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        allow_rules = [r for r in rules if r.get("spec", {}).get("action") == "ALLOW"]
        assert len(allow_rules) == 3

    def test_mask_to_cidr_slash8(self):
        policy = make_minimal_policy(
            whitelist_ips=[IpWhitelistEntry(ip="10.0.0.0", mask="255.0.0.0")]
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        allow_rules = [r for r in rules if r.get("spec", {}).get("action") == "ALLOW"]
        prefixes = allow_rules[0]["spec"]["ip_prefix_list"]["ip_prefixes"]
        assert "10.0.0.0/8" in prefixes

    def test_mask_to_cidr_slash16(self):
        policy = make_minimal_policy(
            whitelist_ips=[IpWhitelistEntry(ip="172.16.0.0", mask="255.255.0.0")]
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        allow_rules = [r for r in rules if r.get("spec", {}).get("action") == "ALLOW"]
        prefixes = allow_rules[0]["spec"]["ip_prefix_list"]["ip_prefixes"]
        assert "172.16.0.0/16" in prefixes

    def test_mask_to_cidr_slash24(self):
        policy = make_minimal_policy(
            whitelist_ips=[IpWhitelistEntry(ip="192.168.1.0", mask="255.255.255.0")]
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        allow_rules = [r for r in rules if r.get("spec", {}).get("action") == "ALLOW"]
        prefixes = allow_rules[0]["spec"]["ip_prefix_list"]["ip_prefixes"]
        assert "192.168.1.0/24" in prefixes

    def test_mask_to_cidr_slash32(self):
        policy = make_minimal_policy(
            whitelist_ips=[IpWhitelistEntry(ip="1.2.3.4", mask="255.255.255.255")]
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        allow_rules = [r for r in rules if r.get("spec", {}).get("action") == "ALLOW"]
        prefixes = allow_rules[0]["spec"]["ip_prefix_list"]["ip_prefixes"]
        assert "1.2.3.4/32" in prefixes

    def test_allow_rule_has_correct_metadata_name(self):
        policy = make_minimal_policy(
            whitelist_ips=[IpWhitelistEntry(ip="10.0.0.0", mask="255.0.0.0")]
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        allow_rules = [r for r in rules if r.get("spec", {}).get("action") == "ALLOW"]
        name = allow_rules[0]["metadata"]["name"]
        assert "10-0-0-0" in name or "allow" in name

    def test_whitelist_only_returns_non_none(self):
        policy = make_minimal_policy(
            whitelist_ips=[IpWhitelistEntry(ip="10.0.0.0", mask="255.0.0.0")]
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is not None


# ---------------------------------------------------------------------------
# TestGeolocation
# ---------------------------------------------------------------------------


class TestGeolocation:
    def _geo_expression(self, result) -> str:
        """Extract the client_selector geo expression from the service policy."""
        rules = result["spec"]["rule_list"]["rules"]
        for rule in rules:
            sel = rule.get("spec", {}).get("client_selector", {})
            exprs = sel.get("expressions", [])
            for expr in exprs:
                if "country in" in expr:
                    return expr
        return ""

    def test_creates_geo_deny_rule(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="ns")
        assert self._geo_expression(result)

    def test_north_korea_maps_to_kp(self, mature_policy):
        expr = self._geo_expression(ServicePolicyTranslator.translate(mature_policy, namespace="ns"))
        assert "KP" in expr

    def test_iran_maps_to_ir(self, mature_policy):
        expr = self._geo_expression(ServicePolicyTranslator.translate(mature_policy, namespace="ns"))
        assert "IR" in expr

    def test_geo_rule_has_deny_action(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        geo_rules = [r for r in rules if r.get("spec", {}).get("client_selector")]
        for rule in geo_rules:
            assert rule["spec"]["action"] == "DENY"

    def test_geo_only_returns_non_none(self):
        policy = make_minimal_policy(
            geolocation=GeolocationConfig(disallowed=["Iran"])
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is not None

    def test_unknown_country_skipped(self):
        policy = make_minimal_policy(
            geolocation=GeolocationConfig(disallowed=["Narnia"])
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is None

    def test_additional_country_mappings(self):
        countries = {
            "China": "CN",
            "Russia": "RU",
            "United States": "US",
        }
        for country_name, expected_code in countries.items():
            policy = make_minimal_policy(
                geolocation=GeolocationConfig(disallowed=[country_name])
            )
            result = ServicePolicyTranslator.translate(policy, namespace="ns")
            assert result is not None, f"Expected result for country {country_name!r}"
            expr = self._geo_expression(result)
            assert expected_code in expr, f"{country_name!r} should map to {expected_code!r}"


# ---------------------------------------------------------------------------
# TestIpIntelligence
# ---------------------------------------------------------------------------


class TestIpIntelligence:
    def test_creates_threat_category_rules(self):
        policy = make_policy_with_ip_intelligence(["botnets", "scanners"])
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is not None
        rules = result["spec"]["rule_list"]["rules"]
        assert len(rules) >= 1

    def test_threat_rules_have_deny_action(self):
        policy = make_policy_with_ip_intelligence(["botnets"])
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        assert all(r["spec"]["action"] == "DENY" for r in rules)

    def test_ip_intelligence_only_returns_non_none(self):
        policy = make_policy_with_ip_intelligence(["windows-exploits"])
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is not None

    def test_empty_ip_intel_categories_with_no_other_features(self):
        policy = make_minimal_policy(
            ip_intelligence=IpIntelligenceConfig(categories=[])
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is None


# ---------------------------------------------------------------------------
# TestServicePolicyMetadata
# ---------------------------------------------------------------------------


class TestServicePolicyMetadata:
    def test_metadata_name_suffix(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="ns")
        name = result["metadata"]["name"]
        assert name.endswith("-service-policy")

    def test_metadata_namespace(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="my-namespace")
        assert result["metadata"]["namespace"] == "my-namespace"

    def test_metadata_name_uses_policy_name(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="ns")
        name = result["metadata"]["name"]
        assert "mature-tuned" in name

    def test_metadata_name_is_sanitized(self):
        policy = make_minimal_policy(
            name="My Policy With Spaces!",
            whitelist_ips=[IpWhitelistEntry(ip="10.0.0.0", mask="255.0.0.0")],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        name = result["metadata"]["name"]
        # Should not contain spaces or special chars
        assert " " not in name
        assert "!" not in name


# ---------------------------------------------------------------------------
# TestRuleOrdering
# ---------------------------------------------------------------------------


class TestRuleOrdering:
    @staticmethod
    def _is_geo_rule(r: dict) -> bool:
        return bool(r.get("spec", {}).get("client_selector"))

    @staticmethod
    def _is_threat_rule(r: dict) -> bool:
        return bool(r.get("spec", {}).get("ip_threat_category_list"))

    def test_ip_allows_before_geo_denies(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        allow_indices = [i for i, r in enumerate(rules) if r.get("spec", {}).get("action") == "ALLOW"]
        geo_indices = [i for i, r in enumerate(rules) if self._is_geo_rule(r)]
        if allow_indices and geo_indices:
            assert max(allow_indices) < min(geo_indices)

    def test_geo_denies_before_threat_intel(self):
        policy = make_minimal_policy(
            geolocation=GeolocationConfig(disallowed=["Iran"]),
            ip_intelligence=IpIntelligenceConfig(
                categories=[IpIntelCategory(name="botnets", action="block")]
            ),
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        geo_indices = [i for i, r in enumerate(rules) if self._is_geo_rule(r)]
        threat_indices = [i for i, r in enumerate(rules) if self._is_threat_rule(r)]
        if geo_indices and threat_indices:
            assert max(geo_indices) < min(threat_indices)

    def test_ip_allows_before_threat_intel(self):
        policy = make_minimal_policy(
            whitelist_ips=[IpWhitelistEntry(ip="10.0.0.0", mask="255.0.0.0")],
            ip_intelligence=IpIntelligenceConfig(
                categories=[IpIntelCategory(name="botnets", action="block")]
            ),
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        allow_indices = [i for i, r in enumerate(rules) if r.get("spec", {}).get("action") == "ALLOW"]
        threat_indices = [i for i, r in enumerate(rules) if self._is_threat_rule(r)]
        if allow_indices and threat_indices:
            assert max(allow_indices) < min(threat_indices)
