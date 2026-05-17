"""Tests for ServicePolicyTranslator."""

from __future__ import annotations

import pytest

from waffleiron.model import (
    EntityCollection,
    EnforcementMode,
    FileTypeEntity,
    GeolocationConfig,
    IpIntelCategory,
    IpIntelligenceConfig,
    IpWhitelistEntry,
    MethodEntity,
    UrlEntity,
    Violation,
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
        assert name.endswith("-svc")

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


# ---------------------------------------------------------------------------
# TestFileTypeDenyRules
# ---------------------------------------------------------------------------


class TestFileTypeDenyRules:
    def test_disallowed_filetype_generates_deny_rule(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                file_types=[FileTypeEntity(name="exe", allowed=False)]
            ),
            violations=[Violation(name="VIOL_FILETYPE", alarm=True, block=True)],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is not None
        rules = result["spec"]["rule_list"]["rules"]
        ft_rules = [r for r in rules if "deny-filetype" in r["metadata"]["name"]]
        assert len(ft_rules) == 1
        assert ft_rules[0]["spec"]["action"] == "DENY"
        assert "path" in ft_rules[0]["spec"]
        assert "exe" in ft_rules[0]["spec"]["path"]["regex"]

    def test_allowed_filetype_no_rule(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                file_types=[FileTypeEntity(name="pdf", allowed=True)]
            ),
            violations=[Violation(name="VIOL_FILETYPE", alarm=True, block=True)],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is None

    def test_multiple_disallowed_filetypes(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                file_types=[
                    FileTypeEntity(name="exe", allowed=False),
                    FileTypeEntity(name="bat", allowed=False),
                    FileTypeEntity(name="pdf", allowed=True),
                ]
            ),
            violations=[Violation(name="VIOL_FILETYPE", alarm=True, block=True)],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        ft_rules = [r for r in rules if "deny-filetype" in r["metadata"]["name"]]
        assert len(ft_rules) == 2

    def test_filetype_gated_by_transparent_mode(self):
        policy = make_minimal_policy(
            enforcement_mode=EnforcementMode.TRANSPARENT,
            entities=EntityCollection(
                file_types=[FileTypeEntity(name="exe", allowed=False)]
            ),
            violations=[Violation(name="VIOL_FILETYPE", alarm=True, block=True)],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is None

    def test_filetype_gated_by_alarm_only_violation(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                file_types=[FileTypeEntity(name="exe", allowed=False)]
            ),
            violations=[Violation(name="VIOL_FILETYPE", alarm=True, block=False)],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is None

    def test_filetype_allowed_when_violation_absent(self):
        """When VIOL_FILETYPE is not in the policy violations, assume blocking."""
        policy = make_minimal_policy(
            entities=EntityCollection(
                file_types=[FileTypeEntity(name="exe", allowed=False)]
            ),
            violations=[],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is not None
        rules = result["spec"]["rule_list"]["rules"]
        ft_rules = [r for r in rules if "deny-filetype" in r["metadata"]["name"]]
        assert len(ft_rules) == 1

    def test_filetype_regex_pattern(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                file_types=[FileTypeEntity(name="exe", allowed=False)]
            ),
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        ft_rules = [r for r in rules if "deny-filetype" in r["metadata"]["name"]]
        regex = ft_rules[0]["spec"]["path"]["regex"]
        assert regex == r".*\.exe(\?.*)?$"

    def test_filetype_special_chars_escaped(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                file_types=[FileTypeEntity(name="tar.gz", allowed=False)]
            ),
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        ft_rules = [r for r in rules if "deny-filetype" in r["metadata"]["name"]]
        regex = ft_rules[0]["spec"]["path"]["regex"]
        assert r"tar\.gz" in regex


# ---------------------------------------------------------------------------
# TestMethodDenyRules
# ---------------------------------------------------------------------------


class TestMethodDenyRules:
    def test_global_method_restriction_generates_deny(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                methods=[MethodEntity(name="GET"), MethodEntity(name="POST")]
            ),
            violations=[Violation(name="VIOL_METHOD", alarm=True, block=True)],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is not None
        rules = result["spec"]["rule_list"]["rules"]
        method_rules = [r for r in rules if "deny-method" in r["metadata"]["name"]]
        assert len(method_rules) == 1
        assert method_rules[0]["metadata"]["name"] == "deny-method-global"
        denied_methods = method_rules[0]["spec"]["http_method"]["methods"]
        assert "GET" not in denied_methods
        assert "POST" not in denied_methods
        assert "DELETE" in denied_methods
        assert "PUT" in denied_methods

    def test_per_url_method_restriction(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                urls=[UrlEntity(name="/api/users", method="GET")],
                methods=[MethodEntity(name="GET"), MethodEntity(name="POST")],
            ),
            violations=[Violation(name="VIOL_METHOD", alarm=True, block=True)],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        url_method_rules = [
            r for r in rules
            if "deny-method" in r["metadata"]["name"] and r["metadata"]["name"] != "deny-method-global"
        ]
        assert len(url_method_rules) == 1
        rule = url_method_rules[0]
        assert rule["spec"]["path"]["prefix"] == "/api/users"
        assert "POST" in rule["spec"]["http_method"]["methods"]
        assert "GET" not in rule["spec"]["http_method"]["methods"]

    def test_method_gated_by_transparent_mode(self):
        policy = make_minimal_policy(
            enforcement_mode=EnforcementMode.TRANSPARENT,
            entities=EntityCollection(
                methods=[MethodEntity(name="GET"), MethodEntity(name="POST")]
            ),
            violations=[Violation(name="VIOL_METHOD", alarm=True, block=True)],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is None

    def test_method_gated_by_alarm_only_violation(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                methods=[MethodEntity(name="GET"), MethodEntity(name="POST")]
            ),
            violations=[Violation(name="VIOL_METHOD", alarm=True, block=False)],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is None

    def test_method_allowed_when_violation_absent(self):
        """When VIOL_METHOD is not in the policy violations, assume blocking."""
        policy = make_minimal_policy(
            entities=EntityCollection(
                methods=[MethodEntity(name="GET"), MethodEntity(name="POST")]
            ),
            violations=[],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is not None

    def test_no_method_rules_when_no_methods_defined(self):
        policy = make_minimal_policy(
            entities=EntityCollection(methods=[]),
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is None

    def test_url_without_method_field_no_rule(self):
        """URLs without a method restriction don't generate per-URL deny rules."""
        policy = make_minimal_policy(
            entities=EntityCollection(
                urls=[UrlEntity(name="/api/data", method=None)],
                methods=[MethodEntity(name="GET")],
            ),
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        url_method_rules = [
            r for r in rules
            if "deny-method" in r["metadata"]["name"] and r["metadata"]["name"] != "deny-method-global"
        ]
        assert len(url_method_rules) == 0

    def test_combined_filetype_and_method_rules(self):
        """Both rule types can coexist in the same service policy."""
        policy = make_minimal_policy(
            entities=EntityCollection(
                file_types=[FileTypeEntity(name="exe", allowed=False)],
                methods=[MethodEntity(name="GET"), MethodEntity(name="POST")],
            ),
            violations=[
                Violation(name="VIOL_FILETYPE", alarm=True, block=True),
                Violation(name="VIOL_METHOD", alarm=True, block=True),
            ],
        )
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        rules = result["spec"]["rule_list"]["rules"]
        ft_rules = [r for r in rules if "deny-filetype" in r["metadata"]["name"]]
        method_rules = [r for r in rules if "deny-method" in r["metadata"]["name"]]
        assert len(ft_rules) == 1
        assert len(method_rules) == 1
