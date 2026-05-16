"""Tests for the ExclusionPolicyTranslator."""

from waffleiron.translators.exclusion_policy import ExclusionPolicyTranslator
from waffleiron.decisions import AlarmOnlyAction, DecisionSet, SignatureDecision
from waffleiron.model import (
    EntityCollection,
    SignatureConfig,
    SignatureOverride,
    UrlEntity,
    AccuracyLevel,
)

from conftest import (
    make_minimal_policy,
    make_policy_with_disabled_sig,
    make_policy_with_per_url_sig_override,
    make_policy_with_url_no_sig_check,
    make_policy_with_param_sig_override,
    make_policy_with_alarm_only_sig,
    make_policy_with_cookie_sig_override,
)


def empty_decisions() -> DecisionSet:
    """Return an empty DecisionSet (all sigs defer by default)."""
    return DecisionSet()


def decisions_with_sig(sig_id: int, action: AlarmOnlyAction) -> DecisionSet:
    """Return a DecisionSet with a single signature decision."""
    ds = DecisionSet()
    ds.add_signature(SignatureDecision(sig_id=sig_id, description="test", scope="global", action=action))
    return ds


# ---------------------------------------------------------------------------
# TestTopLevelStructure
# ---------------------------------------------------------------------------

class TestTopLevelStructure:
    def test_empty_policy_returns_none(self):
        policy = make_minimal_policy()
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        assert result is None

    def test_result_has_metadata(self):
        policy = make_policy_with_disabled_sig(200001001)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="test-ns")
        assert "metadata" in result

    def test_metadata_has_name(self):
        policy = make_policy_with_disabled_sig(200001001, name="my-policy")
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="test-ns")
        assert "name" in result["metadata"]

    def test_metadata_name_contains_policy_name(self):
        policy = make_policy_with_disabled_sig(200001001, name="my-policy")
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="test-ns")
        assert "my-policy" in result["metadata"]["name"]

    def test_metadata_has_namespace(self):
        policy = make_policy_with_disabled_sig(200001001)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="test-ns")
        assert result["metadata"]["namespace"] == "test-ns"

    def test_result_has_spec(self):
        policy = make_policy_with_disabled_sig(200001001)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="test-ns")
        assert "spec" in result

    def test_spec_has_waf_exclusion_rules(self):
        policy = make_policy_with_disabled_sig(200001001)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="test-ns")
        assert "waf_exclusion_rules" in result["spec"]

    def test_waf_exclusion_rules_is_list(self):
        policy = make_policy_with_disabled_sig(200001001)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="test-ns")
        assert isinstance(result["spec"]["waf_exclusion_rules"], list)

    def test_metadata_name_sanitized(self):
        policy = make_policy_with_disabled_sig(200001001, name="My Policy NAME")
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        name = result["metadata"]["name"]
        assert name == name.lower()
        assert " " not in name

    def test_metadata_name_max_64_chars(self):
        policy = make_policy_with_disabled_sig(200001001, name="a" * 100)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        assert len(result["metadata"]["name"]) <= 64


# ---------------------------------------------------------------------------
# TestDisabledSignatures
# ---------------------------------------------------------------------------

class TestDisabledSignatures:
    def test_global_disabled_sig_creates_exclusion_rule(self):
        policy = make_policy_with_disabled_sig(200001002)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        assert len(rules) == 1

    def test_global_disabled_sig_uses_any_domain(self):
        policy = make_policy_with_disabled_sig(200001002)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "any_domain" in rule
        assert rule["any_domain"] == {}

    def test_global_disabled_sig_uses_any_path(self):
        policy = make_policy_with_disabled_sig(200001002)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "any_path" in rule
        assert rule["any_path"] == {}

    def test_global_disabled_sig_has_signature_id(self):
        policy = make_policy_with_disabled_sig(200001002)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        sig_ids = [c["signature_id"] for c in contexts]
        assert 200001002 in sig_ids

    def test_global_disabled_sig_context_is_any(self):
        policy = make_policy_with_disabled_sig(200001002)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert contexts[0]["context"] == "CONTEXT_ANY"

    def test_per_url_disabled_sig_uses_path_prefix(self):
        policy = make_policy_with_per_url_sig_override("/api/v1/data", 200001004)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        assert len(rules) == 1
        assert rules[0]["path_prefix"] == "/api/v1/data"

    def test_per_url_disabled_sig_no_any_path(self):
        policy = make_policy_with_per_url_sig_override("/api/v1/data", 200001004)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "any_path" not in rule

    def test_per_url_disabled_sig_has_signature_id(self):
        policy = make_policy_with_per_url_sig_override("/login", 200001005)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        sig_ids = [c["signature_id"] for c in contexts]
        assert 200001005 in sig_ids

    def test_per_url_disabled_sig_context_is_any(self):
        policy = make_policy_with_per_url_sig_override("/login", 200001005)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert contexts[0]["context"] == "CONTEXT_ANY"

    def test_enabled_sig_produces_no_exclusion(self):
        policy = make_minimal_policy(
            signatures=SignatureConfig(
                global_overrides=[SignatureOverride(sig_id=200001003, enabled=True, alarm=True, block=True)],
                accuracy_level=AccuracyLevel.HIGH_MEDIUM,
                staging_enabled=True,
                staging_period=7,
                threat_campaigns_enabled=True,
            ),
        )
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        assert result is None

    def test_multiple_global_disabled_sigs_coalesced_into_one_rule(self):
        policy = make_minimal_policy(
            signatures=SignatureConfig(
                global_overrides=[
                    SignatureOverride(sig_id=200001001, enabled=False, alarm=False, block=False),
                    SignatureOverride(sig_id=200001002, enabled=False, alarm=False, block=False),
                ],
                accuracy_level=AccuracyLevel.HIGH_MEDIUM,
                staging_enabled=True,
                staging_period=7,
                threat_campaigns_enabled=True,
            ),
        )
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        # Both global disabled sigs should coalesce into one rule
        assert len(rules) == 1
        contexts = rules[0]["app_firewall_detection_control"]["exclude_signature_contexts"]
        sig_ids = [c["signature_id"] for c in contexts]
        assert 200001001 in sig_ids
        assert 200001002 in sig_ids


# ---------------------------------------------------------------------------
# TestAttackSigsCheckFalse
# ---------------------------------------------------------------------------

class TestAttackSigsCheckFalse:
    def test_url_no_sig_check_creates_skip_rule(self):
        policy = make_policy_with_url_no_sig_check("/api/v1/data")
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        skip_rules = [r for r in rules if "waf_skip_processing" in r]
        assert len(skip_rules) == 1

    def test_url_no_sig_check_uses_path_prefix(self):
        policy = make_policy_with_url_no_sig_check("/api/v1/data")
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        skip_rule = next(r for r in rules if "waf_skip_processing" in r)
        assert skip_rule["path_prefix"] == "/api/v1/data"

    def test_url_no_sig_check_has_any_domain(self):
        policy = make_policy_with_url_no_sig_check("/api/v1/data")
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        skip_rule = next(r for r in rules if "waf_skip_processing" in r)
        assert "any_domain" in skip_rule
        assert skip_rule["any_domain"] == {}

    def test_url_no_sig_check_waf_skip_is_empty_dict(self):
        policy = make_policy_with_url_no_sig_check("/health")
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        skip_rule = next(r for r in rules if "waf_skip_processing" in r)
        assert skip_rule["waf_skip_processing"] == {}

    def test_url_with_sig_check_true_no_skip_rule(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                urls=[UrlEntity(name="/api/v1", attack_signatures_check=True)]
            )
        )
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        assert result is None

    def test_url_with_no_sig_check_attr_no_skip_rule(self):
        policy = make_minimal_policy(
            entities=EntityCollection(
                urls=[UrlEntity(name="/api/v1")]
            )
        )
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        assert result is None


# ---------------------------------------------------------------------------
# TestParameterContext
# ---------------------------------------------------------------------------

class TestParameterContext:
    def test_param_sig_override_creates_exclusion_rule(self):
        policy = make_policy_with_param_sig_override("query", 200001010)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        excl_rules = [r for r in rules if "app_firewall_detection_control" in r]
        assert len(excl_rules) == 1

    def test_param_sig_override_uses_any_path(self):
        policy = make_policy_with_param_sig_override("query", 200001010)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "any_path" in rule

    def test_param_sig_override_context_is_parameter(self):
        policy = make_policy_with_param_sig_override("query", 200001010)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert contexts[0]["context"] == "CONTEXT_PARAMETER"

    def test_param_sig_override_context_name_is_param_name(self):
        policy = make_policy_with_param_sig_override("session_id", 200001010)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert contexts[0]["context_name"] == "session_id"

    def test_param_sig_override_has_signature_id(self):
        policy = make_policy_with_param_sig_override("search", 200001099)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert contexts[0]["signature_id"] == 200001099

    def test_param_sig_override_uses_any_domain(self):
        policy = make_policy_with_param_sig_override("q", 200001010)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "any_domain" in rule

    def test_param_enabled_sig_no_exclusion(self):
        from waffleiron.model import ParameterEntity
        policy = make_minimal_policy(
            entities=EntityCollection(
                parameters=[
                    ParameterEntity(
                        name="q",
                        signature_overrides=[
                            SignatureOverride(sig_id=200001010, enabled=True, alarm=True, block=True),
                        ],
                    )
                ]
            )
        )
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        assert result is None


# ---------------------------------------------------------------------------
# TestAlarmOnlyDecisions
# ---------------------------------------------------------------------------

class TestAlarmOnlyDecisions:
    def test_alarm_only_sig_with_exclude_decision_creates_exclusion(self):
        policy = make_policy_with_alarm_only_sig(200001001)
        ds = decisions_with_sig(200001001, AlarmOnlyAction.EXCLUDE)
        result = ExclusionPolicyTranslator.translate(policy, ds, namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        assert len(rules) == 1

    def test_alarm_only_sig_with_exclude_has_any_domain(self):
        policy = make_policy_with_alarm_only_sig(200001001)
        ds = decisions_with_sig(200001001, AlarmOnlyAction.EXCLUDE)
        result = ExclusionPolicyTranslator.translate(policy, ds, namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "any_domain" in rule

    def test_alarm_only_sig_with_exclude_has_any_path(self):
        policy = make_policy_with_alarm_only_sig(200001001)
        ds = decisions_with_sig(200001001, AlarmOnlyAction.EXCLUDE)
        result = ExclusionPolicyTranslator.translate(policy, ds, namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "any_path" in rule

    def test_alarm_only_sig_with_exclude_has_sig_id(self):
        policy = make_policy_with_alarm_only_sig(200001001)
        ds = decisions_with_sig(200001001, AlarmOnlyAction.EXCLUDE)
        result = ExclusionPolicyTranslator.translate(policy, ds, namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert contexts[0]["signature_id"] == 200001001

    def test_alarm_only_sig_with_enforce_creates_no_exclusion(self):
        policy = make_policy_with_alarm_only_sig(200001001)
        ds = decisions_with_sig(200001001, AlarmOnlyAction.ENFORCE)
        result = ExclusionPolicyTranslator.translate(policy, ds, namespace="ns")
        assert result is None

    def test_alarm_only_sig_with_defer_creates_no_exclusion(self):
        policy = make_policy_with_alarm_only_sig(200001001)
        ds = decisions_with_sig(200001001, AlarmOnlyAction.DEFER)
        result = ExclusionPolicyTranslator.translate(policy, ds, namespace="ns")
        assert result is None

    def test_alarm_only_sig_no_decision_creates_no_exclusion(self):
        # No decision in set → defaults to DEFER → no exclusion
        policy = make_policy_with_alarm_only_sig(200001001)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        assert result is None

    def test_alarm_only_exclude_context_is_any(self):
        policy = make_policy_with_alarm_only_sig(200001001)
        ds = decisions_with_sig(200001001, AlarmOnlyAction.EXCLUDE)
        result = ExclusionPolicyTranslator.translate(policy, ds, namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert contexts[0]["context"] == "CONTEXT_ANY"


# ---------------------------------------------------------------------------
# TestCookieAndHeaderContext
# ---------------------------------------------------------------------------

class TestCookieAndHeaderContext:
    def test_cookie_sig_override_creates_exclusion_rule(self):
        policy = make_policy_with_cookie_sig_override("session", 200001020)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        excl_rules = [r for r in rules if "app_firewall_detection_control" in r]
        assert len(excl_rules) == 1

    def test_cookie_sig_override_context_is_cookie(self):
        policy = make_policy_with_cookie_sig_override("session", 200001020)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert contexts[0]["context"] == "CONTEXT_COOKIE"

    def test_cookie_sig_override_context_name_is_cookie_name(self):
        policy = make_policy_with_cookie_sig_override("auth_token", 200001020)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert contexts[0]["context_name"] == "auth_token"

    def test_cookie_sig_override_has_signature_id(self):
        policy = make_policy_with_cookie_sig_override("tracking", 200001021)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        contexts = rule["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert contexts[0]["signature_id"] == 200001021

    def test_cookie_sig_override_uses_any_path(self):
        policy = make_policy_with_cookie_sig_override("session", 200001020)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "any_path" in rule

    def test_cookie_sig_override_uses_any_domain(self):
        policy = make_policy_with_cookie_sig_override("session", 200001020)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "any_domain" in rule

    def test_cookie_enabled_sig_no_exclusion(self):
        from waffleiron.model import CookieEntity
        policy = make_minimal_policy(
            entities=EntityCollection(
                cookies=[
                    CookieEntity(
                        name="session",
                        signature_overrides=[
                            SignatureOverride(sig_id=200001020, enabled=True, alarm=True, block=True),
                        ],
                    )
                ]
            )
        )
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        assert result is None


# ---------------------------------------------------------------------------
# TestMetadata
# ---------------------------------------------------------------------------

class TestMetadata:
    def test_each_rule_has_metadata_name(self):
        policy = make_policy_with_disabled_sig(200001002)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "metadata" in rule
        assert "name" in rule["metadata"]

    def test_global_sig_rule_name_is_descriptive(self):
        policy = make_policy_with_disabled_sig(200001002)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        name = rule["metadata"]["name"]
        # Should contain "excl" and "200001002"
        assert "excl" in name
        assert "200001002" in name

    def test_skip_rule_name_is_descriptive(self):
        policy = make_policy_with_url_no_sig_check("/api/v1/data")
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        skip_rule = next(r for r in rules if "waf_skip_processing" in r)
        name = skip_rule["metadata"]["name"]
        assert "skip" in name

    def test_rule_metadata_name_is_string(self):
        policy = make_policy_with_disabled_sig(200001002)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert isinstance(rule["metadata"]["name"], str)

    def test_rule_metadata_name_non_empty(self):
        policy = make_policy_with_disabled_sig(200001002)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert len(rule["metadata"]["name"]) > 0

    def test_per_url_rule_name_is_descriptive(self):
        policy = make_policy_with_per_url_sig_override("/login", 200001005)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        name = rule["metadata"]["name"]
        assert "excl" in name

    def test_exclusion_rule_has_no_waf_skip_processing(self):
        policy = make_policy_with_disabled_sig(200001002)
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rule = result["spec"]["waf_exclusion_rules"][0]
        assert "waf_skip_processing" not in rule

    def test_skip_rule_has_no_app_firewall_detection_control(self):
        policy = make_policy_with_url_no_sig_check("/health")
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        skip_rule = next(r for r in rules if "waf_skip_processing" in r)
        assert "app_firewall_detection_control" not in skip_rule


# ---------------------------------------------------------------------------
# TestCoalescing
# ---------------------------------------------------------------------------

class TestCoalescing:
    def test_same_path_sigs_coalesced(self):
        """Two URL-scoped disabled sigs on same URL → one rule with 2 contexts."""
        from waffleiron.model import UrlEntity
        policy = make_minimal_policy(
            entities=EntityCollection(
                urls=[
                    UrlEntity(
                        name="/api",
                        signature_overrides=[
                            SignatureOverride(sig_id=200001001, enabled=False, alarm=False, block=False),
                            SignatureOverride(sig_id=200001002, enabled=False, alarm=False, block=False),
                        ],
                    )
                ]
            )
        )
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        excl_rules = [r for r in rules if "app_firewall_detection_control" in r]
        assert len(excl_rules) == 1
        contexts = excl_rules[0]["app_firewall_detection_control"]["exclude_signature_contexts"]
        assert len(contexts) == 2

    def test_different_path_sigs_not_coalesced(self):
        """Disabled sigs on different URLs → separate rules."""
        from waffleiron.model import UrlEntity
        policy = make_minimal_policy(
            entities=EntityCollection(
                urls=[
                    UrlEntity(
                        name="/api",
                        signature_overrides=[
                            SignatureOverride(sig_id=200001001, enabled=False, alarm=False, block=False),
                        ],
                    ),
                    UrlEntity(
                        name="/login",
                        signature_overrides=[
                            SignatureOverride(sig_id=200001002, enabled=False, alarm=False, block=False),
                        ],
                    ),
                ]
            )
        )
        result = ExclusionPolicyTranslator.translate(policy, empty_decisions(), namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        excl_rules = [r for r in rules if "app_firewall_detection_control" in r]
        assert len(excl_rules) == 2
