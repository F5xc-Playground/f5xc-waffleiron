"""Tests for the translation orchestrator."""

from waffleiron.translators import translate, TranslationResult
from waffleiron.decisions import DecisionSet


class TestTranslateReturnsAllObjects:
    def test_returns_translation_result(self, mature_policy):
        decisions = DecisionSet()
        result = translate(mature_policy, decisions, namespace="test-ns")
        assert isinstance(result, TranslationResult)

    def test_app_firewall_present(self, mature_policy):
        decisions = DecisionSet()
        result = translate(mature_policy, decisions, namespace="test-ns")
        assert result.app_firewall is not None
        assert "metadata" in result.app_firewall
        assert "spec" in result.app_firewall

    def test_exclusion_policy_present(self, mature_policy):
        decisions = DecisionSet()
        result = translate(mature_policy, decisions, namespace="test-ns")
        assert result.exclusion_policy is not None
        assert "spec" in result.exclusion_policy

    def test_service_policy_present(self, mature_policy):
        decisions = DecisionSet()
        result = translate(mature_policy, decisions, namespace="test-ns")
        assert result.service_policy is not None

    def test_http_lb_patch_none_when_not_needed(self, mature_policy):
        decisions = DecisionSet()
        result = translate(mature_policy, decisions, namespace="test-ns")
        assert result.http_lb_patch is None

    def test_namespace_propagated(self, mature_policy):
        decisions = DecisionSet()
        result = translate(mature_policy, decisions, namespace="my-ns")
        assert result.app_firewall["metadata"]["namespace"] == "my-ns"
        assert result.exclusion_policy["metadata"]["namespace"] == "my-ns"
        assert result.service_policy["metadata"]["namespace"] == "my-ns"


class TestMinimalPolicy:
    def test_minimal_has_no_service_policy(self, minimal_policy):
        decisions = DecisionSet()
        result = translate(minimal_policy, decisions, namespace="ns")
        assert result.service_policy is None

    def test_minimal_has_no_http_lb_patch(self, minimal_policy):
        decisions = DecisionSet()
        result = translate(minimal_policy, decisions, namespace="ns")
        assert result.http_lb_patch is None

    def test_minimal_has_app_firewall(self, minimal_policy):
        decisions = DecisionSet()
        result = translate(minimal_policy, decisions, namespace="ns")
        assert result.app_firewall is not None

    def test_minimal_has_exclusion_policy(self, minimal_policy):
        decisions = DecisionSet()
        result = translate(minimal_policy, decisions, namespace="ns")
        assert result.exclusion_policy is not None
