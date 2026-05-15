"""Tests for HttpLbPatchTranslator — CSRF and Data Guard → HTTP LB patch fields."""

import pytest

from waffleiron.model import CsrfConfig, DataGuardConfig
from waffleiron.translators.http_lb_patch import HttpLbPatchTranslator

from conftest import make_minimal_policy, make_policy_with_csrf, make_policy_with_data_guard


class TestCsrf:
    def test_csrf_enabled(self):
        policy = make_policy_with_csrf(enabled=True, urls=["/sensitive-form"])
        result = HttpLbPatchTranslator.translate(policy)
        assert result is not None
        assert result["csrf"]["enabled"] is True

    def test_csrf_urls_included(self):
        policy = make_policy_with_csrf(enabled=True, urls=["/form1", "/form2"])
        result = HttpLbPatchTranslator.translate(policy)
        assert result["csrf"]["urls"] == ["/form1", "/form2"]

    def test_csrf_empty_urls(self):
        policy = make_policy_with_csrf(enabled=True, urls=[])
        result = HttpLbPatchTranslator.translate(policy)
        assert result is not None
        assert result["csrf"]["urls"] == []


class TestDataGuard:
    def test_data_guard_enabled(self):
        policy = make_policy_with_data_guard(enabled=True, credit_cards=True, ssn=True)
        result = HttpLbPatchTranslator.translate(policy)
        assert result is not None
        assert result["data_guard"]["enabled"] is True

    def test_data_guard_credit_cards(self):
        policy = make_policy_with_data_guard(enabled=True, credit_cards=True)
        result = HttpLbPatchTranslator.translate(policy)
        assert result["data_guard"]["credit_cards"] is True

    def test_data_guard_ssn(self):
        policy = make_policy_with_data_guard(enabled=True, ssn=True)
        result = HttpLbPatchTranslator.translate(policy)
        assert result["data_guard"]["ssn"] is True

    def test_data_guard_custom_patterns(self):
        policy = make_policy_with_data_guard(
            enabled=True, custom_patterns=["\\d{3}-\\d{2}-\\d{4}"]
        )
        result = HttpLbPatchTranslator.translate(policy)
        assert result["data_guard"]["custom_patterns"] == ["\\d{3}-\\d{2}-\\d{4}"]

    def test_data_guard_exception_urls(self):
        policy = make_policy_with_data_guard(enabled=True, exception_urls=["/api/internal"])
        result = HttpLbPatchTranslator.translate(policy)
        assert result["data_guard"]["exception_urls"] == ["/api/internal"]

    def test_data_guard_credit_cards_false_by_default(self):
        policy = make_policy_with_data_guard(enabled=True)
        result = HttpLbPatchTranslator.translate(policy)
        assert result["data_guard"]["credit_cards"] is False

    def test_data_guard_ssn_false_by_default(self):
        policy = make_policy_with_data_guard(enabled=True)
        result = HttpLbPatchTranslator.translate(policy)
        assert result["data_guard"]["ssn"] is False


class TestNotNeeded:
    def test_returns_none(self, minimal_policy):
        result = HttpLbPatchTranslator.translate(minimal_policy)
        assert result is None

    def test_csrf_disabled_returns_none(self):
        policy = make_policy_with_csrf(enabled=False)
        result = HttpLbPatchTranslator.translate(policy)
        assert result is None

    def test_data_guard_disabled_returns_none(self):
        policy = make_policy_with_data_guard(enabled=False)
        result = HttpLbPatchTranslator.translate(policy)
        assert result is None


class TestBothEnabled:
    def test_both_csrf_and_data_guard(self):
        policy = make_minimal_policy(
            csrf=CsrfConfig(enabled=True, urls=["/form"]),
            data_guard=DataGuardConfig(enabled=True, credit_cards=True),
        )
        result = HttpLbPatchTranslator.translate(policy)
        assert "csrf" in result
        assert "data_guard" in result

    def test_both_keys_have_correct_content(self):
        policy = make_minimal_policy(
            csrf=CsrfConfig(enabled=True, urls=["/checkout"]),
            data_guard=DataGuardConfig(enabled=True, ssn=True, exception_urls=["/safe"]),
        )
        result = HttpLbPatchTranslator.translate(policy)
        assert result["csrf"]["urls"] == ["/checkout"]
        assert result["data_guard"]["ssn"] is True
        assert result["data_guard"]["exception_urls"] == ["/safe"]


class TestOnlyOneEnabled:
    def test_only_csrf(self):
        policy = make_policy_with_csrf(enabled=True)
        result = HttpLbPatchTranslator.translate(policy)
        assert "csrf" in result
        assert "data_guard" not in result

    def test_only_data_guard(self):
        policy = make_policy_with_data_guard(enabled=True)
        result = HttpLbPatchTranslator.translate(policy)
        assert "data_guard" in result
        assert "csrf" not in result
