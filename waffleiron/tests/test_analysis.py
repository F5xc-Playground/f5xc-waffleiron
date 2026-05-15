"""Tests for the analysis engine."""

from waffleiron.analysis import analyze, AnalysisResult


class TestAlarmOnlyDetection:
    def test_detects_alarm_only_signatures(self, mature_policy):
        result = analyze(mature_policy)
        assert len(result.alarm_only_signatures) == 1
        assert result.alarm_only_signatures[0].sig_id == 200001001

    def test_detects_alarm_only_violations(self, mature_policy):
        result = analyze(mature_policy)
        assert len(result.alarm_only_violations) == 2

    def test_no_alarm_only_in_minimal(self, minimal_policy):
        result = analyze(minimal_policy)
        assert len(result.alarm_only_signatures) == 0
        assert len(result.alarm_only_violations) == 0


class TestPositiveSecurityGaps:
    def test_counts_url_entities(self, positive_security_policy):
        result = analyze(positive_security_policy)
        assert result.positive_security.url_count > 0

    def test_counts_parameter_value_types(self, positive_security_policy):
        result = analyze(positive_security_policy)
        assert result.positive_security.constrained_parameter_count > 0

    def test_counts_custom_signatures(self, positive_security_policy):
        result = analyze(positive_security_policy)
        assert result.untranslatable.custom_signature_count == 2

    def test_session_tracking(self, positive_security_policy):
        result = analyze(positive_security_policy)
        assert result.untranslatable.session_tracking_enabled is True


class TestLimitChecks:
    def test_warns_on_excessive_exclusions(self):
        from tests.conftest import make_policy_with_n_overrides

        policy = make_policy_with_n_overrides(300)
        result = analyze(policy)
        assert any("exclusion" in w.message.lower() for w in result.warnings)


class TestSummaryStats:
    def test_summary_counts(self, mature_policy):
        result = analyze(mature_policy)
        assert result.summary.total > 0
        assert result.summary.directly_translated >= 0
        assert result.summary.decisions_required > 0


class TestBotProtectionGaps:
    def test_detects_untranslatable_bot_actions(self, mature_policy):
        result = analyze(mature_policy)
        assert len(result.bot_gaps) > 0
        actions = [g.asm_action for g in result.bot_gaps]
        assert "challenge" in actions
