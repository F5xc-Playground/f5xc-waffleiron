"""Tests for the gap report generator (JSON and Markdown formats)."""

import json

import pytest

from waffleiron.reporters import ReportFormat, generate_report


# ---------------------------------------------------------------------------
# JSON report tests
# ---------------------------------------------------------------------------


class TestJsonReport:
    def test_has_summary(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert "summary" in data
        assert "total" in data["summary"]
        assert "directly_translated" in data["summary"]

    def test_has_policy_name(self, analysis_result, decisions):
        report = generate_report(
            analysis_result, decisions, format=ReportFormat.JSON, policy_name="test-policy"
        )
        data = json.loads(report)
        assert data["policy_name"] == "test-policy"

    def test_has_enforcement_mode(self, analysis_result, decisions):
        report = generate_report(
            analysis_result,
            decisions,
            format=ReportFormat.JSON,
            enforcement_mode="blocking",
        )
        data = json.loads(report)
        assert data["enforcement_mode"] == "blocking"

    def test_summary_counts(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        s = data["summary"]
        assert s["total"] == analysis_result.summary.total
        assert s["directly_translated"] == analysis_result.summary.directly_translated
        assert s["translated_with_loss"] == analysis_result.summary.translated_with_loss
        assert s["decisions_required"] == analysis_result.summary.decisions_required
        assert s["cannot_translate"] == analysis_result.summary.cannot_translate

    def test_has_alarm_only_signatures(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert "alarm_only_signatures" in data
        assert isinstance(data["alarm_only_signatures"], list)

    def test_alarm_only_signatures_include_decision(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        for sig in data["alarm_only_signatures"]:
            assert "sig_id" in sig
            assert "scope" in sig
            assert "decision" in sig

    def test_has_alarm_only_violations(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert "alarm_only_violations" in data
        assert isinstance(data["alarm_only_violations"], list)

    def test_has_positive_security(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert "positive_security" in data

    def test_has_untranslatable(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert "untranslatable" in data

    def test_has_bot_gaps(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert "bot_gaps" in data
        assert isinstance(data["bot_gaps"], list)

    def test_has_warnings(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert "warnings" in data
        assert isinstance(data["warnings"], list)

    def test_has_xc_recommendations(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert "xc_recommendations" in data
        assert isinstance(data["xc_recommendations"], list)

    def test_is_valid_json(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        # Should not raise
        data = json.loads(report)
        assert isinstance(data, dict)

    def test_default_policy_name_empty(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert data["policy_name"] == ""

    def test_bot_gaps_contain_fields(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        for gap in data["bot_gaps"]:
            assert "category" in gap
            assert "asm_action" in gap


# ---------------------------------------------------------------------------
# Markdown report tests
# ---------------------------------------------------------------------------


class TestMarkdownReport:
    def test_has_header(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "# AWAF" in report

    def test_has_summary_section(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "## Summary" in report

    def test_has_positive_security_section(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "Positive Security" in report

    def test_has_xc_recommendations(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "Recommendation" in report

    def test_has_custom_signatures(self, analysis_with_custom_sigs, decisions):
        report = generate_report(
            analysis_with_custom_sigs, decisions, format=ReportFormat.MARKDOWN
        )
        assert "Custom Signature" in report

    def test_summary_contains_total(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "Total features analyzed" in report or str(analysis_result.summary.total) in report

    def test_has_alarm_only_signatures_section(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "Alarm-Only Signature" in report

    def test_has_alarm_only_violations_section(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "Alarm-Only Violation" in report

    def test_has_untranslatable_section(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "Untranslatable" in report

    def test_has_bot_gaps_section(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "Bot" in report

    def test_has_warnings_section(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "Warning" in report

    def test_policy_name_appears_in_output(self, analysis_result, decisions):
        report = generate_report(
            analysis_result,
            decisions,
            format=ReportFormat.MARKDOWN,
            policy_name="my-waf-policy",
        )
        assert "my-waf-policy" in report

    def test_enforcement_mode_appears_in_output(self, analysis_result, decisions):
        report = generate_report(
            analysis_result,
            decisions,
            format=ReportFormat.MARKDOWN,
            enforcement_mode="blocking",
        )
        assert "blocking" in report

    def test_custom_sig_names_appear(self, analysis_with_custom_sigs, decisions):
        report = generate_report(
            analysis_with_custom_sigs, decisions, format=ReportFormat.MARKDOWN
        )
        assert "Custom SQL" in report


# ---------------------------------------------------------------------------
# Empty analysis tests
# ---------------------------------------------------------------------------


class TestEmptyAnalysis:
    def test_json_empty(self):
        from waffleiron.analysis import AnalysisResult
        from waffleiron.decisions import DecisionSet

        result = AnalysisResult()
        ds = DecisionSet()
        report = generate_report(result, ds, format=ReportFormat.JSON)
        data = json.loads(report)
        assert isinstance(data, dict)
        assert data["summary"]["total"] == 0

    def test_markdown_empty(self):
        from waffleiron.analysis import AnalysisResult
        from waffleiron.decisions import DecisionSet

        result = AnalysisResult()
        ds = DecisionSet()
        report = generate_report(result, ds, format=ReportFormat.MARKDOWN)
        assert isinstance(report, str)
        assert len(report) > 0
        assert "## Summary" in report
