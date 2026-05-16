"""Full pipeline integration test — parse → analyze → translate → validate → report."""

from waffleiron import parse, analyze, translate, validate_outputs, generate_report
from waffleiron.decisions import DecisionSet, AlarmOnlyAction
from waffleiron.reporters import ReportFormat


def test_full_pipeline(fixtures_path):
    policy = parse(fixtures_path / "mature_tuned.xml")
    assert policy.name

    analysis = analyze(policy)
    assert analysis.summary.total > 0

    decisions = DecisionSet()
    decisions.bulk_set_signatures(AlarmOnlyAction.EXCLUDE)

    result = translate(policy, decisions, "test-ns")
    assert result.app_firewall is not None
    assert result.exclusion_policy is not None

    for obj_type, obj in [
        ("app_firewall", result.app_firewall),
        ("waf_exclusion_policy", result.exclusion_policy),
    ]:
        vr = validate_outputs(obj, object_type=obj_type)
        assert vr.is_valid, f"Validation failed for {obj_type}: {vr.errors}"

    md = generate_report(
        analysis, decisions, format=ReportFormat.MARKDOWN, policy_name=policy.name
    )
    assert "## Summary" in md


def test_minimal_pipeline(fixtures_path):
    policy = parse(fixtures_path / "minimal_blocking.xml")
    assert policy.enforcement_mode.value == "blocking"

    analysis = analyze(policy)
    decisions = DecisionSet()

    result = translate(policy, decisions, "ns")
    assert result.app_firewall is not None
    assert result.service_policy is None
    assert result.http_lb_patch is None

    vr = validate_outputs(result.app_firewall, object_type="app_firewall")
    assert vr.is_valid


def test_json_report_roundtrip(fixtures_path):
    import json

    policy = parse(fixtures_path / "mature_tuned.xml")
    analysis = analyze(policy)
    decisions = DecisionSet()

    report = generate_report(
        analysis, decisions, format=ReportFormat.JSON, policy_name=policy.name
    )
    data = json.loads(report)
    assert "summary" in data
    assert data["policy_name"] == policy.name
