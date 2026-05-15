"""Tests for the decisions model."""

from waffleiron.decisions import (
    AlarmOnlyAction,
    BotDecision,
    BotDecisionAction,
    DecisionSet,
    SignatureDecision,
    ViolationAction,
    ViolationDecision,
)


class TestDecisionSet:
    def test_empty_decisions(self):
        ds = DecisionSet()
        assert len(ds.signature_decisions) == 0
        assert len(ds.violation_decisions) == 0

    def test_add_signature_decision(self):
        ds = DecisionSet()
        ds.add_signature(
            SignatureDecision(
                sig_id=200001234,
                description="SQL Injection",
                scope="global",
                action=AlarmOnlyAction.EXCLUDE,
            )
        )
        assert ds.get_signature_action(200001234) == AlarmOnlyAction.EXCLUDE

    def test_bulk_set_signatures(self):
        ds = DecisionSet()
        ds.add_signature(SignatureDecision(sig_id=1, description="a", scope="global", action=AlarmOnlyAction.DEFER))
        ds.add_signature(SignatureDecision(sig_id=2, description="b", scope="global", action=AlarmOnlyAction.DEFER))
        ds.bulk_set_signatures(AlarmOnlyAction.EXCLUDE)
        assert ds.get_signature_action(1) == AlarmOnlyAction.EXCLUDE
        assert ds.get_signature_action(2) == AlarmOnlyAction.EXCLUDE

    def test_bulk_set_violations(self):
        ds = DecisionSet()
        ds.add_violation(ViolationDecision(violation="VIOL_A", action=ViolationAction.DEFER))
        ds.add_violation(ViolationDecision(violation="VIOL_B", action=ViolationAction.DEFER))
        ds.bulk_set_violations(ViolationAction.ENFORCE)
        assert ds.get_violation_action("VIOL_A") == ViolationAction.ENFORCE
        assert ds.get_violation_action("VIOL_B") == ViolationAction.ENFORCE

    def test_yaml_round_trip(self, tmp_path):
        ds = DecisionSet()
        ds.add_signature(
            SignatureDecision(
                sig_id=200001234,
                description="SQL Injection",
                scope="global",
                action=AlarmOnlyAction.EXCLUDE,
            )
        )
        ds.add_violation(
            ViolationDecision(
                violation="VIOL_COOKIE_MODIFIED",
                action=ViolationAction.ENFORCE,
            )
        )
        ds.add_bot(
            BotDecision(
                category="unknown-bot",
                asm_action="challenge",
                action=BotDecisionAction.BLOCK,
            )
        )
        path = tmp_path / "decisions.yaml"
        ds.save_yaml(path)
        loaded = DecisionSet.load_yaml(path)
        assert loaded.get_signature_action(200001234) == AlarmOnlyAction.EXCLUDE
        assert loaded.get_violation_action("VIOL_COOKIE_MODIFIED") == ViolationAction.ENFORCE
        assert loaded.get_bot_action("unknown-bot") == BotDecisionAction.BLOCK

    def test_default_action_is_defer(self):
        ds = DecisionSet()
        assert ds.get_signature_action(999) == AlarmOnlyAction.DEFER
        assert ds.get_violation_action("VIOL_ANYTHING") == ViolationAction.DEFER

    def test_default_bot_action(self):
        ds = DecisionSet()
        assert ds.get_bot_action("unknown") == BotDecisionAction.BLOCK
