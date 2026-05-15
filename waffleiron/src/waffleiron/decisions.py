"""Decisions model — how users express alarm-only choices during ASM-to-XC conversion.

This module defines the enums and dataclasses that capture user decisions about
alarm-only signatures, violations, and bot categories.  A ``DecisionSet`` can be
serialised to / from YAML so that decisions persist across sessions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Union

import yaml


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AlarmOnlyAction(Enum):
    """Action for an alarm-only signature."""

    EXCLUDE = "exclude"
    ENFORCE = "enforce"
    DEFER = "defer"


class ViolationAction(Enum):
    """Action for a violation."""

    DISABLE = "disable"
    ENFORCE = "enforce"
    DEFER = "defer"


class BotDecisionAction(Enum):
    """Action for a bot category."""

    BLOCK = "block"
    REPORT = "report"
    IGNORE = "ignore"


# ---------------------------------------------------------------------------
# Decision dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SignatureDecision:
    """A user decision about an individual alarm-only signature."""

    sig_id: int
    description: str
    scope: str
    action: AlarmOnlyAction


@dataclass
class ViolationDecision:
    """A user decision about a violation."""

    violation: str
    action: ViolationAction


@dataclass
class BotDecision:
    """A user decision about a bot category."""

    category: str
    asm_action: str
    action: BotDecisionAction


# ---------------------------------------------------------------------------
# DecisionSet
# ---------------------------------------------------------------------------


class DecisionSet:
    """Container for all user decisions with lookup, bulk-update and YAML I/O."""

    def __init__(self) -> None:
        self.signature_decisions: dict[int, SignatureDecision] = {}
        self.violation_decisions: dict[str, ViolationDecision] = {}
        self.bot_decisions: dict[str, BotDecision] = {}

    # -- mutators -----------------------------------------------------------

    def add_signature(self, decision: SignatureDecision) -> None:
        self.signature_decisions[decision.sig_id] = decision

    def add_violation(self, decision: ViolationDecision) -> None:
        self.violation_decisions[decision.violation] = decision

    def add_bot(self, decision: BotDecision) -> None:
        self.bot_decisions[decision.category] = decision

    def bulk_set_signatures(self, action: AlarmOnlyAction) -> None:
        """Set *action* on every signature decision already in the set."""
        for decision in self.signature_decisions.values():
            decision.action = action

    def bulk_set_violations(self, action: ViolationAction) -> None:
        """Set *action* on every violation decision already in the set."""
        for decision in self.violation_decisions.values():
            decision.action = action

    # -- accessors ----------------------------------------------------------

    def get_signature_action(self, sig_id: int) -> AlarmOnlyAction:
        """Return the action for *sig_id*, defaulting to ``DEFER``."""
        decision = self.signature_decisions.get(sig_id)
        return decision.action if decision else AlarmOnlyAction.DEFER

    def get_violation_action(self, violation: str) -> ViolationAction:
        """Return the action for *violation*, defaulting to ``DEFER``."""
        decision = self.violation_decisions.get(violation)
        return decision.action if decision else ViolationAction.DEFER

    def get_bot_action(self, category: str) -> BotDecisionAction:
        """Return the action for *category*, defaulting to ``BLOCK``."""
        decision = self.bot_decisions.get(category)
        return decision.action if decision else BotDecisionAction.BLOCK

    # -- YAML I/O -----------------------------------------------------------

    def save_yaml(self, path: Union[str, Path]) -> None:
        """Serialise this decision set to a YAML file at *path*."""
        data: dict = {}

        if self.signature_decisions:
            data["alarm_only_signatures"] = [
                {
                    "sig_id": d.sig_id,
                    "description": d.description,
                    "scope": d.scope,
                    "decision": d.action.value,
                }
                for d in self.signature_decisions.values()
            ]

        if self.violation_decisions:
            data["alarm_only_violations"] = [
                {
                    "violation": d.violation,
                    "decision": d.action.value,
                }
                for d in self.violation_decisions.values()
            ]

        if self.bot_decisions:
            data["bot_protection"] = [
                {
                    "category": d.category,
                    "asm_action": d.asm_action,
                    "decision": d.action.value,
                }
                for d in self.bot_decisions.values()
            ]

        path = Path(path)
        path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")

    @classmethod
    def load_yaml(cls, path: Union[str, Path]) -> DecisionSet:
        """Deserialise a ``DecisionSet`` from a YAML file at *path*."""
        path = Path(path)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        ds = cls()

        for entry in data.get("alarm_only_signatures", []):
            ds.add_signature(
                SignatureDecision(
                    sig_id=entry["sig_id"],
                    description=entry["description"],
                    scope=entry["scope"],
                    action=AlarmOnlyAction(entry["decision"]),
                )
            )

        for entry in data.get("alarm_only_violations", []):
            ds.add_violation(
                ViolationDecision(
                    violation=entry["violation"],
                    action=ViolationAction(entry["decision"]),
                )
            )

        for entry in data.get("bot_protection", []):
            ds.add_bot(
                BotDecision(
                    category=entry["category"],
                    asm_action=entry["asm_action"],
                    action=BotDecisionAction(entry["decision"]),
                )
            )

        return ds
