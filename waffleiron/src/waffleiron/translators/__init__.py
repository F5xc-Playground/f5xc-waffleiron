"""Translation orchestrator — wires all four ASM-to-XC translators."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from waffleiron.decisions import DecisionSet
from waffleiron.model import AsmPolicy
from waffleiron.translators.app_firewall import AppFirewallTranslator
from waffleiron.translators.exclusion_policy import ExclusionPolicyTranslator
from waffleiron.translators.http_lb_patch import HttpLbPatchTranslator
from waffleiron.translators.service_policy import ServicePolicyTranslator


@dataclass
class TranslationResult:
    """Container for all XC objects produced by translation."""

    app_firewall: dict
    exclusion_policy: dict
    service_policy: Optional[dict]
    http_lb_patch: Optional[dict]


def translate(
    policy: AsmPolicy,
    decisions: DecisionSet,
    namespace: str,
    name_override: str | None = None,
) -> TranslationResult:
    """Run all four translators and return a unified result."""
    return TranslationResult(
        app_firewall=AppFirewallTranslator.translate(policy, namespace, name_override),
        exclusion_policy=ExclusionPolicyTranslator.translate(policy, decisions, namespace, name_override),
        service_policy=ServicePolicyTranslator.translate(policy, namespace, name_override),
        http_lb_patch=HttpLbPatchTranslator.translate(policy),
    )
