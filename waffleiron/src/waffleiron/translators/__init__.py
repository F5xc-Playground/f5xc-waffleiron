"""Translation orchestrator — wires all four AWAF-to-XC translators."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from waffleiron.decisions import DecisionSet
from waffleiron.model import AsmPolicy
from waffleiron.translators.app_firewall import AppFirewallTranslator
from waffleiron.translators.exclusion_policy import ExclusionPolicyTranslator
from waffleiron.translators.http_lb_patch import HttpLbPatchTranslator
from waffleiron.translators.service_policy import ServicePolicyTranslator
from waffleiron.translators.utils import XC_RESOURCE_TYPES


@dataclass
class TranslationResult:
    """Container for all XC objects produced by translation."""

    app_firewall: dict
    exclusion_policy: Optional[dict]
    service_policy: Optional[dict]
    http_lb_patch: Optional[dict]

    def output_files(self) -> dict[str, dict]:
        """Return {relative_path: object_dict} for backup-tool-compatible output."""
        files: dict[str, dict] = {}

        for attr_name in ("app_firewall", "exclusion_policy", "service_policy"):
            obj = getattr(self, attr_name)
            if obj is None:
                continue
            kind_info = XC_RESOURCE_TYPES[attr_name]
            name = obj["metadata"]["name"]
            path = f"{kind_info['kind']}/{name}.json"
            files[path] = obj

        if self.http_lb_patch is not None:
            files["_advisory/http_lb_patch.json"] = self.http_lb_patch

        return files


def translate(
    policy: AsmPolicy,
    decisions: DecisionSet,
    namespaces: str | dict[str, str],
    name_override: str | None = None,
) -> TranslationResult:
    """Run all four translators and return a unified result.

    Args:
        namespaces: Either a single namespace string (all objects) or a dict
            mapping object keys to namespaces with a "default" fallback.
    """
    def _ns(key: str) -> str:
        if isinstance(namespaces, str):
            return namespaces
        return namespaces.get(key, namespaces.get("default", "default"))

    return TranslationResult(
        app_firewall=AppFirewallTranslator.translate(policy, _ns("app_firewall"), name_override),
        exclusion_policy=ExclusionPolicyTranslator.translate(policy, decisions, _ns("exclusion_policy"), name_override),
        service_policy=ServicePolicyTranslator.translate(policy, _ns("service_policy"), name_override),
        http_lb_patch=HttpLbPatchTranslator.translate(policy),
    )
