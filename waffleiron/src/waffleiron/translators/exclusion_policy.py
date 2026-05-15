"""ExclusionPolicyTranslator: converts AsmPolicy + DecisionSet → XC waf_exclusion_policy dict."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import NamedTuple

from waffleiron.decisions import AlarmOnlyAction, DecisionSet
from waffleiron.model import AsmPolicy

# Maximum number of signature contexts per exclusion rule (XC limit).
_MAX_CONTEXTS_PER_RULE = 1024


# ---------------------------------------------------------------------------
# Internal grouping key
# ---------------------------------------------------------------------------


class _GroupKey(NamedTuple):
    """Key used to coalesce exclusion contexts into a single rule."""

    path_type: str          # "any_path" or "path_prefix"
    path_value: str         # "" for any_path, the URL path for path_prefix
    context: str            # CONTEXT_ANY | CONTEXT_PARAMETER | CONTEXT_COOKIE | CONTEXT_HEADER
    context_name: str       # "" for CONTEXT_ANY, entity name otherwise


# ---------------------------------------------------------------------------
# Name sanitization helpers
# ---------------------------------------------------------------------------


def _sanitize_name(name: str) -> str:
    """Sanitize a name for XC: lowercase, alphanumeric + hyphens, max 64 chars."""
    lowered = name.lower()
    sanitized = re.sub(r"[^a-z0-9-]+", "-", lowered)
    sanitized = re.sub(r"-{2,}", "-", sanitized)
    sanitized = sanitized.strip("-")[:64].strip("-")
    if not sanitized:
        raise ValueError(f"Name {name!r} produces an empty XC resource name after sanitization")
    return sanitized


def _path_slug(path: str) -> str:
    """Convert a URL path to a kebab-case slug suitable for rule names."""
    slug = re.sub(r"[^a-z0-9]+", "-", path.lower())
    slug = slug.strip("-")
    return slug or "root"


# ---------------------------------------------------------------------------
# ExclusionPolicyTranslator
# ---------------------------------------------------------------------------


class ExclusionPolicyTranslator:
    """Translates AsmPolicy + DecisionSet to a XC waf_exclusion_policy dict."""

    @staticmethod
    def translate(policy: AsmPolicy, decisions: DecisionSet, namespace: str) -> dict:
        """Build the XC waf_exclusion_policy JSON object.

        Args:
            policy: Populated AsmPolicy intermediate model.
            decisions: User decisions for alarm-only signatures.
            namespace: Target F5 XC namespace.

        Returns:
            A dict matching the XC waf_exclusion_policy CreateSpec JSON structure.
        """
        # Collect all (group_key → list[sig_id]) for exclusion contexts.
        # Using a list so we preserve insertion order and can chunk at 1024.
        grouped: dict[_GroupKey, list[int]] = defaultdict(list)

        # Collect skip-processing rules (path → rule dict, deduped by path).
        skip_rules: dict[str, dict] = {}

        # 1. Globally disabled signatures
        for override in policy.signatures.global_overrides:
            if not override.enabled:
                key = _GroupKey("any_path", "", "CONTEXT_ANY", "")
                grouped[key].append(override.sig_id)

        # 2. Per-URL disabled signatures + waf_skip_processing for attack_signatures_check=False
        for url in policy.entities.urls:
            # 2a. Whole-URL WAF skip
            if url.attack_signatures_check is False:
                if url.name not in skip_rules:
                    slug = _path_slug(url.name)
                    skip_rules[url.name] = {
                        "metadata": {"name": f"skip-{slug}"},
                        "any_domain": {},
                        "path_prefix": url.name,
                        "waf_skip_processing": {},
                    }

            # 2b. Per-URL signature overrides
            for override in url.signature_overrides:
                if not override.enabled:
                    key = _GroupKey("path_prefix", url.name, "CONTEXT_ANY", "")
                    grouped[key].append(override.sig_id)

        # 3. Per-parameter disabled signatures
        for param in policy.entities.parameters:
            for override in param.signature_overrides:
                if not override.enabled:
                    key = _GroupKey("any_path", "", "CONTEXT_PARAMETER", param.name)
                    grouped[key].append(override.sig_id)

        # 4. Per-cookie disabled signatures
        for cookie in policy.entities.cookies:
            for override in cookie.signature_overrides:
                if not override.enabled:
                    key = _GroupKey("any_path", "", "CONTEXT_COOKIE", cookie.name)
                    grouped[key].append(override.sig_id)

        # 5. Alarm-only signatures where decision is EXCLUDE
        for override in policy.signatures.global_overrides:
            # alarm-only: enabled=True, alarm=True, block=False
            if override.enabled and override.alarm and not override.block:
                action = decisions.get_signature_action(override.sig_id)
                if action == AlarmOnlyAction.EXCLUDE:
                    key = _GroupKey("any_path", "", "CONTEXT_ANY", "")
                    grouped[key].append(override.sig_id)

        # Build exclusion rules from grouped contexts (chunked at _MAX_CONTEXTS_PER_RULE)
        exclusion_rules: list[dict] = []

        for group_key, sig_ids in grouped.items():
            # Chunk into batches of up to 1024
            for chunk_start in range(0, len(sig_ids), _MAX_CONTEXTS_PER_RULE):
                chunk = sig_ids[chunk_start : chunk_start + _MAX_CONTEXTS_PER_RULE]
                rule = ExclusionPolicyTranslator._build_exclusion_rule(group_key, chunk)
                exclusion_rules.append(rule)

        # Add skip-processing rules
        exclusion_rules.extend(skip_rules.values())

        policy_name = _sanitize_name(policy.name) + "-exclusions"
        # Truncate the suffix-appended name to 64 chars
        policy_name = policy_name[:64].rstrip("-")

        return {
            "metadata": {
                "name": policy_name,
                "namespace": namespace,
            },
            "spec": {
                "waf_exclusion_rules": exclusion_rules,
            },
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_exclusion_rule(key: _GroupKey, sig_ids: list[int]) -> dict:
        """Build a single waf_exclusion_rule dict for the given key and sig IDs."""
        contexts = [
            {
                "signature_id": sig_id,
                "context": key.context,
                "context_name": key.context_name,
            }
            for sig_id in sig_ids
        ]

        # Build a descriptive rule name
        if len(sig_ids) == 1:
            sig_label = str(sig_ids[0])
        else:
            sig_label = f"{sig_ids[0]}-plus-{len(sig_ids) - 1}"

        if key.path_type == "any_path":
            if key.context == "CONTEXT_ANY":
                rule_name = f"excl-global-sig-{sig_label}"
            elif key.context == "CONTEXT_PARAMETER":
                rule_name = f"excl-param-{_path_slug(key.context_name)}-sig-{sig_label}"
            elif key.context == "CONTEXT_COOKIE":
                rule_name = f"excl-cookie-{_path_slug(key.context_name)}-sig-{sig_label}"
            elif key.context == "CONTEXT_HEADER":
                rule_name = f"excl-header-{_path_slug(key.context_name)}-sig-{sig_label}"
            else:
                rule_name = f"excl-sig-{sig_label}"
        else:
            # path_prefix scoped
            slug = _path_slug(key.path_value)
            rule_name = f"excl-url-{slug}-sig-{sig_label}"

        # Truncate to 64 chars safely
        rule_name = rule_name[:64].rstrip("-")

        rule: dict = {
            "metadata": {"name": rule_name},
            "any_domain": {},
        }

        if key.path_type == "any_path":
            rule["any_path"] = {}
        else:
            rule["path_prefix"] = key.path_value

        rule["app_firewall_detection_control"] = {
            "exclude_signature_contexts": contexts,
        }

        return rule
