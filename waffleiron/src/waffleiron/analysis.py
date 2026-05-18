"""Analysis engine — examines an AsmPolicy and produces gap/limit/decision reports.

The ``analyze`` function is the single entry point.  It returns an
``AnalysisResult`` that downstream code (CLI reporters, translators) can
consume without needing to re-inspect the raw policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from waffleiron.model import AsmPolicy, CustomSignature, EnforcementMode, SignatureOverride
from waffleiron.translators.mappings import (
    ASM_IP_INTEL_TO_XC,
    find_unsupported_blocking_page_vars,
)

# ---------------------------------------------------------------------------
# Limits — thresholds that trigger warnings
# ---------------------------------------------------------------------------

_EXCLUSION_LIMIT = 256
_ANONYMIZATION_LIMIT = 64

# Actions that have no direct XC WAF equivalent
_UNTRANSLATABLE_BOT_ACTIONS = frozenset({"challenge", "captcha", "rate-limit"})

# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class AlarmOnlySignature:
    """A signature override that is alarm-only (enabled, alarm, not block)."""

    sig_id: int
    description: str
    scope: str


@dataclass
class AlarmOnlyViolation:
    """A violation that is alarm-only (alarm=True, block=False)."""

    violation_name: str
    alarm: bool
    block: bool


@dataclass
class PositiveSecuritySummary:
    """Counts of positive-security entity definitions."""

    url_count: int = 0
    wildcard_url_count: int = 0
    parameter_count: int = 0
    constrained_parameter_count: int = 0
    file_type_count: int = 0
    cookie_count: int = 0
    mandatory_header_count: int = 0
    disallowed_file_type_count: int = 0
    url_method_restriction_count: int = 0
    global_method_restriction: bool = False


@dataclass
class PositiveSecurityTranslated:
    """Tracks which positive security features were translated to service policy rules."""

    filetype_deny_count: int = 0
    method_deny_count: int = 0
    filetype_gated: bool = False
    method_gated: bool = False


@dataclass
class UntranslatableSummary:
    """Features that cannot be directly translated to XC WAF."""

    custom_signature_count: int = 0
    session_tracking_enabled: bool = False
    session_hijacking_enabled: bool = False
    brute_force_enabled: bool = False
    custom_signatures: list[CustomSignature] = field(default_factory=list)


@dataclass
class BotGap:
    """A bot category whose ASM action has no XC equivalent."""

    category: str
    asm_action: str
    reason: str


@dataclass
class BlockingPageGap:
    """A blocking page template variable that has no XC equivalent."""

    variable: str
    reason: str


@dataclass
class IpIntelGap:
    """An IP intelligence category that has no XC equivalent."""

    category: str
    reason: str


@dataclass
class LimitWarning:
    """A warning that a resource count exceeds XC limits."""

    resource: str
    count: int
    limit: int
    message: str


@dataclass
class ConversionSummary:
    """High-level conversion statistics."""

    total: int = 0
    directly_translated: int = 0
    translated_with_loss: int = 0
    decisions_required: int = 0
    cannot_translate: int = 0


@dataclass
class AnalysisResult:
    """Top-level container returned by ``analyze``."""

    alarm_only_signatures: list[AlarmOnlySignature] = field(default_factory=list)
    alarm_only_violations: list[AlarmOnlyViolation] = field(default_factory=list)
    positive_security: PositiveSecuritySummary = field(default_factory=PositiveSecuritySummary)
    positive_security_translated: PositiveSecurityTranslated = field(default_factory=PositiveSecurityTranslated)
    untranslatable: UntranslatableSummary = field(default_factory=UntranslatableSummary)
    bot_gaps: list[BotGap] = field(default_factory=list)
    blocking_page_gaps: list[BlockingPageGap] = field(default_factory=list)
    ip_intel_gaps: list[IpIntelGap] = field(default_factory=list)
    warnings: list[LimitWarning] = field(default_factory=list)
    summary: ConversionSummary = field(default_factory=ConversionSummary)
    csrf_enabled: bool = False
    data_guard_enabled: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_alarm_only(override: SignatureOverride) -> bool:
    """Return True if the override is enabled, alarm-only, and not blocking."""
    return override.enabled and override.alarm and not override.block


def _collect_alarm_only_signatures(policy: AsmPolicy) -> list[AlarmOnlySignature]:
    """Scan global and entity-level overrides for alarm-only signatures."""
    results: list[AlarmOnlySignature] = []

    for ov in policy.signatures.global_overrides:
        if _is_alarm_only(ov):
            results.append(AlarmOnlySignature(sig_id=ov.sig_id, description="", scope="global"))

    for url in policy.entities.urls:
        for ov in url.signature_overrides:
            if _is_alarm_only(ov):
                results.append(
                    AlarmOnlySignature(sig_id=ov.sig_id, description="", scope=f"url:{url.name}")
                )

    for param in policy.entities.parameters:
        for ov in param.signature_overrides:
            if _is_alarm_only(ov):
                results.append(
                    AlarmOnlySignature(
                        sig_id=ov.sig_id, description="", scope=f"parameter:{param.name}"
                    )
                )

    for cookie in policy.entities.cookies:
        for ov in cookie.signature_overrides:
            if _is_alarm_only(ov):
                results.append(
                    AlarmOnlySignature(
                        sig_id=ov.sig_id, description="", scope=f"cookie:{cookie.name}"
                    )
                )

    return results


def _collect_alarm_only_violations(policy: AsmPolicy) -> list[AlarmOnlyViolation]:
    """Return violations that are alarm-only (alarm=True, block=False)."""
    return [
        AlarmOnlyViolation(violation_name=v.name, alarm=v.alarm, block=v.block)
        for v in policy.violations
        if v.alarm and not v.block
    ]


def _build_positive_security(policy: AsmPolicy) -> PositiveSecuritySummary:
    """Count positive-security entity definitions."""
    entities = policy.entities
    constrained = sum(
        1
        for p in entities.parameters
        if p.value_type is not None and p.value_type != "user-input"
    )
    wildcard_urls = sum(
        1
        for u in entities.urls
        if u.type == "wildcard" or (u.name and "*" in u.name)
    )
    mandatory_headers = sum(1 for h in entities.headers if h.mandatory)
    disallowed_file_types = sum(1 for ft in entities.file_types if ft.allowed is False)
    url_method_restrictions = sum(1 for u in entities.urls if u.method is not None)

    return PositiveSecuritySummary(
        url_count=len(entities.urls),
        wildcard_url_count=wildcard_urls,
        parameter_count=len(entities.parameters),
        constrained_parameter_count=constrained,
        file_type_count=len(entities.file_types),
        cookie_count=len(entities.cookies),
        mandatory_header_count=mandatory_headers,
        disallowed_file_type_count=disallowed_file_types,
        url_method_restriction_count=url_method_restrictions,
        global_method_restriction=len(entities.methods) > 0,
    )


def _build_untranslatable(policy: AsmPolicy) -> UntranslatableSummary:
    """Identify features that have no direct XC WAF equivalent."""
    return UntranslatableSummary(
        custom_signature_count=len(policy.custom_signatures),
        session_tracking_enabled=policy.session_tracking.enabled,
        session_hijacking_enabled=policy.session_tracking.hijacking_prevention,
        brute_force_enabled=policy.brute_force.enabled,
        custom_signatures=list(policy.custom_signatures),
    )


def _is_violation_blocking(policy: AsmPolicy, violation_name: str) -> bool:
    """Return True if the violation is blocking. Defaults to True if not present."""
    for v in policy.violations:
        if v.name == violation_name:
            return v.block
    return True


def _build_positive_security_translated(policy: AsmPolicy) -> PositiveSecurityTranslated:
    """Determine which positive security features translate to service policy rules."""
    is_blocking = policy.enforcement_mode == EnforcementMode.BLOCKING

    filetype_can_enforce = is_blocking and _is_violation_blocking(policy, "VIOL_FILETYPE")
    method_can_enforce = is_blocking and _is_violation_blocking(policy, "VIOL_METHOD")

    disallowed_ft_count = sum(1 for ft in policy.entities.file_types if ft.allowed is False)
    method_url_count = sum(1 for u in policy.entities.urls if u.method is not None)
    has_global_methods = len(policy.entities.methods) > 0

    ft_translated = disallowed_ft_count if filetype_can_enforce else 0
    method_translated = (
        (method_url_count + (1 if has_global_methods else 0))
        if method_can_enforce
        else 0
    )

    return PositiveSecurityTranslated(
        filetype_deny_count=ft_translated,
        method_deny_count=method_translated,
        filetype_gated=not filetype_can_enforce and disallowed_ft_count > 0,
        method_gated=not method_can_enforce and (method_url_count > 0 or has_global_methods),
    )


def _collect_bot_gaps(policy: AsmPolicy) -> list[BotGap]:
    """Find bot categories whose ASM action cannot be mapped to XC."""
    gaps: list[BotGap] = []
    for cat in policy.bot_defense.categories:
        if cat.action in _UNTRANSLATABLE_BOT_ACTIONS:
            gaps.append(
                BotGap(
                    category=cat.name,
                    asm_action=cat.action,
                    reason=f"XC WAF has no equivalent of '{cat.action}' for bot categories",
                )
            )
    return gaps


def _collect_blocking_page_gaps(policy: AsmPolicy) -> list[BlockingPageGap]:
    """Detect unsupported template variables in the custom blocking page."""
    if not policy.blocking_page.enabled or not policy.blocking_page.custom_html:
        return []
    unsupported = find_unsupported_blocking_page_vars(policy.blocking_page.custom_html)
    return [
        BlockingPageGap(
            variable=var,
            reason=f"XC WAF does not support the template variable {var}",
        )
        for var in unsupported
    ]


def _collect_ip_intel_gaps(policy: AsmPolicy) -> list[IpIntelGap]:
    """Find IP intelligence categories that cannot be mapped to XC."""
    gaps: list[IpIntelGap] = []
    for category in policy.ip_intelligence.categories:
        if category.name not in ASM_IP_INTEL_TO_XC:
            gaps.append(
                IpIntelGap(
                    category=category.name,
                    reason=f"No XC IPThreatCategory equivalent for '{category.name}'",
                )
            )
    return gaps


def _estimate_exclusion_count(policy: AsmPolicy) -> int:
    """Estimate the number of XC exclusion rules this policy would need.

    Each disabled signature override and each entity with attack_signatures_check=False
    contributes one exclusion rule.
    """
    count = 0

    # Global disabled / alarm-only overrides each need an exclusion rule
    for ov in policy.signatures.global_overrides:
        if _is_alarm_only(ov) or (not ov.enabled):
            count += 1

    # Entity-level disabled overrides
    for url in policy.entities.urls:
        if url.attack_signatures_check is False:
            count += 1
        count += len(url.signature_overrides)

    for param in policy.entities.parameters:
        if param.attack_signatures_check is False:
            count += 1
        count += len(param.signature_overrides)

    for cookie in policy.entities.cookies:
        if cookie.attack_signatures_check is False:
            count += 1
        count += len(cookie.signature_overrides)

    return count


def _estimate_anonymization_count(policy: AsmPolicy) -> int:
    """Count items that would generate anonymization / sensitive-data rules."""
    count = 0
    for param in policy.entities.parameters:
        if param.sensitive:
            count += 1
    if policy.data_guard.enabled:
        count += len(policy.data_guard.custom_patterns)
        if policy.data_guard.credit_cards:
            count += 1
        if policy.data_guard.ssn:
            count += 1
    return count


def _check_limits(policy: AsmPolicy) -> list[LimitWarning]:
    """Emit warnings when projected XC resource counts exceed limits."""
    warnings: list[LimitWarning] = []

    exclusion_count = _estimate_exclusion_count(policy)
    if exclusion_count > _EXCLUSION_LIMIT:
        warnings.append(
            LimitWarning(
                resource="exclusion_rules",
                count=exclusion_count,
                limit=_EXCLUSION_LIMIT,
                message=(
                    f"Estimated exclusion rule count ({exclusion_count}) exceeds "
                    f"XC WAF limit of {_EXCLUSION_LIMIT}. Consider consolidating overrides."
                ),
            )
        )

    anonymization_count = _estimate_anonymization_count(policy)
    if anonymization_count > _ANONYMIZATION_LIMIT:
        warnings.append(
            LimitWarning(
                resource="anonymization_rules",
                count=anonymization_count,
                limit=_ANONYMIZATION_LIMIT,
                message=(
                    f"Estimated anonymization rule count ({anonymization_count}) exceeds "
                    f"XC WAF limit of {_ANONYMIZATION_LIMIT}. Consider reducing sensitive parameters."
                ),
            )
        )

    return warnings


def _build_summary(
    alarm_sigs: list[AlarmOnlySignature],
    alarm_viols: list[AlarmOnlyViolation],
    bot_gaps: list[BotGap],
    untranslatable: UntranslatableSummary,
    policy: AsmPolicy,
) -> ConversionSummary:
    """Compute high-level conversion statistics.

    - *total*: overall number of policy items to convert.
    - *decisions_required*: alarm-only sigs + alarm-only violations (user must choose).
    - *cannot_translate*: custom signatures + bot gaps (no XC equivalent).
    - *translated_with_loss*: untranslatable features that are flagged but partially mapped.
    - *directly_translated*: everything else.
    """
    decisions = len(alarm_sigs) + len(alarm_viols)
    cannot = untranslatable.custom_signature_count + len(bot_gaps)

    # "translated with loss" — features that exist but lose fidelity
    loss = 0
    if untranslatable.session_tracking_enabled:
        loss += 1
    if untranslatable.brute_force_enabled:
        loss += 1

    # Total items: overrides + violations + entities + bot categories + custom sigs
    total = (
        len(policy.signatures.global_overrides)
        + len(policy.violations)
        + len(policy.entities.urls)
        + len(policy.entities.parameters)
        + len(policy.entities.file_types)
        + len(policy.entities.cookies)
        + len(policy.entities.headers)
        + len(policy.bot_defense.categories)
        + len(policy.custom_signatures)
        + len(policy.whitelist_ips)
        + len(policy.geolocation.disallowed)
    )

    directly = total - decisions - cannot - loss

    return ConversionSummary(
        total=total,
        directly_translated=max(directly, 0),
        translated_with_loss=loss,
        decisions_required=decisions,
        cannot_translate=cannot,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(policy: AsmPolicy) -> AnalysisResult:
    """Analyze an ASM policy and return structured gap/limit/decision data."""
    alarm_sigs = _collect_alarm_only_signatures(policy)
    alarm_viols = _collect_alarm_only_violations(policy)
    pos_sec = _build_positive_security(policy)
    pos_sec_translated = _build_positive_security_translated(policy)
    untranslatable = _build_untranslatable(policy)
    bot_gaps = _collect_bot_gaps(policy)
    blocking_page_gaps = _collect_blocking_page_gaps(policy)
    ip_intel_gaps = _collect_ip_intel_gaps(policy)
    warnings = _check_limits(policy)
    summary = _build_summary(alarm_sigs, alarm_viols, bot_gaps, untranslatable, policy)

    return AnalysisResult(
        alarm_only_signatures=alarm_sigs,
        alarm_only_violations=alarm_viols,
        positive_security=pos_sec,
        positive_security_translated=pos_sec_translated,
        untranslatable=untranslatable,
        bot_gaps=bot_gaps,
        blocking_page_gaps=blocking_page_gaps,
        ip_intel_gaps=ip_intel_gaps,
        warnings=warnings,
        summary=summary,
        csrf_enabled=policy.csrf.enabled,
        data_guard_enabled=policy.data_guard.enabled,
    )
