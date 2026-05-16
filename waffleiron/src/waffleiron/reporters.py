"""Gap report generator — produces JSON and Markdown conversion gap reports.

The ``generate_report`` function is the single entry point.  It accepts an
``AnalysisResult`` and a ``DecisionSet``, and renders either a JSON or Markdown
document describing the gaps between the source AWAF policy and what can be
expressed in XC WAF.
"""

from __future__ import annotations

import json
from enum import Enum

from waffleiron.analysis import AnalysisResult
from waffleiron.decisions import DecisionSet


# ---------------------------------------------------------------------------
# Public enum
# ---------------------------------------------------------------------------


class ReportFormat(Enum):
    JSON = "json"
    MARKDOWN = "markdown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_report(
    analysis: AnalysisResult,
    decisions: DecisionSet,
    format: ReportFormat,
    policy_name: str = "",
    enforcement_mode: str = "",
) -> str:
    """Generate a gap report in the requested format.

    Args:
        analysis:         Structured analysis of the AWAF policy.
        decisions:        User decisions for alarm-only items.
        format:           ``ReportFormat.JSON`` or ``ReportFormat.MARKDOWN``.
        policy_name:      Name of the source AWAF policy (optional).
        enforcement_mode: Enforcement mode string (optional).

    Returns:
        A string containing the formatted report.
    """
    if format is ReportFormat.JSON:
        return _render_json(analysis, decisions, policy_name, enforcement_mode)
    return _render_markdown(analysis, decisions, policy_name, enforcement_mode)


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------


def _render_json(
    analysis: AnalysisResult,
    decisions: DecisionSet,
    policy_name: str,
    enforcement_mode: str,
) -> str:
    s = analysis.summary
    data: dict = {
        "policy_name": policy_name,
        "enforcement_mode": enforcement_mode,
        "summary": {
            "total": s.total,
            "directly_translated": s.directly_translated,
            "translated_with_loss": s.translated_with_loss,
            "decisions_required": s.decisions_required,
            "cannot_translate": s.cannot_translate,
        },
        "alarm_only_signatures": [
            {
                "sig_id": sig.sig_id,
                "description": sig.description,
                "scope": sig.scope,
                "decision": decisions.get_signature_action(sig.sig_id).value,
            }
            for sig in analysis.alarm_only_signatures
        ],
        "alarm_only_violations": [
            {
                "violation": v.violation_name,
                "decision": decisions.get_violation_action(v.violation_name).value,
            }
            for v in analysis.alarm_only_violations
        ],
        "positive_security": {
            "url_count": analysis.positive_security.url_count,
            "wildcard_url_count": analysis.positive_security.wildcard_url_count,
            "parameter_count": analysis.positive_security.parameter_count,
            "constrained_parameter_count": analysis.positive_security.constrained_parameter_count,
            "file_type_count": analysis.positive_security.file_type_count,
            "cookie_count": analysis.positive_security.cookie_count,
            "mandatory_header_count": analysis.positive_security.mandatory_header_count,
        },
        "untranslatable": {
            "custom_signature_count": analysis.untranslatable.custom_signature_count,
            "session_tracking_enabled": analysis.untranslatable.session_tracking_enabled,
            "session_hijacking_enabled": analysis.untranslatable.session_hijacking_enabled,
            "brute_force_enabled": analysis.untranslatable.brute_force_enabled,
            "custom_signatures": [
                {
                    "id": cs.id,
                    "name": cs.name,
                    "pattern": cs.pattern,
                    "scope": cs.scope,
                }
                for cs in analysis.untranslatable.custom_signatures
            ],
        },
        "bot_gaps": [
            {
                "category": gap.category,
                "asm_action": gap.asm_action,
                "reason": gap.reason,
            }
            for gap in analysis.bot_gaps
        ],
        "warnings": [
            {
                "resource": w.resource,
                "count": w.count,
                "limit": w.limit,
                "message": w.message,
            }
            for w in analysis.warnings
        ],
        "xc_recommendations": _build_recommendations(analysis),
    }
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------


def _render_markdown(
    analysis: AnalysisResult,
    decisions: DecisionSet,
    policy_name: str,
    enforcement_mode: str,
) -> str:
    lines: list[str] = []

    # --- Header -------------------------------------------------------
    lines.append("# AWAF → XC Conversion Gap Report")
    lines.append("")
    lines.append(f"**Source policy:** {policy_name}")
    lines.append(f"**Enforcement mode:** {enforcement_mode}")
    lines.append("")

    # --- Summary ------------------------------------------------------
    s = analysis.summary
    pct = f" ({s.directly_translated * 100 // s.total}%)" if s.total else ""
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|------:|")
    lines.append(f"| Total features analyzed | {s.total} |")
    lines.append(f"| Directly translated | {s.directly_translated}{pct} |")
    lines.append(f"| Translated with loss | {s.translated_with_loss} |")
    lines.append(f"| Decisions required | {s.decisions_required} |")
    lines.append(f"| Cannot translate | {s.cannot_translate} |")
    lines.append("")

    # --- Alarm-Only Signatures ----------------------------------------
    lines.append("## Alarm-Only Signatures")
    lines.append("")
    if analysis.alarm_only_signatures:
        lines.append("| Sig ID | Description | Scope | Decision |")
        lines.append("|--------|-------------|-------|----------|")
        for sig in analysis.alarm_only_signatures:
            decision = decisions.get_signature_action(sig.sig_id).value
            desc = sig.description or ""
            lines.append(f"| {sig.sig_id} | {desc} | {sig.scope} | {decision} |")
    else:
        lines.append("_None_")
    lines.append("")

    # --- Alarm-Only Violations ----------------------------------------
    lines.append("## Alarm-Only Violations")
    lines.append("")
    if analysis.alarm_only_violations:
        lines.append("| Violation | Decision |")
        lines.append("|-----------|----------|")
        for v in analysis.alarm_only_violations:
            decision = decisions.get_violation_action(v.violation_name).value
            lines.append(f"| {v.violation_name} | {decision} |")
    else:
        lines.append("_None_")
    lines.append("")

    # --- Positive Security --------------------------------------------
    ps = analysis.positive_security
    lines.append("## Positive Security (Cannot Translate)")
    lines.append("")
    lines.append("These AWAF positive security entities have no XC equivalent:")
    lines.append("")
    lines.append("| Entity Type | Count |")
    lines.append("|-------------|------:|")
    lines.append(f"| URL entities | {ps.url_count} ({ps.wildcard_url_count} wildcard) |")
    lines.append(f"| Parameters with value constraints | {ps.constrained_parameter_count} |")
    lines.append(f"| File types | {ps.file_type_count} |")
    lines.append(f"| Cookies | {ps.cookie_count} |")
    lines.append(f"| Mandatory headers | {ps.mandatory_header_count} |")
    lines.append("")

    # --- Custom Signatures --------------------------------------------
    custom_sigs = analysis.untranslatable.custom_signatures
    lines.append("## Custom Signatures (Cannot Translate)")
    lines.append("")
    if custom_sigs:
        lines.append("| ID | Name | Pattern |")
        lines.append("|----|------|---------|")
        for cs in custom_sigs:
            lines.append(f"| {cs.id} | {cs.name} | `{cs.pattern}` |")
    else:
        lines.append("_None_")
    lines.append("")

    # --- Untranslatable Features -------------------------------------
    u = analysis.untranslatable
    lines.append("## Untranslatable Features")
    lines.append("")
    lines.append("| Feature | Status |")
    lines.append("|---------|--------|")
    lines.append(f"| Session tracking | {'Enabled' if u.session_tracking_enabled else 'Disabled'} |")
    lines.append(
        f"| Session hijacking prevention | {'Enabled' if u.session_hijacking_enabled else 'Disabled'} |"
    )
    lines.append(f"| Brute force detection | {'Enabled' if u.brute_force_enabled else 'Disabled'} |")
    lines.append("")

    # --- Bot Protection Gaps ------------------------------------------
    lines.append("## Bot Protection Gaps")
    lines.append("")
    if analysis.bot_gaps:
        lines.append("| Category | AWAF Action | XC Support | Notes |")
        lines.append("|----------|------------|------------|-------|")
        for gap in analysis.bot_gaps:
            lines.append(f"| {gap.category} | {gap.asm_action} | None | {gap.reason} |")
    else:
        lines.append("_None_")
    lines.append("")

    # --- Warnings -----------------------------------------------------
    lines.append("## Warnings")
    lines.append("")
    if analysis.warnings:
        lines.append("| Warning |")
        lines.append("|---------|")
        for w in analysis.warnings:
            lines.append(f"| {w.message} |")
    else:
        lines.append("_None_")
    lines.append("")

    # --- XC Feature Recommendations -----------------------------------
    lines.append("## XC Feature Recommendations")
    lines.append("")
    recommendations = _build_recommendations(analysis)
    if recommendations:
        lines.append("| Feature | Why |")
        lines.append("|---------|-----|")
        for rec in recommendations:
            lines.append(f"| {rec['feature']} | {rec['why']} |")
    else:
        lines.append("_No specific recommendations._")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Shared recommendation builder
# ---------------------------------------------------------------------------


def _build_recommendations(analysis: AnalysisResult) -> list[dict]:
    """Return a list of XC feature recommendations based on the analysis."""
    recs: list[dict] = []

    if analysis.alarm_only_signatures:
        recs.append(
            {
                "feature": "AI Risk-Based Blocking",
                "why": (
                    f"Consider for alarm-only signatures ({len(analysis.alarm_only_signatures)} found) "
                    "that cannot be cleanly excluded or enforced."
                ),
            }
        )

    has_challenge_or_captcha = any(
        gap.asm_action in {"challenge", "captcha"} for gap in analysis.bot_gaps
    )
    if has_challenge_or_captcha:
        recs.append(
            {
                "feature": "Bot Defense Advanced",
                "why": "For challenge/captcha actions that have no direct XC WAF equivalent.",
            }
        )

    if analysis.untranslatable.brute_force_enabled:
        recs.append(
            {
                "feature": "Rate Limiter",
                "why": "For brute force detection, which cannot be directly translated.",
            }
        )

    return recs
