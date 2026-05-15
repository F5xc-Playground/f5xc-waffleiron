"""AppFirewallTranslator: converts AsmPolicy → XC app_firewall CreateSpec dict."""

from __future__ import annotations

from waffleiron.model import AccuracyLevel, AsmPolicy, EnforcementMode
from waffleiron.translators.mappings import (
    ASM_BOT_CATEGORY_TO_XC,
    ASM_SIG_SET_TO_XC_ATTACK_TYPE,
    ASM_VIOLATION_TO_XC_VIOLATIONS,
    translate_blocking_page_vars,
)
from waffleiron.translators.utils import sanitize_xc_name

_BOT_ACTION_MAP: dict[str, str] = {
    "block": "BLOCK",
    "report": "REPORT",
    "ignore": "IGNORE",
}

_HTTP_CODE_TO_XC: dict[int, str] = {
    200: "OK",
    400: "BadRequest",
    401: "Unauthorized",
    403: "Forbidden",
    404: "NotFound",
}


class AppFirewallTranslator:
    """Translates an AsmPolicy intermediate model to an XC app_firewall CreateSpec."""

    @staticmethod
    def translate(policy: AsmPolicy, namespace: str) -> dict:
        """Return the XC app_firewall CreateSpec as a Python dict.

        Args:
            policy: Populated AsmPolicy intermediate model.
            namespace: Target F5 XC namespace.

        Returns:
            A dict matching the XC app_firewall CreateSpec JSON structure.
        """
        spec: dict = {}

        # --- Enforcement mode (oneof: blocking | monitoring) ---
        if policy.enforcement_mode == EnforcementMode.BLOCKING:
            spec["blocking"] = {}
        else:
            spec["monitoring"] = {}

        # --- Detection settings ---
        spec["detection_settings"] = AppFirewallTranslator._build_detection_settings(policy)

        # --- Bot protection (oneof: bot_protection_setting | default_bot_setting) ---
        bot_setting = AppFirewallTranslator._build_bot_protection(policy)
        spec.update(bot_setting)

        # --- Blocking page (oneof: blocking_page | use_default_blocking_page) ---
        bp_setting = AppFirewallTranslator._build_blocking_page(policy)
        spec.update(bp_setting)

        # --- Anonymization (oneof: custom_anonymization | default_anonymization) ---
        anon_setting = AppFirewallTranslator._build_anonymization(policy)
        spec.update(anon_setting)

        # --- Response codes (oneof: allowed_response_codes | allow_all_response_codes) ---
        rc_setting = AppFirewallTranslator._build_response_codes(policy)
        spec.update(rc_setting)

        return {
            "metadata": {
                "name": sanitize_xc_name(policy.name),
                "namespace": namespace,
            },
            "spec": spec,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_detection_settings(policy: AsmPolicy) -> dict:
        detection: dict = {}

        # Signature selection setting (accuracy + attack type settings, merged into one key)
        detection["signature_selection_setting"] = AppFirewallTranslator._build_sig_selection(
            policy
        )

        # Violation settings (oneof: disabled_violation_types | default_violation_settings)
        detection.update(AppFirewallTranslator._build_violation_settings(policy))

        # Staging settings (oneof: stage_new_and_updated_signatures | disable_staging)
        detection.update(AppFirewallTranslator._build_staging(policy))

        # Threat campaigns (oneof: enable_threat_campaigns | disable_threat_campaigns)
        if policy.signatures.threat_campaigns_enabled:
            detection["enable_threat_campaigns"] = {}
        else:
            detection["disable_threat_campaigns"] = {}

        # False positive suppression — always enabled
        detection["enable_suppression"] = {}

        return detection

    @staticmethod
    def _build_sig_selection(policy: AsmPolicy) -> dict:
        """Build the signature_selection_setting dict.

        Contains:
        - Accuracy level choice (oneof)
        - Attack type settings (oneof: attack_type_settings | default_attack_type_settings)
        """
        sig_sel: dict = {}

        # Accuracy level (oneof)
        level = policy.signatures.accuracy_level
        if level == AccuracyLevel.HIGH:
            sig_sel["only_high_accuracy_signatures"] = {}
        elif level == AccuracyLevel.HIGH_MEDIUM:
            sig_sel["high_medium_accuracy_signatures"] = {}
        else:  # ALL
            sig_sel["high_medium_low_accuracy_signatures"] = {}

        # Attack type settings: collect disabled sig sets
        disabled_attack_types = []
        for sig_set in policy.signature_sets:
            if not sig_set.enabled:
                xc_type = ASM_SIG_SET_TO_XC_ATTACK_TYPE.get(sig_set.name)
                if xc_type:
                    disabled_attack_types.append(xc_type)

        if disabled_attack_types:
            sig_sel["attack_type_settings"] = {
                "disabled_attack_types": disabled_attack_types,
            }
        else:
            sig_sel["default_attack_type_settings"] = {}

        return sig_sel

    @staticmethod
    def _build_violation_settings(policy: AsmPolicy) -> dict:
        """Build violation_settings dict.

        Disabled violations: alarm=False AND block=False.
        Alarm-only violations (alarm=True, block=False) are NOT disabled.
        """
        disabled_xc_violations: list[str] = []
        for violation in policy.violations:
            if not violation.alarm and not violation.block:
                xc_list = ASM_VIOLATION_TO_XC_VIOLATIONS.get(violation.name)
                if xc_list:
                    disabled_xc_violations.extend(xc_list)

        if disabled_xc_violations:
            return {"disabled_violation_types": disabled_xc_violations}
        return {"default_violation_settings": {}}

    @staticmethod
    def _build_staging(policy: AsmPolicy) -> dict:
        if policy.signatures.staging_enabled:
            return {
                "stage_new_and_updated_signatures": {
                    "staging_period": policy.signatures.staging_period,
                }
            }
        return {"disable_staging": {}}

    @staticmethod
    def _build_bot_protection(policy: AsmPolicy) -> dict:
        """Build bot protection setting (oneof: bot_protection_setting | default_bot_setting)."""
        bd = policy.bot_defense
        if not bd.enabled or not bd.categories:
            return {"default_bot_setting": {}}

        bot_setting: dict = {}
        for category in bd.categories:
            xc_key = ASM_BOT_CATEGORY_TO_XC.get(category.name)
            if xc_key is None:
                continue
            xc_action = _BOT_ACTION_MAP.get(category.action, "BLOCK")
            bot_setting[xc_key] = xc_action

        if bot_setting:
            return {"bot_protection_setting": bot_setting}
        return {"default_bot_setting": {}}

    @staticmethod
    def _build_blocking_page(policy: AsmPolicy) -> dict:
        """Build blocking page setting (oneof: blocking_page | use_default_blocking_page)."""
        bp = policy.blocking_page
        if bp.enabled and bp.custom_html:
            translated_html = translate_blocking_page_vars(bp.custom_html)
            xc_code = _HTTP_CODE_TO_XC.get(bp.response_code, "Forbidden")
            return {
                "blocking_page": {
                    "blocking_page_body": translated_html,
                    "response_code": xc_code,
                }
            }
        return {"use_default_blocking_page": {}}

    @staticmethod
    def _build_anonymization(policy: AsmPolicy) -> dict:
        """Build anonymization setting (oneof: custom_anonymization | default_anonymization).

        Collects:
        - Sensitive parameters → query_parameter entries
        - (Future: sensitive cookies, sensitive headers — model doesn't have those flags yet)
        """
        anon_config: list[dict] = []

        for param in policy.entities.parameters:
            if param.sensitive:
                anon_config.append({"query_parameter": {"query_param_name": param.name}})

        if anon_config:
            return {"custom_anonymization": {"anonymization_config": anon_config}}
        return {"default_anonymization": {}}

    @staticmethod
    def _build_response_codes(policy: AsmPolicy) -> dict:
        """Build response codes setting (oneof: allowed_response_codes | allow_all_response_codes)."""
        if policy.allowed_response_codes:
            return {"allowed_response_codes": {"response_code": policy.allowed_response_codes}}
        return {"allow_all_response_codes": {}}
