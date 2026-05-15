"""HttpLbPatchTranslator: converts CSRF and Data Guard settings → HTTP LB patch fields."""

from __future__ import annotations

from waffleiron.model import AsmPolicy


class HttpLbPatchTranslator:
    """Translates CSRF and Data Guard settings from an AsmPolicy into HTTP LB patch fields.

    Returns None when neither CSRF nor Data Guard is enabled, signalling that no
    patch to the HTTP Load Balancer is required.
    """

    @staticmethod
    def translate(policy: AsmPolicy) -> dict | None:
        """Return HTTP LB patch fields for CSRF and/or Data Guard, or None if neither is enabled.

        Args:
            policy: Populated AsmPolicy intermediate model.

        Returns:
            A dict with ``csrf`` and/or ``data_guard`` keys, or None if neither feature
            is enabled on the policy.
        """
        result: dict = {}

        if policy.csrf.enabled:
            result["csrf"] = {
                "enabled": True,
                "urls": policy.csrf.urls,
            }

        if policy.data_guard.enabled:
            dg = policy.data_guard
            result["data_guard"] = {
                "enabled": True,
                "credit_cards": dg.credit_cards,
                "ssn": dg.ssn,
                "custom_patterns": dg.custom_patterns,
                "exception_urls": dg.exception_urls,
            }

        return result if result else None
