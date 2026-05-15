"""Output validator for XC API objects.

Performs targeted constraint checks derived from the XC OAS schemas.
This is NOT a generic JSON Schema validator — only XC-specific limits
are checked here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ValidationError:
    path: str
    message: str
    severity: str  # "error" or "warning"


@dataclass
class ValidationResult:
    is_valid: bool
    errors: list[ValidationError]
    warnings: list[ValidationError]


# ---------------------------------------------------------------------------
# Known enum sets
# ---------------------------------------------------------------------------

VALID_BOT_ACTIONS = {"BLOCK", "REPORT", "IGNORE"}

VALID_ATTACK_TYPES = {
    "ATTACK_TYPE_NON_BROWSER_CLIENT",
    "ATTACK_TYPE_OTHER_APPLICATION_ATTACKS",
    "ATTACK_TYPE_TROJAN_BACKDOOR_SPYWARE",
    "ATTACK_TYPE_DETECTION_EVASION",
    "ATTACK_TYPE_VULNERABILITY_SCAN",
    "ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY",
    "ATTACK_TYPE_AUTHENTICATION_AUTHORIZATION_ATTACKS",
    "ATTACK_TYPE_BUFFER_OVERFLOW",
    "ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION",
    "ATTACK_TYPE_INFORMATION_LEAKAGE",
    "ATTACK_TYPE_DIRECTORY_INDEXING",
    "ATTACK_TYPE_PATH_TRAVERSAL",
    "ATTACK_TYPE_XPATH_INJECTION",
    "ATTACK_TYPE_LDAP_INJECTION",
    "ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION",
    "ATTACK_TYPE_COMMAND_EXECUTION",
    "ATTACK_TYPE_SQL_INJECTION",
    "ATTACK_TYPE_CROSS_SITE_SCRIPTING",
    "ATTACK_TYPE_DENIAL_OF_SERVICE",
    "ATTACK_TYPE_HTTP_PARSER_ATTACK",
    "ATTACK_TYPE_SESSION_HIJACKING",
    "ATTACK_TYPE_HTTP_RESPONSE_SPLITTING",
    "ATTACK_TYPE_FORCEFUL_BROWSING",
    "ATTACK_TYPE_REMOTE_FILE_INCLUDE",
    "ATTACK_TYPE_MALICIOUS_FILE_UPLOAD",
    "ATTACK_TYPE_GRAPHQL_PARSER_ATTACK",
}

VALID_VIOLATION_TYPES = {
    "VIOL_FILETYPE",
    "VIOL_METHOD",
    "VIOL_MANDATORY_HEADER",
    "VIOL_HTTP_RESPONSE_STATUS",
    "VIOL_REQUEST_MAX_LENGTH",
    "VIOL_FILE_UPLOAD",
    "VIOL_FILE_UPLOAD_IN_BODY",
    "VIOL_XML_MALFORMED",
    "VIOL_JSON_MALFORMED",
    "VIOL_ASM_COOKIE_MODIFIED",
    "VIOL_HTTP_PROTOCOL_MULTIPLE_HOST_HEADERS",
    "VIOL_HTTP_PROTOCOL_BAD_HOST_HEADER_VALUE",
    "VIOL_HTTP_PROTOCOL_UNPARSABLE_REQUEST_CONTENT",
    "VIOL_HTTP_PROTOCOL_NULL_IN_REQUEST",
    "VIOL_HTTP_PROTOCOL_BAD_HTTP_VERSION",
    "VIOL_HTTP_PROTOCOL_CRLF_CHARACTERS_BEFORE_REQUEST_START",
    "VIOL_HTTP_PROTOCOL_NO_HOST_HEADER_IN_HTTP_1_1_REQUEST",
    "VIOL_HTTP_PROTOCOL_BAD_MULTIPART_PARAMETERS_PARSING",
    "VIOL_HTTP_PROTOCOL_SEVERAL_CONTENT_LENGTH_HEADERS",
    "VIOL_HTTP_PROTOCOL_CONTENT_LENGTH_SHOULD_BE_A_POSITIVE_NUMBER",
    "VIOL_EVASION_DIRECTORY_TRAVERSALS",
    "VIOL_MALFORMED_REQUEST",
    "VIOL_EVASION_MULTIPLE_DECODING",
    "VIOL_DATA_GUARD",
    "VIOL_EVASION_APACHE_WHITESPACE",
    "VIOL_COOKIE_MODIFIED",
    "VIOL_EVASION_IIS_UNICODE_CODEPOINTS",
    "VIOL_EVASION_IIS_BACKSLASHES",
    "VIOL_EVASION_PERCENT_U_DECODING",
    "VIOL_EVASION_BARE_BYTE_DECODING",
    "VIOL_EVASION_BAD_UNESCAPE",
    "VIOL_HTTP_PROTOCOL_BAD_MULTIPART_FORMDATA_REQUEST_PARSING",
    "VIOL_HTTP_PROTOCOL_BODY_IN_GET_OR_HEAD_REQUEST",
    "VIOL_HTTP_PROTOCOL_HIGH_ASCII_CHARACTERS_IN_HEADERS",
    "VIOL_ENCODING",
    "VIOL_COOKIE_MALFORMED",
    "VIOL_GRAPHQL_FORMAT",
    "VIOL_GRAPHQL_MALFORMED",
    "VIOL_GRAPHQL_INTROSPECTION_QUERY",
}

VALID_CONTEXTS = {
    "CONTEXT_ANY",
    "CONTEXT_BODY",
    "CONTEXT_REQUEST",
    "CONTEXT_RESPONSE",
    "CONTEXT_PARAMETER",
    "CONTEXT_HEADER",
    "CONTEXT_COOKIE",
    "CONTEXT_URL",
    "CONTEXT_URI",
}

# Signature ID range (exclusive of 0, which means "all signatures")
SIG_ID_MIN = 200000001
SIG_ID_MAX = 299999999


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _err(path: str, message: str) -> ValidationError:
    return ValidationError(path=path, message=message, severity="error")


def _warn(path: str, message: str) -> ValidationError:
    return ValidationError(path=path, message=message, severity="warning")


def _is_valid_sig_id(sig_id: int) -> bool:
    """Return True if sig_id is 0 (all sigs) or within the valid range."""
    return sig_id == 0 or (SIG_ID_MIN <= sig_id <= SIG_ID_MAX)


# ---------------------------------------------------------------------------
# Per-object validators
# ---------------------------------------------------------------------------


def _validate_app_firewall(obj: dict) -> tuple[list[ValidationError], list[ValidationError]]:
    errors: list[ValidationError] = []
    warnings: list[ValidationError] = []

    # --- Required top-level fields ---
    if "metadata" not in obj:
        errors.append(_err("metadata", "Required field 'metadata' is missing"))
        # Cannot check sub-fields without metadata
    else:
        meta = obj["metadata"]
        if "name" not in meta:
            errors.append(_err("metadata.name", "Required field 'metadata.name' is missing"))
        else:
            name = meta["name"]
            if len(name) > 64:
                errors.append(
                    _err(
                        "metadata.name",
                        f"'metadata.name' exceeds 64 characters (got {len(name)})",
                    )
                )

        if "namespace" not in meta:
            errors.append(_err("metadata.namespace", "Required field 'metadata.namespace' is missing"))

    if "spec" not in obj:
        errors.append(_err("spec", "Required field 'spec' is missing"))
        return errors, warnings

    spec = obj["spec"]

    # --- Blocking page ---
    if "blocking_page" in spec:
        bp = spec["blocking_page"]
        if isinstance(bp, dict) and "blocking_page" in bp:
            page_content = bp["blocking_page"]
            if isinstance(page_content, str):
                byte_len = len(page_content.encode("utf-8"))
                if byte_len > 4096:
                    errors.append(
                        _err(
                            "spec.blocking_page.blocking_page",
                            f"Blocking page content exceeds 4096 bytes (got {byte_len})",
                        )
                    )

    # --- Custom anonymization ---
    if "custom_anonymization" in spec:
        anon = spec["custom_anonymization"]
        if isinstance(anon, dict) and "anonymization_config" in anon:
            config_list = anon["anonymization_config"]
            if isinstance(config_list, list) and len(config_list) > 64:
                errors.append(
                    _err(
                        "spec.custom_anonymization.anonymization_config",
                        f"anonymization_config exceeds 64 items (got {len(config_list)})",
                    )
                )

    # --- Allowed response codes ---
    if "allowed_response_codes" in spec:
        arc = spec["allowed_response_codes"]
        if isinstance(arc, dict) and "response_codes" in arc:
            codes = arc["response_codes"]
            if isinstance(codes, list) and len(codes) > 48:
                errors.append(
                    _err(
                        "spec.allowed_response_codes.response_codes",
                        f"response_codes exceeds 48 items (got {len(codes)})",
                    )
                )

    # --- Bot protection ---
    if "bot_protection_setting" in spec:
        bps = spec["bot_protection_setting"]
        if isinstance(bps, dict):
            action_fields = [
                "malicious_bot_action",
                "suspicious_bot_action",
                "good_bot_action",
            ]
            for action_field in action_fields:
                if action_field in bps:
                    action_val = bps[action_field]
                    if action_val not in VALID_BOT_ACTIONS:
                        errors.append(
                            _err(
                                f"spec.bot_protection_setting.{action_field}",
                                f"Invalid bot action '{action_val}'; must be one of {sorted(VALID_BOT_ACTIONS)}",
                            )
                        )

    # --- Attack types (via detection_settings) ---
    if "detection_settings" in spec:
        ds = spec["detection_settings"]
        if isinstance(ds, dict) and "attack_type_settings" in ds:
            ats = ds["attack_type_settings"]
            if isinstance(ats, dict) and "disabled_attack_types" in ats:
                dat = ats["disabled_attack_types"]
                if isinstance(dat, list):
                    for i, attack_type in enumerate(dat):
                        if attack_type not in VALID_ATTACK_TYPES:
                            errors.append(
                                _err(
                                    f"spec.detection_settings.attack_type_settings.disabled_attack_types[{i}]",
                                    f"Unknown attack type '{attack_type}'",
                                )
                            )

    return errors, warnings


def _validate_waf_exclusion_policy(obj: dict) -> tuple[list[ValidationError], list[ValidationError]]:
    errors: list[ValidationError] = []
    warnings: list[ValidationError] = []

    # --- Required top-level fields ---
    if "metadata" not in obj:
        errors.append(_err("metadata", "Required field 'metadata' is missing"))
    else:
        meta = obj["metadata"]
        if "name" not in meta:
            errors.append(_err("metadata.name", "Required field 'metadata.name' is missing"))

        if "namespace" not in meta:
            errors.append(_err("metadata.namespace", "Required field 'metadata.namespace' is missing"))

    if "spec" not in obj:
        errors.append(_err("spec", "Required field 'spec' is missing"))
        return errors, warnings

    spec = obj["spec"]

    # --- Exclusion rules ---
    if "waf_exclusion_rules" not in spec:
        # Not required to be present per spec but we check if present
        return errors, warnings

    rules = spec["waf_exclusion_rules"]

    if not isinstance(rules, list):
        return errors, warnings

    if len(rules) == 0:
        warnings.append(
            _warn(
                "spec.waf_exclusion_rules",
                "waf_exclusion_rules is empty; no exclusions will be applied",
            )
        )

    if len(rules) > 256:
        errors.append(
            _err(
                "spec.waf_exclusion_rules",
                f"waf_exclusion_rules exceeds 256 rules (got {len(rules)})",
            )
        )

    # --- Per-rule checks ---
    for rule_idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue

        afc = rule.get("app_firewall_detection_control")
        if not isinstance(afc, dict):
            continue

        # exclude_signature_contexts
        esc = afc.get("exclude_signature_contexts")
        if isinstance(esc, list):
            rule_path = f"spec.waf_exclusion_rules[{rule_idx}].app_firewall_detection_control.exclude_signature_contexts"

            if len(esc) > 1024:
                errors.append(
                    _err(
                        rule_path,
                        f"exclude_signature_contexts exceeds 1024 items (got {len(esc)})",
                    )
                )

            for ctx_idx, ctx_entry in enumerate(esc):
                if not isinstance(ctx_entry, dict):
                    continue

                # Validate signature_id
                if "signature_id" in ctx_entry:
                    sig_id = ctx_entry["signature_id"]
                    if isinstance(sig_id, int) and not _is_valid_sig_id(sig_id):
                        errors.append(
                            _err(
                                f"{rule_path}[{ctx_idx}].signature_id",
                                f"Invalid signature_id {sig_id}: must be 0 or in range "
                                f"{SIG_ID_MIN}–{SIG_ID_MAX}",
                            )
                        )

                # Validate context value
                if "context" in ctx_entry:
                    ctx_val = ctx_entry["context"]
                    if ctx_val not in VALID_CONTEXTS:
                        errors.append(
                            _err(
                                f"{rule_path}[{ctx_idx}].context",
                                f"Invalid context value '{ctx_val}'; must be one of {sorted(VALID_CONTEXTS)}",
                            )
                        )

    return errors, warnings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_VALIDATORS = {
    "app_firewall": _validate_app_firewall,
    "waf_exclusion_policy": _validate_waf_exclusion_policy,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate(obj: dict, object_type: str) -> ValidationResult:
    """Validate *obj* against XC API constraints for *object_type*.

    Args:
        obj: The translated XC API object (a plain dict).
        object_type: One of ``"app_firewall"`` or ``"waf_exclusion_policy"``.

    Returns:
        A :class:`ValidationResult` with ``is_valid``, ``errors``, and
        ``warnings`` populated.

    Raises:
        ValueError: If *object_type* is not recognised.
    """
    if object_type not in _VALIDATORS:
        raise ValueError(
            f"Unknown object type '{object_type}'. "
            f"Supported types: {sorted(_VALIDATORS.keys())}"
        )

    validator_fn = _VALIDATORS[object_type]
    errors, warnings = validator_fn(obj)

    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )
