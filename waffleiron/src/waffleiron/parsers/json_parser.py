"""Parse BIG-IP ASM Declarative JSON policy exports into the AsmPolicy model."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from waffleiron.model import (
    AccuracyLevel,
    AsmPolicy,
    BlockingPageConfig,
    BotCategory,
    BotDefenseConfig,
    BruteForceConfig,
    CookieEntity,
    CsrfConfig,
    CustomSignature,
    DataGuardConfig,
    EntityCollection,
    EnforcementMode,
    FileTypeEntity,
    GeolocationConfig,
    HeaderEntity,
    IpIntelCategory,
    IpIntelligenceConfig,
    IpWhitelistEntry,
    MethodEntity,
    ParameterEntity,
    SessionTrackingConfig,
    SignatureConfig,
    SignatureOverride,
    SignatureSet,
    UrlEntity,
    Violation,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(d: dict, key: str, default=None):
    """Get a value from a dict, returning *default* if absent or None."""
    if d is None:
        return default
    val = d.get(key)
    return val if val is not None else default


def _bool(d: dict, key: str, default: bool = False) -> bool:
    """Get a boolean value from dict key."""
    val = _get(d, key)
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() == "true"
    return bool(val)


def _opt_bool(d: dict, key: str) -> Optional[bool]:
    """Get an optional boolean — returns None if key is absent."""
    if key not in d:
        return None
    return _bool(d, key)


def _int(d: dict, key: str, default: int = 0) -> int:
    """Get an integer value from dict key."""
    val = _get(d, key)
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _opt_int(d: dict, key: str) -> Optional[int]:
    """Get an optional integer — returns None if key is absent."""
    if key not in d:
        return None
    return _int(d, key)


def _str(d: dict, key: str, default: str = "") -> str:
    """Get a string value from dict key."""
    val = _get(d, key)
    if val is None:
        return default
    return str(val).strip()


def _opt_str(d: dict, key: str) -> Optional[str]:
    """Get an optional string — returns None if key is absent or empty."""
    if key not in d:
        return None
    val = _str(d, key)
    return val if val else None


# ---------------------------------------------------------------------------
# Section parsers
# ---------------------------------------------------------------------------


def _parse_name(policy: dict) -> str:
    """Extract the policy name, stripping the ``/Common/`` partition prefix."""
    full_path = _str(policy, "fullPath")
    if full_path.startswith("/Common/"):
        return full_path[len("/Common/"):]
    return full_path


def _parse_enforcement_mode(policy: dict) -> EnforcementMode:
    mode_text = _str(policy, "enforcementMode", "blocking").lower()
    if mode_text == "transparent":
        return EnforcementMode.TRANSPARENT
    return EnforcementMode.BLOCKING


def _parse_encoding(policy: dict) -> str:
    return _str(policy, "encoding", "utf-8")


def _parse_accuracy_level(policy: dict) -> AccuracyLevel:
    """Determine the accuracy level from signatureSettings."""
    sig_settings = _get(policy, "signatureSettings", {})
    placeholder_settings = _get(sig_settings, "placeholderSignaturesSettings", [])

    if isinstance(placeholder_settings, list):
        for setting in placeholder_settings:
            acc_filter = _str(setting, "accuracyFilter")
            acc_value = _str(setting, "accuracyValue")
            if acc_filter == "ge" and acc_value == "low":
                return AccuracyLevel.ALL
            if acc_filter == "ge" and acc_value == "medium":
                return AccuracyLevel.HIGH_MEDIUM
            if acc_filter == "eq" and acc_value == "high":
                return AccuracyLevel.HIGH
    elif isinstance(placeholder_settings, dict):
        acc_filter = _str(placeholder_settings, "accuracyFilter")
        acc_value = _str(placeholder_settings, "accuracyValue")
        if acc_filter == "ge" and acc_value == "low":
            return AccuracyLevel.ALL
        if acc_filter == "ge" and acc_value == "medium":
            return AccuracyLevel.HIGH_MEDIUM
        if acc_filter == "eq" and acc_value == "high":
            return AccuracyLevel.HIGH

    return AccuracyLevel.HIGH_MEDIUM


def _parse_signature_override(sig: dict) -> SignatureOverride:
    """Parse a single signature override dict."""
    return SignatureOverride(
        sig_id=_int(sig, "signatureId"),
        enabled=_bool(sig, "enabled", default=True),
        alarm=_bool(sig, "alarm"),
        block=_bool(sig, "block"),
    )


def _parse_signatures(policy: dict) -> SignatureConfig:
    """Parse the signatures and signatureSettings sections."""
    overrides: list[SignatureOverride] = []
    for sig in _get(policy, "signatures", []):
        overrides.append(_parse_signature_override(sig))

    sig_settings = _get(policy, "signatureSettings", {})
    staging_enabled = _bool(sig_settings, "signatureStaging", default=True)
    staging_period = _int(sig_settings, "stagingPeriod", default=7)
    threat_campaigns = _bool(sig_settings, "threatCampaigns", default=True)

    return SignatureConfig(
        global_overrides=overrides,
        accuracy_level=_parse_accuracy_level(policy),
        staging_enabled=staging_enabled,
        staging_period=staging_period,
        threat_campaigns_enabled=threat_campaigns,
    )


def _parse_signature_sets(policy: dict) -> list[SignatureSet]:
    result: list[SignatureSet] = []
    for ss in _get(policy, "signatureSets", []):
        name = _str(ss, "name")
        enabled = _bool(ss, "enabled", default=True)
        if name:
            result.append(SignatureSet(name=name, enabled=enabled))
    return result


def _parse_url_entity(url: dict) -> UrlEntity:
    """Parse a single URL entity dict."""
    sig_overrides: list[SignatureOverride] = []
    for so in _get(url, "signatureOverrides", []):
        sig_overrides.append(_parse_signature_override(so))

    return UrlEntity(
        name=_str(url, "name"),
        protocol=_opt_str(url, "protocol"),
        type=_opt_str(url, "type"),
        method=_opt_str(url, "method"),
        is_allowed=_opt_bool(url, "isAllowed"),
        attack_signatures_check=_opt_bool(url, "attackSignaturesCheck"),
        metachars_on_url_check=_opt_bool(url, "metacharsOnUrlCheck"),
        clickjacking_protection=_opt_bool(url, "clickjackingProtection"),
        perform_staging=_opt_bool(url, "performStaging"),
        signature_overrides=sig_overrides,
    )


def _parse_parameter_entity(param: dict) -> ParameterEntity:
    """Parse a single parameter entity dict."""
    sig_overrides: list[SignatureOverride] = []
    for so in _get(param, "signatureOverrides", []):
        sig_overrides.append(_parse_signature_override(so))

    return ParameterEntity(
        name=_str(param, "name"),
        type=_opt_str(param, "type"),
        value_type=_opt_str(param, "valueType"),
        level=_opt_str(param, "level"),
        data_type=_opt_str(param, "dataType"),
        sensitive=_opt_bool(param, "sensitiveParameter"),
        parameter_location=_opt_str(param, "parameterLocation"),
        allow_empty_value=_opt_bool(param, "allowEmptyValue"),
        check_max_value_length=_opt_bool(param, "checkMaxValueLength"),
        maximum_length=_opt_int(param, "maximumLength"),
        perform_staging=_opt_bool(param, "performStaging"),
        attack_signatures_check=_opt_bool(param, "attackSignaturesCheck"),
        signature_overrides=sig_overrides,
    )


def _parse_filetype_entity(ft: dict) -> FileTypeEntity:
    """Parse a single file type entity dict."""
    return FileTypeEntity(
        name=_str(ft, "name"),
        allowed=_opt_bool(ft, "allowed"),
        response_check=_opt_bool(ft, "responseCheck"),
        query_string_length=_opt_int(ft, "queryStringLength"),
        url_length=_opt_int(ft, "urlLength"),
        post_data_length=_opt_int(ft, "postDataLength"),
        request_length=_opt_int(ft, "requestLength"),
    )


def _parse_cookie_entity(cookie: dict) -> CookieEntity:
    """Parse a single cookie entity dict."""
    sig_overrides: list[SignatureOverride] = []
    for so in _get(cookie, "signatureOverrides", []):
        sig_overrides.append(_parse_signature_override(so))

    return CookieEntity(
        name=_str(cookie, "name"),
        type=_opt_str(cookie, "type"),
        enforcement_type=_opt_str(cookie, "enforcementType"),
        attack_signatures_check=_opt_bool(cookie, "attackSignaturesCheck"),
        signature_overrides=sig_overrides,
    )


def _parse_header_entity(header: dict) -> HeaderEntity:
    """Parse a single header entity dict."""
    return HeaderEntity(
        name=_str(header, "name"),
        type=_opt_str(header, "type"),
        mandatory=_opt_bool(header, "mandatory"),
        check_signatures=_opt_bool(header, "checkSignatures"),
    )


def _parse_method_entity(method: dict) -> MethodEntity:
    """Parse a single method entity dict."""
    return MethodEntity(
        name=_str(method, "name"),
        act_as_method=_opt_str(method, "actAsMethod"),
    )


def _parse_entities(policy: dict) -> EntityCollection:
    """Parse all entity collections (URLs, parameters, file types, etc.)."""
    return EntityCollection(
        urls=[_parse_url_entity(e) for e in _get(policy, "urls", [])],
        parameters=[_parse_parameter_entity(e) for e in _get(policy, "parameters", [])],
        file_types=[_parse_filetype_entity(e) for e in _get(policy, "filetypes", [])],
        cookies=[_parse_cookie_entity(e) for e in _get(policy, "cookies", [])],
        headers=[_parse_header_entity(e) for e in _get(policy, "headers", [])],
        methods=[_parse_method_entity(e) for e in _get(policy, "methods", [])],
    )


def _parse_violations(policy: dict) -> list[Violation]:
    result: list[Violation] = []
    for v in _get(policy, "violations", []):
        name = _str(v, "name")
        if name:
            result.append(
                Violation(
                    name=name,
                    alarm=_bool(v, "alarm"),
                    block=_bool(v, "block"),
                )
            )
    return result


def _parse_whitelist_ips(policy: dict) -> list[IpWhitelistEntry]:
    result: list[IpWhitelistEntry] = []
    for ip_entry in _get(policy, "whitelistIps", []):
        ip_addr = _str(ip_entry, "ipAddress")
        if ip_addr:
            block_text = _str(ip_entry, "blockRequests").lower()
            block_requests = block_text not in ("never", "")

            result.append(
                IpWhitelistEntry(
                    ip=ip_addr,
                    mask=_str(ip_entry, "ipMask"),
                    block_requests=block_requests,
                    never_log=_opt_bool(ip_entry, "neverLog"),
                    trusted_by_builder=_opt_bool(ip_entry, "trustedByBuilder"),
                    ignore_anomalies=_opt_bool(ip_entry, "ignoreAnomalies"),
                    ignore_ip_reputation=_opt_bool(ip_entry, "ignoreIpReputation"),
                )
            )
    return result


def _parse_geolocation(policy: dict) -> GeolocationConfig:
    disallowed: list[str] = []
    geo = _get(policy, "geolocationEnforcement", {})
    for entry in _get(geo, "disallowedGeolocations", []):
        country = _str(entry, "country")
        if country:
            disallowed.append(country)
    return GeolocationConfig(disallowed=disallowed)


def _parse_csrf(policy: dict) -> CsrfConfig:
    csrf = _get(policy, "csrfProtection")
    if csrf is None:
        return CsrfConfig()
    return CsrfConfig(
        enabled=_bool(csrf, "enabled"),
    )


def _parse_data_guard(policy: dict) -> DataGuardConfig:
    dg = _get(policy, "dataGuard")
    if dg is None:
        return DataGuardConfig()
    return DataGuardConfig(
        enabled=_bool(dg, "enabled"),
        credit_cards=_bool(dg, "creditCards"),
        ssn=_bool(dg, "ssn"),
    )


def _parse_brute_force(policy: dict) -> BruteForceConfig:
    bf = _get(policy, "bruteForce")
    if bf is None:
        return BruteForceConfig()
    return BruteForceConfig(
        enabled=_bool(bf, "enabled"),
        detection_period=_int(bf, "detectionPeriod"),
        max_attempts=_int(bf, "maxAttempts"),
        login_url=_str(bf, "loginUrl"),
    )


def _parse_session_tracking(policy: dict) -> SessionTrackingConfig:
    st = _get(policy, "sessionTracking")
    if st is None:
        return SessionTrackingConfig()
    return SessionTrackingConfig(
        enabled=_bool(st, "enabled"),
        hijacking_prevention=_bool(st, "hijackingPrevention"),
    )


def _parse_bot_defense(policy: dict) -> BotDefenseConfig:
    bd = _get(policy, "botDefense")
    if bd is None:
        return BotDefenseConfig()
    categories: list[BotCategory] = []
    for cat in _get(bd, "categories", []):
        name = _str(cat, "name")
        action = _str(cat, "action")
        if name:
            categories.append(BotCategory(name=name, action=action))
    return BotDefenseConfig(
        enabled=_bool(bd, "enabled"),
        mode=_str(bd, "mode"),
        categories=categories,
    )


def _parse_ip_intelligence(policy: dict) -> IpIntelligenceConfig:
    ii = _get(policy, "ipIntelligence")
    if ii is None:
        return IpIntelligenceConfig()
    categories: list[IpIntelCategory] = []
    for cat in _get(ii, "categories", []):
        name = _str(cat, "name")
        action = _str(cat, "action")
        if name:
            categories.append(IpIntelCategory(name=name, action=action))
    return IpIntelligenceConfig(categories=categories)


def _parse_blocking_page(policy: dict) -> BlockingPageConfig:
    bp = _get(policy, "blockingPage")
    if bp is None:
        return BlockingPageConfig()
    return BlockingPageConfig(
        enabled=_bool(bp, "enabled"),
        custom_html=_str(bp, "customHtml"),
        response_code=_int(bp, "responseCode"),
    )


def _parse_response_codes(policy: dict) -> list[int]:
    result: list[int] = []
    for code in _get(policy, "allowedResponseCodes", []):
        try:
            result.append(int(code))
        except (ValueError, TypeError):
            pass
    return result


def _parse_custom_signatures(policy: dict) -> list[CustomSignature]:
    result: list[CustomSignature] = []
    for cs in _get(policy, "customSignatures", []):
        sig_id = _int(cs, "id")
        name = _str(cs, "name")
        pattern = _str(cs, "pattern")
        scope = _str(cs, "scope")
        if name:
            result.append(CustomSignature(id=sig_id, name=name, pattern=pattern, scope=scope))
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class JsonPolicyParser:
    """Parse a BIG-IP ASM Declarative JSON policy export into an ``AsmPolicy`` model."""

    @staticmethod
    def parse(path: Path | str) -> AsmPolicy:
        """Read an ASM JSON policy file and return a populated ``AsmPolicy``.

        Expects the declarative JSON format (BIG-IP v15.1+) with a top-level
        ``"policy"`` key. Falls back to treating the root dict as the policy
        data if ``"policy"`` is absent.
        """
        path = Path(path)
        with open(path) as f:
            data = json.load(f)

        policy_data = data.get("policy", data)

        return AsmPolicy(
            name=_parse_name(policy_data),
            enforcement_mode=_parse_enforcement_mode(policy_data),
            encoding=_parse_encoding(policy_data),
            signatures=_parse_signatures(policy_data),
            signature_sets=_parse_signature_sets(policy_data),
            entities=_parse_entities(policy_data),
            violations=_parse_violations(policy_data),
            whitelist_ips=_parse_whitelist_ips(policy_data),
            geolocation=_parse_geolocation(policy_data),
            csrf=_parse_csrf(policy_data),
            data_guard=_parse_data_guard(policy_data),
            brute_force=_parse_brute_force(policy_data),
            session_tracking=_parse_session_tracking(policy_data),
            bot_defense=_parse_bot_defense(policy_data),
            ip_intelligence=_parse_ip_intelligence(policy_data),
            blocking_page=_parse_blocking_page(policy_data),
            allowed_response_codes=_parse_response_codes(policy_data),
            custom_signatures=_parse_custom_signatures(policy_data),
        )
