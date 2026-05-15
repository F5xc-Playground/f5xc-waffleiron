"""Parse BIG-IP ASM XML policy exports into the AsmPolicy model."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from defusedxml import ElementTree as SafeET
from lxml import etree

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


def _bool(text: Optional[str], default: bool = False) -> bool:
    """Convert an XML text value like ``"true"``/``"false"`` to a Python bool."""
    if text is None:
        return default
    return text.strip().lower() == "true"


def _int(text: Optional[str], default: int = 0) -> int:
    """Convert an XML text value to an int, returning *default* if absent."""
    if text is None:
        return default
    try:
        return int(text.strip())
    except (ValueError, AttributeError):
        return default


def _text(element: Optional[etree._Element], xpath: str, default: str = "") -> str:
    """Get text content at *xpath* relative to *element*, or *default*."""
    if element is None:
        return default
    node = element.find(xpath)
    if node is None or node.text is None:
        return default
    return node.text.strip()


# ---------------------------------------------------------------------------
# Section parsers
# ---------------------------------------------------------------------------


def _parse_name(root: etree._Element) -> str:
    """Extract the policy name, stripping the ``/Common/`` partition prefix."""
    full_path = root.findtext("fullPath") or ""
    full_path = full_path.strip()
    if full_path.startswith("/Common/"):
        return full_path[len("/Common/"):]
    return full_path


def _parse_enforcement_mode(root: etree._Element) -> EnforcementMode:
    mode_text = (root.findtext("enforcementMode") or "blocking").strip().lower()
    if mode_text == "transparent":
        return EnforcementMode.TRANSPARENT
    return EnforcementMode.BLOCKING


def _parse_encoding(root: etree._Element) -> str:
    return (root.findtext("encoding") or "utf-8").strip()


def _parse_accuracy_level(root: etree._Element) -> AccuracyLevel:
    """Determine the accuracy level from signatureSettings."""
    settings = root.findall(".//signatureSettings/placeholderSignaturesSettings/placeholderSignatureSetting")
    for setting in settings:
        acc_filter = (setting.findtext("accuracyFilter") or "").strip()
        acc_value = (setting.findtext("accuracyValue") or "").strip()
        if acc_filter == "ge" and acc_value == "medium":
            return AccuracyLevel.HIGH_MEDIUM
        if acc_filter == "eq" and acc_value == "high":
            return AccuracyLevel.HIGH
    return AccuracyLevel.HIGH_MEDIUM


def _parse_signature_override(elem: etree._Element) -> SignatureOverride:
    """Parse a single signature override element."""
    return SignatureOverride(
        sig_id=_int(elem.findtext("signatureId")),
        enabled=_bool(elem.findtext("enabled"), default=True),
        alarm=_bool(elem.findtext("alarm")),
        block=_bool(elem.findtext("block")),
    )


def _parse_signatures(root: etree._Element) -> SignatureConfig:
    """Parse the signatures and signatureSettings sections."""
    overrides: list[SignatureOverride] = []
    for sig_elem in root.findall(".//signatures/signature"):
        overrides.append(_parse_signature_override(sig_elem))

    staging_text = root.findtext(".//signatureSettings/signatureStaging")
    staging_enabled = _bool(staging_text, default=True)

    staging_period = _int(root.findtext(".//signatureSettings/stagingPeriod"), default=7)

    threat_text = root.findtext(".//signatureSettings/threatCampaigns")
    threat_campaigns = _bool(threat_text, default=True)

    return SignatureConfig(
        global_overrides=overrides,
        accuracy_level=_parse_accuracy_level(root),
        staging_enabled=staging_enabled,
        staging_period=staging_period,
        threat_campaigns_enabled=threat_campaigns,
    )


def _parse_signature_sets(root: etree._Element) -> list[SignatureSet]:
    result: list[SignatureSet] = []
    for ss_elem in root.findall(".//signature-sets/signature-set"):
        name = (ss_elem.findtext("name") or "").strip()
        enabled = _bool(ss_elem.findtext("enabled"), default=True)
        if name:
            result.append(SignatureSet(name=name, enabled=enabled))
    return result


def _parse_url_entity(elem: etree._Element) -> UrlEntity:
    """Parse a single URL entity element."""
    sig_overrides: list[SignatureOverride] = []
    for so in elem.findall("signatureOverrides/signatureOverride"):
        sig_overrides.append(_parse_signature_override(so))

    return UrlEntity(
        name=(elem.findtext("name") or "").strip(),
        protocol=(elem.findtext("protocol") or "").strip() or None,
        type=(elem.findtext("type") or "").strip() or None,
        method=(elem.findtext("method") or "").strip() or None,
        is_allowed=_bool(elem.findtext("isAllowed")) if elem.find("isAllowed") is not None else None,
        attack_signatures_check=(
            _bool(elem.findtext("attackSignaturesCheck"))
            if elem.find("attackSignaturesCheck") is not None
            else None
        ),
        metachars_on_url_check=(
            _bool(elem.findtext("metacharsOnUrlCheck"))
            if elem.find("metacharsOnUrlCheck") is not None
            else None
        ),
        clickjacking_protection=(
            _bool(elem.findtext("clickjackingProtection"))
            if elem.find("clickjackingProtection") is not None
            else None
        ),
        perform_staging=(
            _bool(elem.findtext("performStaging"))
            if elem.find("performStaging") is not None
            else None
        ),
        signature_overrides=sig_overrides,
    )


def _parse_parameter_entity(elem: etree._Element) -> ParameterEntity:
    """Parse a single parameter entity element."""
    sig_overrides: list[SignatureOverride] = []
    for so in elem.findall("signatureOverrides/signatureOverride"):
        sig_overrides.append(_parse_signature_override(so))

    return ParameterEntity(
        name=(elem.findtext("name") or "").strip(),
        type=(elem.findtext("type") or "").strip() or None,
        value_type=(elem.findtext("valueType") or "").strip() or None,
        level=(elem.findtext("level") or "").strip() or None,
        data_type=(elem.findtext("dataType") or "").strip() or None,
        sensitive=_bool(elem.findtext("sensitiveParameter")) if elem.find("sensitiveParameter") is not None else None,
        parameter_location=(elem.findtext("parameterLocation") or "").strip() or None,
        allow_empty_value=(
            _bool(elem.findtext("allowEmptyValue"))
            if elem.find("allowEmptyValue") is not None
            else None
        ),
        check_max_value_length=(
            _bool(elem.findtext("checkMaxValueLength"))
            if elem.find("checkMaxValueLength") is not None
            else None
        ),
        maximum_length=_int(elem.findtext("maximumLength")) if elem.find("maximumLength") is not None else None,
        perform_staging=(
            _bool(elem.findtext("performStaging"))
            if elem.find("performStaging") is not None
            else None
        ),
        attack_signatures_check=(
            _bool(elem.findtext("attackSignaturesCheck"))
            if elem.find("attackSignaturesCheck") is not None
            else None
        ),
        signature_overrides=sig_overrides,
    )


def _parse_filetype_entity(elem: etree._Element) -> FileTypeEntity:
    """Parse a single file type entity element."""
    return FileTypeEntity(
        name=(elem.findtext("name") or "").strip(),
        allowed=_bool(elem.findtext("allowed")) if elem.find("allowed") is not None else None,
        response_check=_bool(elem.findtext("responseCheck")) if elem.find("responseCheck") is not None else None,
        query_string_length=(
            _int(elem.findtext("queryStringLength")) if elem.find("queryStringLength") is not None else None
        ),
        url_length=_int(elem.findtext("urlLength")) if elem.find("urlLength") is not None else None,
        post_data_length=_int(elem.findtext("postDataLength")) if elem.find("postDataLength") is not None else None,
        request_length=_int(elem.findtext("requestLength")) if elem.find("requestLength") is not None else None,
    )


def _parse_cookie_entity(elem: etree._Element) -> CookieEntity:
    """Parse a single cookie entity element."""
    sig_overrides: list[SignatureOverride] = []
    for so in elem.findall("signatureOverrides/signatureOverride"):
        sig_overrides.append(_parse_signature_override(so))

    return CookieEntity(
        name=(elem.findtext("name") or "").strip(),
        type=(elem.findtext("type") or "").strip() or None,
        enforcement_type=(elem.findtext("enforcementType") or "").strip() or None,
        attack_signatures_check=(
            _bool(elem.findtext("attackSignaturesCheck"))
            if elem.find("attackSignaturesCheck") is not None
            else None
        ),
        signature_overrides=sig_overrides,
    )


def _parse_header_entity(elem: etree._Element) -> HeaderEntity:
    """Parse a single header entity element."""
    return HeaderEntity(
        name=(elem.findtext("name") or "").strip(),
        type=(elem.findtext("type") or "").strip() or None,
        mandatory=_bool(elem.findtext("mandatory")) if elem.find("mandatory") is not None else None,
        check_signatures=(
            _bool(elem.findtext("checkSignatures")) if elem.find("checkSignatures") is not None else None
        ),
    )


def _parse_method_entity(elem: etree._Element) -> MethodEntity:
    """Parse a single method entity element."""
    return MethodEntity(
        name=(elem.findtext("name") or "").strip(),
        act_as_method=(elem.findtext("actAsMethod") or "").strip() or None,
    )


def _parse_entities(root: etree._Element) -> EntityCollection:
    """Parse all entity collections (URLs, parameters, file types, etc.)."""
    return EntityCollection(
        urls=[_parse_url_entity(e) for e in root.findall(".//urls/url")],
        parameters=[_parse_parameter_entity(e) for e in root.findall(".//parameters/parameter")],
        file_types=[_parse_filetype_entity(e) for e in root.findall(".//filetypes/filetype")],
        cookies=[_parse_cookie_entity(e) for e in root.findall(".//cookies/cookie")],
        headers=[_parse_header_entity(e) for e in root.findall(".//headers/header")],
        methods=[_parse_method_entity(e) for e in root.findall(".//methods/method")],
    )


def _parse_violations(root: etree._Element) -> list[Violation]:
    result: list[Violation] = []
    for v_elem in root.findall(".//violations/violation"):
        name = (v_elem.findtext("name") or "").strip()
        if name:
            result.append(
                Violation(
                    name=name,
                    alarm=_bool(v_elem.findtext("alarm")),
                    block=_bool(v_elem.findtext("block")),
                )
            )
    return result


def _parse_whitelist_ips(root: etree._Element) -> list[IpWhitelistEntry]:
    result: list[IpWhitelistEntry] = []
    for ip_elem in root.findall(".//whitelist-ips/ip"):
        ip_addr = (ip_elem.findtext("ipAddress") or "").strip()
        if ip_addr:
            block_text = (ip_elem.findtext("blockRequests") or "").strip().lower()
            # "never" means do not block (i.e. block_requests=False)
            block_requests = block_text not in ("never", "")

            result.append(
                IpWhitelistEntry(
                    ip=ip_addr,
                    mask=(ip_elem.findtext("ipMask") or "").strip(),
                    block_requests=block_requests,
                    never_log=_bool(ip_elem.findtext("neverLog")) if ip_elem.find("neverLog") is not None else None,
                    trusted_by_builder=(
                        _bool(ip_elem.findtext("trustedByBuilder"))
                        if ip_elem.find("trustedByBuilder") is not None
                        else None
                    ),
                    ignore_anomalies=(
                        _bool(ip_elem.findtext("ignoreAnomalies"))
                        if ip_elem.find("ignoreAnomalies") is not None
                        else None
                    ),
                    ignore_ip_reputation=(
                        _bool(ip_elem.findtext("ignoreIpReputation"))
                        if ip_elem.find("ignoreIpReputation") is not None
                        else None
                    ),
                )
            )
    return result


def _parse_geolocation(root: etree._Element) -> GeolocationConfig:
    disallowed: list[str] = []
    for geo_elem in root.findall(".//geolocation-enforcement/disallowed-geolocations/geolocation"):
        country = (geo_elem.findtext("country") or "").strip()
        if country:
            disallowed.append(country)
    return GeolocationConfig(disallowed=disallowed)


def _parse_csrf(root: etree._Element) -> CsrfConfig:
    csrf_elem = root.find(".//csrf-protection")
    if csrf_elem is None:
        return CsrfConfig()
    return CsrfConfig(
        enabled=_bool(csrf_elem.findtext("enabled")),
    )


def _parse_data_guard(root: etree._Element) -> DataGuardConfig:
    dg_elem = root.find(".//data-guard")
    if dg_elem is None:
        return DataGuardConfig()
    return DataGuardConfig(
        enabled=_bool(dg_elem.findtext("enabled")),
        credit_cards=_bool(dg_elem.findtext("creditCards")),
        ssn=_bool(dg_elem.findtext("ssn")),
    )


def _parse_brute_force(root: etree._Element) -> BruteForceConfig:
    bf_elem = root.find(".//brute-force")
    if bf_elem is None:
        return BruteForceConfig()
    return BruteForceConfig(
        enabled=_bool(bf_elem.findtext("enabled")),
        detection_period=_int(bf_elem.findtext("detectionPeriod")),
        max_attempts=_int(bf_elem.findtext("maxAttempts")),
        login_url=(bf_elem.findtext("loginUrl") or "").strip(),
    )


def _parse_session_tracking(root: etree._Element) -> SessionTrackingConfig:
    st_elem = root.find(".//session-tracking")
    if st_elem is None:
        return SessionTrackingConfig()
    return SessionTrackingConfig(
        enabled=_bool(st_elem.findtext("enabled")),
        hijacking_prevention=_bool(st_elem.findtext("hijackingPrevention")),
    )


def _parse_bot_defense(root: etree._Element) -> BotDefenseConfig:
    bd_elem = root.find(".//bot-defense")
    if bd_elem is None:
        return BotDefenseConfig()
    categories: list[BotCategory] = []
    for cat_elem in bd_elem.findall("categories/category"):
        name = (cat_elem.findtext("name") or "").strip()
        action = (cat_elem.findtext("action") or "").strip()
        if name:
            categories.append(BotCategory(name=name, action=action))
    return BotDefenseConfig(
        enabled=_bool(bd_elem.findtext("enabled")),
        mode=(bd_elem.findtext("mode") or "").strip(),
        categories=categories,
    )


def _parse_ip_intelligence(root: etree._Element) -> IpIntelligenceConfig:
    ii_elem = root.find(".//ip-intelligence")
    if ii_elem is None:
        return IpIntelligenceConfig()
    categories: list[IpIntelCategory] = []
    for cat_elem in ii_elem.findall("categories/category"):
        name = (cat_elem.findtext("name") or "").strip()
        action = (cat_elem.findtext("action") or "").strip()
        if name:
            categories.append(IpIntelCategory(name=name, action=action))
    return IpIntelligenceConfig(categories=categories)


def _parse_blocking_page(root: etree._Element) -> BlockingPageConfig:
    bp_elem = root.find(".//blocking-page")
    if bp_elem is None:
        return BlockingPageConfig()
    return BlockingPageConfig(
        enabled=_bool(bp_elem.findtext("enabled")),
        custom_html=(bp_elem.findtext("customHtml") or "").strip(),
        response_code=_int(bp_elem.findtext("responseCode")),
    )


def _parse_response_codes(root: etree._Element) -> list[int]:
    result: list[int] = []
    for rc_elem in root.findall(".//allowed-response-codes/code"):
        text = (rc_elem.text or "").strip()
        if text:
            try:
                result.append(int(text))
            except ValueError:
                pass
    return result


def _parse_custom_signatures(root: etree._Element) -> list[CustomSignature]:
    result: list[CustomSignature] = []
    for cs_elem in root.findall(".//custom-signatures/custom-signature"):
        sig_id = _int(cs_elem.findtext("id"))
        name = (cs_elem.findtext("name") or "").strip()
        pattern = (cs_elem.findtext("pattern") or "").strip()
        scope = (cs_elem.findtext("scope") or "").strip()
        if name:
            result.append(CustomSignature(id=sig_id, name=name, pattern=pattern, scope=scope))
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class XmlPolicyParser:
    """Parse a BIG-IP ASM XML policy export into an ``AsmPolicy`` model."""

    @staticmethod
    def parse(path: Path | str) -> AsmPolicy:
        """Read an ASM XML policy file and return a populated ``AsmPolicy``.

        The file is first validated with ``defusedxml`` to guard against XXE
        and entity-expansion attacks, then re-parsed with ``lxml`` for full
        XPath support.
        """
        path = Path(path)
        raw = path.read_bytes()

        # Safe parse first — detects XXE, billion laughs, etc.
        SafeET.fromstring(raw)

        # Re-parse with lxml for XPath navigation
        root = etree.fromstring(raw)

        return AsmPolicy(
            name=_parse_name(root),
            enforcement_mode=_parse_enforcement_mode(root),
            encoding=_parse_encoding(root),
            signatures=_parse_signatures(root),
            signature_sets=_parse_signature_sets(root),
            entities=_parse_entities(root),
            violations=_parse_violations(root),
            whitelist_ips=_parse_whitelist_ips(root),
            geolocation=_parse_geolocation(root),
            csrf=_parse_csrf(root),
            data_guard=_parse_data_guard(root),
            brute_force=_parse_brute_force(root),
            session_tracking=_parse_session_tracking(root),
            bot_defense=_parse_bot_defense(root),
            ip_intelligence=_parse_ip_intelligence(root),
            blocking_page=_parse_blocking_page(root),
            allowed_response_codes=_parse_response_codes(root),
            custom_signatures=_parse_custom_signatures(root),
        )
