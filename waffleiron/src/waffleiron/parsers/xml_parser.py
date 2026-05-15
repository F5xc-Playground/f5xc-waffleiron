"""Parse BIG-IP ASM XML policy exports into the AsmPolicy model.

Supports the native ``tmsh save asm policy`` export format (v11.6–v17+)
as well as the declarative JSON-to-XML schema used by some tooling.
"""

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
    if text is None:
        return default
    return text.strip().lower() in ("true", "1")


def _int(text: Optional[str], default: int = 0) -> int:
    if text is None:
        return default
    try:
        return int(text.strip())
    except (ValueError, AttributeError):
        return default


def _attr_or_child(elem: etree._Element, attr: str, child: str = "") -> str | None:
    """Get a value from an attribute first, falling back to a child element."""
    val = elem.get(attr)
    if val is not None:
        return val.strip()
    child_name = child or attr
    text = elem.findtext(child_name)
    if text is not None:
        return text.strip()
    return None


# ---------------------------------------------------------------------------
# Section parsers
# ---------------------------------------------------------------------------


def _parse_name(root: etree._Element) -> str:
    # Real export: name attribute on root <policy> element
    full_path = root.get("name") or ""
    # Fallback: <policy_version>/<policy_name>
    if not full_path:
        full_path = root.findtext("policy_version/policy_name") or ""
    # Fallback: declarative <fullPath>
    if not full_path:
        full_path = root.findtext("fullPath") or ""
    full_path = full_path.strip()
    if full_path.startswith("/Common/"):
        return full_path[len("/Common/"):]
    return full_path


def _parse_enforcement_mode(root: etree._Element) -> EnforcementMode:
    # Real export: <blocking>/<enforcement_mode> with values "blocking" or "enforcing"
    mode_text = root.findtext(".//blocking/enforcement_mode") or ""
    mode_text = mode_text.strip().lower()
    if mode_text in ("blocking", "enforcing"):
        return EnforcementMode.BLOCKING
    if mode_text == "transparent":
        return EnforcementMode.TRANSPARENT
    # Fallback: declarative <enforcementMode>
    mode_text = (root.findtext("enforcementMode") or "blocking").strip().lower()
    if mode_text == "transparent":
        return EnforcementMode.TRANSPARENT
    return EnforcementMode.BLOCKING


def _parse_encoding(root: etree._Element) -> str:
    return (root.findtext("encoding") or "utf-8").strip()


def _parse_accuracy_level(root: etree._Element) -> AccuracyLevel:
    settings = root.findall(
        ".//signatureSettings/placeholderSignaturesSettings/placeholderSignatureSetting"
    )
    for setting in settings:
        acc_filter = (setting.findtext("accuracyFilter") or "").strip()
        acc_value = (setting.findtext("accuracyValue") or "").strip()
        if acc_filter == "ge" and acc_value == "medium":
            return AccuracyLevel.HIGH_MEDIUM
        if acc_filter == "eq" and acc_value == "high":
            return AccuracyLevel.HIGH
    return AccuracyLevel.HIGH_MEDIUM


def _parse_signature_override(elem: etree._Element) -> SignatureOverride:
    # Real export: <signature signature_id="200001001">
    sig_id = _int(elem.get("signature_id"))
    if not sig_id:
        # Fallback: declarative <signatureId> or <signatureOverride>/<signatureId>
        sig_id = _int(elem.findtext("signatureId"))

    return SignatureOverride(
        sig_id=sig_id,
        enabled=_bool(elem.findtext("enabled"), default=True),
        alarm=_bool(elem.findtext("alarm")),
        block=_bool(elem.findtext("block")),
    )


def _parse_signatures(root: etree._Element) -> SignatureConfig:
    overrides: list[SignatureOverride] = []

    # Real export: <attack_signatures>/<signature signature_id="...">
    for sig_elem in root.findall(".//attack_signatures/signature"):
        overrides.append(_parse_signature_override(sig_elem))

    # Fallback: declarative <signatures>/<signature>
    if not overrides:
        for sig_elem in root.findall(".//signatures/signature"):
            overrides.append(_parse_signature_override(sig_elem))

    # Staging: real export uses <attack_signatures>/<enable_staging>
    staging_text = root.findtext(".//attack_signatures/enable_staging")
    if staging_text is None:
        staging_text = root.findtext(".//signatureSettings/signatureStaging")
    staging_enabled = _bool(staging_text, default=True)

    staging_period_text = root.findtext(".//attack_signatures/staging_period_in_days")
    if staging_period_text is None:
        staging_period_text = root.findtext(".//signatureSettings/stagingPeriod")
    staging_period = _int(staging_period_text, default=7)

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

    # Real export: <attack_signatures>/<signature_set>/<set id="1" name="...">
    for ss_elem in root.findall(".//attack_signatures/signature_set"):
        set_elem = ss_elem.find("set")
        if set_elem is not None:
            name = set_elem.get("name") or (set_elem.findtext("set_name") or "").strip()
            alarm = _bool(ss_elem.findtext("alarm"), default=True)
            block = _bool(ss_elem.findtext("block"), default=True)
            if name:
                result.append(SignatureSet(name=name, enabled=alarm or block))

    if result:
        return result

    # Fallback: declarative <signature-sets>/<signature-set>/<name>
    for ss_elem in root.findall(".//signature-sets/signature-set"):
        name = (ss_elem.findtext("name") or "").strip()
        enabled = _bool(ss_elem.findtext("enabled"), default=True)
        if name:
            result.append(SignatureSet(name=name, enabled=enabled))

    return result


def _parse_url_entity(elem: etree._Element) -> UrlEntity:
    sig_overrides: list[SignatureOverride] = []
    # Real export nests overrides differently; check both paths
    for so in elem.findall("signatureOverrides/signatureOverride"):
        sig_overrides.append(_parse_signature_override(so))

    name = _attr_or_child(elem, "name") or ""
    protocol = _attr_or_child(elem, "protocol")
    url_type = _attr_or_child(elem, "type")
    method = _attr_or_child(elem, "method")

    def _opt_bool(child_name: str) -> bool | None:
        # Try attribute-style names (real export uses snake_case children)
        for cname in (child_name,):
            node = elem.find(cname)
            if node is not None:
                return _bool(node.text)
        return None

    return UrlEntity(
        name=name,
        protocol=protocol or None,
        type=url_type or None,
        method=method or None,
        is_allowed=_opt_bool("isAllowed") if _opt_bool("isAllowed") is not None else _opt_bool("is_allowed"),
        attack_signatures_check=(
            _opt_bool("attackSignaturesCheck")
            if _opt_bool("attackSignaturesCheck") is not None
            else _opt_bool("attack_signatures")
        ),
        metachars_on_url_check=_opt_bool("metacharsOnUrlCheck"),
        clickjacking_protection=_opt_bool("clickjackingProtection") if _opt_bool("clickjackingProtection") is not None else _opt_bool("clickjacking_protection"),
        perform_staging=_opt_bool("performStaging") if _opt_bool("performStaging") is not None else _opt_bool("in_staging"),
        signature_overrides=sig_overrides,
    )


def _parse_parameter_entity(elem: etree._Element) -> ParameterEntity:
    sig_overrides: list[SignatureOverride] = []
    for so in elem.findall("signatureOverrides/signatureOverride"):
        sig_overrides.append(_parse_signature_override(so))

    name = _attr_or_child(elem, "name") or ""
    param_type = _attr_or_child(elem, "type")

    def _find(camel: str, snake: str = "") -> str | None:
        text = elem.findtext(camel)
        if text is not None:
            return text.strip()
        if snake:
            text = elem.findtext(snake)
            if text is not None:
                return text.strip()
        return None

    def _find_bool(camel: str, snake: str = "") -> bool | None:
        for n in (camel, snake) if snake else (camel,):
            node = elem.find(n)
            if node is not None:
                return _bool(node.text)
        return None

    return ParameterEntity(
        name=name,
        type=param_type or None,
        value_type=_find("valueType", "value_type"),
        level=_find("level", "location"),
        data_type=_find("dataType", "data_type"),
        sensitive=_find_bool("sensitiveParameter", "is_sensitive"),
        parameter_location=_find("parameterLocation", "parameter_location"),
        allow_empty_value=_find_bool("allowEmptyValue", "allow_empty_value"),
        check_max_value_length=_find_bool("checkMaxValueLength", "check_maximum_length"),
        maximum_length=_int(_find("maximumLength", "maximum_length")) if _find("maximumLength", "maximum_length") else None,
        perform_staging=_find_bool("performStaging", "in_staging"),
        attack_signatures_check=_find_bool("attackSignaturesCheck", "attack_signatures"),
        signature_overrides=sig_overrides,
    )


def _parse_filetype_entity(elem: etree._Element) -> FileTypeEntity:
    name = _attr_or_child(elem, "name") or ""

    def _find_bool(camel: str, snake: str = "") -> bool | None:
        for n in (camel, snake) if snake else (camel,):
            node = elem.find(n)
            if node is not None:
                return _bool(node.text)
        return None

    def _find_int(camel: str, snake: str = "") -> int | None:
        for n in (camel, snake) if snake else (camel,):
            node = elem.find(n)
            if node is not None:
                return _int(node.text)
        return None

    return FileTypeEntity(
        name=name,
        allowed=_find_bool("allowed"),
        response_check=_find_bool("responseCheck", "check_response"),
        query_string_length=_find_int("queryStringLength", "query_string_length"),
        url_length=_find_int("urlLength", "url_length"),
        post_data_length=_find_int("postDataLength", "post_data_length"),
        request_length=_find_int("requestLength", "request_length"),
    )


def _parse_cookie_entity(elem: etree._Element) -> CookieEntity:
    sig_overrides: list[SignatureOverride] = []
    for so in elem.findall("signatureOverrides/signatureOverride"):
        sig_overrides.append(_parse_signature_override(so))

    name = _attr_or_child(elem, "name") or ""
    cookie_type = _attr_or_child(elem, "type")

    def _find_bool(camel: str, snake: str = "") -> bool | None:
        for n in (camel, snake) if snake else (camel,):
            node = elem.find(n)
            if node is not None:
                return _bool(node.text)
        return None

    return CookieEntity(
        name=name,
        type=cookie_type or None,
        enforcement_type=elem.findtext("enforcementType") or elem.findtext("enforcement_type"),
        attack_signatures_check=_find_bool("attackSignaturesCheck", "check_signatures"),
        signature_overrides=sig_overrides,
    )


def _parse_header_entity(elem: etree._Element) -> HeaderEntity:
    name = _attr_or_child(elem, "name") or ""
    header_type = _attr_or_child(elem, "type")

    def _find_bool(camel: str, snake: str = "") -> bool | None:
        for n in (camel, snake) if snake else (camel,):
            node = elem.find(n)
            if node is not None:
                return _bool(node.text)
        return None

    return HeaderEntity(
        name=name,
        type=header_type or None,
        mandatory=_find_bool("mandatory", "is_mandatory"),
        check_signatures=_find_bool("checkSignatures", "check_signatures"),
    )


def _parse_method_entity(elem: etree._Element) -> MethodEntity:
    name = _attr_or_child(elem, "name") or ""
    return MethodEntity(
        name=name,
        act_as_method=elem.findtext("actAsMethod") or elem.findtext("act_as") or None,
    )


def _parse_entities(root: etree._Element) -> EntityCollection:
    urls = [_parse_url_entity(e) for e in root.findall(".//urls/url")]
    parameters = [_parse_parameter_entity(e) for e in root.findall(".//parameters/parameter")]

    # Real export: <file_types>/<file_type>; declarative: <filetypes>/<filetype>
    file_type_elems = root.findall(".//file_types/file_type") or root.findall(".//filetypes/filetype")
    file_types = [_parse_filetype_entity(e) for e in file_type_elems]

    cookies = [_parse_cookie_entity(e) for e in root.findall(".//cookies/cookie")]

    # Real export: top-level <header name="...">, declarative: <headers>/<header>
    header_elems = root.findall(".//headers/header")
    if not header_elems:
        header_elems = [h for h in root.findall(".//header") if h.get("name")]
    headers = [_parse_header_entity(e) for e in header_elems]

    methods = [_parse_method_entity(e) for e in root.findall(".//methods/method")]

    return EntityCollection(
        urls=urls,
        parameters=parameters,
        file_types=file_types,
        cookies=cookies,
        headers=headers,
        methods=methods,
    )


def _parse_violations(root: etree._Element) -> list[Violation]:
    result: list[Violation] = []

    # Real export: <blocking>/<violation id="X" name="Y">
    for v_elem in root.findall(".//blocking/violation"):
        name = v_elem.get("name") or v_elem.get("id") or ""
        if name:
            result.append(
                Violation(
                    name=name,
                    alarm=_bool(v_elem.findtext("alarm")),
                    block=_bool(v_elem.findtext("block")),
                )
            )

    if result:
        return result

    # Also check for <violation> elements anywhere with id/name attrs (some versions)
    for v_elem in root.findall(".//violation"):
        name = v_elem.get("name") or v_elem.get("id") or ""
        if name:
            result.append(
                Violation(
                    name=name,
                    alarm=_bool(v_elem.findtext("alarm")),
                    block=_bool(v_elem.findtext("block")),
                )
            )

    if result:
        return result

    # Fallback: declarative <violations>/<violation>/<name>
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

    # Real export and declarative both use <whitelist-ips>/<ip>
    for ip_elem in root.findall(".//whitelist-ips/ip"):
        ip_addr = (ip_elem.findtext("ipAddress") or "").strip()
        if ip_addr:
            block_text = (ip_elem.findtext("blockRequests") or "").strip().lower()
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

    # Real export: <ip_address_exceptions>/<ip_address_exception>
    if not result:
        for ip_elem in root.findall(".//ip_address_exceptions/ip_address_exception"):
            ip_addr = (ip_elem.findtext("ip_address") or ip_elem.get("ip_address") or "").strip()
            if ip_addr:
                block_text = (ip_elem.findtext("block_requests") or "").strip().lower()
                block_requests = block_text not in ("never", "")
                result.append(
                    IpWhitelistEntry(
                        ip=ip_addr,
                        mask=(ip_elem.findtext("ip_mask") or "").strip(),
                        block_requests=block_requests,
                    )
                )

    return result


def _parse_geolocation(root: etree._Element) -> GeolocationConfig:
    disallowed: list[str] = []

    # Declarative: <geolocation-enforcement>/<disallowed-geolocations>/<geolocation>/<country>
    for geo_elem in root.findall(".//geolocation-enforcement/disallowed-geolocations/geolocation"):
        country = (geo_elem.findtext("country") or "").strip()
        if country:
            disallowed.append(country)

    # Real export: <geolocation> with <disallowed_country_list> or similar
    if not disallowed:
        for geo_elem in root.findall(".//geolocation/disallowed_country"):
            country = (geo_elem.text or "").strip()
            if country:
                disallowed.append(country)

    return GeolocationConfig(disallowed=disallowed)


def _parse_csrf(root: etree._Element) -> CsrfConfig:
    # Both formats use <csrf> with <enabled> child
    csrf_elem = root.find(".//csrf")
    if csrf_elem is None:
        csrf_elem = root.find(".//csrf-protection")
    if csrf_elem is None:
        return CsrfConfig()
    return CsrfConfig(
        enabled=_bool(csrf_elem.findtext("enabled")),
    )


def _parse_data_guard(root: etree._Element) -> DataGuardConfig:
    # Real export: <data_guard>
    dg_elem = root.find(".//data_guard")
    if dg_elem is not None:
        return DataGuardConfig(
            enabled=_bool(dg_elem.findtext("enabled")),
            credit_cards=_bool(dg_elem.findtext("credit_card_numbers")),
            ssn=_bool(dg_elem.findtext("social_security_numbers")),
        )
    # Declarative: <data-guard>
    dg_elem = root.find(".//data-guard")
    if dg_elem is None:
        return DataGuardConfig()
    return DataGuardConfig(
        enabled=_bool(dg_elem.findtext("enabled")),
        credit_cards=_bool(dg_elem.findtext("creditCards")),
        ssn=_bool(dg_elem.findtext("ssn")),
    )


def _parse_brute_force(root: etree._Element) -> BruteForceConfig:
    # Real export: <brute_force>
    bf_elem = root.find(".//brute_force")
    if bf_elem is not None:
        return BruteForceConfig(
            enabled=True,
            detection_period=0,
            max_attempts=_int(bf_elem.findtext("maximum_login_attempts")),
            login_url="",
        )
    # Declarative: <brute-force>
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
    # Real export: <session_awareness>
    st_elem = root.find(".//session_awareness")
    if st_elem is not None:
        return SessionTrackingConfig(
            enabled=_bool(st_elem.findtext("enabled"), default=True),
            hijacking_prevention=False,
        )
    # Declarative: <session-tracking>
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
    # Declarative: <blocking-page>
    bp_elem = root.find(".//blocking-page")
    if bp_elem is not None:
        return BlockingPageConfig(
            enabled=_bool(bp_elem.findtext("enabled")),
            custom_html=(bp_elem.findtext("customHtml") or "").strip(),
            response_code=_int(bp_elem.findtext("responseCode")),
        )
    return BlockingPageConfig()


def _parse_response_codes(root: etree._Element) -> list[int]:
    result: list[int] = []

    # Real export: repeated <allowed_response_code> elements
    for rc_elem in root.findall(".//allowed_response_code"):
        text = (rc_elem.text or "").strip()
        if text:
            try:
                result.append(int(text))
            except ValueError:
                pass

    if result:
        return result

    # Fallback: declarative <allowed-response-codes>/<code>
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

        SafeET.fromstring(raw)

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
