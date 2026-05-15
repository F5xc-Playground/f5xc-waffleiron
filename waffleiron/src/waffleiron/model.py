"""AsmPolicy intermediate model — the central data structure for ASM/AWAF to XC WAF conversion.

Every parser writes to this model and every translator reads from it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class EnforcementMode(Enum):
    """ASM policy enforcement mode."""

    BLOCKING = "blocking"
    TRANSPARENT = "transparent"


class AccuracyLevel(Enum):
    """Signature accuracy filter level."""

    HIGH = "high"
    HIGH_MEDIUM = "high_medium"
    ALL = "all"


class BotAction(Enum):
    """Action to take on a detected bot category."""

    BLOCK = "block"
    REPORT = "report"
    IGNORE = "ignore"


# ---------------------------------------------------------------------------
# Small value objects
# ---------------------------------------------------------------------------


@dataclass
class SignatureOverride:
    """Per-signature enable/alarm/block override."""

    sig_id: int
    enabled: bool
    alarm: bool
    block: bool


@dataclass
class Violation:
    """A named violation with alarm/block flags."""

    name: str
    alarm: bool
    block: bool


@dataclass
class SignatureSet:
    """A named signature set with an enabled flag."""

    name: str
    enabled: bool


@dataclass
class BotCategory:
    """A bot classification category and the action to apply."""

    name: str
    action: str


@dataclass
class IpIntelCategory:
    """An IP intelligence threat category and the action to apply."""

    name: str
    action: str


@dataclass
class CustomSignature:
    """A user-defined custom attack signature."""

    id: int
    name: str
    pattern: str
    scope: str


# ---------------------------------------------------------------------------
# Entity dataclasses
# ---------------------------------------------------------------------------


@dataclass
class UrlEntity:
    """An ASM URL entity (explicit or wildcard)."""

    name: str
    protocol: Optional[str] = None
    type: Optional[str] = None
    method: Optional[str] = None
    is_allowed: Optional[bool] = None
    attack_signatures_check: Optional[bool] = None
    metachars_on_url_check: Optional[bool] = None
    clickjacking_protection: Optional[bool] = None
    perform_staging: Optional[bool] = None
    signature_overrides: list[SignatureOverride] = field(default_factory=list)


@dataclass
class ParameterEntity:
    """An ASM parameter entity (explicit or wildcard, global or URL-scoped)."""

    name: str
    type: Optional[str] = None
    value_type: Optional[str] = None
    level: Optional[str] = None
    data_type: Optional[str] = None
    sensitive: Optional[bool] = None
    parameter_location: Optional[str] = None
    allow_empty_value: Optional[bool] = None
    check_max_value_length: Optional[bool] = None
    maximum_length: Optional[int] = None
    perform_staging: Optional[bool] = None
    attack_signatures_check: Optional[bool] = None
    signature_overrides: list[SignatureOverride] = field(default_factory=list)


@dataclass
class FileTypeEntity:
    """An ASM file type entity."""

    name: str
    allowed: Optional[bool] = None
    response_check: Optional[bool] = None
    query_string_length: Optional[int] = None
    url_length: Optional[int] = None
    post_data_length: Optional[int] = None
    request_length: Optional[int] = None


@dataclass
class CookieEntity:
    """An ASM cookie entity."""

    name: str
    type: Optional[str] = None
    enforcement_type: Optional[str] = None
    attack_signatures_check: Optional[bool] = None
    signature_overrides: list[SignatureOverride] = field(default_factory=list)


@dataclass
class HeaderEntity:
    """An ASM header entity."""

    name: str
    type: Optional[str] = None
    mandatory: Optional[bool] = None
    check_signatures: Optional[bool] = None


@dataclass
class MethodEntity:
    """An ASM allowed method entity."""

    name: str
    act_as_method: Optional[str] = None


@dataclass
class IpWhitelistEntry:
    """An IP address/network in the ASM whitelist."""

    ip: str
    mask: str
    block_requests: Optional[bool] = None
    never_log: Optional[bool] = None
    trusted_by_builder: Optional[bool] = None
    ignore_anomalies: Optional[bool] = None
    ignore_ip_reputation: Optional[bool] = None


# ---------------------------------------------------------------------------
# Config grouping dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SignatureConfig:
    """Signature-related settings for the ASM policy."""

    global_overrides: list[SignatureOverride]
    accuracy_level: AccuracyLevel
    staging_enabled: bool
    staging_period: int
    threat_campaigns_enabled: bool


@dataclass
class EntityCollection:
    """All entity types collected from the ASM policy."""

    urls: list[UrlEntity] = field(default_factory=list)
    parameters: list[ParameterEntity] = field(default_factory=list)
    file_types: list[FileTypeEntity] = field(default_factory=list)
    cookies: list[CookieEntity] = field(default_factory=list)
    headers: list[HeaderEntity] = field(default_factory=list)
    methods: list[MethodEntity] = field(default_factory=list)


@dataclass
class GeolocationConfig:
    """Geolocation enforcement settings."""

    disallowed: list[str] = field(default_factory=list)


@dataclass
class CsrfConfig:
    """Cross-site request forgery protection settings."""

    enabled: bool = False
    urls: list = field(default_factory=list)


@dataclass
class DataGuardConfig:
    """Data Guard (sensitive data masking) settings."""

    enabled: bool = False
    credit_cards: bool = False
    ssn: bool = False
    custom_patterns: list = field(default_factory=list)
    exception_urls: list = field(default_factory=list)


@dataclass
class BruteForceConfig:
    """Brute-force attack detection settings."""

    enabled: bool = False
    detection_period: int = 0
    max_attempts: int = 0
    login_url: str = ""


@dataclass
class SessionTrackingConfig:
    """Session tracking settings."""

    enabled: bool = False
    hijacking_prevention: bool = False


@dataclass
class BotDefenseConfig:
    """Bot defense settings."""

    enabled: bool = False
    mode: str = ""
    categories: list[BotCategory] = field(default_factory=list)


@dataclass
class IpIntelligenceConfig:
    """IP intelligence / threat feed settings."""

    categories: list[IpIntelCategory] = field(default_factory=list)


@dataclass
class BlockingPageConfig:
    """Custom blocking response page settings."""

    enabled: bool = False
    custom_html: str = ""
    response_code: int = 0


# ---------------------------------------------------------------------------
# Top-level policy model
# ---------------------------------------------------------------------------


@dataclass
class AsmPolicy:
    """Intermediate representation of a BIG-IP ASM/AWAF policy.

    This is the central data structure that parsers populate and translators consume.
    Every field corresponds to an ASM policy concept; translators map these to F5 XC
    WAF objects (app_firewall, waf_exclusion_policy, service_policy, etc.).
    """

    name: str
    enforcement_mode: EnforcementMode
    encoding: str

    signatures: SignatureConfig
    signature_sets: list[SignatureSet]
    entities: EntityCollection
    violations: list[Violation]

    whitelist_ips: list[IpWhitelistEntry]
    geolocation: GeolocationConfig
    csrf: CsrfConfig
    data_guard: DataGuardConfig
    brute_force: BruteForceConfig
    session_tracking: SessionTrackingConfig
    bot_defense: BotDefenseConfig
    ip_intelligence: IpIntelligenceConfig
    blocking_page: BlockingPageConfig

    allowed_response_codes: list[int]
    custom_signatures: list[CustomSignature]
