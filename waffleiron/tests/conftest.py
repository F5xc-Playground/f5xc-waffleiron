from pathlib import Path

import pytest

from waffleiron.model import (
    AccuracyLevel,
    AsmPolicy,
    BotCategory,
    BotDefenseConfig,
    BlockingPageConfig,
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
    IpIntelligenceConfig,
    IpWhitelistEntry,
    ParameterEntity,
    SessionTrackingConfig,
    SignatureConfig,
    SignatureOverride,
    SignatureSet,
    UrlEntity,
    Violation,
)


@pytest.fixture
def fixtures_path():
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def minimal_policy():
    return AsmPolicy(
        name="test-policy",
        enforcement_mode=EnforcementMode.BLOCKING,
        encoding="utf-8",
        signatures=SignatureConfig(
            global_overrides=[],
            accuracy_level=AccuracyLevel.HIGH_MEDIUM,
            staging_enabled=True,
            staging_period=7,
            threat_campaigns_enabled=True,
        ),
        signature_sets=[],
        entities=EntityCollection(),
        violations=[],
        whitelist_ips=[],
        geolocation=GeolocationConfig(),
        csrf=CsrfConfig(),
        data_guard=DataGuardConfig(),
        brute_force=BruteForceConfig(),
        session_tracking=SessionTrackingConfig(),
        bot_defense=BotDefenseConfig(),
        ip_intelligence=IpIntelligenceConfig(),
        blocking_page=BlockingPageConfig(),
        allowed_response_codes=[],
        custom_signatures=[],
    )


@pytest.fixture
def mature_policy():
    """Policy with alarm-only sigs, entity overrides, geo, bot defense, etc."""
    return AsmPolicy(
        name="mature-tuned",
        enforcement_mode=EnforcementMode.BLOCKING,
        encoding="utf-8",
        signatures=SignatureConfig(
            global_overrides=[
                SignatureOverride(sig_id=200001001, enabled=True, alarm=True, block=False),  # alarm-only
                SignatureOverride(sig_id=200001002, enabled=False, alarm=False, block=False),  # disabled
                SignatureOverride(sig_id=200001003, enabled=True, alarm=True, block=True),  # enforced
            ],
            accuracy_level=AccuracyLevel.HIGH_MEDIUM,
            staging_enabled=True,
            staging_period=7,
            threat_campaigns_enabled=True,
        ),
        signature_sets=[],
        entities=EntityCollection(
            urls=[
                UrlEntity(name="/api/v1/data", attack_signatures_check=False),
                UrlEntity(
                    name="/login",
                    signature_overrides=[
                        SignatureOverride(sig_id=200001004, enabled=False, alarm=False, block=False),
                    ],
                ),
            ],
            parameters=[
                ParameterEntity(name="session_id", sensitive=True),
                ParameterEntity(name="query", attack_signatures_check=False),
            ],
            cookies=[CookieEntity(name="tracking", attack_signatures_check=False)],
        ),
        violations=[
            Violation(name="VIOL_COOKIE_MODIFIED", alarm=True, block=False),  # alarm-only
            Violation(name="VIOL_ENCODING", alarm=True, block=False),  # alarm-only
            Violation(name="VIOL_ATTACK_SIGNATURE", alarm=True, block=True),  # enforced
        ],
        whitelist_ips=[IpWhitelistEntry(ip="10.0.0.0", mask="255.0.0.0", block_requests="never")],
        geolocation=GeolocationConfig(disallowed=["North Korea", "Iran"]),
        bot_defense=BotDefenseConfig(
            enabled=True,
            categories=[
                BotCategory(name="malicious-bot", action="block"),
                BotCategory(name="benign-bot", action="report"),
                BotCategory(name="unknown-bot", action="challenge"),  # untranslatable action
            ],
        ),
        blocking_page=BlockingPageConfig(
            enabled=True, custom_html="<p><%TS.request.ID()%></p>", response_code=403
        ),
        custom_signatures=[],
        csrf=CsrfConfig(),
        data_guard=DataGuardConfig(),
        brute_force=BruteForceConfig(),
        session_tracking=SessionTrackingConfig(),
        ip_intelligence=IpIntelligenceConfig(),
        allowed_response_codes=[],
    )


@pytest.fixture
def positive_security_policy():
    """Policy heavy on positive security entities."""
    return AsmPolicy(
        name="positive-security",
        enforcement_mode=EnforcementMode.BLOCKING,
        encoding="utf-8",
        signatures=SignatureConfig(
            global_overrides=[],
            accuracy_level=AccuracyLevel.HIGH_MEDIUM,
            staging_enabled=True,
            staging_period=7,
            threat_campaigns_enabled=True,
        ),
        signature_sets=[],
        entities=EntityCollection(
            urls=[
                UrlEntity(name="/api/v1", type="explicit"),
                UrlEntity(name="/login", type="explicit"),
                UrlEntity(name="/static/*", type="wildcard"),
            ],
            parameters=[
                ParameterEntity(name="id", value_type="numeric"),
                ParameterEntity(name="name", value_type="alpha"),
                ParameterEntity(name="email", value_type="email"),
                ParameterEntity(name="free", value_type="user-input"),
            ],
            file_types=[
                FileTypeEntity(name="pdf", allowed=True),
                FileTypeEntity(name="exe", allowed=False),
            ],
            cookies=[CookieEntity(name="session")],
            headers=[
                HeaderEntity(name="X-Custom", mandatory=True),
                HeaderEntity(name="Accept"),
            ],
        ),
        violations=[],
        whitelist_ips=[],
        geolocation=GeolocationConfig(),
        csrf=CsrfConfig(),
        data_guard=DataGuardConfig(),
        brute_force=BruteForceConfig(),
        session_tracking=SessionTrackingConfig(enabled=True, hijacking_prevention=True),
        bot_defense=BotDefenseConfig(),
        ip_intelligence=IpIntelligenceConfig(),
        blocking_page=BlockingPageConfig(),
        allowed_response_codes=[],
        custom_signatures=[
            CustomSignature(id=300000001, name="Custom SQL", pattern=r"/union\s+select/i", scope="/api/*"),
            CustomSignature(id=300000002, name="Header Inject", pattern=r"/X-Internal/", scope="global"),
        ],
    )


def make_policy_with_disabled_sig_set(set_name: str):
    """Create a policy with one disabled SignatureSet (enabled=False)."""
    return AsmPolicy(
        name="sig-set-test",
        enforcement_mode=EnforcementMode.BLOCKING,
        encoding="utf-8",
        signatures=SignatureConfig(
            global_overrides=[],
            accuracy_level=AccuracyLevel.HIGH_MEDIUM,
            staging_enabled=True,
            staging_period=7,
            threat_campaigns_enabled=True,
        ),
        signature_sets=[SignatureSet(name=set_name, enabled=False)],
        entities=EntityCollection(),
        violations=[],
        whitelist_ips=[],
        geolocation=GeolocationConfig(),
        csrf=CsrfConfig(),
        data_guard=DataGuardConfig(),
        brute_force=BruteForceConfig(),
        session_tracking=SessionTrackingConfig(),
        bot_defense=BotDefenseConfig(),
        ip_intelligence=IpIntelligenceConfig(),
        blocking_page=BlockingPageConfig(),
        allowed_response_codes=[],
        custom_signatures=[],
    )


def make_policy_with_disabled_violation(violation_name: str):
    """Create a policy with one Violation where alarm=False, block=False (disabled)."""
    return AsmPolicy(
        name="violation-test",
        enforcement_mode=EnforcementMode.BLOCKING,
        encoding="utf-8",
        signatures=SignatureConfig(
            global_overrides=[],
            accuracy_level=AccuracyLevel.HIGH_MEDIUM,
            staging_enabled=True,
            staging_period=7,
            threat_campaigns_enabled=True,
        ),
        signature_sets=[],
        entities=EntityCollection(),
        violations=[Violation(name=violation_name, alarm=False, block=False)],
        whitelist_ips=[],
        geolocation=GeolocationConfig(),
        csrf=CsrfConfig(),
        data_guard=DataGuardConfig(),
        brute_force=BruteForceConfig(),
        session_tracking=SessionTrackingConfig(),
        bot_defense=BotDefenseConfig(),
        ip_intelligence=IpIntelligenceConfig(),
        blocking_page=BlockingPageConfig(),
        allowed_response_codes=[],
        custom_signatures=[],
    )


def make_policy_with_n_overrides(n):
    """Create a policy with n alarm-only signature overrides."""
    overrides = [
        SignatureOverride(sig_id=200001000 + i, enabled=True, alarm=True, block=False)
        for i in range(n)
    ]
    return AsmPolicy(
        name="bulk-test",
        enforcement_mode=EnforcementMode.BLOCKING,
        encoding="utf-8",
        signatures=SignatureConfig(
            global_overrides=overrides,
            accuracy_level=AccuracyLevel.HIGH_MEDIUM,
            staging_enabled=True,
            staging_period=7,
            threat_campaigns_enabled=True,
        ),
        signature_sets=[],
        entities=EntityCollection(),
        violations=[],
        whitelist_ips=[],
        geolocation=GeolocationConfig(),
        csrf=CsrfConfig(),
        data_guard=DataGuardConfig(),
        brute_force=BruteForceConfig(),
        session_tracking=SessionTrackingConfig(),
        bot_defense=BotDefenseConfig(),
        ip_intelligence=IpIntelligenceConfig(),
        blocking_page=BlockingPageConfig(),
        allowed_response_codes=[],
        custom_signatures=[],
    )
