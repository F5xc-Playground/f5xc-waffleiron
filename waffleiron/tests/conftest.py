from pathlib import Path

import pytest

from waffleiron.model import (
    AccuracyLevel,
    AsmPolicy,
    EntityCollection,
    EnforcementMode,
    GeolocationConfig,
    CsrfConfig,
    DataGuardConfig,
    BruteForceConfig,
    SessionTrackingConfig,
    BotDefenseConfig,
    IpIntelligenceConfig,
    BlockingPageConfig,
    SignatureConfig,
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
