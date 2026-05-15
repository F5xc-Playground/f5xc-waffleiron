"""Tests for the AsmPolicy intermediate model and all supporting types."""

from dataclasses import fields as dc_fields

from waffleiron.model import (
    AccuracyLevel,
    AsmPolicy,
    BlockingPageConfig,
    BotAction,
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
# Enum tests
# ---------------------------------------------------------------------------


class TestEnforcementMode:
    def test_has_blocking(self):
        assert EnforcementMode.BLOCKING is not None

    def test_has_transparent(self):
        assert EnforcementMode.TRANSPARENT is not None

    def test_values_are_distinct(self):
        assert EnforcementMode.BLOCKING != EnforcementMode.TRANSPARENT


class TestAccuracyLevel:
    def test_has_high(self):
        assert AccuracyLevel.HIGH is not None

    def test_has_high_medium(self):
        assert AccuracyLevel.HIGH_MEDIUM is not None

    def test_has_all(self):
        assert AccuracyLevel.ALL is not None

    def test_values_are_distinct(self):
        levels = {AccuracyLevel.HIGH, AccuracyLevel.HIGH_MEDIUM, AccuracyLevel.ALL}
        assert len(levels) == 3


class TestBotAction:
    def test_has_block(self):
        assert BotAction.BLOCK is not None

    def test_has_report(self):
        assert BotAction.REPORT is not None

    def test_has_ignore(self):
        assert BotAction.IGNORE is not None

    def test_values_are_distinct(self):
        actions = {BotAction.BLOCK, BotAction.REPORT, BotAction.IGNORE}
        assert len(actions) == 3


# ---------------------------------------------------------------------------
# Entity dataclass tests
# ---------------------------------------------------------------------------


class TestSignatureOverride:
    def test_construction(self):
        so = SignatureOverride(sig_id=200000001, enabled=True, alarm=True, block=False)
        assert so.sig_id == 200000001
        assert so.enabled is True
        assert so.alarm is True
        assert so.block is False

    def test_field_types(self):
        field_map = {f.name: f.type for f in dc_fields(SignatureOverride)}
        assert field_map["sig_id"] == "int"
        assert field_map["enabled"] == "bool"
        assert field_map["alarm"] == "bool"
        assert field_map["block"] == "bool"


class TestViolation:
    def test_construction(self):
        v = Violation(name="VIOL_URL", alarm=True, block=True)
        assert v.name == "VIOL_URL"
        assert v.alarm is True
        assert v.block is True

    def test_field_types(self):
        field_map = {f.name: f.type for f in dc_fields(Violation)}
        assert field_map["name"] == "str"
        assert field_map["alarm"] == "bool"
        assert field_map["block"] == "bool"


class TestSignatureSet:
    def test_construction(self):
        ss = SignatureSet(name="Generic Detection Signatures", enabled=True)
        assert ss.name == "Generic Detection Signatures"
        assert ss.enabled is True


class TestUrlEntity:
    def test_construction_minimal(self):
        url = UrlEntity(name="/api/v1/*")
        assert url.name == "/api/v1/*"

    def test_construction_full(self):
        so = SignatureOverride(sig_id=200000001, enabled=False, alarm=False, block=False)
        url = UrlEntity(
            name="/login",
            protocol="https",
            type="explicit",
            method="*",
            is_allowed=True,
            attack_signatures_check=True,
            metachars_on_url_check=True,
            clickjacking_protection=False,
            perform_staging=True,
            signature_overrides=[so],
        )
        assert url.name == "/login"
        assert url.protocol == "https"
        assert url.type == "explicit"
        assert url.method == "*"
        assert url.is_allowed is True
        assert url.attack_signatures_check is True
        assert url.metachars_on_url_check is True
        assert url.clickjacking_protection is False
        assert url.perform_staging is True
        assert len(url.signature_overrides) == 1
        assert url.signature_overrides[0].sig_id == 200000001

    def test_defaults(self):
        url = UrlEntity(name="/test")
        assert url.protocol is None
        assert url.type is None
        assert url.method is None
        assert url.is_allowed is None
        assert url.attack_signatures_check is None
        assert url.metachars_on_url_check is None
        assert url.clickjacking_protection is None
        assert url.perform_staging is None
        assert url.signature_overrides == []


class TestParameterEntity:
    def test_construction_minimal(self):
        p = ParameterEntity(name="username")
        assert p.name == "username"

    def test_construction_full(self):
        so = SignatureOverride(sig_id=200000002, enabled=True, alarm=True, block=True)
        p = ParameterEntity(
            name="password",
            type="explicit",
            value_type="user-input",
            level="global",
            data_type="alpha-numeric",
            sensitive=True,
            parameter_location="any",
            allow_empty_value=False,
            check_max_value_length=True,
            maximum_length=256,
            perform_staging=False,
            attack_signatures_check=True,
            signature_overrides=[so],
        )
        assert p.name == "password"
        assert p.type == "explicit"
        assert p.value_type == "user-input"
        assert p.level == "global"
        assert p.data_type == "alpha-numeric"
        assert p.sensitive is True
        assert p.parameter_location == "any"
        assert p.allow_empty_value is False
        assert p.check_max_value_length is True
        assert p.maximum_length == 256
        assert p.perform_staging is False
        assert p.attack_signatures_check is True
        assert len(p.signature_overrides) == 1

    def test_defaults(self):
        p = ParameterEntity(name="q")
        assert p.type is None
        assert p.value_type is None
        assert p.level is None
        assert p.data_type is None
        assert p.sensitive is None
        assert p.parameter_location is None
        assert p.allow_empty_value is None
        assert p.check_max_value_length is None
        assert p.maximum_length is None
        assert p.perform_staging is None
        assert p.attack_signatures_check is None
        assert p.signature_overrides == []


class TestFileTypeEntity:
    def test_construction(self):
        ft = FileTypeEntity(
            name="php",
            allowed=True,
            response_check=False,
            query_string_length=2048,
            url_length=2048,
            post_data_length=10000,
            request_length=10000,
        )
        assert ft.name == "php"
        assert ft.allowed is True
        assert ft.response_check is False
        assert ft.query_string_length == 2048
        assert ft.url_length == 2048
        assert ft.post_data_length == 10000
        assert ft.request_length == 10000

    def test_defaults(self):
        ft = FileTypeEntity(name="html")
        assert ft.allowed is None
        assert ft.response_check is None
        assert ft.query_string_length is None
        assert ft.url_length is None
        assert ft.post_data_length is None
        assert ft.request_length is None


class TestCookieEntity:
    def test_construction_full(self):
        so = SignatureOverride(sig_id=200000003, enabled=True, alarm=False, block=False)
        c = CookieEntity(
            name="session_id",
            type="explicit",
            enforcement_type="allow",
            attack_signatures_check=True,
            signature_overrides=[so],
        )
        assert c.name == "session_id"
        assert c.type == "explicit"
        assert c.enforcement_type == "allow"
        assert c.attack_signatures_check is True
        assert len(c.signature_overrides) == 1

    def test_defaults(self):
        c = CookieEntity(name="csrf_token")
        assert c.type is None
        assert c.enforcement_type is None
        assert c.attack_signatures_check is None
        assert c.signature_overrides == []


class TestHeaderEntity:
    def test_construction(self):
        h = HeaderEntity(name="X-Custom-Header", type="explicit", mandatory=False, check_signatures=True)
        assert h.name == "X-Custom-Header"
        assert h.type == "explicit"
        assert h.mandatory is False
        assert h.check_signatures is True

    def test_defaults(self):
        h = HeaderEntity(name="Host")
        assert h.type is None
        assert h.mandatory is None
        assert h.check_signatures is None


class TestMethodEntity:
    def test_construction(self):
        m = MethodEntity(name="DELETE", act_as_method="DELETE")
        assert m.name == "DELETE"
        assert m.act_as_method == "DELETE"

    def test_defaults(self):
        m = MethodEntity(name="GET")
        assert m.act_as_method is None


class TestIpWhitelistEntry:
    def test_construction_full(self):
        entry = IpWhitelistEntry(
            ip="10.0.0.1",
            mask="255.255.255.255",
            block_requests=False,
            never_log=False,
            trusted_by_builder=True,
            ignore_anomalies=True,
            ignore_ip_reputation=True,
        )
        assert entry.ip == "10.0.0.1"
        assert entry.mask == "255.255.255.255"
        assert entry.block_requests is False
        assert entry.never_log is False
        assert entry.trusted_by_builder is True
        assert entry.ignore_anomalies is True
        assert entry.ignore_ip_reputation is True

    def test_defaults(self):
        entry = IpWhitelistEntry(ip="192.168.1.0", mask="255.255.255.0")
        assert entry.block_requests is None
        assert entry.never_log is None
        assert entry.trusted_by_builder is None
        assert entry.ignore_anomalies is None
        assert entry.ignore_ip_reputation is None


class TestBotCategory:
    def test_construction(self):
        bc = BotCategory(name="search_engine", action="report")
        assert bc.name == "search_engine"
        assert bc.action == "report"


class TestIpIntelCategory:
    def test_construction(self):
        ic = IpIntelCategory(name="botnets", action="block")
        assert ic.name == "botnets"
        assert ic.action == "block"


class TestCustomSignature:
    def test_construction(self):
        cs = CustomSignature(id=300000001, name="My Sig", pattern=".*evil.*", scope="url")
        assert cs.id == 300000001
        assert cs.name == "My Sig"
        assert cs.pattern == ".*evil.*"
        assert cs.scope == "url"


# ---------------------------------------------------------------------------
# Config dataclass tests
# ---------------------------------------------------------------------------


class TestSignatureConfig:
    def test_construction(self):
        sc = SignatureConfig(
            global_overrides=[],
            accuracy_level=AccuracyLevel.HIGH,
            staging_enabled=False,
            staging_period=14,
            threat_campaigns_enabled=False,
        )
        assert sc.accuracy_level == AccuracyLevel.HIGH
        assert sc.staging_enabled is False
        assert sc.staging_period == 14
        assert sc.threat_campaigns_enabled is False
        assert sc.global_overrides == []

    def test_with_overrides(self):
        overrides = [
            SignatureOverride(sig_id=200000001, enabled=False, alarm=True, block=False),
            SignatureOverride(sig_id=200000002, enabled=True, alarm=True, block=True),
        ]
        sc = SignatureConfig(
            global_overrides=overrides,
            accuracy_level=AccuracyLevel.ALL,
            staging_enabled=True,
            staging_period=7,
            threat_campaigns_enabled=True,
        )
        assert len(sc.global_overrides) == 2
        assert sc.global_overrides[0].sig_id == 200000001


class TestEntityCollection:
    def test_defaults(self):
        ec = EntityCollection()
        assert ec.urls == []
        assert ec.parameters == []
        assert ec.file_types == []
        assert ec.cookies == []
        assert ec.headers == []
        assert ec.methods == []

    def test_with_entities(self):
        ec = EntityCollection(
            urls=[UrlEntity(name="/test")],
            parameters=[ParameterEntity(name="q")],
            file_types=[FileTypeEntity(name="html")],
            cookies=[CookieEntity(name="sid")],
            headers=[HeaderEntity(name="Host")],
            methods=[MethodEntity(name="GET")],
        )
        assert len(ec.urls) == 1
        assert len(ec.parameters) == 1
        assert len(ec.file_types) == 1
        assert len(ec.cookies) == 1
        assert len(ec.headers) == 1
        assert len(ec.methods) == 1


class TestGeolocationConfig:
    def test_defaults(self):
        gc = GeolocationConfig()
        assert gc.disallowed == []

    def test_with_countries(self):
        gc = GeolocationConfig(disallowed=["North Korea", "Iran"])
        assert len(gc.disallowed) == 2
        assert "North Korea" in gc.disallowed


class TestCsrfConfig:
    def test_defaults(self):
        cc = CsrfConfig()
        assert cc.enabled is False
        assert cc.urls == []

    def test_enabled(self):
        cc = CsrfConfig(enabled=True, urls=["/login"])
        assert cc.enabled is True
        assert cc.urls == ["/login"]


class TestDataGuardConfig:
    def test_defaults(self):
        dg = DataGuardConfig()
        assert dg.enabled is False
        assert dg.credit_cards is False
        assert dg.ssn is False
        assert dg.custom_patterns == []
        assert dg.exception_urls == []

    def test_enabled_full(self):
        dg = DataGuardConfig(
            enabled=True,
            credit_cards=True,
            ssn=True,
            custom_patterns=[r"\d{3}-\d{2}-\d{4}"],
            exception_urls=["/api/health"],
        )
        assert dg.enabled is True
        assert dg.credit_cards is True
        assert dg.ssn is True
        assert len(dg.custom_patterns) == 1
        assert len(dg.exception_urls) == 1


class TestBruteForceConfig:
    def test_defaults(self):
        bf = BruteForceConfig()
        assert bf.enabled is False
        assert bf.detection_period == 0
        assert bf.max_attempts == 0
        assert bf.login_url == ""

    def test_enabled(self):
        bf = BruteForceConfig(
            enabled=True,
            detection_period=600,
            max_attempts=5,
            login_url="/auth/login",
        )
        assert bf.enabled is True
        assert bf.detection_period == 600
        assert bf.max_attempts == 5
        assert bf.login_url == "/auth/login"


class TestSessionTrackingConfig:
    def test_defaults(self):
        st = SessionTrackingConfig()
        assert st.enabled is False
        assert st.hijacking_prevention is False

    def test_enabled(self):
        st = SessionTrackingConfig(enabled=True, hijacking_prevention=True)
        assert st.enabled is True
        assert st.hijacking_prevention is True


class TestBotDefenseConfig:
    def test_defaults(self):
        bd = BotDefenseConfig()
        assert bd.enabled is False
        assert bd.mode == ""
        assert bd.categories == []

    def test_with_categories(self):
        cats = [
            BotCategory(name="search_engine", action="report"),
            BotCategory(name="dos_tool", action="block"),
        ]
        bd = BotDefenseConfig(enabled=True, mode="during_attacks", categories=cats)
        assert bd.enabled is True
        assert bd.mode == "during_attacks"
        assert len(bd.categories) == 2
        assert bd.categories[1].action == "block"


class TestIpIntelligenceConfig:
    def test_defaults(self):
        ii = IpIntelligenceConfig()
        assert ii.categories == []

    def test_with_categories(self):
        cats = [IpIntelCategory(name="botnets", action="block")]
        ii = IpIntelligenceConfig(categories=cats)
        assert len(ii.categories) == 1


class TestBlockingPageConfig:
    def test_defaults(self):
        bp = BlockingPageConfig()
        assert bp.enabled is False
        assert bp.custom_html == ""
        assert bp.response_code == 0

    def test_custom(self):
        bp = BlockingPageConfig(
            enabled=True,
            custom_html="<html><body>Blocked</body></html>",
            response_code=403,
        )
        assert bp.enabled is True
        assert "Blocked" in bp.custom_html
        assert bp.response_code == 403


# ---------------------------------------------------------------------------
# AsmPolicy tests
# ---------------------------------------------------------------------------


class TestAsmPolicy:
    def test_minimal_construction(self, minimal_policy):
        """Verify the minimal_policy fixture builds a valid AsmPolicy."""
        policy = minimal_policy
        assert policy.name == "test-policy"
        assert policy.enforcement_mode == EnforcementMode.BLOCKING
        assert policy.encoding == "utf-8"
        assert policy.signatures.accuracy_level == AccuracyLevel.HIGH_MEDIUM
        assert policy.signatures.staging_enabled is True
        assert policy.signatures.staging_period == 7
        assert policy.signatures.threat_campaigns_enabled is True
        assert isinstance(policy.violations, list)
        assert isinstance(policy.signature_sets, list)
        assert isinstance(policy.whitelist_ips, list)
        assert isinstance(policy.allowed_response_codes, list)
        assert isinstance(policy.custom_signatures, list)

    def test_entity_collection_on_minimal(self, minimal_policy):
        ec = minimal_policy.entities
        assert isinstance(ec, EntityCollection)
        assert ec.urls == []
        assert ec.parameters == []
        assert ec.file_types == []
        assert ec.cookies == []
        assert ec.headers == []
        assert ec.methods == []

    def test_nested_configs_on_minimal(self, minimal_policy):
        p = minimal_policy
        assert isinstance(p.geolocation, GeolocationConfig)
        assert isinstance(p.csrf, CsrfConfig)
        assert isinstance(p.data_guard, DataGuardConfig)
        assert isinstance(p.brute_force, BruteForceConfig)
        assert isinstance(p.session_tracking, SessionTrackingConfig)
        assert isinstance(p.bot_defense, BotDefenseConfig)
        assert isinstance(p.ip_intelligence, IpIntelligenceConfig)
        assert isinstance(p.blocking_page, BlockingPageConfig)

    def test_full_construction(self):
        """Build a fully-populated AsmPolicy to verify all fields accept data."""
        sig_override = SignatureOverride(sig_id=200000001, enabled=False, alarm=True, block=False)

        policy = AsmPolicy(
            name="full-policy",
            enforcement_mode=EnforcementMode.TRANSPARENT,
            encoding="iso-8859-1",
            signatures=SignatureConfig(
                global_overrides=[sig_override],
                accuracy_level=AccuracyLevel.ALL,
                staging_enabled=False,
                staging_period=14,
                threat_campaigns_enabled=False,
            ),
            signature_sets=[
                SignatureSet(name="Generic Detection Signatures", enabled=True),
                SignatureSet(name="OS Command Injection Signatures", enabled=False),
            ],
            entities=EntityCollection(
                urls=[UrlEntity(name="/api", type="wildcard", attack_signatures_check=False)],
                parameters=[ParameterEntity(name="token", sensitive=True, level="global")],
                file_types=[FileTypeEntity(name="jsp", allowed=True, request_length=65536)],
                cookies=[CookieEntity(name="JSESSIONID", type="explicit")],
                headers=[HeaderEntity(name="Authorization", mandatory=True, check_signatures=False)],
                methods=[MethodEntity(name="PATCH", act_as_method="POST")],
            ),
            violations=[
                Violation(name="VIOL_URL", alarm=True, block=True),
                Violation(name="VIOL_PARAMETER", alarm=True, block=False),
            ],
            whitelist_ips=[
                IpWhitelistEntry(
                    ip="10.0.0.0",
                    mask="255.0.0.0",
                    block_requests=False,
                    never_log=True,
                    trusted_by_builder=True,
                    ignore_anomalies=True,
                    ignore_ip_reputation=True,
                ),
            ],
            geolocation=GeolocationConfig(disallowed=["North Korea"]),
            csrf=CsrfConfig(enabled=True, urls=["/login", "/checkout"]),
            data_guard=DataGuardConfig(enabled=True, credit_cards=True, ssn=True),
            brute_force=BruteForceConfig(enabled=True, detection_period=600, max_attempts=5, login_url="/login"),
            session_tracking=SessionTrackingConfig(enabled=True, hijacking_prevention=True),
            bot_defense=BotDefenseConfig(
                enabled=True,
                mode="always",
                categories=[BotCategory(name="dos_tool", action="block")],
            ),
            ip_intelligence=IpIntelligenceConfig(
                categories=[IpIntelCategory(name="botnets", action="block")],
            ),
            blocking_page=BlockingPageConfig(
                enabled=True,
                custom_html="<html>Blocked</html>",
                response_code=403,
            ),
            allowed_response_codes=[200, 201, 301, 302, 404],
            custom_signatures=[
                CustomSignature(id=300000001, name="Block Evil", pattern=".*evil.*", scope="request"),
            ],
        )

        assert policy.name == "full-policy"
        assert policy.enforcement_mode == EnforcementMode.TRANSPARENT
        assert len(policy.signatures.global_overrides) == 1
        assert len(policy.signature_sets) == 2
        assert len(policy.entities.urls) == 1
        assert len(policy.entities.parameters) == 1
        assert len(policy.entities.file_types) == 1
        assert len(policy.entities.cookies) == 1
        assert len(policy.entities.headers) == 1
        assert len(policy.entities.methods) == 1
        assert len(policy.violations) == 2
        assert len(policy.whitelist_ips) == 1
        assert len(policy.geolocation.disallowed) == 1
        assert len(policy.csrf.urls) == 2
        assert policy.data_guard.credit_cards is True
        assert policy.brute_force.login_url == "/login"
        assert policy.session_tracking.hijacking_prevention is True
        assert len(policy.bot_defense.categories) == 1
        assert len(policy.ip_intelligence.categories) == 1
        assert policy.blocking_page.response_code == 403
        assert len(policy.allowed_response_codes) == 5
        assert len(policy.custom_signatures) == 1

    def test_all_fields_present(self):
        """Ensure AsmPolicy dataclass has all expected fields."""
        expected_fields = {
            "name",
            "enforcement_mode",
            "encoding",
            "signatures",
            "signature_sets",
            "entities",
            "violations",
            "whitelist_ips",
            "geolocation",
            "csrf",
            "data_guard",
            "brute_force",
            "session_tracking",
            "bot_defense",
            "ip_intelligence",
            "blocking_page",
            "allowed_response_codes",
            "custom_signatures",
        }
        actual_fields = {f.name for f in dc_fields(AsmPolicy)}
        assert expected_fields == actual_fields
