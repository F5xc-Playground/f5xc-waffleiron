# WaffleIron Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a tool that converts BIG-IP ASM/AWAF policies into F5 XC WAF configurations, with a web UI, CLI, and direct XC API push capability.

**Architecture:** Library-first — a standalone Python package (`waffleiron`) contains all conversion logic. A FastAPI app (`waffleiron-api`) wraps it as a REST API and serves a React SPA (`waffleiron-web`). A Typer CLI (`waffleiron-cli`) provides command-line access. All ship in one Docker container.

**Tech Stack:** Python 3.12, defusedxml + lxml, FastAPI, React 19 + TypeScript + Vite + Tailwind CSS, Typer, Docker multi-stage build.

**Reference docs (read before starting any task):**
- `docs/superpowers/specs/2026-05-15-waffleiron-prd-design.md` — full PRD
- `docs/field-mapping.md` — field-by-field ASM → XC translation rules
- `docs/gaps-and-decisions.md` — translation gaps and decision logic
- `docs/asm-xml-schema.md` — ASM XML export structure
- `docs/xc-target-objects.md` — XC API object schemas
- `docs/schemas/xc-app-firewall.json` — XC app_firewall OpenAPI spec
- `docs/schemas/xc-waf-exclusion-policy.json` — XC waf_exclusion_policy OpenAPI spec

---

## File Structure

```
waffleiron/                          # Core Python library (pip-installable)
├── pyproject.toml                   # Package config, dependencies
├── src/
│   └── waffleiron/
│       ├── __init__.py              # Public API: parse(), analyze(), translate(), validate(), report()
│       ├── model.py                 # AsmPolicy dataclass + all sub-models, enums
│       ├── decisions.py             # DecisionSet model, YAML load/save, bulk decision helpers
│       ├── parsers/
│       │   ├── __init__.py          # Re-export parse() which auto-detects format
│       │   ├── detect.py            # Format detection (XML vs JSON)
│       │   ├── xml_parser.py        # ASM XML → AsmPolicy
│       │   └── json_parser.py       # ASM Declarative JSON → AsmPolicy
│       ├── analysis.py              # Analyze AsmPolicy → AnalysisResult
│       ├── translators/
│       │   ├── __init__.py          # Re-export translate() orchestrator
│       │   ├── app_firewall.py      # AsmPolicy → app_firewall JSON
│       │   ├── exclusion_policy.py  # AsmPolicy + decisions → waf_exclusion_policy JSON
│       │   ├── service_policy.py    # AsmPolicy → service_policy JSON
│       │   ├── http_lb_patch.py     # AsmPolicy → http_lb_patch JSON
│       │   └── mappings.py          # Shared constants: sig set → attack type, violation maps, etc.
│       ├── validators.py            # Validate output JSON against XC OAS constraints
│       ├── reporters.py             # Gap report generation (JSON + Markdown)
│       └── xc_client/
│           ├── __init__.py          # Re-export XCClient
│           ├── client.py            # XCClient: auth, CRUD, rate limiting, retry
│           ├── config.py            # XCConfig: env var / file-based credential resolution
│           └── errors.py            # XCAuthError, XCNotFoundError, etc.
├── tests/
│   ├── conftest.py                  # Shared fixtures: sample policies, model builders
│   ├── fixtures/                    # Sample ASM XML/JSON policy files for tests
│   │   ├── minimal_blocking.xml     # Minimal blocking-mode policy
│   │   ├── minimal_blocking.json    # Same policy in Declarative JSON
│   │   ├── rapid_deployment.xml     # Rapid Deployment template defaults
│   │   ├── mature_tuned.xml         # Policy with alarm-only sigs, entity overrides
│   │   └── positive_security.xml    # Heavy positive security (URLs, params, file types)
│   ├── test_model.py
│   ├── test_decisions.py
│   ├── test_detect.py
│   ├── test_xml_parser.py
│   ├── test_json_parser.py
│   ├── test_analysis.py
│   ├── test_app_firewall.py
│   ├── test_exclusion_policy.py
│   ├── test_service_policy.py
│   ├── test_http_lb_patch.py
│   ├── test_mappings.py
│   ├── test_validators.py
│   ├── test_reporters.py
│   ├── test_xc_client.py
│   └── test_xc_config.py

waffleiron-cli/                      # CLI package
├── pyproject.toml
├── src/
│   └── waffleiron_cli/
│       ├── __init__.py
│       └── main.py                  # Typer app: convert, analyze, validate, push, xc-status
└── tests/
    └── test_cli.py

waffleiron-api/                      # API package
├── pyproject.toml
├── src/
│   └── waffleiron_api/
│       ├── __init__.py
│       ├── main.py                  # FastAPI app, lifespan, static mount, health
│       ├── config.py                # API config (SESSION_TTL, LOG_LEVEL, PORT, XC creds)
│       ├── sessions.py              # In-memory session store with TTL expiry
│       ├── routers/
│       │   ├── conversions.py       # /api/v1/conversions/* endpoints
│       │   └── xc.py                # /api/v1/xc/* endpoints
│       └── schemas.py               # Pydantic request/response models for API
└── tests/
    ├── conftest.py                  # TestClient fixture
    ├── test_conversions.py
    ├── test_xc_endpoints.py
    └── test_sessions.py

waffleiron-web/                      # React SPA
├── package.json
├── tsconfig.json
├── vite.config.ts
├── tailwind.config.js
├── index.html
├── src/
│   ├── main.tsx                     # Entry point
│   ├── App.tsx                      # Router / wizard shell
│   ├── api.ts                       # API client (fetch wrappers for /api/v1/*)
│   ├── types.ts                     # TypeScript types matching API schemas
│   ├── context/
│   │   └── ConversionContext.tsx     # Session state: useReducer + context
│   ├── views/
│   │   ├── UploadView.tsx           # View 1: upload & parse
│   │   ├── AnalysisView.tsx         # View 2: analysis & decisions
│   │   ├── ReviewView.tsx           # View 3: review & export
│   │   └── PushView.tsx             # View 4: push to XC
│   └── components/
│       ├── DecisionsTable.tsx        # Interactive alarm-only decisions table
│       ├── SummaryCards.tsx          # Stat cards (translated / lossy / gaps / decisions)
│       ├── JsonViewer.tsx            # Syntax-highlighted JSON with copy button
│       ├── GapReport.tsx             # Rendered Markdown gap report
│       ├── FileDropzone.tsx          # Drag-and-drop file upload
│       └── NamespaceSelector.tsx     # XC namespace dropdown

Dockerfile                           # Multi-stage: node build → python runtime
docker-compose.yml                   # Dev convenience (optional)
```

---

## Phase 1: Core Library — Model & Parsers

### Task 1: Project Scaffolding & Intermediate Model

**Files:**
- Create: `waffleiron/pyproject.toml`
- Create: `waffleiron/src/waffleiron/__init__.py`
- Create: `waffleiron/src/waffleiron/model.py`
- Create: `waffleiron/tests/conftest.py`
- Create: `waffleiron/tests/test_model.py`

This task sets up the Python package and defines the `AsmPolicy` intermediate model — the central data structure that every other component reads or writes.

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "waffleiron"
version = "0.1.0"
description = "Convert BIG-IP ASM/AWAF policies to F5 XC WAF configurations"
requires-python = ">=3.12"
dependencies = [
    "defusedxml>=0.7.1",
    "lxml>=5.0",
    "pyyaml>=6.0",
    "requests>=2.31",
    "urllib3>=2.0",
    "requests-pkcs12>=1.24",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "responses>=0.25",
    "ruff>=0.4",
]

[tool.hatch.build.targets.wheel]
packages = ["src/waffleiron"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]

[tool.ruff]
line-length = 120
```

- [ ] **Step 2: Write model tests**

Write tests in `waffleiron/tests/test_model.py` that verify:
- `AsmPolicy` can be constructed with all fields
- Enums (`EnforcementMode`, `AccuracyLevel`, `AlarmOnlyAction`, `BotAction`) have the expected members
- Entity dataclasses (`UrlEntity`, `ParameterEntity`, `SignatureOverride`, `Violation`, etc.) can be constructed and their fields are typed
- A helper `make_minimal_policy()` builds a valid minimal policy (used across all tests)

The model must cover every field in the intermediate model from the spec (lines 86–121 of the PRD). Key types:

```python
# Enums to test
EnforcementMode.BLOCKING, EnforcementMode.TRANSPARENT
AccuracyLevel.HIGH, AccuracyLevel.HIGH_MEDIUM, AccuracyLevel.ALL
BotAction.BLOCK, BotAction.REPORT, BotAction.IGNORE

# Core dataclass assertions
policy = make_minimal_policy()
assert policy.enforcement_mode == EnforcementMode.BLOCKING
assert policy.signatures.accuracy_level == AccuracyLevel.HIGH_MEDIUM
assert isinstance(policy.violations, list)
```

- [ ] **Step 3: Run tests — expect failure**

Run: `cd waffleiron && pip install -e ".[dev]" && pytest tests/test_model.py -v`
Expected: ImportError / ModuleNotFoundError (model.py doesn't exist yet)

- [ ] **Step 4: Implement the model**

Create `waffleiron/src/waffleiron/model.py` with all dataclasses and enums. Reference the intermediate model definition in the PRD (lines 86–121) and the full field reference in `docs/asm-xml-schema.md`.

Key implementation notes:
- Use `@dataclass` with type annotations for every field
- Use `enum.Enum` for all enumerated types
- Use `Optional[...]` for fields that may not be present in all policies
- Use `field(default_factory=list)` for list fields
- Group related fields into nested dataclasses: `SignatureConfig`, `EntityCollection`, `GeolocationConfig`, `CsrfConfig`, `DataGuardConfig`, `BruteForceConfig`, `SessionTrackingConfig`, `BotDefenseConfig`, `IpIntelligenceConfig`, `BlockingPageConfig`
- Every entity type (`UrlEntity`, `ParameterEntity`, `FileTypeEntity`, `CookieEntity`, `HeaderEntity`, `MethodEntity`) needs all fields from `docs/asm-xml-schema.md`
- `SignatureOverride` needs: `sig_id: int`, `enabled: bool`, `alarm: bool`, `block: bool`
- `Violation` needs: `name: str`, `alarm: bool`, `block: bool`
- `IpWhitelistEntry` needs: `ip: str`, `mask: str`, `block_requests: str`, `never_log: bool`, `trusted_by_builder: bool`, `ignore_anomalies: bool`, `ignore_ip_reputation: bool`
- `CustomSignature` needs: `id: int`, `name: str`, `pattern: str`, `scope: str`

Also create the `make_minimal_policy()` fixture in `waffleiron/tests/conftest.py`:
```python
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
```

- [ ] **Step 5: Run tests — expect pass**

Run: `pytest tests/test_model.py -v`
Expected: All tests pass

- [ ] **Step 6: Create `__init__.py` with public API stubs**

```python
from waffleiron.model import AsmPolicy, EnforcementMode, AccuracyLevel

__version__ = "0.1.0"
```

- [ ] **Step 7: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): project scaffolding and AsmPolicy intermediate model"
```

---

### Task 2: Format Detection & Test Fixtures

**Files:**
- Create: `waffleiron/src/waffleiron/parsers/__init__.py`
- Create: `waffleiron/src/waffleiron/parsers/detect.py`
- Create: `waffleiron/tests/test_detect.py`
- Create: `waffleiron/tests/fixtures/minimal_blocking.xml`
- Create: `waffleiron/tests/fixtures/minimal_blocking.json`

This task builds the format auto-detection and creates the test fixture files that all parser tests will use.

- [ ] **Step 1: Create test fixture files**

Create `waffleiron/tests/fixtures/minimal_blocking.xml` — a minimal but structurally valid ASM XML export. Must include the top-level `<policy>` element with at least:
- `<fullPath>/Common/test-policy</fullPath>`
- `<enforcementMode>blocking</enforcementMode>`
- `<encoding>utf-8</encoding>`
- A `<signature-settings>` block with accuracy/staging
- One signature override (sig ID 200001001, alarm=true, block=true)
- One violation (VIOL_ATTACK_SIGNATURE, alarm=true, block=true)
- Empty entity sections (urls, parameters, file-types, etc.)

Reference `docs/asm-xml-schema.md` for the exact XML structure — the elements use kebab-case names like `<enforcement-mode>`, `<signature-settings>`, etc.

Create `waffleiron/tests/fixtures/minimal_blocking.json` — the same policy in ASM Declarative JSON format. Uses the structure documented in `docs/asm-xml-schema.md` under "JSON (Declarative)" format. Top-level key is `"policy"` with camelCase property names.

- [ ] **Step 2: Write detection tests**

```python
# waffleiron/tests/test_detect.py
from waffleiron.parsers.detect import detect_format, PolicyFormat

def test_detect_xml(fixtures_path):
    content = (fixtures_path / "minimal_blocking.xml").read_bytes()
    assert detect_format(content) == PolicyFormat.XML

def test_detect_json(fixtures_path):
    content = (fixtures_path / "minimal_blocking.json").read_bytes()
    assert detect_format(content) == PolicyFormat.JSON

def test_detect_invalid():
    with pytest.raises(ValueError, match="Unrecognized policy format"):
        detect_format(b"this is not a policy")

def test_detect_empty():
    with pytest.raises(ValueError, match="Empty input"):
        detect_format(b"")
```

Add a `fixtures_path` fixture to `conftest.py`:
```python
from pathlib import Path

@pytest.fixture
def fixtures_path():
    return Path(__file__).parent / "fixtures"
```

- [ ] **Step 3: Run tests — expect failure**

Run: `pytest tests/test_detect.py -v`
Expected: ImportError

- [ ] **Step 4: Implement format detection**

`waffleiron/src/waffleiron/parsers/detect.py`:
```python
import enum

class PolicyFormat(enum.Enum):
    XML = "xml"
    JSON = "json"

def detect_format(content: bytes) -> PolicyFormat:
    if not content:
        raise ValueError("Empty input")
    stripped = content.lstrip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<"):
        return PolicyFormat.XML
    if stripped.startswith(b"{"):
        return PolicyFormat.JSON
    raise ValueError("Unrecognized policy format: expected XML (starts with '<') or JSON (starts with '{')")
```

- [ ] **Step 5: Run tests — expect pass**

Run: `pytest tests/test_detect.py -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): format auto-detection and test fixture files"
```

---

### Task 3: XML Parser

**Files:**
- Create: `waffleiron/src/waffleiron/parsers/xml_parser.py`
- Create: `waffleiron/tests/test_xml_parser.py`
- Create: `waffleiron/tests/fixtures/rapid_deployment.xml`
- Create: `waffleiron/tests/fixtures/mature_tuned.xml`
- Create: `waffleiron/tests/fixtures/positive_security.xml`

The XML parser is the largest single component. It navigates the deeply nested ASM XML export and populates every field of the `AsmPolicy` model. Reference `docs/asm-xml-schema.md` for the complete XML structure.

- [ ] **Step 1: Create additional test fixtures**

Create `rapid_deployment.xml` — based on the Rapid Deployment template. Should include:
- Blocking mode, high+medium accuracy signatures, staging enabled (7 days), threat campaigns on
- Default violation settings (VIOL_ATTACK_SIGNATURE alarm+block, VIOL_COOKIE_MODIFIED alarm only, VIOL_DATA_GUARD alarm only, etc. — see the table in `docs/asm-xml-schema.md`)
- Default signature sets (Generic Detection, High Accuracy, OS Command Injection, SQL Injection, XSS)
- No custom entities, no IP whitelist, no geo, no CSRF/Data Guard

Create `mature_tuned.xml` — a policy that exercises alarm-only logic:
- Blocking mode
- 3 global signature overrides: one alarm-only (200001001, alarm=true, block=false), one disabled (200001002, enabled=false), one fully enforced (200001003, alarm=true, block=true)
- 2 URL entities: `/api/v1/data` with `attackSignaturesCheck=false`, `/login` with 1 per-URL signature override (200001004, enabled=false)
- 2 parameter entities: `session_id` as sensitive, `query` with `attackSignaturesCheck=false`
- 1 cookie entity: `tracking` with `attackSignaturesCheck=false`
- Violations: VIOL_COOKIE_MODIFIED (alarm=true, block=false), VIOL_ENCODING (alarm=true, block=false)
- IP whitelist: 10.0.0.0/8 (blockRequests=never)
- Geolocation: disallow "North Korea", "Iran"
- Bot defense: malicious=block, benign=report, unknown=challenge
- Custom blocking page with `<%TS.request.ID()%>` variable

Create `positive_security.xml` — exercises positive security entities:
- 5 URL entities (3 explicit, 2 wildcard) with method restrictions
- 10 parameter entities with various `valueType` settings (alpha, numeric, email)
- 3 file type entities with size limits
- 2 cookie entities with enforcement types
- 2 header entities (1 mandatory)
- Custom signatures (2 entries with regex patterns)

- [ ] **Step 2: Write XML parser tests**

`waffleiron/tests/test_xml_parser.py` — one test per fixture, plus targeted tests for specific field extractions:

```python
from waffleiron.parsers.xml_parser import XmlPolicyParser

class TestMinimalPolicy:
    def test_parse_enforcement_mode(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "minimal_blocking.xml")
        assert policy.enforcement_mode == EnforcementMode.BLOCKING
        assert policy.name == "test-policy"
        assert policy.encoding == "utf-8"

    def test_parse_signatures(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "minimal_blocking.xml")
        assert policy.signatures.accuracy_level == AccuracyLevel.HIGH_MEDIUM
        assert policy.signatures.staging_enabled is True
        assert len(policy.signatures.global_overrides) == 1

class TestMatureTunedPolicy:
    def test_alarm_only_signatures(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        alarm_only = [s for s in policy.signatures.global_overrides if s.alarm and not s.block]
        assert len(alarm_only) == 1
        assert alarm_only[0].sig_id == 200001001

    def test_disabled_signatures(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        disabled = [s for s in policy.signatures.global_overrides if not s.enabled]
        assert len(disabled) == 1
        assert disabled[0].sig_id == 200001002

    def test_url_entities(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        assert len(policy.entities.urls) == 2
        api_url = next(u for u in policy.entities.urls if u.name == "/api/v1/data")
        assert api_url.attack_signatures_check is False

    def test_per_url_signature_overrides(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        login_url = next(u for u in policy.entities.urls if u.name == "/login")
        assert len(login_url.signature_overrides) == 1
        assert login_url.signature_overrides[0].sig_id == 200001004

    def test_sensitive_parameter(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        session = next(p for p in policy.entities.parameters if p.name == "session_id")
        assert session.sensitive is True

    def test_alarm_only_violations(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        alarm_only = [v for v in policy.violations if v.alarm and not v.block]
        assert len(alarm_only) == 2

    def test_ip_whitelist(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        assert len(policy.whitelist_ips) == 1
        assert policy.whitelist_ips[0].ip == "10.0.0.0"

    def test_geolocation(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        assert "North Korea" in policy.geolocation.disallowed
        assert "Iran" in policy.geolocation.disallowed

    def test_bot_defense(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        assert policy.bot_defense.enabled is True
        malicious = next(c for c in policy.bot_defense.categories if c.name == "malicious-bot")
        assert malicious.action == "block"

    def test_custom_blocking_page(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "mature_tuned.xml")
        assert policy.blocking_page.enabled is True
        assert "<%TS.request.ID()%>" in policy.blocking_page.custom_html

class TestPositiveSecurityPolicy:
    def test_url_entity_counts(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "positive_security.xml")
        explicit = [u for u in policy.entities.urls if u.type == "explicit"]
        wildcard = [u for u in policy.entities.urls if u.type == "wildcard"]
        assert len(explicit) == 3
        assert len(wildcard) == 2

    def test_parameter_value_types(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "positive_security.xml")
        value_types = {p.value_type for p in policy.entities.parameters if p.value_type}
        assert "alpha" in value_types
        assert "numeric" in value_types

    def test_custom_signatures(self, fixtures_path):
        policy = XmlPolicyParser.parse(fixtures_path / "positive_security.xml")
        assert len(policy.custom_signatures) == 2
        assert all(sig.pattern for sig in policy.custom_signatures)
```

- [ ] **Step 3: Run tests — expect failure**

Run: `pytest tests/test_xml_parser.py -v`
Expected: ImportError

- [ ] **Step 4: Implement XML parser**

Create `waffleiron/src/waffleiron/parsers/xml_parser.py`. The parser class:

```python
from pathlib import Path
from defusedxml import ElementTree as SafeET
from lxml import etree
from waffleiron.model import AsmPolicy, EnforcementMode, ...

class XmlPolicyParser:
    @staticmethod
    def parse(path: Path | str) -> AsmPolicy:
        # 1. Safe initial parse with defusedxml (catches XXE, billion laughs, etc.)
        SafeET.parse(str(path))
        # 2. Re-parse with lxml for XPath support
        tree = etree.parse(str(path))
        root = tree.getroot()
        # 3. Extract each section into model objects
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
```

Each `_parse_*` function uses lxml XPath to navigate the XML tree. The exact element names and paths come from `docs/asm-xml-schema.md`. Key patterns:
- `root.findtext("fullPath")` → extract policy name (strip `/Common/` prefix)
- `root.findtext("enforcementMode")` or `root.findtext("enforcement-mode")` → try both naming conventions
- Signature overrides: iterate `root.findall(".//sig-overrides/sig-override")` or similar
- Entity sections: `root.findall(".//urls/url")`, `root.findall(".//parameters/parameter")`, etc.
- Boolean fields: ASM XML uses `"true"/"false"` strings — parse to Python bool
- Missing/optional elements: return defaults from the model when elements are absent

This is the most complex parser. Take care to handle both compact and full XML exports. When an element is missing, use the model's default rather than raising.

- [ ] **Step 5: Run tests — expect pass**

Run: `pytest tests/test_xml_parser.py -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): XML parser for ASM policy exports"
```

---

### Task 4: JSON Parser

**Files:**
- Create: `waffleiron/src/waffleiron/parsers/json_parser.py`
- Create: `waffleiron/tests/test_json_parser.py`
- Modify: `waffleiron/tests/fixtures/minimal_blocking.json` (ensure it's complete)

The JSON parser handles ASM Declarative JSON exports (BIG-IP v15.1+). These use camelCase property names and a `"policy"` top-level key. The parser must produce the exact same `AsmPolicy` output as the XML parser for equivalent policies.

- [ ] **Step 1: Write JSON parser tests**

Mirror the structure of `test_xml_parser.py` but use `.json` fixtures. Add a cross-parser consistency test:

```python
class TestJsonParserMinimal:
    def test_parse_enforcement_mode(self, fixtures_path):
        policy = JsonPolicyParser.parse(fixtures_path / "minimal_blocking.json")
        assert policy.enforcement_mode == EnforcementMode.BLOCKING
        assert policy.name == "test-policy"

class TestJsonXmlConsistency:
    def test_minimal_policy_matches(self, fixtures_path):
        xml_policy = XmlPolicyParser.parse(fixtures_path / "minimal_blocking.xml")
        json_policy = JsonPolicyParser.parse(fixtures_path / "minimal_blocking.json")
        assert xml_policy.enforcement_mode == json_policy.enforcement_mode
        assert xml_policy.name == json_policy.name
        assert xml_policy.signatures.accuracy_level == json_policy.signatures.accuracy_level
        assert len(xml_policy.violations) == len(json_policy.violations)
```

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_json_parser.py -v`

- [ ] **Step 3: Implement JSON parser**

```python
import json
from pathlib import Path
from waffleiron.model import AsmPolicy, ...

class JsonPolicyParser:
    @staticmethod
    def parse(path: Path | str) -> AsmPolicy:
        with open(path) as f:
            data = json.load(f)
        policy_data = data.get("policy", data)
        return AsmPolicy(
            name=_parse_name(policy_data),
            enforcement_mode=_parse_enforcement_mode(policy_data),
            # ... same structure as XML parser but navigating dict keys
        )
```

JSON keys use camelCase (`enforcementMode`, `signatureSettings`, `attackSignaturesCheck`, etc.). The mapping from JSON keys to model fields should be straightforward dictionary access.

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_json_parser.py -v`

- [ ] **Step 5: Wire up auto-detection in `parsers/__init__.py`**

```python
from waffleiron.parsers.detect import detect_format, PolicyFormat
from waffleiron.parsers.xml_parser import XmlPolicyParser
from waffleiron.parsers.json_parser import JsonPolicyParser
from waffleiron.model import AsmPolicy
from pathlib import Path

def parse(path: Path | str) -> AsmPolicy:
    content = Path(path).read_bytes()
    fmt = detect_format(content)
    if fmt == PolicyFormat.XML:
        return XmlPolicyParser.parse(path)
    return JsonPolicyParser.parse(path)
```

- [ ] **Step 6: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): JSON parser and auto-detection dispatch"
```

---

### Task 5: Decisions Model

**Files:**
- Create: `waffleiron/src/waffleiron/decisions.py`
- Create: `waffleiron/tests/test_decisions.py`

The decisions model defines how users express their alarm-only choices, supports bulk operations, and handles YAML serialization for the decisions file.

- [ ] **Step 1: Write decisions tests**

```python
from waffleiron.decisions import (
    DecisionSet, SignatureDecision, ViolationDecision, BotDecision,
    AlarmOnlyAction, ViolationAction, BotDecisionAction,
)

class TestDecisionSet:
    def test_empty_decisions(self):
        ds = DecisionSet()
        assert len(ds.signature_decisions) == 0
        assert len(ds.violation_decisions) == 0

    def test_add_signature_decision(self):
        ds = DecisionSet()
        ds.add_signature(SignatureDecision(
            sig_id=200001234, description="SQL Injection", scope="global",
            action=AlarmOnlyAction.EXCLUDE,
        ))
        assert ds.get_signature_action(200001234) == AlarmOnlyAction.EXCLUDE

    def test_bulk_set_signatures(self):
        ds = DecisionSet()
        ds.add_signature(SignatureDecision(sig_id=1, description="a", scope="global", action=AlarmOnlyAction.DEFER))
        ds.add_signature(SignatureDecision(sig_id=2, description="b", scope="global", action=AlarmOnlyAction.DEFER))
        ds.bulk_set_signatures(AlarmOnlyAction.EXCLUDE)
        assert ds.get_signature_action(1) == AlarmOnlyAction.EXCLUDE
        assert ds.get_signature_action(2) == AlarmOnlyAction.EXCLUDE

    def test_yaml_round_trip(self, tmp_path):
        ds = DecisionSet()
        ds.add_signature(SignatureDecision(
            sig_id=200001234, description="SQL Injection", scope="global",
            action=AlarmOnlyAction.EXCLUDE,
        ))
        ds.add_violation(ViolationDecision(
            violation="VIOL_COOKIE_MODIFIED", action=ViolationAction.ENFORCE,
        ))
        ds.add_bot(BotDecision(
            category="unknown-bot", asm_action="challenge", action=BotDecisionAction.BLOCK,
        ))
        path = tmp_path / "decisions.yaml"
        ds.save_yaml(path)
        loaded = DecisionSet.load_yaml(path)
        assert loaded.get_signature_action(200001234) == AlarmOnlyAction.EXCLUDE
        assert loaded.get_violation_action("VIOL_COOKIE_MODIFIED") == ViolationAction.ENFORCE
        assert loaded.get_bot_action("unknown-bot") == BotDecisionAction.BLOCK

    def test_default_action_is_defer(self):
        ds = DecisionSet()
        assert ds.get_signature_action(999) == AlarmOnlyAction.DEFER
        assert ds.get_violation_action("VIOL_ANYTHING") == ViolationAction.DEFER
```

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_decisions.py -v`

- [ ] **Step 3: Implement decisions model**

`waffleiron/src/waffleiron/decisions.py`:

Enums:
- `AlarmOnlyAction`: `EXCLUDE`, `ENFORCE`, `DEFER`
- `ViolationAction`: `DISABLE`, `ENFORCE`, `DEFER`
- `BotDecisionAction`: `BLOCK`, `REPORT`, `IGNORE`

Dataclasses:
- `SignatureDecision`: `sig_id`, `description`, `scope`, `action`
- `ViolationDecision`: `violation`, `action`
- `BotDecision`: `category`, `asm_action`, `action`

`DecisionSet` class with:
- `signature_decisions: dict[int, SignatureDecision]`
- `violation_decisions: dict[str, ViolationDecision]`
- `bot_decisions: dict[str, BotDecision]`
- `add_signature()`, `add_violation()`, `add_bot()`
- `get_signature_action()`, `get_violation_action()`, `get_bot_action()` — return DEFER/DEFER/BLOCK as defaults
- `bulk_set_signatures(action)`, `bulk_set_violations(action)`
- `save_yaml(path)`, `load_yaml(path)` — using PyYAML, matching the format in the PRD (lines 417–441)

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_decisions.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): decisions model with YAML serialization"
```

---

### Task 6: Analysis Engine

**Files:**
- Create: `waffleiron/src/waffleiron/analysis.py`
- Create: `waffleiron/tests/test_analysis.py`

The analysis engine examines an `AsmPolicy` and produces an `AnalysisResult` with decision points, gap counts, and limit warnings.

- [ ] **Step 1: Write analysis tests**

```python
from waffleiron.analysis import analyze, AnalysisResult

class TestAlarmOnlyDetection:
    def test_detects_alarm_only_signatures(self, mature_policy):
        result = analyze(mature_policy)
        assert len(result.alarm_only_signatures) == 1
        assert result.alarm_only_signatures[0].sig_id == 200001001

    def test_detects_alarm_only_violations(self, mature_policy):
        result = analyze(mature_policy)
        assert len(result.alarm_only_violations) == 2

    def test_no_alarm_only_in_minimal(self, minimal_policy):
        result = analyze(minimal_policy)
        assert len(result.alarm_only_signatures) == 0
        assert len(result.alarm_only_violations) == 0

class TestPositiveSecurityGaps:
    def test_counts_url_entities(self, positive_security_policy):
        result = analyze(positive_security_policy)
        assert result.positive_security.url_count > 0

    def test_counts_parameter_value_types(self, positive_security_policy):
        result = analyze(positive_security_policy)
        assert result.positive_security.constrained_parameter_count > 0

    def test_counts_custom_signatures(self, positive_security_policy):
        result = analyze(positive_security_policy)
        assert result.untranslatable.custom_signature_count == 2

class TestLimitChecks:
    def test_warns_on_excessive_exclusions(self):
        # Build a policy with 300+ signature overrides (exceeds 256 rule limit)
        policy = make_policy_with_n_overrides(300)
        result = analyze(policy)
        assert any("exclusion" in w.message.lower() for w in result.warnings)

class TestSummaryStats:
    def test_summary_percentages(self, mature_policy):
        result = analyze(mature_policy)
        assert result.summary.total > 0
        assert result.summary.directly_translated >= 0
        assert result.summary.decisions_required > 0

class TestBotProtectionGaps:
    def test_detects_untranslatable_bot_actions(self, mature_policy):
        result = analyze(mature_policy)
        assert len(result.bot_gaps) > 0
        actions = [g.asm_action for g in result.bot_gaps]
        assert "challenge" in actions
```

Add `mature_policy` and `positive_security_policy` fixtures to `conftest.py` — construct them programmatically using the model (don't parse files here; parser tests already cover that). Also add a `make_policy_with_n_overrides(n)` helper.

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_analysis.py -v`

- [ ] **Step 3: Implement analysis engine**

`waffleiron/src/waffleiron/analysis.py`:

Define result dataclasses:
- `AnalysisResult`: top-level container
- `AlarmOnlySignature`: `sig_id`, `description`, `scope`, `alarm`, `block`
- `AlarmOnlyViolation`: `violation_name`, `alarm`, `block`
- `PositiveSecuritySummary`: `url_count`, `wildcard_url_count`, `parameter_count`, `constrained_parameter_count`, `file_type_count`, `cookie_count`, `mandatory_header_count`
- `UntranslatableSummary`: `custom_signature_count`, `session_tracking_enabled`, `session_hijacking_enabled`, `brute_force_enabled`
- `BotGap`: `category`, `asm_action`, `reason`
- `LimitWarning`: `resource`, `count`, `limit`, `message`
- `ConversionSummary`: `total`, `directly_translated`, `translated_with_loss`, `decisions_required`, `cannot_translate`

The `analyze(policy: AsmPolicy) -> AnalysisResult` function:
1. Scan `policy.signatures.global_overrides` for alarm-only (alarm=True, block=False)
2. Scan entity signature overrides for alarm-only
3. Scan `policy.violations` for alarm-only
4. Count positive security entities (URLs with method restrictions, parameters with value_type, etc.)
5. Count untranslatable features (custom sigs, session tracking, brute force)
6. Check bot defense categories for untranslatable actions (challenge, captcha, rate-limit)
7. Check XC limits: estimate exclusion rule count from signature overrides + entity overrides; warn if > 256
8. Compute summary statistics

XC limits to check (from `docs/xc-target-objects.md`):
- 256 exclusion rules
- 1024 signature contexts per exclusion rule
- 64 anonymization items
- 48 response codes
- 4096 bytes blocking page (base64)

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_analysis.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): analysis engine for gap detection and limit checking"
```

---

## Phase 2: Core Library — Translators

### Task 7: Shared Mapping Constants

**Files:**
- Create: `waffleiron/src/waffleiron/translators/__init__.py`
- Create: `waffleiron/src/waffleiron/translators/mappings.py`
- Create: `waffleiron/tests/test_mappings.py`

Shared constants used by all translators: signature set → attack type mapping, ASM violation → XC violation mapping, ASM bot category → XC bot category, blocking page variable replacement.

- [ ] **Step 1: Write mapping tests**

```python
from waffleiron.translators.mappings import (
    ASM_SIG_SET_TO_XC_ATTACK_TYPE,
    ASM_VIOLATION_TO_XC_VIOLATIONS,
    ASM_EVASION_XC_SUBTYPES,
    ASM_HTTP_PROTOCOL_XC_SUBTYPES,
    ASM_BOT_CATEGORY_TO_XC,
    translate_blocking_page_vars,
)

def test_sig_set_mapping_covers_all_xc_attack_types():
    xc_types = set(ASM_SIG_SET_TO_XC_ATTACK_TYPE.values())
    assert "ATTACK_TYPE_SQL_INJECTION" in xc_types
    assert "ATTACK_TYPE_CROSS_SITE_SCRIPTING" in xc_types
    assert len(xc_types) >= 20

def test_evasion_subtypes():
    assert len(ASM_EVASION_XC_SUBTYPES) == 8
    assert all(v.startswith("VIOL_EVASION_") for v in ASM_EVASION_XC_SUBTYPES)

def test_http_protocol_subtypes():
    assert len(ASM_HTTP_PROTOCOL_XC_SUBTYPES) == 10
    assert all(v.startswith("VIOL_HTTP_PROTOCOL_") for v in ASM_HTTP_PROTOCOL_XC_SUBTYPES)

def test_blocking_page_variable_translation():
    html = '<p>Request ID: <%TS.request.ID()%></p>'
    result = translate_blocking_page_vars(html)
    assert result == '<p>Request ID: {{request_id}}</p>'

def test_bot_category_mapping():
    assert ASM_BOT_CATEGORY_TO_XC["malicious-bot"] == "malicious_bot_action"
    assert ASM_BOT_CATEGORY_TO_XC["benign-bot"] == "good_bot_action"
    assert ASM_BOT_CATEGORY_TO_XC["unknown-bot"] == "suspicious_bot_action"
```

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_mappings.py -v`

- [ ] **Step 3: Implement mappings**

Populate all mapping dictionaries using the tables in `docs/field-mapping.md`:
- `ASM_SIG_SET_TO_XC_ATTACK_TYPE`: dict from ASM signature set names → XC `AttackType` enum strings (21 entries from the table in field-mapping.md section 3)
- `ASM_VIOLATION_TO_XC_VIOLATIONS`: dict from ASM violation name → list of XC violation names (handles 1:1 and 1:many splits)
- `ASM_EVASION_XC_SUBTYPES`: list of 8 `VIOL_EVASION_*` XC violation names
- `ASM_HTTP_PROTOCOL_XC_SUBTYPES`: list of 10 `VIOL_HTTP_PROTOCOL_*` XC violation names
- `ASM_BOT_CATEGORY_TO_XC`: dict from ASM category → XC field name
- `translate_blocking_page_vars(html: str) -> str`: replace `<%TS.request.ID()%>` → `{{request_id}}`

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_mappings.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): shared ASM-to-XC mapping constants"
```

---

### Task 8: AppFirewall Translator

**Files:**
- Create: `waffleiron/src/waffleiron/translators/app_firewall.py`
- Create: `waffleiron/tests/test_app_firewall.py`

Translates the `AsmPolicy` into a XC `app_firewall` JSON object. This is the primary output object. Reference `docs/xc-target-objects.md` for the full schema and `docs/field-mapping.md` sections 1–6, 8 for the mapping rules.

- [ ] **Step 1: Write app_firewall translator tests**

```python
from waffleiron.translators.app_firewall import AppFirewallTranslator

class TestEnforcementMode:
    def test_blocking_mode(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="test-ns")
        assert result["spec"]["blocking"] == {}

    def test_transparent_mode(self, minimal_policy):
        minimal_policy.enforcement_mode = EnforcementMode.TRANSPARENT
        result = AppFirewallTranslator.translate(minimal_policy, namespace="test-ns")
        assert result["spec"]["monitoring"] == {}

class TestMetadata:
    def test_name_and_namespace(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="my-ns")
        assert result["metadata"]["name"] == "test-policy"
        assert result["metadata"]["namespace"] == "my-ns"

class TestSignatureSettings:
    def test_high_accuracy(self, minimal_policy):
        minimal_policy.signatures.accuracy_level = AccuracyLevel.HIGH
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        detection = result["spec"]["detection_settings"]
        assert "only_high_accuracy_signatures" in detection["signature_selection_setting"]

    def test_staging_enabled(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        staging = result["spec"]["detection_settings"]["signatures_staging_settings"]
        assert "stage_new_and_updated_signatures" in staging

    def test_disabled_attack_types(self):
        # Policy with "SQL Injection Signatures" set disabled
        policy = make_policy_with_disabled_sig_set("SQL Injection Signatures")
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        disabled = result["spec"]["detection_settings"]["signature_selection_setting"]["attack_type_settings"]["disabled_attack_types"]
        assert "ATTACK_TYPE_SQL_INJECTION" in disabled

class TestViolationSettings:
    def test_disabled_violations(self):
        policy = make_policy_with_disabled_violation("VIOL_ENCODING")
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        disabled = result["spec"]["detection_settings"]["violation_settings"]["disabled_violation_types"]
        assert "VIOL_ENCODING" in disabled

    def test_evasion_split(self):
        # ASM VIOL_EVASION disabled → all 8 XC VIOL_EVASION_* disabled
        policy = make_policy_with_disabled_violation("VIOL_EVASION")
        result = AppFirewallTranslator.translate(policy, namespace="ns")
        disabled = result["spec"]["detection_settings"]["violation_settings"]["disabled_violation_types"]
        assert len([v for v in disabled if v.startswith("VIOL_EVASION_")]) == 8

class TestBotProtection:
    def test_bot_actions(self, mature_policy):
        result = AppFirewallTranslator.translate(mature_policy, namespace="ns")
        bot = result["spec"]["bot_protection_setting"]
        assert bot["malicious_bot_action"] == "BLOCK"
        assert bot["good_bot_action"] == "REPORT"

class TestBlockingPage:
    def test_custom_page_variable_translated(self, mature_policy):
        result = AppFirewallTranslator.translate(mature_policy, namespace="ns")
        page = result["spec"]["blocking_page"]
        assert "{{request_id}}" in page["blocking_page"]
        assert "<%TS.request.ID()%>" not in page["blocking_page"]

class TestAnonymization:
    def test_sensitive_parameters(self, mature_policy):
        result = AppFirewallTranslator.translate(mature_policy, namespace="ns")
        anon = result["spec"]["custom_anonymization"]["anonymization_config"]
        names = [a.get("query_parameter", {}).get("query_param_name") for a in anon if "query_parameter" in a]
        assert "session_id" in names

class TestThreatCampaigns:
    def test_enabled(self, minimal_policy):
        result = AppFirewallTranslator.translate(minimal_policy, namespace="ns")
        assert "enable_threat_campaigns" in result["spec"]["detection_settings"]
```

Add `make_policy_with_disabled_sig_set()` and `make_policy_with_disabled_violation()` helpers to conftest.py.

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_app_firewall.py -v`

- [ ] **Step 3: Implement translator**

`AppFirewallTranslator.translate(policy: AsmPolicy, namespace: str) -> dict`:

Build the XC `app_firewall` CreateSpec JSON structure. The output must match the schema in `docs/schemas/xc-app-firewall.json`. Key implementation:

- Set `metadata.name` (sanitize policy name for XC: lowercase, alphanumeric + hyphens, max 64 chars)
- Set `metadata.namespace`
- Set enforcement mode choice: `{"blocking": {}}` or `{"monitoring": {}}`
- Build `detection_settings`:
  - `signature_selection_setting` with accuracy level + disabled attack types (using `ASM_SIG_SET_TO_XC_ATTACK_TYPE` mapping)
  - `violation_settings` with `disabled_violation_types` list (handle VIOL_EVASION → 8 sub-types, VIOL_HTTP_PROTOCOL → 10 sub-types using mappings)
  - `signatures_staging_settings` with period
  - Threat campaign choice
  - False positive suppression: `enable_suppression` by default
- Build `bot_protection_setting` from bot defense categories (using `ASM_BOT_CATEGORY_TO_XC` mapping)
- Build `blocking_page` with variable translation (using `translate_blocking_page_vars`)
- Build `custom_anonymization` from sensitive entities (parameters, cookies, headers)
- Build `allowed_response_codes` if specified
- Use XC's oneof pattern: each choice group gets exactly one key set

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_app_firewall.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): app_firewall translator"
```

---

### Task 9: Exclusion Policy Translator

**Files:**
- Create: `waffleiron/src/waffleiron/translators/exclusion_policy.py`
- Create: `waffleiron/tests/test_exclusion_policy.py`

Translates per-entity signature overrides and alarm-only decisions into a `waf_exclusion_policy` object. Reference `docs/xc-target-objects.md` Object 2 and `docs/field-mapping.md` section 2.

- [ ] **Step 1: Write exclusion policy tests**

```python
from waffleiron.translators.exclusion_policy import ExclusionPolicyTranslator
from waffleiron.decisions import DecisionSet, SignatureDecision, AlarmOnlyAction

class TestDisabledSignatures:
    def test_global_disabled_sig_creates_exclusion(self):
        # Policy with globally disabled sig 200001002
        policy = make_policy_with_disabled_sig(200001002, scope="global")
        decisions = DecisionSet()
        result = ExclusionPolicyTranslator.translate(policy, decisions, namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        assert any(
            200001002 in [ctx["signature_id"] for ctx in rule.get("app_firewall_detection_control", {}).get("exclude_signature_contexts", [])]
            for rule in rules
        )

    def test_per_url_disabled_sig(self):
        # URL /api/v1/data with sig 200001004 disabled
        policy = make_policy_with_per_url_sig_override("/api/v1/data", 200001004)
        decisions = DecisionSet()
        result = ExclusionPolicyTranslator.translate(policy, decisions, namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        matching = [r for r in rules if r.get("path_prefix") == "/api/v1/data"]
        assert len(matching) >= 1

class TestAttackSigsCheckFalse:
    def test_url_skip_processing(self):
        # URL with attackSignaturesCheck=false → waf_skip_processing
        policy = make_policy_with_url_no_sig_check("/api/v1/data")
        decisions = DecisionSet()
        result = ExclusionPolicyTranslator.translate(policy, decisions, namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        skip_rules = [r for r in rules if "waf_skip_processing" in r]
        assert len(skip_rules) >= 1

class TestParameterContext:
    def test_parameter_sig_override_uses_context(self):
        policy = make_policy_with_param_sig_override("query", 200001005)
        decisions = DecisionSet()
        result = ExclusionPolicyTranslator.translate(policy, decisions, namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        contexts = []
        for rule in rules:
            for ctx in rule.get("app_firewall_detection_control", {}).get("exclude_signature_contexts", []):
                contexts.append(ctx)
        param_contexts = [c for c in contexts if c.get("context") == "CONTEXT_PARAMETER"]
        assert len(param_contexts) >= 1

class TestAlarmOnlyDecisions:
    def test_exclude_decision_creates_exclusion(self):
        policy = make_policy_with_alarm_only_sig(200001001)
        decisions = DecisionSet()
        decisions.add_signature(SignatureDecision(
            sig_id=200001001, description="test", scope="global",
            action=AlarmOnlyAction.EXCLUDE,
        ))
        result = ExclusionPolicyTranslator.translate(policy, decisions, namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        sig_ids = []
        for rule in rules:
            for ctx in rule.get("app_firewall_detection_control", {}).get("exclude_signature_contexts", []):
                sig_ids.append(ctx["signature_id"])
        assert 200001001 in sig_ids

    def test_enforce_decision_no_exclusion(self):
        policy = make_policy_with_alarm_only_sig(200001001)
        decisions = DecisionSet()
        decisions.add_signature(SignatureDecision(
            sig_id=200001001, description="test", scope="global",
            action=AlarmOnlyAction.ENFORCE,
        ))
        result = ExclusionPolicyTranslator.translate(policy, decisions, namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        sig_ids = []
        for rule in rules:
            for ctx in rule.get("app_firewall_detection_control", {}).get("exclude_signature_contexts", []):
                sig_ids.append(ctx["signature_id"])
        assert 200001001 not in sig_ids

    def test_defer_decision_no_exclusion(self):
        policy = make_policy_with_alarm_only_sig(200001001)
        decisions = DecisionSet()  # default is DEFER
        result = ExclusionPolicyTranslator.translate(policy, decisions, namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        sig_ids = []
        for rule in rules:
            for ctx in rule.get("app_firewall_detection_control", {}).get("exclude_signature_contexts", []):
                sig_ids.append(ctx["signature_id"])
        assert 200001001 not in sig_ids

class TestCookieAndHeaderContext:
    def test_cookie_sig_override(self):
        policy = make_policy_with_cookie_sig_override("tracking", 200001006)
        decisions = DecisionSet()
        result = ExclusionPolicyTranslator.translate(policy, decisions, namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        cookie_contexts = []
        for rule in rules:
            for ctx in rule.get("app_firewall_detection_control", {}).get("exclude_signature_contexts", []):
                if ctx.get("context") == "CONTEXT_COOKIE":
                    cookie_contexts.append(ctx)
        assert len(cookie_contexts) >= 1
        assert cookie_contexts[0]["context_name"] == "tracking"

class TestMetadata:
    def test_rule_names_are_descriptive(self):
        policy = make_policy_with_disabled_sig(200001002, scope="global")
        decisions = DecisionSet()
        result = ExclusionPolicyTranslator.translate(policy, decisions, namespace="ns")
        rules = result["spec"]["waf_exclusion_rules"]
        assert all("metadata" in r and "name" in r["metadata"] for r in rules)
```

Add all the `make_policy_with_*` helpers to `conftest.py`.

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_exclusion_policy.py -v`

- [ ] **Step 3: Implement exclusion policy translator**

`ExclusionPolicyTranslator.translate(policy, decisions, namespace) -> dict`:

Build the XC `waf_exclusion_policy` JSON. Walk through:
1. All globally disabled signatures → exclusion rules with `any_domain` + `any_path` + signature ID
2. All per-URL disabled signatures → exclusion rules with path prefix/regex + signature ID
3. All per-parameter/cookie/header disabled signatures → exclusion rules with appropriate context + context_name
4. All URLs with `attackSignaturesCheck=false` → `waf_skip_processing` rules
5. All alarm-only signatures where decision is EXCLUDE → exclusion rules
6. Coalesce rules where possible (same path + same action → combine signature contexts into one rule, up to 1024 per rule)

Each rule needs:
- `metadata.name`: descriptive name (e.g., `excl-global-sig-200001002`)
- Domain choice: `any_domain` (unless scope specifies a domain)
- Path choice: `any_path`, `path_prefix`, or `path_regex`
- Detection control or skip processing
- Detection contexts with proper `context` enum and `context_name`

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_exclusion_policy.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): exclusion policy translator with decision support"
```

---

### Task 10: Service Policy Translator

**Files:**
- Create: `waffleiron/src/waffleiron/translators/service_policy.py`
- Create: `waffleiron/tests/test_service_policy.py`

Translates IP whitelist, geolocation, and IP intelligence into a Service Policy. Only produced when at least one of these features is configured. Reference `docs/field-mapping.md` sections 9–10.

- [ ] **Step 1: Write service policy tests**

```python
from waffleiron.translators.service_policy import ServicePolicyTranslator

class TestIpWhitelist:
    def test_creates_allow_rule(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="ns")
        rules = result["spec"]["rules"]
        allow_rules = [r for r in rules if r.get("action") == "ALLOW"]
        assert len(allow_rules) >= 1

    def test_ip_prefix(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="ns")
        rules = result["spec"]["rules"]
        ip_match = rules[0]["match"]["src_ip_prefix_list"]["prefixes"]
        assert "10.0.0.0/8" in ip_match

class TestGeolocation:
    def test_creates_geo_deny_rules(self, mature_policy):
        result = ServicePolicyTranslator.translate(mature_policy, namespace="ns")
        rules = result["spec"]["rules"]
        geo_rules = [r for r in rules if "geo" in str(r.get("match", {}))]
        assert len(geo_rules) >= 1

class TestNoServicePolicy:
    def test_returns_none_when_not_needed(self, minimal_policy):
        result = ServicePolicyTranslator.translate(minimal_policy, namespace="ns")
        assert result is None

class TestIpIntelligence:
    def test_creates_threat_category_rules(self):
        policy = make_policy_with_ip_intelligence(["botnets", "scanners"])
        result = ServicePolicyTranslator.translate(policy, namespace="ns")
        assert result is not None
        rules = result["spec"]["rules"]
        assert len(rules) >= 1
```

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_service_policy.py -v`

- [ ] **Step 3: Implement service policy translator**

Returns `None` if no IP whitelist, geolocation, or IP intelligence is configured. Otherwise builds a service policy with ordered rules:
1. IP allow rules (from whitelist)
2. Geo deny rules (from geolocation disallowed list — map country names to country codes)
3. IP threat category rules (from IP intelligence)

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_service_policy.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): service policy translator for IP/geo/threat-intel"
```

---

### Task 11: HTTP LB Patch Translator

**Files:**
- Create: `waffleiron/src/waffleiron/translators/http_lb_patch.py`
- Create: `waffleiron/tests/test_http_lb_patch.py`

Translates CSRF and Data Guard settings into HTTP LB configuration fields. Only produced when CSRF or Data Guard is enabled. Reference `docs/field-mapping.md` section 11.

- [ ] **Step 1: Write HTTP LB patch tests**

```python
from waffleiron.translators.http_lb_patch import HttpLbPatchTranslator

class TestCsrf:
    def test_csrf_enabled(self):
        policy = make_policy_with_csrf(enabled=True, urls=["/sensitive-form"])
        result = HttpLbPatchTranslator.translate(policy)
        assert result is not None
        assert result["csrf"]["enabled"] is True

class TestDataGuard:
    def test_data_guard_enabled(self):
        policy = make_policy_with_data_guard(enabled=True, credit_cards=True, ssn=True)
        result = HttpLbPatchTranslator.translate(policy)
        assert result is not None
        assert result["data_guard"]["enabled"] is True

class TestNotNeeded:
    def test_returns_none(self, minimal_policy):
        result = HttpLbPatchTranslator.translate(minimal_policy)
        assert result is None
```

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_http_lb_patch.py -v`

- [ ] **Step 3: Implement translator**

Returns `None` if neither CSRF nor Data Guard is enabled. Otherwise builds a JSON object with the fields that should be patched on an existing HTTP LB.

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_http_lb_patch.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): HTTP LB patch translator for CSRF and Data Guard"
```

---

### Task 12: Translation Orchestrator

**Files:**
- Modify: `waffleiron/src/waffleiron/translators/__init__.py`

Wire all four translators into a single `translate()` function.

- [ ] **Step 1: Write orchestrator test**

```python
from waffleiron.translators import translate, TranslationResult

def test_translate_returns_all_objects(mature_policy):
    decisions = DecisionSet()
    result = translate(mature_policy, decisions, namespace="test-ns")
    assert isinstance(result, TranslationResult)
    assert result.app_firewall is not None
    assert result.exclusion_policy is not None
    assert result.service_policy is not None  # mature policy has IP/geo
    assert result.http_lb_patch is not None   # mature policy has blocking page but not CSRF/Data Guard - adjust fixture
```

- [ ] **Step 2: Implement orchestrator**

```python
@dataclass
class TranslationResult:
    app_firewall: dict
    exclusion_policy: dict
    service_policy: dict | None
    http_lb_patch: dict | None

def translate(policy: AsmPolicy, decisions: DecisionSet, namespace: str) -> TranslationResult:
    return TranslationResult(
        app_firewall=AppFirewallTranslator.translate(policy, namespace),
        exclusion_policy=ExclusionPolicyTranslator.translate(policy, decisions, namespace),
        service_policy=ServicePolicyTranslator.translate(policy, namespace),
        http_lb_patch=HttpLbPatchTranslator.translate(policy),
    )
```

- [ ] **Step 3: Run test — expect pass**

Run: `pytest tests/ -k test_translate_returns -v`

- [ ] **Step 4: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): translation orchestrator"
```

---

## Phase 3: Core Library — Validators, Reporters

### Task 13: Output Validator

**Files:**
- Create: `waffleiron/src/waffleiron/validators.py`
- Create: `waffleiron/tests/test_validators.py`

Validates translator output against XC constraints from the OAS schemas in `docs/schemas/`.

- [ ] **Step 1: Write validator tests**

```python
from waffleiron.validators import validate, ValidationResult

class TestValidOutput:
    def test_valid_app_firewall(self, valid_app_firewall_json):
        result = validate(valid_app_firewall_json, object_type="app_firewall")
        assert result.is_valid
        assert len(result.errors) == 0

class TestInvalidOutput:
    def test_too_many_exclusion_rules(self):
        obj = make_exclusion_policy_with_n_rules(300)
        result = validate(obj, object_type="waf_exclusion_policy")
        assert not result.is_valid
        assert any("256" in e.message for e in result.errors)

    def test_invalid_signature_id(self):
        obj = make_exclusion_with_bad_sig_id(999)
        result = validate(obj, object_type="waf_exclusion_policy")
        assert not result.is_valid
        assert any("signature_id" in e.message.lower() for e in result.errors)

    def test_blocking_page_too_large(self):
        obj = make_app_firewall_with_page("x" * 5000)
        result = validate(obj, object_type="app_firewall")
        assert not result.is_valid
        assert any("4096" in e.message for e in result.errors)

    def test_too_many_anonymization_items(self):
        obj = make_app_firewall_with_n_anon_items(70)
        result = validate(obj, object_type="app_firewall")
        assert not result.is_valid

    def test_invalid_enum_value(self):
        obj = make_app_firewall_with_bad_enum()
        result = validate(obj, object_type="app_firewall")
        assert not result.is_valid
```

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_validators.py -v`

- [ ] **Step 3: Implement validator**

`validate(obj: dict, object_type: str) -> ValidationResult`:

The validator performs constraint checks derived from the OAS schemas. It does NOT use a generic JSON Schema validator (the XC OAS uses oneofs and discriminators that generic validators handle poorly). Instead, implement targeted checks:

- Array length limits: exclusion rules ≤ 256, signature contexts ≤ 1024, anonymization ≤ 64, response codes ≤ 48, methods ≤ 16, etc.
- String length limits: blocking page ≤ 4096 bytes base64, context names ≤ 256 chars, metadata names ≤ 64 chars
- Signature ID range: 200000001–299999999 or 0
- Enum values: check against known valid values for attack types, violations, bot actions, contexts
- Oneof integrity: each choice group has exactly one key set
- Required fields: metadata.name, metadata.namespace, spec

`ValidationResult` dataclass:
- `is_valid: bool`
- `errors: list[ValidationError]`
- `warnings: list[ValidationError]`

`ValidationError` dataclass:
- `path: str` (JSON path to the invalid field)
- `message: str`
- `severity: str` ("error" or "warning")

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_validators.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): output validator against XC OAS constraints"
```

---

### Task 14: Gap Report Generator

**Files:**
- Create: `waffleiron/src/waffleiron/reporters.py`
- Create: `waffleiron/tests/test_reporters.py`

Generates gap reports in both JSON and Markdown formats. Uses the `AnalysisResult` and `DecisionSet` to produce a comprehensive report matching the template in the PRD (lines 187–252).

- [ ] **Step 1: Write reporter tests**

```python
from waffleiron.reporters import generate_report, ReportFormat

class TestJsonReport:
    def test_has_summary(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert "summary" in data
        assert "total" in data["summary"]
        assert "directly_translated" in data["summary"]

    def test_has_decisions(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.JSON)
        data = json.loads(report)
        assert "decisions_made" in data

class TestMarkdownReport:
    def test_has_header(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "# ASM → XC Conversion Gap Report" in report

    def test_has_summary_section(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "## Summary" in report
        assert "Directly translated:" in report

    def test_has_positive_security_section(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "Positive Security" in report

    def test_has_xc_recommendations(self, analysis_result, decisions):
        report = generate_report(analysis_result, decisions, format=ReportFormat.MARKDOWN)
        assert "XC Feature Recommendations" in report
        assert "AI Risk-Based Blocking" in report

    def test_has_custom_signatures(self, analysis_with_custom_sigs, decisions):
        report = generate_report(analysis_with_custom_sigs, decisions, format=ReportFormat.MARKDOWN)
        assert "Custom Signatures" in report
```

Add `analysis_result` and `analysis_with_custom_sigs` fixtures to conftest.py that construct `AnalysisResult` objects programmatically.

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_reporters.py -v`

- [ ] **Step 3: Implement reporter**

`generate_report(analysis: AnalysisResult, decisions: DecisionSet, format: ReportFormat, policy_name: str = "", enforcement_mode: str = "") -> str`:

For `ReportFormat.JSON`: build a dict with summary, decisions_made, cannot_translate, xc_recommendations sections and `json.dumps()` with indent.

For `ReportFormat.MARKDOWN`: build the report string matching the template in the PRD. Sections:
1. Header (timestamp, source policy, enforcement mode)
2. Summary (counts and percentages)
3. Decisions Made (alarm-only signatures table, alarm-only violations table, deferred items)
4. Cannot Translate (positive security entities, custom signatures, session/stateful features, bot protection gaps)
5. XC Feature Recommendations table

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_reporters.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): gap report generator (JSON + Markdown)"
```

---

### Task 15: Library Public API

**Files:**
- Modify: `waffleiron/src/waffleiron/__init__.py`

Wire up the public API so external callers (API, CLI) have clean entry points.

- [ ] **Step 1: Write integration test**

```python
# waffleiron/tests/test_integration.py
from waffleiron import parse, analyze, translate, validate_outputs, generate_report
from waffleiron.decisions import DecisionSet, AlarmOnlyAction
from waffleiron.reporters import ReportFormat

def test_full_pipeline(fixtures_path):
    # Parse
    policy = parse(fixtures_path / "mature_tuned.xml")
    assert policy.name

    # Analyze
    analysis = analyze(policy)
    assert analysis.summary.total > 0

    # Make decisions
    decisions = DecisionSet()
    decisions.bulk_set_signatures(AlarmOnlyAction.EXCLUDE)

    # Translate
    result = translate(policy, decisions, namespace="test-ns")
    assert result.app_firewall is not None
    assert result.exclusion_policy is not None

    # Validate
    for obj_type, obj in [("app_firewall", result.app_firewall), ("waf_exclusion_policy", result.exclusion_policy)]:
        vr = validate_outputs(obj, object_type=obj_type)
        assert vr.is_valid, f"Validation failed for {obj_type}: {vr.errors}"

    # Report
    md = generate_report(analysis, decisions, format=ReportFormat.MARKDOWN, policy_name=policy.name)
    assert "## Summary" in md
```

- [ ] **Step 2: Update `__init__.py`**

```python
from waffleiron.model import AsmPolicy, EnforcementMode, AccuracyLevel
from waffleiron.parsers import parse
from waffleiron.analysis import analyze
from waffleiron.translators import translate, TranslationResult
from waffleiron.validators import validate as validate_outputs
from waffleiron.reporters import generate_report, ReportFormat
from waffleiron.decisions import DecisionSet

__version__ = "0.1.0"
```

- [ ] **Step 3: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): public API and full pipeline integration test"
```

---

## Phase 4: XC Client

### Task 16: XC Client Configuration

**Files:**
- Create: `waffleiron/src/waffleiron/xc_client/__init__.py`
- Create: `waffleiron/src/waffleiron/xc_client/config.py`
- Create: `waffleiron/src/waffleiron/xc_client/errors.py`
- Create: `waffleiron/tests/test_xc_config.py`

Credential resolution, env var support, and K8s secrets patterns.

- [ ] **Step 1: Write config tests**

```python
from waffleiron.xc_client.config import XCConfig

class TestTokenAuth:
    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("F5XC_TENANT_URL", "https://tenant.console.ves.volterra.io")
        monkeypatch.setenv("F5XC_API_TOKEN", "test-token")
        config = XCConfig.from_env()
        assert config.tenant_url == "https://tenant.console.ves.volterra.io"
        assert config.api_token == "test-token"
        assert config.auth_method == "token"

    def test_token_file(self, monkeypatch, tmp_path):
        token_file = tmp_path / "api-token"
        token_file.write_text("file-token")
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_API_TOKEN_FILE", str(token_file))
        config = XCConfig.from_env()
        assert config.api_token == "file-token"

    def test_file_takes_precedence(self, monkeypatch, tmp_path):
        token_file = tmp_path / "api-token"
        token_file.write_text("file-token")
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_API_TOKEN", "env-token")
        monkeypatch.setenv("F5XC_API_TOKEN_FILE", str(token_file))
        config = XCConfig.from_env()
        assert config.api_token == "file-token"

class TestP12Auth:
    def test_from_env(self, monkeypatch, tmp_path):
        p12 = tmp_path / "api-creds.p12"
        p12.write_bytes(b"fake-p12")
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_P12_PATH", str(p12))
        monkeypatch.setenv("F5XC_P12_PASSWORD", "pass")
        config = XCConfig.from_env()
        assert config.auth_method == "p12"

class TestMutualExclusion:
    def test_both_raises(self, monkeypatch, tmp_path):
        p12 = tmp_path / "api-creds.p12"
        p12.write_bytes(b"fake-p12")
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_API_TOKEN", "token")
        monkeypatch.setenv("F5XC_P12_PATH", str(p12))
        monkeypatch.setenv("F5XC_P12_PASSWORD", "pass")
        with pytest.raises(ValueError, match="[Mm]utually exclusive"):
            XCConfig.from_env()

class TestNotConfigured:
    def test_no_creds_returns_none(self, monkeypatch):
        monkeypatch.delenv("F5XC_TENANT_URL", raising=False)
        monkeypatch.delenv("F5XC_API_TOKEN", raising=False)
        config = XCConfig.from_env()
        assert config is None

class TestDefaultPaths:
    def test_default_p12_path(self, monkeypatch):
        monkeypatch.setenv("F5XC_TENANT_URL", "https://t.example.com")
        monkeypatch.setenv("F5XC_P12_PASSWORD", "pass")
        monkeypatch.delenv("F5XC_P12_PATH", raising=False)
        monkeypatch.delenv("F5XC_API_TOKEN", raising=False)
        # Default path /certs/api-creds.p12 won't exist in test, so should return None
        config = XCConfig.from_env()
        assert config is None  # file doesn't exist at default path
```

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_xc_config.py -v`

- [ ] **Step 3: Implement config and errors**

`XCConfig` class with:
- `tenant_url`, `api_token`, `p12_path`, `p12_password`, `auth_method`
- `from_env()` classmethod: resolves credentials per the order in the PRD (line 500)
- Default paths: P12 at `/certs/api-creds.p12`, token file at `/secrets/api-token`
- Validates mutual exclusion

`errors.py`:
```python
class XCError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code

class XCAuthError(XCError): pass
class XCNotFoundError(XCError): pass
class XCConflictError(XCError): pass
class XCRateLimitError(XCError): pass
class XCServerError(XCError): pass
```

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_xc_config.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): XC client config with K8s secrets support"
```

---

### Task 17: XC API Client

**Files:**
- Create: `waffleiron/src/waffleiron/xc_client/client.py`
- Create: `waffleiron/tests/test_xc_client.py`

HTTP client with auth, rate limiting, retry, and error handling. Uses `responses` library for HTTP mocking in tests.

- [ ] **Step 1: Write XC client tests**

```python
import responses
from waffleiron.xc_client.client import XCClient
from waffleiron.xc_client.config import XCConfig
from waffleiron.xc_client.errors import XCAuthError, XCNotFoundError, XCConflictError

@pytest.fixture
def xc_config():
    return XCConfig(
        tenant_url="https://test.console.ves.volterra.io",
        api_token="test-token",
        auth_method="token",
    )

class TestAuth:
    @responses.activate
    def test_token_auth_header(self, xc_config):
        responses.add(responses.GET, "https://test.console.ves.volterra.io/api/web/namespaces",
                      json={"items": []}, status=200)
        client = XCClient(xc_config)
        client.list_namespaces()
        assert responses.calls[0].request.headers["Authorization"] == "APIToken test-token"

class TestCRUD:
    @responses.activate
    def test_create_app_firewall(self, xc_config):
        responses.add(responses.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/test-ns/app_firewalls",
            json={"metadata": {"name": "test"}}, status=200)
        client = XCClient(xc_config)
        result = client.create_object("app_firewalls", "test-ns", {"metadata": {"name": "test"}})
        assert result["metadata"]["name"] == "test"

    @responses.activate
    def test_list_namespaces(self, xc_config):
        responses.add(responses.GET,
            "https://test.console.ves.volterra.io/api/web/namespaces",
            json={"items": [{"name": "ns1"}, {"name": "ns2"}]}, status=200)
        client = XCClient(xc_config)
        ns = client.list_namespaces()
        assert len(ns) == 2

class TestErrorHandling:
    @responses.activate
    def test_401_raises_auth_error(self, xc_config):
        responses.add(responses.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/ns/app_firewalls",
            json={"message": "unauthorized"}, status=401)
        client = XCClient(xc_config)
        with pytest.raises(XCAuthError):
            client.create_object("app_firewalls", "ns", {})

    @responses.activate
    def test_409_raises_conflict(self, xc_config):
        responses.add(responses.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/ns/app_firewalls",
            json={"message": "already exists"}, status=409)
        client = XCClient(xc_config)
        with pytest.raises(XCConflictError):
            client.create_object("app_firewalls", "ns", {})

class TestSharedNamespace:
    @responses.activate
    def test_shared_ns_url(self, xc_config):
        responses.add(responses.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/shared/app_firewalls",
            json={"metadata": {"name": "test"}}, status=200)
        client = XCClient(xc_config)
        client.create_object("app_firewalls", "shared", {})
        assert "/namespaces/shared/" in responses.calls[0].request.url

class TestConnectivity:
    @responses.activate
    def test_check_connection(self, xc_config):
        responses.add(responses.GET,
            "https://test.console.ves.volterra.io/api/web/custom/namespaces/system/whoami",
            json={"tenant": "test"}, status=200)
        client = XCClient(xc_config)
        assert client.check_connection() is True
```

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_xc_client.py -v`

- [ ] **Step 3: Implement XC client**

`XCClient` class:
- Constructor takes `XCConfig`, builds `requests.Session` with auth and retry adapter
- Token auth: set `Authorization: APIToken {token}` header on session
- P12 auth: use `requests_pkcs12` adapter or extract cert/key with `cryptography`
- Rate limiting: `time.sleep()` based on a token bucket (2 RPS default)
- Retry: `urllib3.util.retry.Retry` on session adapter (3 retries, backoff_factor=1.0, status_forcelist=[429, 500, 502, 503, 504])
- Error mapping: 401/403 → XCAuthError, 404 → XCNotFoundError, 409 → XCConflictError, 429 → XCRateLimitError, 5xx → XCServerError

Methods:
- `check_connection() -> bool`: GET `/api/web/custom/namespaces/system/whoami`
- `list_namespaces() -> list[dict]`: GET `/api/web/namespaces`
- `create_object(resource: str, namespace: str, body: dict) -> dict`: POST `/api/config/namespaces/{ns}/{resource}`
- `update_object(resource: str, namespace: str, name: str, body: dict) -> dict`: PUT
- `get_object(resource: str, namespace: str, name: str) -> dict`: GET

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_xc_client.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron/
git commit -m "feat(lib): XC API client with auth, retry, and error handling"
```

---

## Phase 5: CLI

### Task 18: CLI Application

**Files:**
- Create: `waffleiron-cli/pyproject.toml`
- Create: `waffleiron-cli/src/waffleiron_cli/__init__.py`
- Create: `waffleiron-cli/src/waffleiron_cli/main.py`
- Create: `waffleiron-cli/tests/test_cli.py`

Typer CLI wrapping the library. Commands: `convert`, `analyze`, `validate`, `push`, `xc-status`.

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "waffleiron-cli"
version = "0.1.0"
description = "CLI for WaffleIron ASM-to-XC policy converter"
requires-python = ">=3.12"
dependencies = [
    "waffleiron>=0.1.0",
    "typer>=0.12",
    "rich>=13.0",
]

[project.scripts]
waffleiron = "waffleiron_cli.main:app"

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[tool.hatch.build.targets.wheel]
packages = ["src/waffleiron_cli"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

- [ ] **Step 2: Write CLI tests**

```python
from typer.testing import CliRunner
from waffleiron_cli.main import app

runner = CliRunner()

class TestConvert:
    def test_basic_conversion(self, fixtures_path, tmp_path):
        result = runner.invoke(app, [
            "convert", str(fixtures_path / "minimal_blocking.xml"),
            "--namespace", "test-ns",
            "--output", str(tmp_path / "output"),
        ])
        assert result.exit_code == 0
        assert (tmp_path / "output" / "app_firewall.json").exists()
        assert (tmp_path / "output" / "gap_report.md").exists()
        assert (tmp_path / "output" / "decisions.yaml").exists()

    def test_with_bulk_alarm_only(self, fixtures_path, tmp_path):
        result = runner.invoke(app, [
            "convert", str(fixtures_path / "mature_tuned.xml"),
            "--namespace", "test-ns",
            "--output", str(tmp_path / "output"),
            "--alarm-only-signatures=exclude",
        ])
        assert result.exit_code == 0

    def test_with_decisions_file(self, fixtures_path, tmp_path):
        # First analyze to generate decisions file
        runner.invoke(app, [
            "analyze", str(fixtures_path / "mature_tuned.xml"),
            "--output", str(tmp_path / "analysis"),
        ])
        decisions_path = tmp_path / "analysis" / "decisions.yaml"
        assert decisions_path.exists()
        # Then convert with decisions
        result = runner.invoke(app, [
            "convert", str(fixtures_path / "mature_tuned.xml"),
            "--namespace", "test-ns",
            "--output", str(tmp_path / "output"),
            "--decisions", str(decisions_path),
        ])
        assert result.exit_code == 0

class TestAnalyze:
    def test_produces_report_and_decisions(self, fixtures_path, tmp_path):
        result = runner.invoke(app, [
            "analyze", str(fixtures_path / "mature_tuned.xml"),
            "--output", str(tmp_path / "output"),
        ])
        assert result.exit_code == 0
        assert (tmp_path / "output" / "gap_report.md").exists()
        assert (tmp_path / "output" / "gap_report.json").exists()
        assert (tmp_path / "output" / "decisions.yaml").exists()

class TestValidate:
    def test_valid_output(self, fixtures_path, tmp_path):
        # Generate output first
        runner.invoke(app, [
            "convert", str(fixtures_path / "minimal_blocking.xml"),
            "--namespace", "ns", "--output", str(tmp_path / "output"),
        ])
        result = runner.invoke(app, ["validate", str(tmp_path / "output")])
        assert result.exit_code == 0

class TestMissingFile:
    def test_nonexistent_file(self, tmp_path):
        result = runner.invoke(app, [
            "convert", str(tmp_path / "nonexistent.xml"),
            "--namespace", "ns", "--output", str(tmp_path / "output"),
        ])
        assert result.exit_code != 0
```

- [ ] **Step 3: Run tests — expect failure**

Run: `cd waffleiron-cli && pip install -e ".[dev]" && pip install -e ../waffleiron && pytest tests/test_cli.py -v`

- [ ] **Step 4: Implement CLI**

`waffleiron_cli/main.py`:

```python
import typer
from pathlib import Path

app = typer.Typer(name="waffleiron", help="Convert BIG-IP ASM/AWAF policies to F5 XC WAF configurations")

@app.command()
def convert(
    policy_file: Path,
    namespace: str = typer.Option(..., help="Target XC namespace"),
    output: Path = typer.Option(..., help="Output directory"),
    alarm_only_signatures: str = typer.Option("defer", help="Bulk action for alarm-only sigs: exclude|enforce|defer"),
    alarm_only_violations: str = typer.Option("defer", help="Bulk action for alarm-only violations: disable|enforce|defer"),
    decisions: Path | None = typer.Option(None, help="Path to decisions YAML file"),
):
    ...

@app.command()
def analyze(policy_file: Path, output: Path = typer.Option(...)):
    ...

@app.command()
def validate(output_dir: Path):
    ...

@app.command()
def push(
    output_dir: Path,
    namespace: str = typer.Option(None, help="Target namespace"),
    shared: bool = typer.Option(False, help="Push to shared namespace"),
    tenant_url: str = typer.Option(None, envvar="F5XC_TENANT_URL"),
    api_token: str = typer.Option(None, envvar="F5XC_API_TOKEN"),
    p12_path: Path = typer.Option(None, envvar="F5XC_P12_PATH"),
    p12_password: str = typer.Option(None, envvar="F5XC_P12_PASSWORD"),
):
    ...

@app.command()
def xc_status(
    tenant_url: str = typer.Option(None, envvar="F5XC_TENANT_URL"),
    api_token: str = typer.Option(None, envvar="F5XC_API_TOKEN"),
):
    ...
```

Each command follows the same pattern: validate inputs → call library functions → write output / print results. Use `rich` for formatted console output (tables, colored status indicators).

- [ ] **Step 5: Run tests — expect pass**

Run: `pytest tests/test_cli.py -v`

- [ ] **Step 6: Commit**

```bash
git add waffleiron-cli/
git commit -m "feat(cli): Typer CLI with convert, analyze, validate, push, xc-status"
```

---

## Phase 6: REST API

### Task 19: API Scaffolding & Session Store

**Files:**
- Create: `waffleiron-api/pyproject.toml`
- Create: `waffleiron-api/src/waffleiron_api/__init__.py`
- Create: `waffleiron-api/src/waffleiron_api/config.py`
- Create: `waffleiron-api/src/waffleiron_api/sessions.py`
- Create: `waffleiron-api/src/waffleiron_api/schemas.py`
- Create: `waffleiron-api/tests/conftest.py`
- Create: `waffleiron-api/tests/test_sessions.py`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "waffleiron-api"
version = "0.1.0"
description = "REST API for WaffleIron ASM-to-XC policy converter"
requires-python = ">=3.12"
dependencies = [
    "waffleiron>=0.1.0",
    "fastapi>=0.111",
    "uvicorn[standard]>=0.30",
    "python-multipart>=0.0.9",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "httpx>=0.27"]

[tool.hatch.build.targets.wheel]
packages = ["src/waffleiron_api"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

- [ ] **Step 2: Write session store tests**

```python
import time
from waffleiron_api.sessions import SessionStore, Session

class TestSessionStore:
    def test_create_and_get(self):
        store = SessionStore(ttl_seconds=3600)
        session_id = store.create()
        session = store.get(session_id)
        assert session is not None
        assert session.id == session_id

    def test_get_nonexistent(self):
        store = SessionStore(ttl_seconds=3600)
        assert store.get("nonexistent") is None

    def test_delete(self):
        store = SessionStore(ttl_seconds=3600)
        sid = store.create()
        store.delete(sid)
        assert store.get(sid) is None

    def test_expiry(self):
        store = SessionStore(ttl_seconds=0)  # immediate expiry
        sid = store.create()
        time.sleep(0.1)
        store.cleanup_expired()
        assert store.get(sid) is None

    def test_session_holds_state(self):
        store = SessionStore(ttl_seconds=3600)
        sid = store.create()
        session = store.get(sid)
        session.policy_name = "test"
        session.status = "analyzed"
        retrieved = store.get(sid)
        assert retrieved.policy_name == "test"
```

- [ ] **Step 3: Run tests — expect failure**

Run: `cd waffleiron-api && pip install -e ".[dev]" && pip install -e ../waffleiron && pytest tests/test_sessions.py -v`

- [ ] **Step 4: Implement session store and config**

`sessions.py`:
- `Session` dataclass: `id`, `created_at`, `status` (created/parsed/analyzed/translated), `policy_name`, `policy_file_content`, `asm_policy` (AsmPolicy | None), `analysis` (AnalysisResult | None), `decisions` (DecisionSet), `translation` (TranslationResult | None), `push_results`
- `SessionStore`: dict-backed store with TTL, `create()`, `get()`, `delete()`, `cleanup_expired()`

`config.py`:
- `ApiConfig` class reading from env vars: `SESSION_TTL`, `LOG_LEVEL`, `PORT`, plus all `F5XC_*` vars via `XCConfig.from_env()`

`schemas.py`:
- Pydantic models for API request/response bodies: `ConversionResponse`, `AnalysisResponse`, `DecisionRequest`, `TranslationResponse`, `PushRequest`, `PushResponse`, `XCStatusResponse`

- [ ] **Step 5: Run tests — expect pass**

Run: `pytest tests/test_sessions.py -v`

- [ ] **Step 6: Commit**

```bash
git add waffleiron-api/
git commit -m "feat(api): project scaffolding, session store, and schemas"
```

---

### Task 20: Conversion Endpoints

**Files:**
- Create: `waffleiron-api/src/waffleiron_api/main.py`
- Create: `waffleiron-api/src/waffleiron_api/routers/__init__.py`
- Create: `waffleiron-api/src/waffleiron_api/routers/conversions.py`
- Create: `waffleiron-api/tests/test_conversions.py`

The core API endpoints for the conversion workflow.

- [ ] **Step 1: Write endpoint tests**

```python
from fastapi.testclient import TestClient
from waffleiron_api.main import app

client = TestClient(app)

class TestCreateConversion:
    def test_upload_xml(self, minimal_xml_bytes):
        response = client.post("/api/v1/conversions",
            files={"file": ("policy.xml", minimal_xml_bytes, "application/xml")})
        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert data["status"] == "parsed"
        assert data["policy_name"] == "test-policy"

    def test_upload_json(self, minimal_json_bytes):
        response = client.post("/api/v1/conversions",
            files={"file": ("policy.json", minimal_json_bytes, "application/json")})
        assert response.status_code == 201

    def test_upload_invalid(self):
        response = client.post("/api/v1/conversions",
            files={"file": ("bad.txt", b"not a policy", "text/plain")})
        assert response.status_code == 422

class TestGetConversion:
    def test_get_session(self, created_session_id):
        response = client.get(f"/api/v1/conversions/{created_session_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "parsed"

    def test_get_nonexistent(self):
        response = client.get("/api/v1/conversions/nonexistent")
        assert response.status_code == 404

class TestAnalysis:
    def test_get_analysis(self, created_session_id):
        response = client.get(f"/api/v1/conversions/{created_session_id}/analysis")
        assert response.status_code == 200
        data = response.json()
        assert "summary" in data
        assert "alarm_only_signatures" in data

class TestDecisions:
    def test_submit_decisions(self, created_session_id):
        response = client.put(f"/api/v1/conversions/{created_session_id}/decisions",
            json={"alarm_only_signatures": [{"sig_id": 200001001, "action": "exclude"}]})
        assert response.status_code == 200

class TestTranslate:
    def test_translate(self, created_session_id):
        # Submit decisions first
        client.put(f"/api/v1/conversions/{created_session_id}/decisions",
            json={"alarm_only_signatures": []})
        response = client.post(
            f"/api/v1/conversions/{created_session_id}/translate",
            json={"namespace": "test-ns"})
        assert response.status_code == 200
        data = response.json()
        assert "app_firewall" in data["outputs"]

class TestOutputs:
    def test_list_outputs(self, translated_session_id):
        response = client.get(f"/api/v1/conversions/{translated_session_id}/outputs")
        assert response.status_code == 200
        assert "app_firewall" in response.json()["available"]

    def test_download_output(self, translated_session_id):
        response = client.get(f"/api/v1/conversions/{translated_session_id}/outputs/app_firewall")
        assert response.status_code == 200
        assert "metadata" in response.json()

class TestReport:
    def test_json_report(self, translated_session_id):
        response = client.get(f"/api/v1/conversions/{translated_session_id}/report",
            headers={"Accept": "application/json"})
        assert response.status_code == 200
        assert "summary" in response.json()

    def test_markdown_report(self, translated_session_id):
        response = client.get(f"/api/v1/conversions/{translated_session_id}/report",
            headers={"Accept": "text/markdown"})
        assert response.status_code == 200
        assert "# ASM" in response.text

class TestDelete:
    def test_cleanup(self, created_session_id):
        response = client.delete(f"/api/v1/conversions/{created_session_id}")
        assert response.status_code == 204
        assert client.get(f"/api/v1/conversions/{created_session_id}").status_code == 404
```

Add fixtures to `conftest.py`: `minimal_xml_bytes`, `minimal_json_bytes`, `created_session_id` (uploads a policy), `translated_session_id` (uploads + translates).

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_conversions.py -v`

- [ ] **Step 3: Implement main.py and conversion router**

`main.py`:
```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from waffleiron_api.config import ApiConfig
from waffleiron_api.sessions import SessionStore
from waffleiron_api.routers import conversions, xc

config = ApiConfig.from_env()
session_store = SessionStore(ttl_seconds=config.session_ttl)

app = FastAPI(title="WaffleIron API", version="0.1.0")
app.include_router(conversions.router, prefix="/api/v1")
app.include_router(xc.router, prefix="/api/v1")

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "xc_configured": config.xc_config is not None}
```

`routers/conversions.py`:
Each endpoint follows: validate input → get session from store → call library function → update session → return response. The endpoints map directly to the library's public API: `parse()` → `analyze()` → `translate()` → `generate_report()`.

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_conversions.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron-api/
git commit -m "feat(api): conversion workflow endpoints"
```

---

### Task 21: XC Integration Endpoints

**Files:**
- Create: `waffleiron-api/src/waffleiron_api/routers/xc.py`
- Create: `waffleiron-api/tests/test_xc_endpoints.py`

XC connectivity, namespace listing, and push-to-XC endpoints.

- [ ] **Step 1: Write XC endpoint tests**

```python
import responses as responses_mock

class TestXCStatus:
    def test_no_creds_configured(self):
        response = client.get("/api/v1/xc/status")
        assert response.status_code == 200
        assert response.json()["configured"] is False

class TestXCConnect:
    @responses_mock.activate
    def test_successful_connection(self):
        responses_mock.add(responses_mock.GET,
            "https://test.console.ves.volterra.io/api/web/custom/namespaces/system/whoami",
            json={"tenant": "test"}, status=200)
        response = client.post("/api/v1/xc/connect",
            json={"tenant_url": "https://test.console.ves.volterra.io", "api_token": "token"})
        assert response.status_code == 200
        assert response.json()["connected"] is True

class TestXCNamespaces:
    @responses_mock.activate
    def test_list_namespaces(self):
        responses_mock.add(responses_mock.GET,
            "https://test.console.ves.volterra.io/api/web/namespaces",
            json={"items": [{"name": "ns1"}, {"name": "ns2"}]}, status=200)
        response = client.get("/api/v1/xc/namespaces",
            params={"tenant_url": "https://test.console.ves.volterra.io", "api_token": "token"})
        assert response.status_code == 200
        namespaces = response.json()["namespaces"]
        assert "shared" in namespaces  # always included
        assert "ns1" in namespaces

class TestPush:
    @responses_mock.activate
    def test_push_to_xc(self, translated_session_id):
        responses_mock.add(responses_mock.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/test-ns/app_firewalls",
            json={"metadata": {"name": "test"}}, status=200)
        responses_mock.add(responses_mock.POST,
            "https://test.console.ves.volterra.io/api/config/namespaces/test-ns/waf_exclusion_policys",
            json={"metadata": {"name": "test"}}, status=200)
        response = client.post(f"/api/v1/conversions/{translated_session_id}/push",
            json={
                "namespace": "test-ns",
                "tenant_url": "https://test.console.ves.volterra.io",
                "api_token": "token",
                "objects": ["app_firewall", "waf_exclusion_policy"],
            })
        assert response.status_code == 200
        results = response.json()["results"]
        assert all(r["success"] for r in results)
```

- [ ] **Step 2: Run tests — expect failure**

Run: `pytest tests/test_xc_endpoints.py -v`

- [ ] **Step 3: Implement XC router**

`routers/xc.py`:
- `GET /xc/status`: return which creds are configured (from `ApiConfig.xc_config`)
- `POST /xc/connect`: accept tenant_url + token/p12 in request body, construct temporary `XCClient`, call `check_connection()`
- `GET /xc/namespaces`: construct `XCClient` (from container config or request params), call `list_namespaces()`, always prepend "shared"
- `POST /conversions/{id}/push`: get session, construct `XCClient`, push each selected object via `create_object()`, return per-object results

When container-level creds are configured, the push endpoint uses those. When not, it expects `tenant_url` + `api_token` in the request body.

- [ ] **Step 4: Run tests — expect pass**

Run: `pytest tests/test_xc_endpoints.py -v`

- [ ] **Step 5: Commit**

```bash
git add waffleiron-api/
git commit -m "feat(api): XC integration endpoints (status, connect, namespaces, push)"
```

---

## Phase 7: Web Frontend

### Task 22: React Project Scaffolding

**Files:**
- Create: `waffleiron-web/package.json`
- Create: `waffleiron-web/tsconfig.json`
- Create: `waffleiron-web/vite.config.ts`
- Create: `waffleiron-web/tailwind.config.js`
- Create: `waffleiron-web/index.html`
- Create: `waffleiron-web/src/main.tsx`
- Create: `waffleiron-web/src/App.tsx`
- Create: `waffleiron-web/src/api.ts`
- Create: `waffleiron-web/src/types.ts`
- Create: `waffleiron-web/src/context/ConversionContext.tsx`

- [ ] **Step 1: Initialize project**

```bash
cd waffleiron-web
npm create vite@latest . -- --template react-ts
npm install tailwindcss @tailwindcss/vite
```

- [ ] **Step 2: Configure Vite proxy**

`vite.config.ts`:
```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
      '/healthz': 'http://localhost:8080',
    },
  },
})
```

- [ ] **Step 3: Create TypeScript types**

`src/types.ts` — types matching the API response schemas:

```typescript
export interface ConversionSession {
  id: string;
  status: 'parsed' | 'analyzed' | 'translated';
  policy_name: string;
  enforcement_mode: string;
  entity_counts: EntityCounts;
}

export interface EntityCounts {
  urls: number;
  parameters: number;
  file_types: number;
  signatures: number;
  violations: number;
}

export interface AnalysisResult {
  summary: ConversionSummary;
  alarm_only_signatures: AlarmOnlySignature[];
  alarm_only_violations: AlarmOnlyViolation[];
  positive_security: PositiveSecuritySummary;
  bot_gaps: BotGap[];
  warnings: LimitWarning[];
}

export interface ConversionSummary {
  total: number;
  directly_translated: number;
  translated_with_loss: number;
  decisions_required: number;
  cannot_translate: number;
}

export interface AlarmOnlySignature {
  sig_id: number;
  description: string;
  scope: string;
  action: 'exclude' | 'enforce' | 'defer';
}

export interface AlarmOnlyViolation {
  violation: string;
  action: 'disable' | 'enforce' | 'defer';
}

// ... remaining types for PositiveSecuritySummary, BotGap, LimitWarning,
//     TranslationOutputs, PushResult, XCStatus
```

- [ ] **Step 4: Create API client**

`src/api.ts` — fetch wrappers for each API endpoint:

```typescript
const BASE = '/api/v1';

export async function createConversion(file: File): Promise<ConversionSession> {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${BASE}/conversions`, { method: 'POST', body: form });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getAnalysis(id: string): Promise<AnalysisResult> { ... }
export async function submitDecisions(id: string, decisions: DecisionRequest): Promise<void> { ... }
export async function runTranslation(id: string, namespace: string): Promise<TranslationOutputs> { ... }
export async function getOutput(id: string, type: string): Promise<object> { ... }
export async function getReport(id: string, format: 'json' | 'markdown'): Promise<string> { ... }
export async function pushToXC(id: string, request: PushRequest): Promise<PushResult[]> { ... }
export async function getXCStatus(): Promise<XCStatus> { ... }
export async function listNamespaces(config?: XCConnectConfig): Promise<string[]> { ... }
export async function deleteConversion(id: string): Promise<void> { ... }
```

- [ ] **Step 5: Create ConversionContext**

`src/context/ConversionContext.tsx` — React context with useReducer:

```typescript
type WizardStep = 'upload' | 'analysis' | 'review' | 'push';

interface ConversionState {
  step: WizardStep;
  sessionId: string | null;
  session: ConversionSession | null;
  analysis: AnalysisResult | null;
  outputs: TranslationOutputs | null;
  xcStatus: XCStatus | null;
}

type ConversionAction =
  | { type: 'UPLOAD_SUCCESS'; session: ConversionSession }
  | { type: 'ANALYSIS_LOADED'; analysis: AnalysisResult }
  | { type: 'DECISIONS_UPDATED'; decisions: ... }
  | { type: 'TRANSLATION_COMPLETE'; outputs: TranslationOutputs }
  | { type: 'PUSH_COMPLETE'; results: PushResult[] }
  | { type: 'RESET' }
  | { type: 'GO_TO_STEP'; step: WizardStep };
```

- [ ] **Step 6: Create App shell with wizard navigation**

`src/App.tsx`:
```typescript
function App() {
  return (
    <ConversionProvider>
      <div className="min-h-screen bg-gray-50">
        <header>...</header>
        <WizardSteps />
        <main>
          <CurrentView />
        </main>
      </div>
    </ConversionProvider>
  );
}
```

`CurrentView` renders the appropriate view component based on `state.step`.

- [ ] **Step 7: Verify dev server starts**

Run: `npm run dev`
Expected: Vite dev server starts, shows the app shell at `http://localhost:5173`

- [ ] **Step 8: Commit**

```bash
git add waffleiron-web/
git commit -m "feat(web): React project scaffolding with types, API client, and context"
```

---

### Task 23: Upload View

**Files:**
- Create: `waffleiron-web/src/views/UploadView.tsx`
- Create: `waffleiron-web/src/components/FileDropzone.tsx`

- [ ] **Step 1: Implement FileDropzone component**

Drag-and-drop file upload with click-to-browse fallback. Accepts `.xml` and `.json` files. Shows file name and size after selection. Calls `onFileSelected(file: File)` prop.

- [ ] **Step 2: Implement UploadView**

When a file is selected:
1. Call `createConversion(file)` API
2. On success: dispatch `UPLOAD_SUCCESS`, show policy summary (name, enforcement mode, entity counts)
3. On error: show error message inline
4. Show "Analyze" button to proceed to next step

On "Analyze" click:
1. Call `getAnalysis(sessionId)` API
2. Dispatch `ANALYSIS_LOADED`
3. Dispatch `GO_TO_STEP('analysis')`

- [ ] **Step 3: Test in browser**

Run the FastAPI backend (`uvicorn waffleiron_api.main:app --port 8080`) and Vite dev server. Upload a test XML file. Verify:
- File is accepted
- Policy summary appears
- Clicking "Analyze" transitions to the next view

- [ ] **Step 4: Commit**

```bash
git add waffleiron-web/
git commit -m "feat(web): upload view with drag-and-drop file picker"
```

---

### Task 24: Analysis & Decisions View

**Files:**
- Create: `waffleiron-web/src/views/AnalysisView.tsx`
- Create: `waffleiron-web/src/components/DecisionsTable.tsx`
- Create: `waffleiron-web/src/components/SummaryCards.tsx`

This is the most complex UI component — the interactive decisions table with bulk actions.

- [ ] **Step 1: Implement SummaryCards**

Row of cards showing: total features, directly translated, translated with loss, decisions required, cannot translate. Use color coding (green, yellow, orange, red).

- [ ] **Step 2: Implement DecisionsTable**

Interactive table with:
- Columns: type (signature/violation), ID, description, scope, decision dropdown
- Per-row dropdown: Exclude/Enforce/Defer (signatures) or Disable/Enforce/Defer (violations)
- Bulk action toolbar above the table with dropdowns: "All signatures →" and "All violations →"
- Column sort (click headers)
- Filter by type (signatures only, violations only, all)
- Color-coded rows: green (enforce), yellow (defer), red (exclude/disable)
- Row count indicator

State management: local state for decisions (array of `{id, type, action}`). On "Translate" click, submit all decisions via `submitDecisions()` API.

- [ ] **Step 3: Implement AnalysisView**

Layout:
1. SummaryCards at top
2. DecisionsTable (main area)
3. Collapsible panels below: "Positive Security Entities", "Custom Signatures", "Bot Protection Gaps", "Session/Stateful Features"
4. "Translate" button at bottom with namespace input field and deferred-count badge

On "Translate" click:
1. Call `submitDecisions(sessionId, decisions)`
2. Call `runTranslation(sessionId, namespace)`
3. Dispatch `TRANSLATION_COMPLETE`
4. Dispatch `GO_TO_STEP('review')`

- [ ] **Step 4: Test in browser**

Upload a mature_tuned.xml fixture. Verify:
- Summary cards show correct counts
- Alarm-only items appear in the decisions table
- Bulk actions work (set all sigs to exclude, verify all rows update)
- Individual dropdown changes work
- Collapsible gap panels show positive security info
- Translate button submits and transitions

- [ ] **Step 5: Commit**

```bash
git add waffleiron-web/
git commit -m "feat(web): analysis view with interactive decisions table and bulk actions"
```

---

### Task 25: Review & Export View

**Files:**
- Create: `waffleiron-web/src/views/ReviewView.tsx`
- Create: `waffleiron-web/src/components/JsonViewer.tsx`
- Create: `waffleiron-web/src/components/GapReport.tsx`

- [ ] **Step 1: Implement JsonViewer**

Syntax-highlighted JSON display with:
- Formatted with 2-space indent
- Line numbers
- Copy-to-clipboard button
- Validation status badge (green checkmark or red warning with error count)

Use a lightweight approach: `<pre>` with CSS for syntax highlighting (apply classes to keys, strings, numbers, booleans via regex replacement on the JSON string). No heavy library needed.

- [ ] **Step 2: Implement GapReport**

Render the Markdown gap report. Use a lightweight Markdown renderer (or render server-side and display as HTML). Include expandable sections for long lists.

- [ ] **Step 3: Implement ReviewView**

Layout:
1. Tabbed panel for generated objects (only show tabs for objects that were produced)
   - Each tab shows JsonViewer with the object's JSON
2. Gap report section below
3. Export toolbar:
   - "Download ZIP" button — calls a utility that creates a client-side ZIP
   - "Download" per-object buttons
   - "Copy JSON" per-object buttons
   - "Push to XC" button → transitions to push view

For ZIP download, use `JSZip` library (add to package.json) to create a client-side ZIP containing all JSON files + gap_report.md + decisions.yaml.

- [ ] **Step 4: Test in browser**

Complete a full conversion flow. Verify:
- All generated objects appear as tabs
- JSON is syntax-highlighted and copyable
- Gap report renders correctly
- ZIP download contains all files
- Validation warnings appear on objects with issues

- [ ] **Step 5: Commit**

```bash
git add waffleiron-web/
git commit -m "feat(web): review view with JSON viewer, gap report, and export"
```

---

### Task 26: Push to XC View

**Files:**
- Create: `waffleiron-web/src/views/PushView.tsx`
- Create: `waffleiron-web/src/components/NamespaceSelector.tsx`

- [ ] **Step 1: Implement NamespaceSelector**

Dropdown populated by calling `listNamespaces()` API. Always includes "shared" option at the top. Shows loading state while fetching.

- [ ] **Step 2: Implement PushView**

Conditional layout based on XC status:
- **No container creds:** Show tenant URL input, auth method toggle (API Token text input / P12 file upload), "Test Connection" button with success/error feedback
- **Container creds configured:** Skip auth section entirely

Always show:
- NamespaceSelector dropdown
- Object checklist (checkboxes for each generated object, all checked by default)
- Dry-run toggle
- "Push" button
- Results panel: per-object success/failure with status icon and error messages

On push:
1. Call `pushToXC(sessionId, { namespace, objects, tenant_url?, api_token?, dry_run })`
2. Show progress (can be simple — push happens fast for 2-4 objects)
3. Display results per object

- [ ] **Step 3: Test in browser**

Since we can't push to a real XC tenant in development, test:
- Auth form appears when no container creds
- Auth form hidden when `XC_STATUS` shows configured
- Namespace dropdown populates (mock the API response)
- Push button sends correct request
- Results display correctly for success/failure

- [ ] **Step 4: Commit**

```bash
git add waffleiron-web/
git commit -m "feat(web): push-to-XC view with auth, namespace selector, and results"
```

---

## Phase 8: Container & Integration

### Task 27: Dockerfile & Static File Serving

**Files:**
- Create: `Dockerfile`
- Modify: `waffleiron-api/src/waffleiron_api/main.py` (add static file mount)

- [ ] **Step 1: Build the frontend**

```bash
cd waffleiron-web && npm run build
```

Verify `waffleiron-web/dist/` contains `index.html` and built assets.

- [ ] **Step 2: Add static file serving to FastAPI**

Update `main.py` to mount the SPA:

```python
import os
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

STATIC_DIR = Path(os.getenv("STATIC_DIR", "static"))

# Mount static assets (JS, CSS, images)
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    # SPA fallback: serve index.html for non-API, non-asset routes
    @app.get("/{path:path}")
    async def spa_fallback(path: str):
        return FileResponse(STATIC_DIR / "index.html")
```

- [ ] **Step 3: Create Dockerfile**

```dockerfile
# Stage 1: Build React frontend
FROM node:20-slim AS frontend
WORKDIR /app
COPY waffleiron-web/package*.json ./
RUN npm ci
COPY waffleiron-web/ ./
RUN npm run build

# Stage 2: Python runtime
FROM python:3.12-slim AS runtime
RUN groupadd -r waffleiron && useradd -r -g waffleiron -d /app waffleiron
WORKDIR /app

# Install Python packages
COPY waffleiron/pyproject.toml waffleiron/
COPY waffleiron/src/ waffleiron/src/
RUN pip install --no-cache-dir ./waffleiron

COPY waffleiron-cli/pyproject.toml waffleiron-cli/
COPY waffleiron-cli/src/ waffleiron-cli/src/
RUN pip install --no-cache-dir ./waffleiron-cli

COPY waffleiron-api/pyproject.toml waffleiron-api/
COPY waffleiron-api/src/ waffleiron-api/src/
RUN pip install --no-cache-dir ./waffleiron-api

# Copy built frontend
COPY --from=frontend /app/dist /app/static

# Create default mount points for K8s secrets
RUN mkdir -p /certs /secrets

ENV STATIC_DIR=/app/static
ENV PORT=8080
EXPOSE 8080

USER waffleiron
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

CMD ["uvicorn", "waffleiron_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

- [ ] **Step 4: Build and test container**

```bash
docker build -t waffleiron .
docker run -p 8080:8080 waffleiron
```

Verify:
- `http://localhost:8080` serves the React SPA
- `http://localhost:8080/healthz` returns `{"status": "ok"}`
- `http://localhost:8080/api/docs` shows Swagger UI
- Upload a policy file through the web UI and complete a conversion

- [ ] **Step 5: Commit**

```bash
git add Dockerfile waffleiron-api/
git commit -m "feat: Dockerfile and static file serving for containerized deployment"
```

---

### Task 28: End-to-End Integration Test

**Files:**
- Create: `tests/test_e2e.py`

A full end-to-end test that exercises the entire pipeline through the API.

- [ ] **Step 1: Write E2E test**

```python
from fastapi.testclient import TestClient
from waffleiron_api.main import app

client = TestClient(app)

def test_full_conversion_workflow():
    # 1. Upload
    fixture_path = Path(__file__).resolve().parent.parent / "waffleiron" / "tests" / "fixtures" / "mature_tuned.xml"
    with open(fixture_path, "rb") as f:
        resp = client.post("/api/v1/conversions", files={"file": ("policy.xml", f)})
    assert resp.status_code == 201
    session_id = resp.json()["id"]

    # 2. Get analysis
    resp = client.get(f"/api/v1/conversions/{session_id}/analysis")
    assert resp.status_code == 200
    analysis = resp.json()
    assert analysis["summary"]["decisions_required"] > 0

    # 3. Submit decisions (exclude all alarm-only sigs)
    decisions = {
        "alarm_only_signatures": [
            {"sig_id": s["sig_id"], "action": "exclude"}
            for s in analysis["alarm_only_signatures"]
        ],
        "alarm_only_violations": [
            {"violation": v["violation"], "action": "enforce"}
            for v in analysis["alarm_only_violations"]
        ],
    }
    resp = client.put(f"/api/v1/conversions/{session_id}/decisions", json=decisions)
    assert resp.status_code == 200

    # 4. Translate
    resp = client.post(f"/api/v1/conversions/{session_id}/translate",
        json={"namespace": "test-ns"})
    assert resp.status_code == 200
    outputs = resp.json()["outputs"]
    assert "app_firewall" in outputs
    assert "waf_exclusion_policy" in outputs

    # 5. Get outputs
    resp = client.get(f"/api/v1/conversions/{session_id}/outputs/app_firewall")
    assert resp.status_code == 200
    app_fw = resp.json()
    assert app_fw["metadata"]["namespace"] == "test-ns"

    # 6. Get gap report
    resp = client.get(f"/api/v1/conversions/{session_id}/report",
        headers={"Accept": "text/markdown"})
    assert resp.status_code == 200
    assert "## Summary" in resp.text

    # 7. Cleanup
    resp = client.delete(f"/api/v1/conversions/{session_id}")
    assert resp.status_code == 204
```

- [ ] **Step 2: Run E2E test**

Run: `pytest tests/test_e2e.py -v`
Expected: Pass

- [ ] **Step 3: Commit**

```bash
git add tests/
git commit -m "test: end-to-end integration test for full conversion workflow"
```

---

### Task 29: Final Verification

- [ ] **Step 1: Run full test suite**

```bash
cd waffleiron && pytest tests/ -v --tb=short
cd ../waffleiron-cli && pytest tests/ -v --tb=short
cd ../waffleiron-api && pytest tests/ -v --tb=short
cd .. && pytest tests/test_e2e.py -v --tb=short
```

Expected: All tests pass.

- [ ] **Step 2: Run linter**

```bash
cd waffleiron && ruff check src/ tests/
cd ../waffleiron-cli && ruff check src/ tests/
cd ../waffleiron-api && ruff check src/ tests/
```

Fix any issues.

- [ ] **Step 3: Build and test container one more time**

```bash
docker build -t waffleiron .
docker run -p 8080:8080 waffleiron
```

Open browser, upload a test policy, complete full workflow through the UI: upload → analyze → make decisions → translate → review → export ZIP.

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix: final verification fixes"
```
