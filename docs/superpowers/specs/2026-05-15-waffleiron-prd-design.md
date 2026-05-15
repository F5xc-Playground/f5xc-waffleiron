# WaffleIron — Product Requirements & Design Specification

## Overview

WaffleIron converts BIG-IP ASM/Advanced WAF policies into F5 Distributed Cloud (XC) WAF/WAAP configurations. It parses ASM XML and Declarative JSON exports, produces XC API-ready JSON payloads, generates a detailed gap report documenting everything that cannot translate 1:1, and optionally pushes the resulting objects directly to an XC tenant.

### Problem

BIG-IP ASM policies cannot be directly imported into F5 XC WAF. The engines share ~8,000 attack signatures but use fundamentally different policy models. Migration today requires manual recreation of WAF configurations — error-prone and time-consuming for mature policies with extensive tuning. A typical mature ASM policy has 200+ alarm-only signatures, dozens of per-entity overrides, and positive security entities with no XC equivalent. Manual migration misses nuance and produces incomplete configurations.

### Users

Both F5 SEs/Solution Architects and customer WAF administrators. Neither persona is assumed to be an expert in both ASM and XC. The tool provides detailed contextual information — explaining what each ASM feature does, what the XC equivalent is (or why there isn't one), and what the implications of each decision are. A savvy engineer unfamiliar with either platform should be able to use WaffleIron effectively.

### Delivery

- **Primary form factor:** Container (Docker image) with a web interface
- **Secondary interface:** CLI for programmatic/scripted use
- **Architecture:** API-first — the web UI and CLI are both thin consumers of a REST API, which wraps a standalone Python conversion library

---

## Architecture

### Library-First Design

The system is structured as three packages sharing a core engine:

```
waffleiron/                  # Standalone Python library (pip-installable)
├── parsers/                 # ASM XML + JSON parsers
│   ├── xml_parser.py        # defusedxml + lxml for ASM XML exports
│   ├── json_parser.py       # ASM Declarative JSON exports (v15.1+)
│   └── detect.py            # Auto-detect input format
├── model/                   # Intermediate ASM policy model (dataclasses)
├── analysis/                # Gap detection, alarm-only identification, limit checks
├── translators/             # ASM model → XC object translators
│   ├── app_firewall.py
│   ├── exclusion_policy.py
│   ├── service_policy.py
│   └── http_lb_patch.py
├── validators/              # Validate output against XC OAS schemas
├── reporters/               # Gap report generation (JSON + Markdown)
├── xc_client/               # XC API client (adapted from prom-exporter pattern)
└── decisions.py             # Decision model for alarm-only items

waffleiron-api/              # FastAPI wrapper — REST API + serves React SPA
waffleiron-cli/              # Typer wrapper — CLI commands
waffleiron-web/              # React 19 + TypeScript SPA (Vite)
```

The conversion engine (`waffleiron` library) has zero dependency on FastAPI, React, or any web framework. The API and CLI are thin wrappers that call library functions.

### Tech Stack

| Component | Technology | Rationale |
|---|---|---|
| Conversion engine | Python 3.12 | Best XML/JSON parsing ecosystem, matches qkview pattern |
| XML parsing | defusedxml + lxml | Safe parsing (defusedxml) + XPath navigation (lxml) for deep ASM trees |
| API layer | FastAPI + uvicorn | Auto-generated OpenAPI docs, async support, lightweight |
| Web frontend | React 19 + TypeScript + Vite | Matches qkview pattern, fast builds, strong typing |
| CSS | Tailwind CSS | Lightweight, no heavy UI framework needed |
| CLI | Typer | Python CLI framework, auto-generated help, same process as engine |
| Container | Multi-stage Docker (Node build + Python runtime) | Single image, follows qkview pattern |
| XC API client | Custom (requests + urllib3 retry) | Adapted from prom-exporter's F5XCClient pattern |

---

## Core Conversion Engine

### Stage 1: Parsing (Input → Intermediate Model)

Two parsers produce the same normalized intermediate model:

**`XmlPolicyParser`** — Reads ASM XML exports from any BIG-IP version. Uses `defusedxml` for safe XML parsing and `lxml` for XPath navigation of deeply nested policy structures.

**`JsonPolicyParser`** — Reads ASM Declarative JSON exports (BIG-IP v15.1+). Uses stdlib `json` with structural validation.

**Auto-detection:** The parser inspects the input content to determine format (XML declaration / JSON object). Callers do not specify format.

**Output:** An `AsmPolicy` dataclass — a fully typed, normalized Python representation. Every field uses enums, typed dataclasses, or typed lists. No raw XML/JSON survives past this stage.

The `AsmPolicy` intermediate model covers:

```
AsmPolicy:
  name: str
  enforcement_mode: EnforcementMode (blocking | transparent)
  encoding: str

  signatures:
    global_overrides: list[SignatureOverride]  # sig_id, enabled, alarm, block
    accuracy_level: AccuracyLevel             # high | high_medium | all
    staging_enabled: bool
    staging_period: int (days)
    threat_campaigns_enabled: bool

  signature_sets: list[SignatureSet]           # name, enabled

  entities:
    urls: list[UrlEntity]
    parameters: list[ParameterEntity]
    file_types: list[FileTypeEntity]
    cookies: list[CookieEntity]
    headers: list[HeaderEntity]
    methods: list[MethodEntity]

  violations: list[Violation]                 # name, alarm, block

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
```

### Stage 2: Analysis

Examines the intermediate model before translation to identify decision points and gaps:

- **Alarm-only items** — Signatures and violations with `alarm=True, block=False`. Each becomes a decision point with options (exclude/enforce/defer) and contextual explanation.
- **Positive security entities** — URLs, parameters, file types, cookies, headers with value constraints. Counted and categorized. No XC equivalent exists.
- **Untranslatable features** — Custom signatures (with patterns), session tracking, session-aware brute force.
- **XC limit checks** — Will the policy exceed 256 exclusion rules? 1024 signature contexts? 64 anonymization items? 48 response codes? Flags warnings early before translation.
- **Bot protection gaps** — Identifies ASM bot actions (challenge, captcha, rate-limit) with no XC basic bot protection equivalent.

Output: An `AnalysisResult` containing decision points, gap inventory, limit warnings, and summary statistics. This is what drives the interactive decision-making UI.

### Stage 3: Translation (Intermediate Model + Decisions → XC Objects)

Four independent translators, each producing a validated XC API payload:

| Translator | Output | When Produced |
|---|---|---|
| `AppFirewallTranslator` | `app_firewall` JSON | Always |
| `ExclusionPolicyTranslator` | `waf_exclusion_policy` JSON | Always (may be empty) |
| `ServicePolicyTranslator` | `service_policy` JSON | Only if IP whitelist, geolocation, or IP intelligence rules exist |
| `HttpLbPatchTranslator` | `http_lb_patch` JSON | Only if CSRF or Data Guard is configured |

The `decisions` object carries the user's alarm-only choices. Each decision maps a specific signature or violation to an action:

- **Exclude** — Create an exclusion rule (signature won't fire at all)
- **Enforce** — Leave active (will block in blocking mode)
- **Defer** — No action; appears in gap report for manual review

Translation rules follow the field-by-field mapping in `docs/field-mapping.md`. Key translations:

- `enforcement_mode` → `blocking` / `monitoring` (1:1)
- Signature accuracy level → `signature_selection_by_accuracy` (1:1)
- Disabled signature sets → `disabled_attack_types` via set-to-attack-type mapping
- Staging settings → `signatures_staging_settings` (1:1)
- Per-entity signature overrides → exclusion rules with path/context + signature ID
- Sensitive parameters/cookies/headers → anonymization config (max 64 items)
- Bot defense categories → `bot_protection_setting` (malicious/suspicious/good with BLOCK/REPORT/IGNORE)
- Custom blocking page → `blocking_page` (with `<%TS.request.ID()%>` → `{{request_id}}` variable translation, max 4096 bytes base64)
- ASM `VIOL_EVASION` (single flag) → 8 XC `VIOL_EVASION_*` sub-types (enable/disable together)
- ASM `VIOL_HTTP_PROTOCOL` (single flag) → 10 XC `VIOL_HTTP_PROTOCOL_*` sub-types (enable/disable together)
- IP whitelist → Service Policy allow rules
- Geolocation → Service Policy geo deny rules
- IP intelligence → Service Policy threat category rules
- CSRF → HTTP LB CSRF settings
- Data Guard → HTTP LB Data Guard settings (custom regex patterns may not translate)

### Stage 4: Validation

Output JSON is validated against the XC OpenAPI schemas in `docs/schemas/`:

- Enum values are valid members of their type
- Array lengths within XC limits (256 exclusion rules, 1024 signature contexts, 64 anonymization items, 48 response codes, etc.)
- Required fields are present
- String lengths within bounds (blocking page max 4096 bytes base64, context names max 256 chars)
- Signature IDs in valid range (200000001–299999999, or 0 for wildcard)
- Mutually exclusive oneof groups have exactly one choice set

Validation errors are returned alongside the output — they don't block generation. The user can see what's invalid and adjust decisions to fix it (e.g., if they have too many exclusion rules, they might switch some alarm-only signatures from "exclude" to "enforce").

### Stage 5: Report Generation

Produces the gap report in both structured JSON and rendered Markdown:

```markdown
# ASM → XC Conversion Gap Report
Generated: {timestamp}
Source: {asm_policy_name}
Enforcement Mode: {blocking|transparent}

## Summary
- Total ASM features assessed: N
- Directly translated: N (N%)
- Translated with loss: N (N%)
- Decisions required: N
- Cannot translate: N (N%)

## Decisions Made
### Alarm-Only Signatures (N items)
| Signature ID | Description | Scope | Decision | Implication |
|---|---|---|---|---|
| 200001234 | SQL Injection - UNION SELECT | Global | Excluded | Signature will not fire |

### Alarm-Only Violations (N items)
| Violation | Decision | Implication |
|---|---|---|
| VIOL_COOKIE_MODIFIED | Enforced | Will block in blocking mode |

### Deferred Items (N items)
Items left for manual review — no exclusion or enforcement action taken.

## Cannot Translate

### Positive Security Entities
| Entity Type | Count | Details |
|---|---|---|
| URLs (explicit) | 47 | Including 23 with method restrictions |
| Parameters (with value constraints) | 23 | Types: numeric (8), alpha (6), email (4), phone (3), custom (2) |
| ...

These entities enforce application-specific input validation that XC cannot replicate.
Consider supplementing XC WAF with:
- API schema validation (XC API Definition + API Discovery)
- Application-level input validation
- Service Policy method/path restrictions

### Custom Signatures (N items)
| ID | Name | Pattern | Scope |
|---|---|---|---|
| 300000001 | Custom SQL for legacy API | /union\s+all\s+select.*from\s+users/i | /api/v1/legacy/* |

### Session/Stateful Features
- Session tracking: {enabled|disabled}
- Session hijacking prevention: {enabled|disabled}
- Brute force: {enabled|disabled} — XC Rate Limiter is a partial alternative (no session awareness)

### Bot Protection Gaps
- challenge action → no XC equivalent (XC Bot Defense Advanced is separate product)
- captcha action → no XC equivalent
- rate-limit per bot category → no XC equivalent (use XC Rate Limiter separately)

## XC Feature Recommendations
| Feature | Why | Partially Compensates For |
|---|---|---|
| AI Risk-Based Blocking | ML risk assessment per request | Alarm-only tuning loss |
| ML False Positive Suppression | Auto-suppress likely false positives | Per-signature tuning loss |
| API Discovery | Automatic API endpoint/schema detection | Positive security entities |
| Malicious User Detection | Per-user behavioral scoring | Session tracking |
| Threat Campaigns | High-fidelity campaign signatures (near-zero FP) | General protection |
```

---

## REST API (`waffleiron-api`)

Thin FastAPI wrapper around the engine library. The web UI and future automation are consumers of this API.

### Endpoints

#### Conversion Workflow (Session-Based)

```
POST   /api/v1/conversions                    → Upload ASM policy, create session
GET    /api/v1/conversions/{id}               → Session status + summary
GET    /api/v1/conversions/{id}/analysis       → Analysis result (gaps, decisions needed)
PUT    /api/v1/conversions/{id}/decisions      → Submit alarm-only decisions
POST   /api/v1/conversions/{id}/translate      → Run translation with current decisions
GET    /api/v1/conversions/{id}/outputs        → List generated XC objects
GET    /api/v1/conversions/{id}/outputs/{type} → Download specific object JSON
GET    /api/v1/conversions/{id}/report         → Gap report (JSON or Markdown via Accept header)
POST   /api/v1/conversions/{id}/push           → Push objects to XC API
DELETE /api/v1/conversions/{id}               → Clean up session
```

#### XC Integration

```
GET    /api/v1/xc/status                       → Auth config status (what's configured, no secrets)
POST   /api/v1/xc/connect                      → Test XC API connectivity
GET    /api/v1/xc/namespaces                   → List available namespaces (incl. shared)
```

#### Health

```
GET    /healthz                                → Service health + XC connectivity status
```

### Session Storage

Sessions are stored in-memory with optional file-backed persistence for container restarts. Each session holds: uploaded policy file, parsed intermediate model, analysis result, user decisions, generated outputs, push results.

Sessions auto-expire after a configurable TTL (default 24 hours, set via `SESSION_TTL` env var).

No database is required.

### API Documentation

FastAPI auto-generates OpenAPI 3.0 documentation at `/api/docs` (Swagger UI) and `/api/redoc` (ReDoc).

---

## Web Interface (`waffleiron-web`)

React 19 + TypeScript SPA built with Vite. Served as static assets by the FastAPI app.

### Technology

- React 19 + TypeScript
- Vite for builds
- Tailwind CSS for styling
- State management: React context + useReducer for conversion session state
- Purpose-built components (no heavy UI framework)

### Page Flow

The UI is a single-page wizard with four views:

#### View 1: Upload & Parse

- Drag-and-drop or file picker for ASM policy file (XML or JSON)
- Auto-detects format, shows immediate feedback: policy name, enforcement mode, entity counts, signature count
- Displays parse errors inline
- "Analyze" button to proceed

#### View 2: Analysis & Decisions

- **Summary cards** at top: total features assessed, directly translatable, lossy, decisions required, untranslatable
- **Alarm-only decisions table** — the primary interactive element:
  - Columns: type (signature/violation), ID, description, ASM scope, current state
  - Per-row dropdown: Exclude / Enforce / Defer
  - Bulk action toolbar: "Set all signatures to…", "Set all violations to…", filter by type/scope
  - Sort and filter by any column
  - Color-coded rows by decision state
- **Positive security summary** — read-only panel with entity counts and explanation
- **Other gaps** — collapsible sections for custom signatures, session tracking, bot protection gaps
- "Translate" button (with badge showing count of deferred items)

#### View 3: Review & Export

- **Generated objects panel** — tabbed view with syntax-highlighted JSON:
  - Tabs: app_firewall | waf_exclusion_policy | service_policy | http_lb_patch
  - Per-tab: full JSON payload, copy button, validation status indicator
  - Tabs only appear for objects that were generated
- **Gap report** — rendered Markdown with expandable sections
- **Export options:**
  - Download all as ZIP (JSON files + gap_report.md + decisions.yaml)
  - Download individual objects
  - Copy JSON to clipboard
  - "Push to XC" button (transitions to View 4)

#### View 4: Push to XC

- **If no container-level creds configured:**
  - Tenant URL input
  - Auth method toggle (API Token / P12 Certificate upload)
  - "Test Connection" button
- **If container-level creds configured:** This section is hidden — connection is pre-established
- **Always shown:**
  - Namespace selector (dropdown populated from XC API, includes "shared" namespace option)
  - Object checklist (which objects to push, all checked by default)
  - Dry-run toggle
  - Push button with per-object progress indicator
  - Results view: success/failure per object with XC API response details

---

## CLI (`waffleiron-cli`)

Thin Typer wrapper around the engine library.

### Commands

```bash
# Full conversion
waffleiron convert <policy-file> \
  --namespace <ns> \
  --output <dir> \
  --alarm-only-signatures=<exclude|enforce|defer> \
  --alarm-only-violations=<exclude|enforce|defer>

# Convert with per-item decisions file
waffleiron convert <policy-file> \
  --namespace <ns> \
  --output <dir> \
  --decisions <decisions.yaml>

# Analysis only (gap report, no XC output)
waffleiron analyze <policy-file> --output <dir>

# Validate generated output against XC schemas
waffleiron validate <output-dir>

# Push to XC
waffleiron push <output-dir> \
  --namespace <ns> \
  --tenant-url <url> \
  --api-token <token>

# Push to shared namespace
waffleiron push <output-dir> --shared

# Test XC connectivity
waffleiron xc-status
```

### Decision Handling

- **Bulk flags** for quick runs: `--alarm-only-signatures=exclude`
- **Decisions file** for per-item control: `analyze` generates a `decisions.yaml` template; user edits it; `convert` consumes it
- **Default** (no flags): all alarm-only items deferred to gap report

### Decisions File Format

```yaml
# Generated by: waffleiron analyze policy.xml
# Edit decisions below, then run: waffleiron convert policy.xml --decisions decisions.yaml

alarm_only_signatures:
  - sig_id: 200001234
    description: "SQL Injection - UNION SELECT"
    scope: global
    decision: defer        # exclude | enforce | defer
  - sig_id: 200005678
    description: "XSS - Script Tag"
    scope: "/api/v1/data"
    decision: defer

alarm_only_violations:
  - violation: VIOL_COOKIE_MODIFIED
    decision: defer        # disable | enforce | defer
  - violation: VIOL_ENCODING
    decision: defer

bot_protection:
  - category: unknown-bot
    asm_action: challenge
    decision: block        # block | report | ignore
```

### Auth

Environment variables (`F5XC_TENANT_URL`, `F5XC_API_TOKEN`, etc.) or CLI flags (`--tenant-url`, `--api-token`, `--p12-path`, `--p12-password`). CLI flags override env vars. Only required for `push` and `xc-status` commands.

### Output Structure

```
output/
├── app_firewall.json
├── waf_exclusion_policy.json
├── service_policy.json             # only if IP/geo/threat-intel rules
├── http_lb_patch.json              # only if CSRF/Data Guard configured
├── gap_report.md
├── gap_report.json
└── decisions.yaml                  # template for re-runs
```

---

## Container & Deployment

### Docker Image

Single multi-stage build:

```dockerfile
# Stage 1: Build React frontend
FROM node:20-slim AS frontend
# npm ci → vite build → /app/dist

# Stage 2: Python runtime
FROM python:3.12-slim AS runtime
# pip install waffleiron + waffleiron-api
# Copy frontend dist → FastAPI static dir
# Non-root user
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"
CMD ["uvicorn", "waffleiron_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

### Configuration

| Env Var | Default | Description |
|---|---|---|
| `F5XC_TENANT_URL` | — | XC tenant URL |
| `F5XC_API_TOKEN` | — | API token (mutually exclusive with P12) |
| `F5XC_API_TOKEN_FILE` | `/secrets/api-token` | File containing API token (K8s secret mount) |
| `F5XC_P12_PATH` | `/certs/api-creds.p12` | P12 certificate path |
| `F5XC_P12_PASSWORD` | — | P12 password |
| `F5XC_P12_PASSWORD_FILE` | `/secrets/p12-password` | File containing P12 password |
| `SESSION_TTL` | `86400` | Session expiry in seconds |
| `LOG_LEVEL` | `info` | Logging level |
| `PORT` | `8080` | Listen port |

**Credential resolution order:** `_FILE` variant (if file exists at path) → env var → not configured.

**Token and P12 are mutually exclusive.** Container validates at startup; exits with a clear error if both are set.

### Running

```bash
# No pre-configured creds (user provides in UI)
docker run -p 8080:8080 waffleiron

# With API token
docker run -p 8080:8080 \
  -e F5XC_TENANT_URL=https://tenant.console.ves.volterra.io \
  -e F5XC_API_TOKEN=your-token \
  waffleiron

# With P12 cert (default path, just mount the file)
docker run -p 8080:8080 \
  -e F5XC_TENANT_URL=https://tenant.console.ves.volterra.io \
  -e F5XC_P12_PASSWORD=password \
  -v /path/to/api-creds.p12:/certs/api-creds.p12:ro \
  waffleiron
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: waffleiron
spec:
  template:
    spec:
      containers:
      - name: waffleiron
        image: waffleiron:latest
        ports:
        - containerPort: 8080
        env:
        - name: F5XC_TENANT_URL
          valueFrom:
            secretKeyRef:
              name: xc-credentials
              key: tenant-url
        # Option A: API token from secret (env var)
        - name: F5XC_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: xc-credentials
              key: api-token
        # Option B: API token from secret (file mount — more secure)
        volumeMounts:
        - name: xc-secrets
          mountPath: /secrets
          readOnly: true
        # Option C: P12 cert from secret
        - name: xc-certs
          mountPath: /certs
          readOnly: true
      volumes:
      - name: xc-secrets
        secret:
          secretName: xc-credentials
          items:
          - key: api-token
            path: api-token
      - name: xc-certs
        secret:
          secretName: xc-p12-cert
          items:
          - key: api-creds.p12
            path: api-creds.p12
```

---

## XC API Client

Adapted from the prom-exporter's `F5XCClient` pattern with additions from the Go projects:

### Auth

- **API Token:** `Authorization: APIToken {token}` header
- **P12 Certificate:** mTLS via `requests` with PKCS12 adapter (using `requests-pkcs12` or extracting cert/key from P12 with `cryptography` library)
- Mutually exclusive — validated at client construction

### Error Handling

Sentinel error types matching the pattern across all F5 XC projects:

| HTTP Status | Error | Meaning |
|---|---|---|
| 401/403 | `XCAuthError` | Authentication/authorization failure |
| 404 | `XCNotFoundError` | Resource not found |
| 409 | `XCConflictError` | Resource already exists |
| 429 | `XCRateLimitError` | Rate limited |
| 5xx | `XCServerError` | Server error |

### Resilience

- **Rate limiting:** Client-side rate limiter (2 RPS default, matching operator pattern)
- **Retry:** urllib3 retry adapter with exponential backoff (3 retries, backoff factor 1.0)
- **Timeout:** Configurable request timeout (default 30s)

### Endpoints Used

```
GET    /api/web/namespaces                                          → list namespaces
POST   /api/config/namespaces/{ns}/app_firewalls                    → create app_firewall
PUT    /api/config/namespaces/{ns}/app_firewalls/{name}             → update app_firewall
POST   /api/config/namespaces/{ns}/waf_exclusion_policys            → create exclusion policy
PUT    /api/config/namespaces/{ns}/waf_exclusion_policys/{name}     → update exclusion policy
POST   /api/config/namespaces/{ns}/service_policys                  → create service policy
PUT    /api/config/namespaces/{ns}/service_policys/{name}           → update service policy
GET    /api/config/namespaces/{ns}/http_loadbalancers/{name}        → get HTTP LB (for patching)
PUT    /api/config/namespaces/{ns}/http_loadbalancers/{name}        → update HTTP LB
POST   /api/config/namespaces/shared/app_firewalls                  → create in shared namespace
...                                                                  → (same pattern for shared NS)
```

---

## Testing Strategy

### Unit Tests (pytest)

- **Parsers:** Parse known ASM XML/JSON exports → verify intermediate model fields
- **Translators:** Feed intermediate model → verify each XC JSON field mapping
- **Analysis:** Verify alarm-only detection, positive security counting, limit checking
- **Validators:** Verify OAS schema validation catches invalid output
- **Reporters:** Verify gap report content and structure
- **Decisions:** Verify decision application (exclude/enforce/defer) produces correct exclusion rules

### Integration Tests

- **Round-trip:** Parse → analyze → decide (bulk) → translate → validate against OAS
- **Edge cases:** Empty policies, policies with only positive security, policies with 1000+ signature overrides, policies that exceed XC limits
- **XC client:** Mock HTTP server (using `responses` library) verifying correct API calls, auth headers, error handling

### API Tests

- **Endpoint tests:** Each API endpoint with valid/invalid inputs
- **Session lifecycle:** Create → analyze → decide → translate → export → cleanup
- **Auth:** Token, P12, no-auth, invalid-auth scenarios

### Sample Policies Needed

| Type | Description |
|---|---|
| Rapid Deployment | Default template, minimal tuning |
| Mature (tuned) | 6+ months of policy builder, many alarm-only items |
| API-focused | Heavy parameter validation, JSON/XML profiles |
| Positive security heavy | Many URL/parameter entities, strict allowlisting |
| Minimal | Blocking mode, default signatures, no entities |

---

## Key Design Decisions

1. **Library-first architecture.** The conversion engine is a standalone Python package. The API and CLI are thin wrappers. This enables programmatic use, clean testing, and future interfaces without duplicating logic.

2. **API-first web design.** Every action in the web UI goes through the REST API. This ensures the full workflow is automatable and that the CLI, web UI, and direct API consumers all share the same behavior.

3. **Session-based workflow.** A conversion is stateful (upload → analyze → decide → translate). Sessions are in-memory with configurable TTL. No database.

4. **Alarm-only decisions are explicit.** The tool never silently drops or enforces alarm-only items. Every alarm-only signature and violation is surfaced as a decision point with clear options and implications.

5. **Gap report is a first-class output.** Not an afterthought — the gap report is as important as the XC JSON payloads. It's the documentation of what changed, what was lost, and what needs manual attention.

6. **Both namespace and shared namespace support.** XC objects can target a specific namespace or the shared namespace for org-wide policies.

7. **Container-level credential pre-configuration.** XC auth can be baked into the container deployment (env vars, K8s secrets, volume mounts) so users don't re-enter credentials per session. Default P12 path at `/certs/api-creds.p12`, default token file at `/secrets/api-token`. The UI adapts — hiding auth fields when credentials are pre-configured.

8. **Validation is advisory, not blocking.** Output that fails XC schema validation is still generated and returned. The user sees validation warnings and can adjust decisions to fix them.

## Scope Boundaries

### In Scope (v1)

- ASM XML export parsing (all BIG-IP versions)
- ASM Declarative JSON export parsing (v15.1+)
- XC `app_firewall` object generation
- XC `waf_exclusion_policy` object generation
- XC Service Policy generation (IP whitelist, geolocation, IP intelligence)
- XC HTTP LB patch generation (CSRF, Data Guard)
- Alarm-only decision workflow (interactive table in web UI, bulk flags + decisions file in CLI)
- Gap report generation (Markdown + JSON)
- XC API push (API token + P12 auth, namespace + shared namespace)
- Output validation against XC OAS schemas
- Web UI (React SPA, 4-view wizard)
- CLI (convert, analyze, validate, push, xc-status commands)
- Container (single Docker image, multi-stage build)
- K8s deployment support (secrets, volume mounts)

### Out of Scope (Future)

- NAP (NGINX App Protect) policy ingestion
- AS3 declaration ingestion
- Interactive CLI decision-making (TUI)
- Batch conversion of multiple policies in web UI
- Terraform output format
- vesctl command generation
- PDF report export
- Diff/comparison between two ASM policies
- ASM policy retrieval from live BIG-IP (only exported files)
- XC object update/merge with existing configs (always creates new)
