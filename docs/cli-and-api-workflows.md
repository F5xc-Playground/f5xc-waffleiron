# CLI & API Workflow Guide

WaffleIron provides three interfaces: a web UI, a CLI, and a REST API. This document covers programmatic usage via CLI and API.

## Concepts

Every conversion follows the same logical steps regardless of interface:

1. **Parse** — ingest an AWAF XML or JSON export
2. **Analyze** — identify what translates, what doesn't, and what needs decisions
3. **Decide** — choose how to handle alarm-only signatures/violations (enforce, exclude, or defer)
4. **Translate** — produce XC API objects targeting a specific namespace
5. **Push** (optional) — deploy the objects to an XC tenant

The CLI operates statelessly (one-shot commands), while the API uses server-side sessions.

---

## CLI Workflows

### Prerequisites

```bash
pip install waffleiron-cli
```

Or run via Docker:

```bash
docker compose run --rm waffleiron <command>
```

### Workflow 1: Quick Convert (Non-Interactive)

For automation or when you want to defer all decisions:

```bash
waffleiron convert policy.xml \
  --namespace my-namespace \
  --output ./output \
  --alarm-only-signatures=enforce \
  --alarm-only-violations=enforce
```

This produces:
```
output/
├── app_firewall.json          # XC App Firewall object
├── waf_exclusion_policy.json  # XC WAF Exclusion Policy (if applicable)
├── service_policy.json        # XC Service Policy (if applicable)
├── http_lb_patch.json         # HTTP LB config snippet (if CSRF/DataGuard)
├── gap_report.md              # Markdown gap report
└── decisions.yaml             # Decisions record (for reproducibility)
```

### Workflow 2: Analyze → Edit Decisions → Convert (Recommended)

For mature policies where alarm-only items need individual review:

**Step 1: Analyze the policy**

```bash
waffleiron analyze policy.xml --output ./analysis
```

This produces:
```
analysis/
├── gap_report.md    # Human-readable gap/coverage report
├── gap_report.json  # Machine-readable analysis
└── decisions.yaml   # Template with all items set to "defer"
```

**Step 2: Edit the decisions file**

Open `analysis/decisions.yaml` and set actions for each item:

```yaml
alarm_only_signatures:
  - sig_id: 200003505
    description: "SQL Injection (parameterized)"
    scope: global
    decision: enforce      # enforce | exclude | defer

  - sig_id: 200004560
    description: "XSS in href attribute"
    scope: "/api/*"
    decision: exclude      # this one is a known false-positive

alarm_only_violations:
  - violation: VIOL_EVASION
    decision: enforce

bot_protection:
  - category: search_engine
    asm_action: alarm
    decision: report       # block | report | ignore
```

**Decision meanings:**

| Decision | Signatures | Violations | Effect |
|----------|-----------|------------|--------|
| `enforce` | Block in XC | Block in XC | Stricter than AWAF was |
| `exclude` | Add to exclusion policy | — | Maintains AWAF behavior (detect-only via exclusion) |
| `defer` | Skip (no rule created) | Skip | Relies on XC defaults |
| `disable` | — | Disable violation | Removes detection entirely |

**Step 3: Convert with decisions**

```bash
waffleiron convert policy.xml \
  --namespace my-namespace \
  --output ./output \
  --decisions ./analysis/decisions.yaml
```

You can also apply bulk overrides on top of a decisions file:

```bash
waffleiron convert policy.xml \
  --namespace my-namespace \
  --output ./output \
  --decisions ./analysis/decisions.yaml \
  --alarm-only-signatures=enforce
```

### Workflow 3: Validate → Push

After conversion, optionally validate and push to XC:

```bash
# Validate JSON against XC API constraints
waffleiron validate ./output

# Check XC connectivity
export F5XC_TENANT_URL=https://your-tenant.console.ves.volterra.io
export F5XC_API_TOKEN=your-token
waffleiron xc-status

# Push objects (reads namespace from the JSON metadata)
waffleiron push ./output

# Or override namespace at push time
waffleiron push ./output --namespace production-ns

# Dry run to see what would be pushed
waffleiron push ./output --dry-run
```

### XC Authentication

The CLI supports two authentication methods:

**API Token (recommended):**
```bash
export F5XC_TENANT_URL=https://tenant.console.ves.volterra.io
export F5XC_API_TOKEN=your-api-token

# Or pass directly:
waffleiron push ./output --tenant-url https://... --api-token your-token
```

**P12 Certificate:**
```bash
export F5XC_TENANT_URL=https://tenant.console.ves.volterra.io
export F5XC_P12_PATH=/path/to/api-creds.p12
export F5XC_P12_PASSWORD=password
```

---

## REST API Workflows

The API runs on port 8080 (Docker) or 8000 (local dev). All endpoints are prefixed with `/api/v1`.

### Session Lifecycle

The API is session-based. A conversion session tracks state through the pipeline:

```
POST /conversions          →  session created (status: "parsed")
GET  /conversions/{id}/analysis  →  analysis computed (lazy)
PUT  /conversions/{id}/decisions →  decisions recorded
POST /conversions/{id}/translate →  XC objects generated
POST /conversions/{id}/push      →  objects pushed to XC
```

Sessions expire after 1 hour (configurable via `SESSION_TTL` env var).

### Workflow: Full API Conversion (curl)

**Step 1: Upload a policy**

```bash
SESSION=$(curl -s -X POST http://localhost:8080/api/v1/conversions \
  -F "file=@policy.xml" | jq -r '.id')

echo "Session: $SESSION"
```

Response:
```json
{"id": "abc123", "status": "parsed", "policy_name": "my-policy"}
```

**Step 2: Get analysis**

```bash
curl -s http://localhost:8080/api/v1/conversions/$SESSION/analysis | jq .
```

Key response fields:
```json
{
  "policy_info": {
    "name": "my-policy",
    "enforcement_mode": "blocking",
    "features": { "data_guard": true, "csrf": false, ... }
  },
  "summary": {
    "total": 145,
    "directly_translated": 120,
    "decisions_required": 12,
    "cannot_translate": 13
  },
  "alarm_only_signatures": [
    {"sig_id": 200003505, "description": "SQL Injection", "scope": "global"}
  ],
  "alarm_only_violations": [
    {"violation_name": "VIOL_EVASION", "alarm": true, "block": false}
  ]
}
```

**Step 3: Submit decisions**

```bash
curl -s -X PUT http://localhost:8080/api/v1/conversions/$SESSION/decisions \
  -H "Content-Type: application/json" \
  -d '{
    "alarm_only_signatures": [
      {"sig_id": 200003505, "action": "enforce"},
      {"sig_id": 200004560, "action": "exclude"}
    ],
    "alarm_only_violations": [
      {"violation": "VIOL_EVASION", "action": "enforce"}
    ]
  }'
```

**Step 4: Translate**

```bash
curl -s -X POST http://localhost:8080/api/v1/conversions/$SESSION/translate \
  -H "Content-Type: application/json" \
  -d '{
    "namespace": "my-namespace",
    "name": "my-policy-xc"
  }'
```

Response:
```json
{
  "id": "abc123",
  "status": "translated",
  "outputs": {
    "app_firewall": { ... },
    "exclusion_policy": { ... },
    "service_policy": null,
    "http_lb_patch": null
  }
}
```

**Step 5: Download individual objects**

```bash
# List available object types
curl -s http://localhost:8080/api/v1/conversions/$SESSION/outputs | jq .

# Download specific object
curl -s http://localhost:8080/api/v1/conversions/$SESSION/outputs/app_firewall > app_firewall.json
```

**Step 6: Get gap report**

```bash
# JSON format
curl -s http://localhost:8080/api/v1/conversions/$SESSION/report \
  -H "Accept: application/json" > gap_report.json

# Markdown format
curl -s http://localhost:8080/api/v1/conversions/$SESSION/report \
  -H "Accept: text/markdown" > gap_report.md
```

**Step 7: Push to XC**

```bash
curl -s -X POST http://localhost:8080/api/v1/conversions/$SESSION/push \
  -H "Content-Type: application/json" \
  -d '{
    "objects": ["app_firewall", "waf_exclusion_policy", "service_policy"],
    "tenant_url": "https://tenant.console.ves.volterra.io",
    "api_token": "your-token"
  }'
```

Response:
```json
{
  "results": [
    {"object_type": "app_firewall", "success": true, "namespace": "my-namespace"},
    {"object_type": "waf_exclusion_policy", "success": true, "namespace": "my-namespace"},
    {"object_type": "service_policy", "success": false, "error": "not available"}
  ]
}
```

If XC credentials are configured as environment variables on the server, omit `tenant_url` and `api_token` from the push request.

**Step 8: Clean up**

```bash
curl -s -X DELETE http://localhost:8080/api/v1/conversions/$SESSION
```

### XC Connectivity Endpoints

```bash
# Check if server has XC credentials configured
curl -s http://localhost:8080/api/v1/xc/status

# Test connection with specific credentials
curl -s -X POST http://localhost:8080/api/v1/xc/connect \
  -H "Content-Type: application/json" \
  -d '{"tenant_url": "https://...", "api_token": "..."}'

# List available namespaces
curl -s "http://localhost:8080/api/v1/xc/namespaces?tenant_url=https://...&api_token=..."
```

---

## Automation / CI Pipeline

Example: convert all policies in a directory and push to XC.

```bash
#!/usr/bin/env bash
set -euo pipefail

POLICY_DIR="./policies"
OUTPUT_BASE="./xc-output"
NAMESPACE="production"

for policy in "$POLICY_DIR"/*.xml; do
  name=$(basename "$policy" .xml)
  output="$OUTPUT_BASE/$name"

  echo "Converting: $name"
  waffleiron convert "$policy" \
    --namespace "$NAMESPACE" \
    --output "$output" \
    --alarm-only-signatures=enforce \
    --alarm-only-violations=enforce

  echo "Validating: $name"
  waffleiron validate "$output"

  echo "Pushing: $name"
  waffleiron push "$output" --dry-run
done
```

For per-policy decisions in CI, store decisions YAML files alongside policies:

```
policies/
├── production-app.xml
├── production-app.decisions.yaml
├── staging-api.xml
└── staging-api.decisions.yaml
```

```bash
for policy in "$POLICY_DIR"/*.xml; do
  name=$(basename "$policy" .xml)
  decisions="$POLICY_DIR/$name.decisions.yaml"

  args=(convert "$policy" --namespace "$NAMESPACE" --output "$OUTPUT_BASE/$name")
  [[ -f "$decisions" ]] && args+=(--decisions "$decisions")

  waffleiron "${args[@]}"
done
```

---

## Object Types Reference

| Object Type | CLI Output File | API Key | XC API Resource | Pushable |
|------------|----------------|---------|-----------------|----------|
| App Firewall | `app_firewall.json` | `app_firewall` | `app_firewalls` | Yes |
| WAF Exclusion Policy | `waf_exclusion_policy.json` | `exclusion_policy` | `waf_exclusion_policys` | Yes |
| Service Policy | `service_policy.json` | `service_policy` | `service_policys` | Yes |
| HTTP LB Patch | `http_lb_patch.json` | `http_lb_patch` | — | No (reference) |

The HTTP LB patch contains CSRF and Data Guard configuration that must be applied at the HTTP Load Balancer level in XC. It cannot be pushed as a standalone object.

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `F5XC_TENANT_URL` | XC tenant console URL | — |
| `F5XC_API_TOKEN` | XC API token | — |
| `F5XC_API_TOKEN_FILE` | Path to file containing token | — |
| `F5XC_P12_PATH` | Path to P12 client certificate | `/certs/api-creds.p12` |
| `F5XC_P12_PASSWORD` | P12 certificate password | — |
| `SESSION_TTL` | API session expiry (seconds) | `3600` |
| `PORT` | API listen port | `8000` (Docker: `8080`) |
