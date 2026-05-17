# WaffleIron

Convert BIG-IP Advanced WAF (AWAF) policies to F5 Distributed Cloud (XC) WAF configurations.

## The Problem

BIG-IP AWAF policies cannot be directly imported into F5 XC. Both platforms share the same ~8,000 attack signatures, but use fundamentally different policy models. Migrating a mature AWAF policy — with tuned signatures, alarm-only overrides, IP lists, custom exclusions, and entity-level settings — means manually recreating the WAF configuration in XC. For complex policies this is error-prone and time-consuming.

## What WaffleIron Does

WaffleIron parses AWAF XML or JSON policy exports, analyzes what can and can't translate to XC, guides the user through decisions where the platforms differ, and produces XC API-ready JSON objects that can be downloaded or pushed directly to a tenant.

### Translation Pipeline

```
AWAF Policy Export (XML/JSON)
  → Parse into intermediate model
  → Analyze gaps, limits, and decision points
  → User makes decisions on alarm-only items
  → Translate to XC API objects
  → Validate against XC constraints
  → Download JSON or push to XC tenant
```

### Generated XC Objects

| Object | What It Contains |
|--------|-----------------|
| **App Firewall** | Enforcement mode, signature sets, violation settings, bot protection, blocking page, data anonymization |
| **WAF Exclusion Policy** | Per-signature and per-path exclusion rules derived from AWAF tuning and alarm-only decisions |
| **Service Policy** | IP allow/deny lists, geolocation restrictions, IP intelligence threat categories |
| **HTTP LB Patch** | CSRF and Data Guard settings (reference snippet — applied at the HTTP Load Balancer level, not pushed as a standalone object) |

### Key Translation Constraints

- **No alarm-only in XC.** AWAF supports per-signature "detect and log without blocking." XC is binary — enforce or exclude. WaffleIron flags these for user decision.
- **No positive security model.** AWAF URL/parameter/file-type entities with value constraints have no XC equivalent. These appear in the gap report.
- **Same engine, different model.** The translation is about policy structure, not detection capability.

### Analysis & Gap Reporting

Every conversion produces a gap report (Markdown or JSON) covering:

- Alarm-only signatures and violations requiring decisions
- Positive security entities that can't translate
- Custom signatures without XC equivalents
- Bot defense actions not supported in XC (challenge, CAPTCHA, rate-limiting)
- Blocking page template variables without XC equivalents
- IP intelligence categories without XC equivalents
- Resource limit warnings (e.g., >256 exclusion rules, >64 anonymization rules)
- Recommendations for XC features to enable (Bot Defense Advanced, Rate Limiter, etc.)

## Interfaces

WaffleIron provides three interfaces. All follow the same pipeline: parse → analyze → decide → translate → export.

### Web UI

A guided wizard for interactive use. Upload a policy, review the analysis, make decisions on alarm-only items, configure the output namespace, then download JSON or push to XC.

```bash
docker compose up -d --build
# Open http://localhost:8080
```

### CLI

Stateless commands for scripting and automation.

```bash
# One-shot: convert with bulk decisions
waffleiron convert policy.xml \
  --namespace my-ns \
  --output ./output \
  --alarm-only-signatures=enforce

# Two-step: analyze first, then convert with reviewed decisions
waffleiron analyze policy.xml --output ./analysis
# Creates: analysis/gap_report.md, analysis/gap_report.json, analysis/decisions.yaml
# Review the gap report, then edit decisions.yaml to set actions per signature/violation
waffleiron convert policy.xml \
  --namespace my-ns \
  --output ./output \
  --decisions ./analysis/decisions.yaml

# Validate and push
waffleiron validate ./output
waffleiron push ./output --dry-run
waffleiron push ./output
```

See [docs/cli-usage.md](docs/cli-usage.md) for the full CLI reference.

### REST API

Session-based API for integration with other tools and custom workflows.

```bash
# Upload → analyze → decide → translate → download
SESSION=$(curl -s -X POST http://localhost:8080/api/v1/conversions \
  -F "file=@policy.xml" | jq -r '.id')

curl -s http://localhost:8080/api/v1/conversions/$SESSION/analysis | jq .summary
curl -s -X PUT http://localhost:8080/api/v1/conversions/$SESSION/decisions \
  -H "Content-Type: application/json" -d '{"alarm_only_signatures": [...]}'
curl -s -X POST http://localhost:8080/api/v1/conversions/$SESSION/translate \
  -H "Content-Type: application/json" -d '{"namespace": "my-ns"}'
curl -s http://localhost:8080/api/v1/conversions/$SESSION/outputs/app_firewall > app_firewall.json
```

See [docs/api-usage.md](docs/api-usage.md) for the full API reference.

## XC Authentication

All interfaces support two authentication methods:

**API Token (recommended):**
```bash
export F5XC_TENANT_URL=https://your-tenant.console.ves.volterra.io
export F5XC_API_TOKEN=your-api-token
```

**P12 Client Certificate:**
```bash
export F5XC_TENANT_URL=https://your-tenant.console.ves.volterra.io
export F5XC_P12_PATH=/path/to/api-creds.p12
export F5XC_P12_PASSWORD=password
```

For the web UI and API, credentials can also be provided per-request. For Kubernetes deployments, the API auto-discovers tokens from `/secrets/api-token` and certificates from `/certs/api-creds.p12`.

## Quick Start

### Docker (recommended)

```bash
docker compose up -d --build
```

Open [http://localhost:8080](http://localhost:8080) for the web UI. The CLI is also available inside the container:

```bash
docker compose run --rm waffleiron waffleiron convert /path/to/policy.xml \
  --namespace my-ns --output /tmp/output
```

### Local Development

```bash
make dev          # Build and start Docker container
make test         # Run Playwright E2E tests
make logs         # Stream container logs
make dev-down     # Stop container
```

## Project Structure

```
waffleiron/          # Core Python library (parse, analyze, translate, validate, report)
waffleiron-api/      # FastAPI REST API
waffleiron-cli/      # Typer CLI (convert, analyze, validate, push, xc-status)
waffleiron-web/      # React + Vite frontend
```

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `F5XC_TENANT_URL` | XC tenant console URL | — |
| `F5XC_API_TOKEN` | XC API token | — |
| `F5XC_API_TOKEN_FILE` | Path to file containing API token | — |
| `F5XC_P12_PATH` | Path to P12 client certificate | `/certs/api-creds.p12` |
| `F5XC_P12_PASSWORD` | P12 certificate password | — |
| `SESSION_TTL` | API session expiry in seconds | `3600` |
| `PORT` | API listen port | `8080` |
