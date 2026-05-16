# WaffleIron

Convert BIG-IP Advanced WAF (AWAF) policy exports to F5 Distributed Cloud (XC) WAF configurations.

## Overview

BIG-IP AWAF policies cannot be directly imported into F5 XC WAF. The engines share ~8,000 attack signatures but use different policy models. Migration requires manual recreation of WAF configurations — error-prone and time-consuming for mature policies with extensive tuning.

WaffleIron parses AWAF XML/JSON exports, analyzes what can and can't translate, guides the user through decisions, and produces XC API-ready JSON objects.

## Quick Start

```bash
docker compose up -d --build
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

To push objects directly to an XC tenant, set environment variables before starting:

```bash
export F5XC_TENANT_URL=https://your-tenant.console.ves.volterra.io
export F5XC_API_TOKEN=your-api-token
docker compose up -d --build
```

## Web UI Workflow

### 1. Upload

Upload an AWAF XML or JSON policy export. The policy is parsed and analyzed automatically.

### 2. Analysis

Review the analysis results:

- **Policy info** — name, enforcement mode, signature accuracy, and enabled features with color-coded translation status (green = fully translates, yellow = partially translates, red = no XC equivalent)
- **Summary** — counts of directly translated, translated-with-loss, decisions-required, and untranslatable items
- **Alarm-only decisions** — signatures and violations in alarm-only mode require a decision: enforce in XC, exclude from detection, or defer
- **Translated with loss** — features like session tracking and brute force that exist in AWAF and have related XC capabilities but can't be automatically migrated
- **Cannot translate** — custom signatures and bot defense actions with no XC equivalent

### 3. Export

Configure the output namespace and policy name, then generate XC objects:

- **Download JSON** — ZIP archive of all generated objects plus a gap report
- **Push to XC** — deploy objects directly to an XC tenant namespace

## Generated XC Objects

| Object | Contents |
|--------|----------|
| `app_firewall` | WAF policy: enforcement mode, signature sets, violations, bot protection, blocking page, data anonymization |
| `waf_exclusion_policy` | Per-signature/path exclusion rules from AWAF tuning and alarm-only decisions |
| `service_policy` | IP allow/deny lists, geolocation blocks, IP intelligence threat categories |
| `http_lb_patch` | CSRF and Data Guard settings (applied at the load balancer level) |

## Key Constraints

1. **No alarm-only in XC.** AWAF supports per-signature "detect and log without blocking." XC is binary — enforce or exclude. The tool flags alarm-only items for user decision.

2. **No positive security model in XC.** AWAF URL/parameter/file-type entities with value validation have no XC equivalent. These appear in the gap report.

3. **Same engine, different model.** The translation is about policy structure, not detection capability.

## Project Structure

```
waffleiron/          # Core Python library (parse, analyze, translate)
waffleiron-api/      # FastAPI backend
waffleiron-web/      # React + Vite frontend
waffleiron-cli/      # CLI interface (planned)
```

## Development

```bash
# Full rebuild (recommended after code changes)
make dev

# Run e2e tests
make test
```

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/architecture.md](docs/architecture.md) | Tool architecture and processing pipeline |
| [docs/asm-xml-schema.md](docs/asm-xml-schema.md) | AWAF XML export structure and field reference |
| [docs/xc-target-objects.md](docs/xc-target-objects.md) | XC API objects and schemas |
| [docs/field-mapping.md](docs/field-mapping.md) | Field-by-field translation rules |
| [docs/gaps-and-decisions.md](docs/gaps-and-decisions.md) | What can't translate and user decisions |
