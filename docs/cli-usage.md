# CLI Usage

The WaffleIron CLI provides stateless commands for converting, analyzing, validating, and pushing AWAF policies. Each command runs independently — there are no sessions or server dependencies (except `push` and `xc-status`, which call the XC API).

## Installation

```bash
pip install waffleiron-cli
```

Or run via Docker (no installation needed):

```bash
docker compose run --rm waffleiron waffleiron <command> [args]
```

## Commands

### convert

Parse an AWAF policy and produce XC WAF configuration files.

```bash
waffleiron convert <policy-file> --namespace <ns> --output <dir> [options]
```

| Option | Required | Description |
|--------|----------|-------------|
| `--namespace` | Yes | Target XC namespace for generated objects |
| `--output` | Yes | Output directory (created if needed) |
| `--alarm-only-signatures` | No | Bulk action: `enforce`, `exclude`, or `defer` (default: `defer`) |
| `--alarm-only-violations` | No | Bulk action: `enforce`, `disable`, or `defer` (default: `defer`) |
| `--decisions` | No | Path to a decisions YAML file (from `analyze`) |

**Output files:**

```
output/
├── app_firewall.json          # Always generated
├── waf_exclusion_policy.json  # If policy has tuning or alarm-only exclusions
├── service_policy.json        # If policy has IP lists, geo blocks, IP intel, file type denies, or method restrictions
├── http_lb_patch.json         # If policy uses CSRF or Data Guard (reference only — not pushable)
├── gap_report.md              # Markdown gap report
└── decisions.yaml             # Record of decisions applied (for reproducibility)
```

### analyze

Analyze a policy without converting. Produces gap reports and a decisions template.

```bash
waffleiron analyze <policy-file> --output <dir>
```

| Option | Required | Description |
|--------|----------|-------------|
| `--output` | Yes | Output directory |

**Output files:**

```
analysis/
├── gap_report.md    # Human-readable gap/coverage report
├── gap_report.json  # Machine-readable analysis data
└── decisions.yaml   # Template with all items set to "defer"
```

### validate

Validate generated XC JSON files against XC API constraints (field lengths, array limits, enum values).

```bash
waffleiron validate <output-dir>
```

Validates `app_firewall.json` and `waf_exclusion_policy.json` if present. Exits with code 1 on validation errors.

### push

Push generated XC configuration objects to an F5 XC tenant.

```bash
waffleiron push <output-dir> [options]
```

| Option | Required | Description |
|--------|----------|-------------|
| `--namespace` | No | Override namespace in pushed objects |
| `--shared` | No | Push to the `shared` namespace |
| `--tenant-url` | No | XC tenant URL (or set `F5XC_TENANT_URL`) |
| `--api-token` | No | XC API token (or set `F5XC_API_TOKEN`) |
| `--p12-path` | No | P12 certificate path (or set `F5XC_P12_PATH`) |
| `--p12-password` | No | P12 password (or set `F5XC_P12_PASSWORD`) |
| `--dry-run` | No | Show what would be pushed without pushing |

Pushes `app_firewall.json`, `waf_exclusion_policy.json`, and `service_policy.json` if they exist. `http_lb_patch.json` is skipped (it's a reference snippet, not a standalone XC object).

### xc-status

Check connectivity to an XC tenant and list available namespaces.

```bash
waffleiron xc-status [options]
```

| Option | Required | Description |
|--------|----------|-------------|
| `--tenant-url` | No | XC tenant URL (or set `F5XC_TENANT_URL`) |
| `--api-token` | No | XC API token (or set `F5XC_API_TOKEN`) |
| `--p12-path` | No | P12 certificate path |
| `--p12-password` | No | P12 password |

---

## Workflows

### Quick Convert (Non-Interactive)

For automation or when you want to apply the same action to all alarm-only items:

```bash
waffleiron convert policy.xml \
  --namespace production \
  --output ./output \
  --alarm-only-signatures=enforce \
  --alarm-only-violations=enforce
```

### Analyze → Edit Decisions → Convert (Recommended)

For mature policies where alarm-only items need individual review:

**1. Analyze the policy:**

```bash
waffleiron analyze policy.xml --output ./analysis
```

**2. Edit the decisions file:**

Open `analysis/decisions.yaml`. Each item defaults to `defer`. Set the action for each:

```yaml
alarm_only_signatures:
  - sig_id: 200003505
    description: "SQL Injection (parameterized)"
    scope: global
    decision: enforce      # enforce | exclude | defer

  - sig_id: 200004560
    description: "XSS in href attribute"
    scope: "/api/*"
    decision: exclude      # known false-positive — keep detecting but don't block

alarm_only_violations:
  - violation: VIOL_EVASION
    decision: enforce

bot_protection:
  - category: search_engine
    asm_action: alarm
    decision: report       # block | report | ignore
```

**Decision reference:**

| Decision | For Signatures | For Violations | Effect |
|----------|---------------|----------------|--------|
| `enforce` | Block in XC | Block in XC | Stricter than AWAF was (alarm → block) |
| `exclude` | Add exclusion rule | — | Preserves AWAF behavior (detect-only via exclusion) |
| `defer` | No rule created | No rule created | Rely on XC defaults |
| `disable` | — | Remove violation check | Removes detection entirely |

**3. Convert with decisions:**

```bash
waffleiron convert policy.xml \
  --namespace production \
  --output ./output \
  --decisions ./analysis/decisions.yaml
```

Bulk overrides can be layered on top of a decisions file:

```bash
waffleiron convert policy.xml \
  --namespace production \
  --output ./output \
  --decisions ./analysis/decisions.yaml \
  --alarm-only-signatures=enforce
```

### Validate → Push

```bash
waffleiron validate ./output
waffleiron xc-status
waffleiron push ./output --dry-run
waffleiron push ./output
```

---

## Automation / CI

Batch convert all policies in a directory:

```bash
#!/usr/bin/env bash
set -euo pipefail

POLICY_DIR="./policies"
OUTPUT_BASE="./xc-output"
NAMESPACE="production"

for policy in "$POLICY_DIR"/*.xml; do
  name=$(basename "$policy" .xml)
  output="$OUTPUT_BASE/$name"

  echo "=== $name ==="
  waffleiron convert "$policy" \
    --namespace "$NAMESPACE" \
    --output "$output" \
    --alarm-only-signatures=enforce \
    --alarm-only-violations=enforce

  waffleiron validate "$output"
  waffleiron push "$output" --dry-run
done
```

For per-policy decisions, store decisions YAML files alongside policies:

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

## XC Authentication

**API Token (recommended):**
```bash
export F5XC_TENANT_URL=https://tenant.console.ves.volterra.io
export F5XC_API_TOKEN=your-api-token
```

**P12 Certificate:**
```bash
export F5XC_TENANT_URL=https://tenant.console.ves.volterra.io
export F5XC_P12_PATH=/path/to/api-creds.p12
export F5XC_P12_PASSWORD=password
```

CLI flags (`--tenant-url`, `--api-token`) override environment variables.
