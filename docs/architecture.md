# Conversion Tool — Architecture

## Overview

The tool reads a BIG-IP ASM XML policy export and produces:

1. **XC `app_firewall` object** — JSON payload ready for `POST /api/config/namespaces/{ns}/app_firewalls`
2. **XC `waf_exclusion_policy` object** — JSON payload for per-signature/per-path exclusions
3. **Supplementary configs** — Service Policy rules (IP exceptions, geo), HTTP LB settings (CSRF, Data Guard)
4. **Gap report** — Markdown document listing everything that can't translate and decisions the user must make

```
┌──────────────────┐
│  ASM XML Export   │
│  (policy.xml)     │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌─────────────────────┐
│   XML Parser     │────▶│  Intermediate Model  │
│                  │     │  (normalized ASM)     │
└──────────────────┘     └────────┬────────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
           ┌──────────────┐ ┌──────────┐ ┌──────────────┐
           │ app_firewall │ │ exclusion│ │ supplementary│
           │ translator   │ │ rule     │ │ translator   │
           │              │ │ builder  │ │ (svc policy, │
           │              │ │          │ │  HTTP LB)    │
           └──────┬───────┘ └────┬─────┘ └──────┬───────┘
                  │              │              │
                  ▼              ▼              ▼
           ┌──────────────┐ ┌──────────┐ ┌──────────────┐
           │ app_firewall │ │ waf_excl │ │ svc_policy   │
           │ .json        │ │ .json    │ │ .json        │
           └──────────────┘ └──────────┘ │ http_lb_     │
                                         │ patch.json   │
                  ┌──────────────┐       └──────────────┘
                  │  Gap Report  │
                  │  .md         │
                  └──────────────┘
```

## Processing Pipeline

### Phase 1: Parse ASM XML

Read the XML export and build a normalized intermediate model:

```
ASM Policy Model:
  enforcement_mode: blocking | transparent
  encoding: utf-8
  policy_builder:
    learning_mode: automatic | manual | disabled
  
  signatures:
    global_overrides: [{sig_id, enabled, alarm, block}]
    accuracy_level: high | high_medium | all
    staging_enabled: bool
    staging_period: int (days)
    threat_campaigns_enabled: bool
  
  signature_sets: [{name, enabled}]
  
  entities:
    urls: [{name, type, allowed, attack_sigs_check, sig_overrides, ...}]
    parameters: [{name, type, value_type, sensitive, level, sig_overrides, ...}]
    file_types: [{name, allowed, size_limits, ...}]
    cookies: [{name, type, enforcement, sig_overrides, ...}]
    headers: [{name, type, mandatory, check_sigs, ...}]
    methods: [{name, act_as}]
  
  violations: [{name, alarm, block}]
  
  whitelist_ips: [{ip, mask, block_requests, ...}]
  geolocation: {disallowed: [country_names]}
  
  csrf: {enabled, urls: [{url, method, token_param}]}
  data_guard: {enabled, credit_cards, ssn, custom_patterns, exception_urls}
  brute_force: {enabled, login_url, detection_period, max_attempts, ...}
  session_tracking: {enabled, hijacking_prevention, ...}
  
  bot_defense: {mode, categories: [{name, action}]}
  ip_intelligence: {categories: [{name, action}]}
  
  blocking_page: {custom_html, response_code}
  allowed_response_codes: [int]
  
  custom_signatures: [{id, name, pattern}]
```

### Phase 2: Translate to XC Objects

#### 2a: Build `app_firewall`

Direct field mapping from intermediate model:

- `enforcement_mode` → `blocking` / `monitoring`
- `signatures.accuracy_level` → `signature_selection_by_accuracy`
- `signature_sets` → `disabled_attack_types` (via set-to-attack-type mapping)
- `signatures.staging_*` → staging settings
- `signatures.threat_campaigns_enabled` → threat campaign choice
- Sensitive parameters/cookies/headers → anonymization config
- Bot defense categories → bot protection setting
- Blocking page → blocking page or default
- Allowed response codes → response code list

#### 2b: Build `waf_exclusion_policy`

For each ASM signature override or entity with `attackSignaturesCheck: false`:

1. Determine scope (domain, path, method)
2. Determine context (parameter, header, cookie, URL, any)
3. Build exclusion rule with `app_firewall_detection_control`

For ASM entities with `attackSignaturesCheck: false` (entire URL bypasses WAF):

1. Build exclusion rule with `waf_skip_processing`

#### 2c: Identify Alarm-Only Items

Scan all violations and signature overrides for `alarm: true, block: false`:

1. Collect into decisions list
2. Apply bulk decision flags if provided
3. Otherwise flag for user review

#### 2d: Build Supplementary Configs

- IP whitelist → Service Policy allow rules
- Geolocation → Service Policy geo deny rules
- IP intelligence → Service Policy threat intel rules
- CSRF → HTTP LB CSRF settings
- Data Guard → HTTP LB Data Guard settings

#### 2e: Build Gap Report

Collect all untranslatable features:

- Positive security entities (with counts and details)
- Alarm-only items (with decision options)
- Session tracking / brute force
- Custom signatures (with patterns)
- Bot actions without XC equivalent
- Recommendations for XC features to enable

### Phase 3: Output

Write all files to output directory:

```
output/
├── app_firewall.json              # POST to /api/config/namespaces/{ns}/app_firewalls
├── waf_exclusion_policy.json      # POST to /api/config/namespaces/{ns}/waf_exclusion_policys
├── service_policy.json            # POST to /api/config/namespaces/{ns}/service_policys (if needed)
├── http_lb_patch.json             # Fields to set on the HTTP LB (CSRF, Data Guard)
├── gap_report.md                  # Human-readable gap analysis
└── decisions.yaml                 # Machine-readable decisions file (for re-runs)
```

## CLI Interface (Proposed)

```bash
# Basic conversion
asm-to-xc convert policy.xml --namespace my-ns --output ./output/

# With bulk alarm-only decisions
asm-to-xc convert policy.xml \
  --namespace my-ns \
  --alarm-only-signatures=exclude \
  --alarm-only-violations=disable

# With a decisions file from a previous run
asm-to-xc convert policy.xml \
  --namespace my-ns \
  --decisions decisions.yaml

# Dry run (gap report only, no XC configs)
asm-to-xc analyze policy.xml

# Validate output against XC API schemas
asm-to-xc validate ./output/
```

## Validation

The converter should validate output against the XC OpenAPI specs:

- All enum values are valid
- All array lengths within limits (e.g., max 1024 signature exclusions, max 256 exclusion rules, max 64 anonymization items)
- Required fields are present
- String lengths within bounds (e.g., blocking page max 4096 bytes)
- Signature IDs in valid range (200000001-299999999 or 0)

## Testing Strategy

### Unit Tests

- Parse known ASM XML exports (need sample policies)
- Verify each field mapping produces correct XC JSON
- Verify alarm-only detection and decision logic
- Verify gap report completeness

### Integration Tests

- Round-trip: parse → translate → validate against OAS
- Compare output against manually-created XC policies
- Test with edge cases (empty policies, policies with only positive security, policies with 1000+ signature overrides)

### Sample Policies Needed

| Type | Description |
|------|-------------|
| Rapid Deployment | Default template, minimal tuning |
| Mature (tuned) | 6+ months of policy builder, many alarm-only items |
| API-focused | Heavy parameter validation, JSON/XML profiles |
| Positive security heavy | Many URL/parameter entities, strict allowlisting |
| Minimal | Blocking mode, default signatures, no entities |
