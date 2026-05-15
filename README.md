# waffleiron

Convert BIG-IP ASM/Advanced WAF XML policy exports to F5 Distributed Cloud (XC) WAF configurations.

## Status

Research and design phase. See [docs/](docs/) for analysis and architecture.

## Problem

BIG-IP ASM policies cannot be directly imported into F5 XC WAF. The engines share signatures but use different policy models. Migration requires manual recreation of WAF configurations — error-prone and time-consuming for mature policies with extensive tuning.

## Approach

Parse ASM XML exports and produce XC API-ready JSON payloads:

- `app_firewall` — WAF policy (enforcement mode, signatures, violations, bot protection)
- `waf_exclusion_policy` — Per-signature/path exclusion rules (tuning)
- Service Policy — IP exceptions, geolocation, threat intel
- HTTP LB settings — CSRF, Data Guard
- Gap report — What can't translate and decisions required

## Key Constraints

1. **No alarm-only state in XC.** ASM supports per-signature "detect and log without blocking." XC exclusion rules are binary (exclude or enforce). The tool flags these for user decision.

2. **No positive security model in XC.** ASM URL/parameter/file-type entities with value validation have no XC equivalent. These appear in the gap report.

3. **Same engine, different model.** ASM and XC share ~8,000 attack signatures. The translation is about policy structure, not detection capability.

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/architecture.md](docs/architecture.md) | Tool architecture and processing pipeline |
| [docs/asm-xml-schema.md](docs/asm-xml-schema.md) | ASM XML export structure and field reference |
| [docs/xc-target-objects.md](docs/xc-target-objects.md) | XC API objects and schemas |
| [docs/field-mapping.md](docs/field-mapping.md) | Field-by-field translation rules |
| [docs/gaps-and-decisions.md](docs/gaps-and-decisions.md) | What can't translate and user decisions |
