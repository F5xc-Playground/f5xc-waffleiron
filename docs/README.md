# ASM-to-XC Policy Conversion — Research & Analysis

Reference documentation for building an automated tool that translates BIG-IP ASM/Advanced WAF XML policy exports into F5 Distributed Cloud (XC) WAF configurations.

## Contents

| Document | Purpose |
|----------|---------|
| [architecture.md](architecture.md) | High-level architecture of the conversion tool |
| [asm-xml-schema.md](asm-xml-schema.md) | ASM XML policy export structure and field reference |
| [xc-target-objects.md](xc-target-objects.md) | XC API objects the converter produces |
| [field-mapping.md](field-mapping.md) | Field-by-field ASM → XC translation rules |
| [gaps-and-decisions.md](gaps-and-decisions.md) | What can't translate, and the decisions users must make |
| [schemas/](schemas/) | Raw OpenAPI specs for XC target objects |

## Key Findings

1. **ASM policies are stored in MySQL, not bigip.conf.** Full policy data requires an explicit XML or JSON export. QKView captures metadata only.

2. **XC uses the same WAF engine as ASM** but with a different policy model. Shared signatures (~8,000), but not shared policy format. No direct import path exists.

3. **The conversion produces multiple XC objects**, not a single policy. An ASM policy maps to an `app_firewall` + `waf_exclusion_policy` + Service Policy rules + HTTP LB settings.

4. **The critical gap is the alarm-only state.** ASM supports per-signature `block: false, alarm: true` (detect and log without blocking). XC exclusion rules are binary: exclude entirely or leave active (blocks in blocking mode). There is no per-signature "warn" in XC.

5. **ASM's positive security model has no XC equivalent.** URL/parameter/file-type entities with value-type enforcement, length limits, and per-entity staging exist only in ASM. XC operates as a negative security model with exclusion-based tuning.

## Source Material

- ASM/WAF research: `claus-docs/Research/tmshDSL/asm-waf/`
- XC WAF/WAAP research: `claus-docs/Research/f5-xc/collateral/03-waf-and-waap.md`
- XC migration mapping: `claus-docs/Research/tmshDSL/reference/xc-migration.md`
- XC OpenAPI specs: `claus-docs/Research/f5-xc/oas/`
- XC API docs: https://docs.cloud.f5.com/docs-v2/api
