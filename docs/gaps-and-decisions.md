# Gaps & User Decisions

This document catalogs every translation gap between ASM and XC WAF, categorized by severity and whether the converter can handle it automatically or needs user input.

## Critical Gap: The Alarm-Only State

### Problem

ASM supports three states per signature and per violation:

| State | alarm | block | Behavior |
|-------|:-----:|:-----:|----------|
| Full enforcement | ✓ | ✓ | Detect, log, block |
| **Alarm only** | **✓** | **✗** | **Detect, log, do NOT block** |
| Disabled | ✗ | ✗ | Skip entirely |

XC has two states:

| State | Behavior |
|-------|----------|
| Enabled | Detect, log, block (in blocking mode) |
| Excluded / Disabled | Skip entirely |

**There is no XC equivalent of "detect and log without blocking" at the individual signature or violation level.**

### Why This Matters

Mature ASM policies — especially those built by Policy Builder over weeks/months — accumulate large numbers of signatures and violations in alarm-only state. This represents the operator's tuning work: "I know this signature fires on legitimate traffic for this app, but I want to see it in logs, not block it."

A typical mature ASM policy might have:
- 200+ signatures globally in alarm-only
- 50+ per-URL/per-parameter signature overrides in alarm-only
- 10-15 violations in alarm-only

All of this tuning knowledge must be translated into a binary decision for XC.

### Converter Behavior

The converter MUST flag every alarm-only item and present the user with options:

**For each alarm-only signature:**
```
DECISION REQUIRED: Signature 200001234 (SQL Injection - UNION SELECT)
  ASM state: alarm only (detect + log, no block)
  Scope: Global (all URLs)

  Options:
  [A] EXCLUDE — Create exclusion rule. Signature will not fire at all.
                Risk: Lose visibility into this attack pattern.
  [B] ENFORCE — Leave signature active. Will BLOCK in blocking mode.
                Risk: May block legitimate traffic (this sig was alarm-only for a reason).
  [C] DEFER  — Include in gap report for manual review. No exclusion created.
```

**For each alarm-only violation:**
```
DECISION REQUIRED: VIOL_COOKIE_MODIFIED
  ASM state: alarm only
  XC equivalent: VIOL_COOKIE_MODIFIED

  Options:
  [A] DISABLE — Add to disabled_violation_types. No detection at all.
  [B] ENFORCE — Leave enabled. Will block in blocking mode.
  [C] DEFER  — Include in gap report for manual review.
```

### Bulk Decision Support

For policies with hundreds of alarm-only items, the converter should support bulk decisions:

- `--alarm-only-signatures=exclude` — Exclude all alarm-only signatures
- `--alarm-only-signatures=enforce` — Leave all alarm-only signatures active
- `--alarm-only-signatures=defer` — Flag all for manual review (default)
- `--alarm-only-violations=disable` — Disable all alarm-only violations
- `--alarm-only-violations=enforce` — Leave all alarm-only violations active

---

## Architectural Gap: Positive Security Model

### Problem

ASM's positive security model defines what IS allowed:
- Explicit URL entities with allowed methods, value constraints
- Parameter entities with data types, length limits, value patterns
- File type entities with size limits
- Cookie entities with enforcement types
- Header entities with mandatory flags

XC operates as a negative security model: block what's bad, allow everything else. There are no positive security entities.

### Impact

Policies that rely heavily on positive security (common in financial services, healthcare) lose significant protection surface. The converter cannot replicate:

- "Parameter `account_id` must be numeric, max 10 chars" → No XC equivalent
- "Only `/login`, `/api/*`, `/static/*` URLs are allowed" → No XC equivalent
- "Only `GET`, `POST` methods allowed on `/api/v1/users`" → Partial (service policy can do method filtering)
- "File uploads limited to `.pdf`, `.jpg` under 5MB" → No XC equivalent

### Converter Behavior

Include a **Positive Security Assessment** section in the gap report:

```
POSITIVE SECURITY ENTITIES (no XC equivalent)
  URLs: 47 explicit, 3 wildcard
  Parameters: 128 explicit (23 with value-type constraints), 5 wildcard
  File Types: 12 allowed, 8 with size limits
  Cookies: 15 explicit
  Headers: 4 mandatory

  These entities enforce application-specific input validation that XC
  cannot replicate. Consider supplementing XC WAF with:
  - API schema validation (XC API Definition + API Discovery)
  - Application-level input validation
  - Service Policy method/path restrictions
```

---

## Violation Mapping Gaps

### ASM Violations With No XC Equivalent

These violations exist only in ASM's positive security model:

| ASM Violation | Description | Why No XC Equivalent |
|---------------|-------------|----------------------|
| `VIOL_URL` | Request to URL not in allowed list | No URL allowlist in XC |
| `VIOL_PARAMETER` | Unknown parameter detected | No parameter allowlist in XC |
| `VIOL_PARAMETER_DATA_TYPE` | Parameter value wrong type | No parameter type validation |
| `VIOL_PARAMETER_EMPTY_VALUE` | Empty value not allowed | No empty value enforcement |
| `VIOL_PARAMETER_VALUE_LENGTH` | Value exceeds max length | No length enforcement |
| `VIOL_PARAMETER_NUMERIC_VALUE` | Numeric range violation | No numeric validation |
| `VIOL_PARAMETER_REPEATED` | Repeated parameter | No repeat detection |
| `VIOL_PARAMETER_STATIC_VALUE` | Static value violation | No static value enforcement |
| `VIOL_PARAMETER_LOCATION` | Parameter in wrong location | No location enforcement |
| `VIOL_MANDATORY_PARAMETER` | Required parameter missing | No mandatory params |
| `VIOL_MANDATORY_REQUEST_BODY` | Request body required | No body requirement |
| `VIOL_COOKIE_EXPIRED` | Cookie expired | No cookie expiry tracking |
| `VIOL_COOKIE_LENGTH` | Cookie exceeds length | No cookie length limit |
| `VIOL_HEADER_LENGTH` | Header exceeds length | No header length limit |
| `VIOL_POST_DATA_LENGTH` | POST body too large | No POST size limit (at WAF level) |
| `VIOL_QUERY_STRING_LENGTH` | Query string too long | No query string limit |
| `VIOL_URL_LENGTH` | URL too long | No URL length limit |
| `VIOL_URL_CONTENT_TYPE` | Wrong content type for URL | No per-URL content type enforcement |
| `VIOL_PARAMETER_VALUE_BASE64` | Base64 value violation | No base64 validation |
| `VIOL_PARAMETER_MULTIPART` | Multipart parameter violation | No multipart validation |

### ASM Violations That Split in XC

| ASM Violation | XC Violations | Notes |
|---------------|---------------|-------|
| `VIOL_EVASION` (single flag) | 8 specific `VIOL_EVASION_*` types | Converter should enable/disable all 8 together |
| `VIOL_HTTP_PROTOCOL` (single flag) | 10 specific `VIOL_HTTP_PROTOCOL_*` types | Converter should enable/disable all 10 together |

---

## Bot Protection Gaps

| ASM Capability | XC Status | Notes |
|----------------|-----------|-------|
| `challenge` action (JS challenge) | ❌ Not in basic bot protection | XC Bot Defense Advanced (Shape) has JS challenge, but it's a separate paid product |
| `captcha` action | ❌ Not in basic bot protection | |
| `rate-limit` action | ❌ Not in basic bot protection | XC has separate Rate Limiter, not per-bot-category |
| Per-bot-name actions | ❌ Limited | XC basic bot protection operates on 3 categories only (malicious/suspicious/good) |

### Converter Behavior

```
BOT DEFENSE TRANSLATION
  ASM bot profile: /Common/my_bot_profile

  Translated:
    malicious-bot: block → XC malicious_bot_action: BLOCK
    benign-bot: report → XC good_bot_action: REPORT

  Requires Decision:
    unknown-bot: challenge → XC suspicious_bot_action: ???
      [A] BLOCK — strictest available action
      [B] REPORT — log only
      [C] IGNORE — disable detection

  Cannot Translate:
    - rate-limit actions (use XC Rate Limiter separately)
    - captcha actions (not available in XC basic bot protection)
    - Per-bot-name overrides (XC uses 3 categories, not individual bots)
```

---

## Session and Stateful Features

| ASM Feature | XC Status | Alternative |
|-------------|-----------|-------------|
| Session tracking | ❌ | XC Malicious User Detection (different approach — ML-based behavioral scoring) |
| Session hijacking prevention | ❌ | None |
| Brute force (session-aware) | ⚠️ Partial | XC Rate Limiter (per-IP/cookie/header, no session awareness) |
| Login page enforcement | ⚠️ Partial | XC Rate Limiter can target specific paths |

---

## Custom Signatures

ASM supports user-defined attack signatures with custom regex patterns. XC does not support custom signatures.

### Converter Behavior

List all custom signatures in the gap report with their patterns:

```
CUSTOM SIGNATURES (no XC equivalent)
  Sig 300000001: "Custom SQL injection for legacy API"
    Pattern: /union\s+all\s+select.*from\s+users/i
    Applied to: /api/v1/legacy/*

  Sig 300000002: "Block internal header injection"
    Pattern: /X-Internal-Auth:\s*true/
    Applied to: Global

  These custom patterns must be enforced at the application layer
  or via XC Service Policy header matching (limited regex support).
```

---

## XC Capabilities Not in ASM

Features available in XC that the converter could recommend enabling:

| XC Feature | Description | Recommendation |
|------------|-------------|----------------|
| AI Risk-Based Blocking | ML-assessed risk per request | Consider for policies with heavy alarm-only tuning — AI can make per-request block/allow decisions that approximate ASM's alarm-only behavior |
| ML False Positive Suppression | Auto-suppress likely false positives | Enable by default — partially compensates for loss of ASM's per-signature tuning |
| API Discovery | Automatic API endpoint detection | Recommend for APIs — can discover and validate schemas, partially replacing positive security |
| Threat Campaigns | High-fidelity attack campaign signatures | Enable by default (near-zero FP) |
| Malicious User Detection | Per-user behavioral scoring | Recommend as partial replacement for session tracking |

---

## Gap Report Template

The converter should produce a structured gap report alongside the XC configuration:

```markdown
# ASM → XC Conversion Gap Report
Generated: <timestamp>
Source: <asm-policy-name>

## Summary
- Total ASM features assessed: N
- Directly translated: N (N%)
- Translated with loss: N (N%)
- Decisions required: N
- Cannot translate: N (N%)

## Decisions Required
### Alarm-Only Signatures (N items)
[list with options A/B/C for each]

### Alarm-Only Violations (N items)
[list with options]

### Bot Protection Actions (N items)
[list with options]

## Cannot Translate
### Positive Security Entities
[summary with counts and recommendations]

### Session/Stateful Features
[list]

### Custom Signatures
[list with patterns]

## XC Recommendations
[features to enable that partially compensate for gaps]
```
