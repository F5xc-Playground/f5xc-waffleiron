# WaffleIron Translation Coverage Report

This document provides a detailed accounting of every AWAF policy feature, whether WaffleIron translates it, how it translates, and what gets lost or dropped.

---

## How to Read This Document

Each section covers a category of AWAF policy features. Features are classified as:

- **Full** — 1:1 translation with no loss of fidelity.
- **Partial** — Translates but with semantic differences, constraints, or loss of granularity.
- **Gated** — Translatable only when specific conditions are met (enforcement mode, violation status).
- **Gap (reported)** — Cannot translate. Appears in the gap report so the user knows.
- **Dropped** — Not parsed or not relevant to the XC translation.

---

## 1. Policy-Level Settings

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Policy name | All XC object `metadata.name` fields | Full | Sanitized to lowercase kebab-case, suffixed per object type (`-waf`, `-exc`, `-svc`) |
| Enforcement mode (blocking) | `spec.blocking: {}` | Full | |
| Enforcement mode (transparent) | `spec.monitoring: {}` | Full | |
| Character encoding | Preserved in intermediate model | Full | Passed through, not transformed |

---

## 2. Attack Signatures

### 2a. Signature Detection & Accuracy

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Signature accuracy: high only | `only_high_accuracy_signatures: {}` | Full | |
| Signature accuracy: high + medium | `high_medium_accuracy_signatures: {}` | Full | |
| Signature accuracy: all | `high_medium_low_accuracy_signatures: {}` | Full | |
| Signature staging (enabled) | `stage_new_and_updated_signatures: {staging_period: N}` | Full | Period in days preserved |
| Signature staging (disabled) | `disable_staging: {}` | Full | |
| Threat campaigns (enabled) | `enable_threat_campaigns: {}` | Full | |
| Threat campaigns (disabled) | `disable_threat_campaigns: {}` | Full | |
| Signature suppression | `enable_suppression: {}` | Full | Always enabled in XC output |

### 2b. Signature Sets

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Enabled signature sets | Default (no exclusion needed) | Full | |
| Disabled signature sets | `disabled_attack_types: [...]` | Full | Mapped via `ASM_SIG_SET_TO_XC_ATTACK_TYPE` |

**Mapped signature sets (30):**

| AWAF Signature Set | XC Attack Type |
|---|---|
| SQL Injection Signatures | ATTACK_TYPE_SQL_INJECTION |
| Cross Site Scripting Signatures | ATTACK_TYPE_CROSS_SITE_SCRIPTING |
| OS Command Injection Signatures | ATTACK_TYPE_COMMAND_EXECUTION |
| Path Traversal Signatures | ATTACK_TYPE_PATH_TRAVERSAL |
| XPath Injection Signatures | ATTACK_TYPE_XPATH_INJECTION |
| LDAP Injection Signatures | ATTACK_TYPE_LDAP_INJECTION |
| Server Side Code Injection Signatures | ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION |
| Buffer Overflow Signatures | ATTACK_TYPE_BUFFER_OVERFLOW |
| Information Leakage Signatures | ATTACK_TYPE_INFORMATION_LEAKAGE |
| Directory Indexing Signatures | ATTACK_TYPE_DIRECTORY_INDEXING |
| Remote File Include Signatures | ATTACK_TYPE_REMOTE_FILE_INCLUDE |
| Vulnerability Scanner Signatures | ATTACK_TYPE_VULNERABILITY_SCAN |
| Trojan/Backdoor/Spyware Signatures | ATTACK_TYPE_TROJAN_BACKDOOR_SPYWARE |
| Authentication/Authorization Attacks | ATTACK_TYPE_AUTHENTICATION_AUTHORIZATION_ATTACKS |
| Denial of Service Signatures | ATTACK_TYPE_DENIAL_OF_SERVICE |
| Predictable Resource Location | ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION |
| Abuse of Functionality Signatures | ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY |
| HTTP Response Splitting Signatures | ATTACK_TYPE_HTTP_RESPONSE_SPLITTING |
| Detection Evasion Signatures | ATTACK_TYPE_DETECTION_EVASION |
| Non-browser Client Signatures | ATTACK_TYPE_NON_BROWSER_CLIENT |
| Other Application Attacks | ATTACK_TYPE_OTHER_APPLICATION_ATTACKS |

*Signature sets not in this table produce no XC mapping and are silently omitted. The gap report does not currently flag unmapped signature sets.*

### 2c. Per-Signature Overrides

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Globally disabled signature (enabled=false) | WAF exclusion rule (signature context) | Full | One exclusion rule per disabled signature |
| Per-URL disabled signature | WAF exclusion rule with path prefix match | Full | Scoped to the URL path |
| Per-parameter disabled signature | WAF exclusion rule with parameter context | Full | Context: CONTEXT_PARAMETER |
| Per-cookie disabled signature | WAF exclusion rule with cookie context | Full | Context: CONTEXT_COOKIE |
| Alarm-only signature (enabled, alarm, !block) | **Requires user decision** | Partial | User chooses: enforce (block in XC), exclude (exclusion rule), or defer (XC defaults) |
| URL with `attack_signatures_check=false` | WAF skip-processing rule | Full | Entire path excluded from WAF processing |
| Parameter with `attack_signatures_check=false` | WAF exclusion rule | Full | Parameter excluded from signature checking |
| Cookie with `attack_signatures_check=false` | WAF exclusion rule | Full | Cookie excluded from signature checking |

**Key semantic difference:** AWAF supports alarm-only mode where a signature detects and logs without blocking. XC has no alarm-only mode — signatures either enforce (block) or must be excluded entirely. This is the most significant policy model difference and requires explicit user decisions during conversion.

### 2d. Custom Signatures

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Custom attack signatures (user-defined patterns) | None | Gap (reported) | XC WAF does not support custom signature patterns. Count and details appear in gap report. |

---

## 3. Violations

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Violation enabled (alarm + block) | Enabled in XC (default) | Full | No action needed |
| Violation disabled (alarm=false, block=false) | `disabled_violation_types: [...]` | Full | Mapped via `ASM_VIOLATION_TO_XC_VIOLATIONS` |
| Violation alarm-only (alarm=true, block=false) | **Requires user decision** | Partial | User chooses: enforce, disable, or defer |

**Mapped violations:**

| AWAF Violation | XC Violation(s) |
|---|---|
| VIOL_FILETYPE | VIOL_FILETYPE |
| VIOL_METHOD | VIOL_METHOD |
| VIOL_REQUEST_MAX_LENGTH | VIOL_REQUEST_MAX_LENGTH |
| VIOL_DATA_GUARD | VIOL_DATA_GUARD |
| VIOL_COOKIE_MODIFIED | VIOL_COOKIE_MODIFIED |
| VIOL_ASM_COOKIE_MODIFIED | VIOL_ASM_COOKIE_MODIFIED |
| VIOL_ENCODING | VIOL_ENCODING |
| VIOL_XML_FORMAT | VIOL_XML_MALFORMED |
| VIOL_JSON_FORMAT | VIOL_JSON_MALFORMED |
| VIOL_FILE_UPLOAD | VIOL_FILE_UPLOAD |
| VIOL_MANDATORY_HEADER | VIOL_MANDATORY_HEADER |
| VIOL_EVASION | 8 evasion subtypes (see below) |
| VIOL_HTTP_PROTOCOL | 10 HTTP protocol subtypes (see below) |

**VIOL_EVASION expands to:**
`VIOL_EVASION_DIRECTORY_TRAVERSALS`, `VIOL_EVASION_MULTIPLE_DECODING`, `VIOL_EVASION_APACHE_WHITESPACE`, `VIOL_EVASION_IIS_UNICODE_CODEPOINTS`, `VIOL_EVASION_IIS_BACKSLASHES`, `VIOL_EVASION_PERCENT_U_DECODING`, `VIOL_EVASION_BARE_BYTE_DECODING`, `VIOL_EVASION_BAD_UNESCAPE`

**VIOL_HTTP_PROTOCOL expands to:**
`VIOL_HTTP_PROTOCOL_MULTIPLE_HOST_HEADERS`, `VIOL_HTTP_PROTOCOL_BAD_HOST_HEADER_VALUE`, `VIOL_HTTP_PROTOCOL_UNPARSABLE_REQUEST_CONTENT`, `VIOL_HTTP_PROTOCOL_NULL_IN_BODY`, `VIOL_HTTP_PROTOCOL_BAD_HTTP_VERSION`, `VIOL_HTTP_PROTOCOL_CRLF_BEFORE_REQUEST_START`, `VIOL_HTTP_PROTOCOL_MISSING_HOST_HEADER`, `VIOL_HTTP_PROTOCOL_BAD_MULTIPART_PARSING`, `VIOL_HTTP_PROTOCOL_SEVERAL_CONTENT_LENGTH`, `VIOL_HTTP_PROTOCOL_NON_POSITIVE_CONTENT_LENGTH`

*Violations not in this table are silently ignored. The gap report does not currently flag unmapped violations.*

---

## 4. Positive Security (Entity Definitions)

AWAF positive security defines "what's allowed" — requests that violate these definitions trigger violations. XC has no positive security model, but some features can be approximated via service policy DENY rules.

### 4a. Translatable Positive Security

These features generate service policy DENY rules **only when both conditions are met**:
1. Policy enforcement mode is **blocking**
2. The relevant violation (VIOL_FILETYPE or VIOL_METHOD) is **not alarm-only** (block=true, or not present in the policy)

If either condition fails, the feature appears in the gap report as "gated" with an explanation.

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Disallowed file types (`allowed=false`) | Service policy DENY rule with path regex | Gated | Regex: `.*\.{ext}(\?.*)?$`. One rule per disallowed extension. |
| Global allowed methods list | Service policy DENY rule for disallowed methods | Gated | Denies all methods not in the allowlist. Compares against: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT. |
| Per-URL method restriction | Service policy DENY rule with path prefix + method match | Gated | One rule per URL with a method field. Wildcard URLs (`name="*"`) and wildcard methods (`method="*"`) are skipped. |

**Semantic difference:** AWAF routes file type and method violations through its violation enforcement pipeline (alarm/block). XC service policy DENY is a hard block — there is no "alarm-only DENY." This is why the rules are gated on enforcement mode and violation status: generating a hard-block rule for something that was only alarming in AWAF would change behavior.

### 4b. Untranslatable Positive Security

These features have no XC equivalent. They appear in the gap report.

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| URL entities (path definitions) | None | Gap (reported) | URL/wildcard URL count reported. No XC positive security URL model. |
| Parameter value type constraints | None | Gap (reported) | AWAF can enforce that a parameter is numeric, alpha, email, etc. XC cannot. Count of constrained parameters reported. |
| Cookie entities | None | Gap (reported) | Cookie count reported. |
| Mandatory header enforcement | None | Gap (reported) | Count of mandatory headers reported. |
| File type length limits (query string, URL, POST data, request) | None | Gap (reported) | File type entities are counted but length constraints have no XC mapping. |
| Parameter max length constraints | None | Dropped | Parsed into model but not translated or reported. |
| URL `is_allowed` flag | None | Dropped | Only relevant to AWAF positive security pipeline. |
| URL `metachars_on_url_check` | None | Dropped | No XC metacharacter checking equivalent. |
| URL `clickjacking_protection` | None | Dropped | No XC clickjacking protection equivalent. |

---

## 5. Network-Level Controls (Service Policy)

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| IP whitelist entries | Service policy ALLOW rules with `ip_prefix_list` | Full | Subnet mask converted to CIDR notation. One rule per IP entry. |
| Geolocation blocking | Service policy DENY rule with `client_selector` | Full | Country names mapped to ISO 3166-1 alpha-2 codes. All blocked countries in a single rule. 186 countries supported. |
| IP intelligence threat categories | Service policy DENY rules with `ip_threat_category_list` | Partial | One rule per category. Unmapped categories flagged in gap report. |

**Mapped IP intelligence categories (14):**

| AWAF Category | XC IPThreatCategory |
|---|---|
| botnets | BOTNETS |
| scanners | SCANNERS |
| spam_sources / spam-sources | SPAM_SOURCES |
| phishing | PHISHING |
| denial_of_service / denial-of-service | DENIAL_OF_SERVICE |
| windows_exploits / windows-exploits | WINDOWS_EXPLOITS |
| web_attacks / web-attacks | WEB_ATTACKS |
| proxy | PROXY |
| tor_proxy / tor-proxy | TOR_PROXY |
| mobile_threats / mobile-threats | MOBILE_THREATS |
| infected_sources / infected-sources | REPUTATION |

*Categories not in this table are flagged in the gap report with `IpIntelGap` entries.*

**Service policy rule ordering:** IP allows → geolocation denies → IP intel denies → file type denies → method denies.

---

## 6. Bot Protection

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Malicious bot → block | `malicious_bot_action: BLOCK` | Full | |
| Malicious bot → report | `malicious_bot_action: REPORT` | Full | |
| Benign bot → block/report/ignore | `good_bot_action: BLOCK/REPORT/IGNORE` | Full | |
| Unknown bot → block/report/ignore | `suspicious_bot_action: BLOCK/REPORT/IGNORE` | Full | |
| Bot category → challenge | None | Gap (reported) | XC WAF has no challenge action. Flagged in `bot_gaps`. |
| Bot category → captcha | None | Gap (reported) | XC WAF has no CAPTCHA action. Flagged in `bot_gaps`. |
| Bot category → rate-limit | None | Gap (reported) | XC WAF has no rate-limit bot action. Flagged in `bot_gaps`. |
| No bot defense configured | `default_bot_setting: {}` | Full | |

**XC recommendation:** When challenge/CAPTCHA gaps exist, the gap report recommends enabling **Bot Defense Advanced** in XC.

---

## 7. Blocking Page

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Custom blocking page HTML | `blocking_page.body_message` | Partial | HTML preserved, but template variables have limited support. |
| Response code mapping | `blocking_page.response_code` | Full | Maps: 200→OK, 400→BadRequest, 401→Unauthorized, 403→Forbidden, 404→NotFound. Others default to Forbidden. |
| Template variable `<%TS.request.ID()%>` | `{{request_id}}` | Full | The only mapped template variable. |
| Other template variables (e.g., `<%TS.request.uri()%>`) | None | Gap (reported) | Unsupported variables flagged in `blocking_page_gaps`. |
| Default blocking page | `use_default_blocking_page: {}` | Full | |

---

## 8. Data Protection

### 8a. Data Anonymization (Sensitive Parameters)

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Parameter marked `sensitive=true` | `custom_anonymization.anonymization_config[].query_parameter` | Full | Each sensitive parameter becomes an anonymization rule. |
| No sensitive parameters | `default_anonymization: {}` | Full | |

**Limit:** XC supports max 64 anonymization items. WaffleIron warns if the policy would exceed this.

### 8b. Data Guard

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Data Guard enabled | `http_lb_patch.data_guard.enabled: true` | Full | Output as HTTP LB patch (not pushable as standalone object). |
| Credit card masking | `http_lb_patch.data_guard.credit_cards` | Full | |
| SSN masking | `http_lb_patch.data_guard.ssn` | Full | |
| Custom patterns | `http_lb_patch.data_guard.custom_patterns` | Full | |
| Exception URLs | `http_lb_patch.data_guard.exception_urls` | Full | |

**Important:** Data Guard settings live on the XC HTTP Load Balancer, not on the WAF policy. The `http_lb_patch` output is a reference snippet that must be applied manually. It cannot be pushed via the API as a standalone object.

### 8c. CSRF Protection

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| CSRF enabled | `http_lb_patch.csrf.enabled: true` | Full | |
| CSRF URL list | `http_lb_patch.csrf.urls` | Full | |

**Same constraint as Data Guard:** CSRF settings live on the HTTP LB, not the WAF policy. Must be applied manually.

---

## 9. Features With No XC Equivalent

These AWAF features are parsed and reported in the gap analysis but cannot be translated.

| AWAF Feature | Gap Report Section | Recommendation |
|---|---|---|
| Custom attack signatures | Untranslatable → custom_signatures | Re-implement as XC custom rules or use API discovery |
| Session tracking | Untranslatable features | No XC equivalent. Flagged as "translated with loss." |
| Session hijacking prevention | Untranslatable features | No XC equivalent. Flagged as "translated with loss." |
| Brute force detection | Untranslatable features | Gap report recommends XC **Rate Limiter** feature. |

---

## 10. Response Codes

| AWAF Feature | XC Equivalent | Status | Notes |
|---|---|---|---|
| Allowed response codes list | `allowed_response_codes.response_code: [...]` | Full | |
| No response code filtering | `allow_all_response_codes: {}` | Full | |

**Limit:** XC supports max 48 allowed response codes. WaffleIron's validator enforces this.

---

## 11. XC Object Limits & Validation

WaffleIron validates generated XC objects against known API constraints before push.

### App Firewall Validation

| Constraint | Limit | Consequence |
|---|---|---|
| `metadata.name` length | 64 characters | Validation error |
| `metadata.namespace` | Required | Validation error |
| Blocking page body | 4,096 bytes (UTF-8) | Validation error |
| Custom anonymization items | 64 | Validation error |
| Allowed response codes | 48 | Validation error |
| Bot actions | Must be BLOCK, REPORT, or IGNORE | Validation error |
| Attack types | Must be in valid XC attack type set | Validation error |

### WAF Exclusion Policy Validation

| Constraint | Limit | Consequence |
|---|---|---|
| Total exclusion rules | 256 | Validation error; analysis warning if exceeded |
| Signature contexts per rule | 1,024 | Enforced by translator (chunked automatically) |
| Signature ID range | 0 or 200000001–299999999 | Validation error |
| Context values | Must be in valid XC context set | Validation error |

### Service Policy

Service policies are not validated locally — they are accepted or rejected by the XC API on push. The tool generates rules using the documented XC service policy schema (`prefix_values`, `regex_values`, `methods` arrays).

---

## 12. Exclusion Rule Generation Details

The WAF exclusion policy translator produces XC exclusion rules from multiple sources. Understanding how these rules are generated matters when estimating whether a policy will exceed XC limits.

| Source | Exclusion Rule Type | Count Contribution |
|---|---|---|
| Globally disabled signature (enabled=false) | Signature context, any path | 1 per disabled signature |
| Per-URL disabled signature | Signature context, path-scoped | 1 per override |
| Per-parameter disabled signature | Signature context, CONTEXT_PARAMETER | 1 per override |
| Per-cookie disabled signature | Signature context, CONTEXT_COOKIE | 1 per override |
| Alarm-only signature (decision=exclude) | Signature context, scope from decision | 1 per excluded signature |
| URL with `attack_signatures_check=false` | Skip-processing rule | 1 per URL |
| Parameter with `attack_signatures_check=false` | Skip-processing rule | 1 per parameter |
| Cookie with `attack_signatures_check=false` | Skip-processing rule | 1 per cookie |

**Deduplication:** Skip-processing rules for the same path are deduplicated. Signature exclusion rules are not deduplicated across scopes (a signature disabled globally AND on a specific URL produces two rules).

**Naming convention:** `excl-{scope}-sig-{sig_id}` for single signatures, `excl-{scope}-sig-{first_id}-plus-{N}` for grouped rules.

---

## 13. Decision Model

When the policy contains alarm-only items, WaffleIron requires explicit user decisions. The decisions can be provided via:
- Interactive web UI
- YAML file (CLI `--decisions` flag)
- API endpoint (`PUT /conversions/{id}/decisions`)
- Bulk flags (CLI `--alarm-only-signatures=enforce`)

### Signature Decisions

| Decision | Effect in XC | Behavioral Change vs AWAF |
|---|---|---|
| `enforce` | Signature blocks requests | **Stricter** — alarm-only → blocking |
| `exclude` | Exclusion rule added | Functionally similar — detection logs without blocking |
| `defer` | No rule created | Relies on XC default behavior for the signature |

### Violation Decisions

| Decision | Effect in XC | Behavioral Change vs AWAF |
|---|---|---|
| `enforce` | Violation remains enabled (blocking) | **Stricter** — alarm-only → blocking |
| `disable` | Violation added to `disabled_violation_types` | Removes detection entirely |
| `defer` | No rule created | Relies on XC default |

### Bot Decisions

| Decision | Effect in XC | Behavioral Change vs AWAF |
|---|---|---|
| `block` | `*_bot_action: BLOCK` | May differ from AWAF challenge/captcha behavior |
| `report` | `*_bot_action: REPORT` | Closest to alarm-only |
| `ignore` | `*_bot_action: IGNORE` | No protection |

---

## 14. Gap Report Contents

The gap report (Markdown or JSON) includes all of the following sections when applicable:

| Section | Contains |
|---|---|
| Summary | Total features, directly translated, translated with loss, decisions required, cannot translate |
| Alarm-Only Signatures | Each alarm-only signature with ID, description, scope, and user decision |
| Alarm-Only Violations | Each alarm-only violation and user decision |
| Positive Security — Translated | File type and method rules that were generated as service policy DENY rules |
| Positive Security — Gated | File type and method features that were NOT translated due to enforcement mode or violation status |
| Positive Security — Cannot Translate | URL entities, constrained parameters, cookies, mandatory headers (no XC equivalent) |
| Custom Signatures | Each custom signature with ID, name, pattern |
| Untranslatable Features | Session tracking, session hijacking, brute force status |
| Bot Protection Gaps | Bot categories with challenge/captcha/rate-limit actions |
| Warnings | Resource limit exceedances (exclusion rules > 256, anonymization > 64) |
| Manual Steps Required | CSRF and Data Guard settings that must be applied to the HTTP Load Balancer |
| XC Feature Recommendations | Suggested XC features based on gaps (Bot Defense Advanced, Rate Limiter, AI Risk-Based Blocking) |

---

## 15. Input Format Support

| Format | Source | Status |
|---|---|---|
| AWAF XML export (bigip_base.conf style) | BIG-IP GUI export, tmsh, iControl REST | Full |
| AWAF JSON export (Declarative WAF / AS3) | Declarative format, AS3 policy blobs | Full |
| Merged/parent-child policies | Multiple XML files | Not supported — each file processed independently |
| qkview / UCS archives | Support bundles | Not supported — extract the policy XML/JSON first |

**Detection:** The parser auto-detects XML vs JSON based on the first character of the file content (`<` for XML, `{` for JSON).

---

## 16. XC API Integration

| Operation | Supported | Notes |
|---|---|---|
| Create objects | Yes | POST to `/api/config/namespaces/{ns}/{resource}` |
| Update objects | Yes | PUT (replace) existing objects |
| Delete objects | Yes | Used for cleanup after push |
| List namespaces | Yes | GET `/api/web/namespaces` |
| Connection check | Yes | GET `/api/web/custom/namespaces/system/whoami` |
| Token authentication | Yes | `Authorization: APIToken {token}` header |
| P12 certificate authentication | Planned | Config parsing exists but client raises `NotImplementedError` |
| Rate limiting | Yes | Configurable RPS (default 2.0) |
| Retry on transient errors | Yes | 3 retries with backoff on 502/503/504 |
| Dry-run mode | Yes (CLI only) | Shows what would be pushed without making API calls |

**Pushable object types:** `app_firewall` (→ `app_firewalls`), `waf_exclusion_policy` (→ `waf_exclusion_policys`), `service_policy` (→ `service_policys`).

**Not pushable:** `http_lb_patch` — this is a reference snippet for manual application to an HTTP Load Balancer.
