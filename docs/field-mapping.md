# Field-by-Field ASM → XC Translation Rules

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Direct or near-direct translation |
| ⚠️ | Lossy translation — information or behavior is lost |
| ❌ | No translation possible — appears in gap report |
| ➡️ | Translates to a different XC object (not `app_firewall`) |

---

## 1. Policy-Level Settings

| ASM Field | XC Target | Mapping | Notes |
|-----------|-----------|---------|-------|
| `enforcement-mode: blocking` | `app_firewall.blocking` | ✅ | 1:1 |
| `enforcement-mode: transparent` | `app_firewall.monitoring` | ✅ | 1:1 |
| `encoding` | N/A | ❌ | XC handles encoding internally |
| `policy-builder.learning-mode` | N/A | ❌ | XC uses ML auto-tuning, not policy builder. Include in gap report as informational. |

---

## 2. Signature Configuration

| ASM Field | XC Target | Mapping | Notes |
|-----------|-----------|---------|-------|
| High Accuracy signature set enabled | `detection_settings.signature_selection_setting.only_high_accuracy_signatures` | ✅ | |
| High + Medium accuracy sets | `...high_medium_accuracy_signatures` | ✅ | Default |
| All accuracy sets | `...high_medium_low_accuracy_signatures` | ✅ | |
| Signature staging enabled | `detection_settings.stage_new_signatures` or `stage_new_and_updated_signatures` | ✅ | |
| Staging period (days) | `staging_period` (1-20) | ✅ | ASM default 7, XC range 1-20 |
| Signature staging disabled | `detection_settings.disable_staging` | ✅ | |
| Per-signature `enabled: false` (global) | `waf_exclusion_policy` rule: `any_domain` + `any_path` + signature ID | ✅ | Exclusion rule with wildcard scope |
| Per-signature `enabled: false` (per-URL) | `waf_exclusion_policy` rule: path + signature ID | ✅ | |
| Per-signature `enabled: false` (per-parameter) | `waf_exclusion_policy` rule: `CONTEXT_PARAMETER` + context name + signature ID | ✅ | |
| Per-signature `block: false, alarm: true` | **NO XC EQUIVALENT** | ⚠️ | **Critical gap.** See [gaps-and-decisions.md](gaps-and-decisions.md). Converter must flag and ask user to choose: exclude (lose visibility) or leave active (will block). |
| Per-signature `block: true` | Leave signature active (not in exclusion list) | ✅ | Default behavior in blocking mode |

---

## 3. Attack Type Configuration

| ASM Field | XC Target | Mapping | Notes |
|-----------|-----------|---------|-------|
| Signature set disabled by category (e.g., "SQL Injection Signatures" set removed) | `detection_settings.signature_selection_setting.attack_type_settings.disabled_attack_types[]` | ✅ | Map ASM signature set names to XC `AttackType` enum values |
| All signature sets enabled | `detection_settings.signature_selection_setting.default_attack_type_settings` | ✅ | |

### ASM Signature Set → XC Attack Type Mapping

| ASM Signature Set | XC `AttackType` Enum |
|-------------------|----------------------|
| SQL Injection Signatures | `ATTACK_TYPE_SQL_INJECTION` |
| Cross-Site Scripting Signatures | `ATTACK_TYPE_CROSS_SITE_SCRIPTING` |
| OS Command Injection Signatures | `ATTACK_TYPE_COMMAND_EXECUTION` |
| Path Traversal Signatures | `ATTACK_TYPE_PATH_TRAVERSAL` |
| XPath Injection Signatures | `ATTACK_TYPE_XPATH_INJECTION` |
| LDAP Injection Signatures | `ATTACK_TYPE_LDAP_INJECTION` |
| Server Side Code Injection | `ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION` |
| Buffer Overflow Signatures | `ATTACK_TYPE_BUFFER_OVERFLOW` |
| Information Leakage Signatures | `ATTACK_TYPE_INFORMATION_LEAKAGE` |
| Directory Indexing Signatures | `ATTACK_TYPE_DIRECTORY_INDEXING` |
| Remote File Include Signatures | `ATTACK_TYPE_REMOTE_FILE_INCLUDE` |
| Vulnerability Scanner Signatures | `ATTACK_TYPE_VULNERABILITY_SCAN` |
| Trojan/Backdoor/Spyware Signatures | `ATTACK_TYPE_TROJAN_BACKDOOR_SPYWARE` |
| Authentication/Authorization Signatures | `ATTACK_TYPE_AUTHENTICATION_AUTHORIZATION_ATTACKS` |
| Denial of Service Signatures | `ATTACK_TYPE_DENIAL_OF_SERVICE` |
| Predictable Resource Location | `ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION` |
| Abuse of Functionality | `ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY` |
| HTTP Response Splitting | `ATTACK_TYPE_HTTP_RESPONSE_SPLITTING` |
| Detection Evasion Signatures | `ATTACK_TYPE_DETECTION_EVASION` |
| Non-Browser Client Signatures | `ATTACK_TYPE_NON_BROWSER_CLIENT` |
| Other Application Attacks | `ATTACK_TYPE_OTHER_APPLICATION_ATTACKS` |

---

## 4. Violation Settings

| ASM Violation | XC Violation Enum | Mapping | Notes |
|---------------|-------------------|---------|-------|
| `VIOL_FILETYPE` | `VIOL_FILETYPE` | ✅ | |
| `VIOL_METHOD` | `VIOL_METHOD` | ✅ | |
| `VIOL_REQUEST_MAX_LENGTH` | `VIOL_REQUEST_MAX_LENGTH` | ✅ | |
| `VIOL_EVASION` | `VIOL_EVASION_DIRECTORY_TRAVERSALS`, `VIOL_EVASION_MULTIPLE_DECODING`, `VIOL_EVASION_APACHE_WHITESPACE`, `VIOL_EVASION_IIS_UNICODE_CODEPOINTS`, `VIOL_EVASION_IIS_BACKSLASHES`, `VIOL_EVASION_PERCENT_U_DECODING`, `VIOL_EVASION_BARE_BYTE_DECODING`, `VIOL_EVASION_BAD_UNESCAPE` | ⚠️ | ASM has one `VIOL_EVASION`; XC splits into 8 specific evasion sub-types. Converter should enable/disable all 8 together when translating ASM's single flag. |
| `VIOL_HTTP_PROTOCOL` | `VIOL_HTTP_PROTOCOL_*` (10 sub-types) | ⚠️ | Same split pattern — ASM has one flag, XC has 10 sub-types |
| `VIOL_DATA_GUARD` | `VIOL_DATA_GUARD` | ✅ | |
| `VIOL_COOKIE_MODIFIED` | `VIOL_COOKIE_MODIFIED` | ✅ | |
| `VIOL_ASM_COOKIE_MODIFIED` | `VIOL_ASM_COOKIE_MODIFIED` | ✅ | |
| `VIOL_ENCODING` | `VIOL_ENCODING` | ✅ | |
| `VIOL_XML_FORMAT` | `VIOL_XML_MALFORMED` | ✅ | Name difference |
| `VIOL_JSON_FORMAT` | `VIOL_JSON_MALFORMED` | ✅ | Name difference |
| `VIOL_FILE_UPLOAD` | `VIOL_FILE_UPLOAD` | ✅ | |
| `VIOL_MANDATORY_HEADER` | `VIOL_MANDATORY_HEADER` | ✅ | |
| `VIOL_ATTACK_SIGNATURE` | N/A | ✅ | Always active in XC when signatures are enabled; not a toggleable violation in XC |
| `VIOL_URL` | ❌ | ❌ | Positive security — no XC equivalent |
| `VIOL_PARAMETER` | ❌ | ❌ | Positive security — no XC equivalent |
| `VIOL_PARAMETER_DATA_TYPE` | ❌ | ❌ | Positive security |
| `VIOL_PARAMETER_EMPTY_VALUE` | ❌ | ❌ | Positive security |
| `VIOL_PARAMETER_VALUE_LENGTH` | ❌ | ❌ | Positive security |
| `VIOL_PARAMETER_NUMERIC_VALUE` | ❌ | ❌ | Positive security |
| `VIOL_COOKIE_EXPIRED` | ❌ | ❌ | No XC equivalent |
| `VIOL_COOKIE_LENGTH` | ❌ | ❌ | No XC equivalent |
| `VIOL_HEADER_LENGTH` | ❌ | ❌ | No XC equivalent |
| `VIOL_MANDATORY_PARAMETER` | ❌ | ❌ | Positive security |
| `VIOL_POST_DATA_LENGTH` | ❌ | ❌ | No XC equivalent |
| `VIOL_QUERY_STRING_LENGTH` | ❌ | ❌ | No XC equivalent |
| `VIOL_URL_LENGTH` | ❌ | ❌ | No XC equivalent |

### Violation Alarm-Only Translation Logic

For ASM violations with `alarm: true, block: false`:

```
IF the violation has a direct XC equivalent:
    Add to gap report as "alarm-only violation"
    User must choose:
        Option A: Add to disabled_violation_types (lose all visibility)
        Option B: Leave enabled (will block in blocking mode)
        Option C: Set app_firewall to monitoring mode (global, affects all violations)

IF the violation has no XC equivalent:
    Add to gap report as "untranslatable violation"
    No action needed (XC doesn't enforce it regardless)
```

---

## 5. Threat Campaigns

| ASM Field | XC Target | Mapping |
|-----------|-----------|---------|
| Threat campaigns enabled | `detection_settings.enable_threat_campaigns` | ✅ |
| Threat campaigns disabled | `detection_settings.disable_threat_campaigns` | ✅ |

Note: ASM and XC share the same threat campaign signature feed. No per-campaign granularity in either platform.

---

## 6. Bot Protection

| ASM Field | XC Target | Mapping | Notes |
|-----------|-----------|---------|-------|
| `malicious-bot { action block }` | `bot_protection_setting.malicious_bot_action: BLOCK` | ✅ | |
| `malicious-bot { action report }` | `...malicious_bot_action: REPORT` | ✅ | |
| `benign-bot { action report }` | `...good_bot_action: REPORT` | ✅ | Name difference: benign → good |
| `unknown-bot { action challenge }` | `...suspicious_bot_action: BLOCK` | ⚠️ | XC has no `challenge` action in basic bot protection; closest is `BLOCK`. Name difference: unknown → suspicious. |
| `action rate-limit` | ❌ | ❌ | No rate-limit action in XC basic bot protection |
| `action captcha` | ❌ | ❌ | No captcha action in XC basic bot protection |
| ASM bot `challenge` action | ❌ | ❌ | XC basic bot protection has BLOCK/REPORT/IGNORE only. XC Bot Defense Advanced (Shape) has JS challenge but is a separate product. |

---

## 7. Sensitive Data Masking

| ASM Field | XC Target | Mapping |
|-----------|-----------|---------|
| Parameter with `sensitiveParameter: true` | `app_firewall.custom_anonymization.anonymization_config[]` with `query_parameter` type | ✅ |
| Cookie with sensitive flag | `...anonymization_config[]` with `cookie` type | ✅ |
| Header with sensitive flag | `...anonymization_config[]` with `http_header` type | ✅ |

Limit: XC supports max 64 anonymization items.

---

## 8. Blocking Page

| ASM Field | XC Target | Mapping | Notes |
|-----------|-----------|---------|-------|
| Custom blocking page HTML | `app_firewall.blocking_page.blocking_page` | ✅ | Max 4096 bytes (base64), ~3070 plain text. Must use `{{request_id}}` placeholder (ASM uses `<%TS.request.ID()%>`). |
| Blocking page response code | `app_firewall.blocking_page.response_code` | ✅ | |
| Default blocking page | `app_firewall.use_default_blocking_page` | ✅ | |

### Blocking Page Template Variable Translation

| ASM Variable | XC Variable |
|-------------|-------------|
| `<%TS.request.ID()%>` | `{{request_id}}` |

---

## 9. IP Exceptions → Service Policy

| ASM Field | XC Target | Mapping |
|-----------|-----------|---------|
| `whitelist-ips` with `blockRequests: never` | ➡️ Service Policy: IP allow rule | ✅ |
| `whitelist-ips` with `ignoreIpReputation: true` | ➡️ Service Policy: IP allow rule (bypasses threat intel) | ⚠️ |
| `whitelist-ips` with `trustedByPolicyBuilder: true` | N/A | ❌ |
| `whitelist-ips` with `neverLogRequests: true` | N/A | ❌ |

---

## 10. Geolocation → Service Policy

| ASM Field | XC Target | Mapping |
|-----------|-----------|---------|
| `disallowed-geolocations` list | ➡️ Service Policy: geo deny rules | ✅ |

Country name mapping may be needed (ASM uses display names, XC uses country codes).

---

## 11. Features Landing on HTTP Load Balancer

| ASM Field | XC Target | Mapping | Notes |
|-----------|-----------|---------|-------|
| `csrf-protection.enabled` | ➡️ HTTP LB CSRF config | ✅ | Different attachment model |
| `data-guard.enabled` | ➡️ HTTP LB Data Guard | ⚠️ | XC has credit card / SSN masking; custom regex patterns may not translate |
| `data-guard.custom-patterns` | ➡️ HTTP LB Data Guard | ⚠️ | Check XC support for custom patterns |

---

## 12. Fully Untranslatable (Gap Report Only)

| ASM Feature | Why |
|-------------|-----|
| URL entities (positive security) | XC has no positive security model for URLs |
| Parameter entities (value types, length limits) | XC has no parameter validation |
| File type entities (allowed/disallowed, length limits) | XC has no file type allowlist |
| Cookie enforcement types | XC has no cookie enforcement model |
| Mandatory headers/parameters | XC has no mandatory entity enforcement |
| Session tracking / hijacking prevention | No XC equivalent |
| Brute force (session-aware) | XC Rate Limiter is partial (no session awareness) |
| Policy Builder / learning engine | XC uses ML auto-tuning (different paradigm) |
| Custom attack signatures | XC does not support custom signatures |
| `actAsMethod` on HTTP methods | No XC equivalent |
