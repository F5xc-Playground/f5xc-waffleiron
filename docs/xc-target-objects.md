# XC Target Objects — API Reference

The converter produces multiple XC API objects. This document details each object's schema, sourced from the F5 XC OpenAPI 3.0.0 specifications.

Full OAS specs are in `schemas/`:
- `xc-app-firewall.json` — `app_firewall` (58 schemas, 6 API paths)
- `xc-waf-exclusion-policy.json` — `waf_exclusion_policy` (40 schemas, 4 API paths)

## Object 1: `app_firewall`

**API path:** `POST /api/config/namespaces/{namespace}/app_firewalls`

The primary WAF policy object. Attached to an HTTP Load Balancer. One ASM policy produces one `app_firewall`.

### CreateSpecType Fields

The `app_firewallCreateSpecType` uses XC's oneof pattern — each group offers mutually exclusive choices.

#### Enforcement Mode (`enforcement_mode_choice`)

| Choice | Description |
|--------|-------------|
| `blocking` | Log and block violations |
| `monitoring` | Log only, do not block |

#### Detection Settings (`detection_setting_choice`)

| Choice | Description |
|--------|-------------|
| `default_detection_settings` | High + medium accuracy signatures, all violations, threat campaigns on, ML auto-tuning on |
| `detection_settings` | Custom `DetectionSetting` object (see below) |
| `ai_risk_based_blocking` | AI/ML risk assessment per request; configurable actions per risk level (high/medium/low) |

#### Blocking Page (`blocking_page_choice`)

| Choice | Description |
|--------|-------------|
| `use_default_blocking_page` | Standard F5 blocking page |
| `blocking_page` | Custom HTML (max 4096 bytes after base64, ~3070 plain text), supports `{{request_id}}` placeholder |

#### Bot Protection (`bot_protection_choice`)

| Choice | Description |
|--------|-------------|
| `default_bot_setting` | Default bot protection |
| `bot_protection_setting` | Custom per-category actions (see below) |

#### Response Codes (`allowed_response_codes_choice`)

| Choice | Description |
|--------|-------------|
| `allow_all_response_codes` | All response codes allowed |
| `allowed_response_codes` | Explicit list (100-999, max 48 items) |

#### Anonymization (`anonymization_setting`)

| Choice | Description |
|--------|-------------|
| `default_anonymization` | Default masking |
| `custom_anonymization` | Explicit list of headers, cookies, and query parameters to mask (max 64 items) |
| `disable_anonymization` | No masking |

### DetectionSetting (Custom Detection)

When `detection_settings` is chosen, this object provides granular control:

#### Signature Selection (`signature_selection_setting`)

**Accuracy level** (`signature_selection_by_accuracy`, oneof):

| Choice | ASM Equivalent |
|--------|----------------|
| `only_high_accuracy_signatures` | High Accuracy Signatures set only |
| `high_medium_accuracy_signatures` | High + Medium accuracy sets |
| `high_medium_low_accuracy_signatures` | All signature sets |

**Attack type control** (`attack_type_setting`, oneof):

| Choice | Description |
|--------|-------------|
| `default_attack_type_settings` | All 22 attack types enabled |
| `attack_type_settings` | Explicit list of disabled attack types (max 22) |

Available attack types (enum `app_firewallAttackType`):
```
ATTACK_TYPE_NON_BROWSER_CLIENT
ATTACK_TYPE_OTHER_APPLICATION_ATTACKS
ATTACK_TYPE_TROJAN_BACKDOOR_SPYWARE
ATTACK_TYPE_DETECTION_EVASION
ATTACK_TYPE_VULNERABILITY_SCAN
ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY
ATTACK_TYPE_AUTHENTICATION_AUTHORIZATION_ATTACKS
ATTACK_TYPE_BUFFER_OVERFLOW
ATTACK_TYPE_PREDICTABLE_RESOURCE_LOCATION
ATTACK_TYPE_INFORMATION_LEAKAGE
ATTACK_TYPE_DIRECTORY_INDEXING
ATTACK_TYPE_PATH_TRAVERSAL
ATTACK_TYPE_XPATH_INJECTION
ATTACK_TYPE_LDAP_INJECTION
ATTACK_TYPE_SERVER_SIDE_CODE_INJECTION
ATTACK_TYPE_COMMAND_EXECUTION
ATTACK_TYPE_SQL_INJECTION
ATTACK_TYPE_CROSS_SITE_SCRIPTING
ATTACK_TYPE_DENIAL_OF_SERVICE
ATTACK_TYPE_HTTP_PARSER_ATTACK
ATTACK_TYPE_SESSION_HIJACKING
ATTACK_TYPE_HTTP_RESPONSE_SPLITTING
ATTACK_TYPE_FORCEFUL_BROWSING
ATTACK_TYPE_REMOTE_FILE_INCLUDE
ATTACK_TYPE_MALICIOUS_FILE_UPLOAD
ATTACK_TYPE_GRAPHQL_PARSER_ATTACK
```

#### Violation Settings (`violation_detection_setting`, oneof)

| Choice | Description |
|--------|-------------|
| `default_violation_settings` | All violations enabled |
| `violation_settings` | Explicit list of disabled violations (max 40) |

Available violations (enum `app_firewallAppFirewallViolationType`):
```
VIOL_FILETYPE
VIOL_METHOD
VIOL_MANDATORY_HEADER
VIOL_HTTP_RESPONSE_STATUS
VIOL_REQUEST_MAX_LENGTH
VIOL_FILE_UPLOAD
VIOL_FILE_UPLOAD_IN_BODY
VIOL_XML_MALFORMED
VIOL_JSON_MALFORMED
VIOL_ASM_COOKIE_MODIFIED
VIOL_HTTP_PROTOCOL_MULTIPLE_HOST_HEADERS
VIOL_HTTP_PROTOCOL_BAD_HOST_HEADER_VALUE
VIOL_HTTP_PROTOCOL_UNPARSABLE_REQUEST_CONTENT
VIOL_HTTP_PROTOCOL_NULL_IN_REQUEST
VIOL_HTTP_PROTOCOL_BAD_HTTP_VERSION
VIOL_HTTP_PROTOCOL_CRLF_CHARACTERS_BEFORE_REQUEST_START
VIOL_HTTP_PROTOCOL_NO_HOST_HEADER_IN_HTTP_1_1_REQUEST
VIOL_HTTP_PROTOCOL_BAD_MULTIPART_PARAMETERS_PARSING
VIOL_HTTP_PROTOCOL_SEVERAL_CONTENT_LENGTH_HEADERS
VIOL_HTTP_PROTOCOL_CONTENT_LENGTH_SHOULD_BE_A_POSITIVE_NUMBER
VIOL_EVASION_DIRECTORY_TRAVERSALS
VIOL_MALFORMED_REQUEST
VIOL_EVASION_MULTIPLE_DECODING
VIOL_DATA_GUARD
VIOL_EVASION_APACHE_WHITESPACE
VIOL_COOKIE_MODIFIED
VIOL_EVASION_IIS_UNICODE_CODEPOINTS
VIOL_EVASION_IIS_BACKSLASHES
VIOL_EVASION_PERCENT_U_DECODING
VIOL_EVASION_BARE_BYTE_DECODING
VIOL_EVASION_BAD_UNESCAPE
VIOL_HTTP_PROTOCOL_BAD_MULTIPART_FORMDATA_REQUEST_PARSING
VIOL_HTTP_PROTOCOL_BODY_IN_GET_OR_HEAD_REQUEST
VIOL_HTTP_PROTOCOL_HIGH_ASCII_CHARACTERS_IN_HEADERS
VIOL_ENCODING
VIOL_COOKIE_MALFORMED
VIOL_GRAPHQL_FORMAT
VIOL_GRAPHQL_MALFORMED
VIOL_GRAPHQL_INTROSPECTION_QUERY
```

#### Signature Staging (`signatures_staging_settings`, oneof)

| Choice | Description |
|--------|-------------|
| `disable_staging` | No staging |
| `stage_new_signatures` | Stage only new signatures |
| `stage_new_and_updated_signatures` | Stage new and updated signatures |

Both staging options accept a `staging_period` (1-20 days, default 7).

#### Threat Campaigns (`threat_campaign_choice`, oneof)

| Choice | Description |
|--------|-------------|
| `enable_threat_campaigns` | Threat campaign signatures active |
| `disable_threat_campaigns` | Threat campaigns off |

#### False Positive Suppression (`false_positive_suppression`, oneof)

| Choice | Description |
|--------|-------------|
| `enable_suppression` | ML-based auto-suppression of likely false positives |
| `disable_suppression` | No auto-suppression |

### BotProtectionSetting

Per-category actions for WAF-level bot protection:

| Field | Type | Values |
|-------|------|--------|
| `malicious_bot_action` | `BotAction` enum | `BLOCK`, `REPORT`, `IGNORE` |
| `suspicious_bot_action` | `BotAction` enum | `BLOCK`, `REPORT`, `IGNORE` |
| `good_bot_action` | `BotAction` enum | `BLOCK`, `REPORT`, `IGNORE` |

### AnonymizationSetting

List of up to 64 items, each one of:

| Type | Field | Description |
|------|-------|-------------|
| `http_header` | `header_name` | Mask header value (not name) |
| `cookie` | `cookie_name` | Mask cookie value (max 256 chars) |
| `query_parameter` | `query_param_name` | Mask query param value (max 256 chars) |

---

## Object 2: `waf_exclusion_policy`

**API path:** `POST /api/config/namespaces/{namespace}/waf_exclusion_policys`

Contains an ordered list of exclusion rules (max 256). Attached to an HTTP Load Balancer separately from the `app_firewall`. This is where per-signature and per-path tuning lives.

### SimpleWafExclusionRule

Each rule specifies match conditions and what to exclude.

#### Match Conditions

**Domain** (`domain_choice`, oneof):

| Choice | Description |
|--------|-------------|
| `any_domain` | Match all domains |
| `exact_value` | Exact hostname match (max 256 chars) |
| `suffix_value` | Domain suffix match (e.g., `xyz.com` matches `*.xyz.com`) |

**Path** (`path_choice`, oneof):

| Choice | Description |
|--------|-------------|
| `any_path` | Match all paths |
| `path_prefix` | Path prefix match (max 256 chars) |
| `path_regex` | Path regex match (max 256 bytes) |

**Methods**: Array of HTTP methods (max 16).

**Expiration**: Optional RFC 3339 timestamp after which the rule is logically expired but remains in config.

**Metadata**: Name and description for the rule.

#### Exclusion Action (`waf_advanced_configuration`, oneof)

| Choice | Description |
|--------|-------------|
| `waf_skip_processing` | Skip WAF entirely for matched requests (no logging) |
| `app_firewall_detection_control` | Granular control over what to exclude (see below) |

### AppFirewallDetectionControl

Fine-grained exclusion by signature, attack type, violation, or bot name. Each exclusion is scoped by detection context.

#### Exclude Signature Contexts (max 1024)

| Field | Description |
|-------|-------------|
| `signature_id` | Signature ID (200000001-299999999, or 0 for all signatures) |
| `context` | Detection context (see below) |
| `context_name` | Name for PARAMETER/HEADER/COOKIE contexts (supports wildcard `*`) |

#### Exclude Attack Type Contexts (max 64)

| Field | Description |
|-------|-------------|
| `exclude_attack_type` | One of the 22 `AttackType` enum values |
| `context` | Detection context |
| `context_name` | Name for PARAMETER/HEADER/COOKIE contexts |

#### Exclude Violation Contexts (max 64)

| Field | Description |
|-------|-------------|
| `exclude_violation` | One of the 40 `AppFirewallViolationType` enum values |
| `context` | Detection context |
| `context_name` | Name for PARAMETER/HEADER/COOKIE contexts |

#### Exclude Bot Name Contexts (max 64)

| Field | Description |
|-------|-------------|
| `bot_name` | Bot name string (e.g., "Hydra") |

### Detection Context Enum

| Value | Description |
|-------|-------------|
| `CONTEXT_ANY` | All contexts |
| `CONTEXT_BODY` | Request body |
| `CONTEXT_REQUEST` | Entire request |
| `CONTEXT_RESPONSE` | Response |
| `CONTEXT_PARAMETER` | Parameters (name in `context_name`, empty = all params) |
| `CONTEXT_HEADER` | Headers (name in `context_name`, empty = all headers) |
| `CONTEXT_COOKIE` | Cookies (name in `context_name`, empty = all cookies) |
| `CONTEXT_URL` | Request URL |
| `CONTEXT_URI` | Request URI |

---

## Object 3: Service Policy (Supplementary)

**API path:** `POST /api/config/namespaces/{namespace}/service_policys`

Used for ASM features that don't map to `app_firewall` or exclusion rules:

| ASM Feature | Service Policy Rule |
|-------------|---------------------|
| IP whitelist/exceptions | IP allow rules |
| Geolocation enforcement | Geo filtering rules |
| IP intelligence categories | IP threat category rules |

Full OAS spec: `docs-cloud-f5-com.0208.public.ves.io.schema.service_policy.ves-swagger.json` (132 schemas).

---

## Object 4: HTTP Load Balancer Settings (Supplementary)

**API path:** `PUT /api/config/namespaces/{namespace}/http_loadbalancers/{name}`

Some ASM features map to HTTP LB configuration rather than standalone objects:

| ASM Feature | HTTP LB Setting |
|-------------|-----------------|
| CSRF protection | CSRF configuration (allowed origin domains) |
| Data Guard | Data Guard toggle and settings |
| Custom error pages | Direct response routes |

Full OAS spec: `docs-cloud-f5-com.0073.public.ves.io.schema.views.http_loadbalancer.ves-swagger.json` (388 schemas).
