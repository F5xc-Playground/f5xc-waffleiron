# ASM XML Policy Export — Structure & Field Reference

## Overview

ASM policies are stored in a MySQL database on BIG-IP (`/var/lib/mysql/f5#_asm/`). They are **not** in `bigip.conf` — only a thin reference appears there. Full policy data must be explicitly exported as XML or JSON.

### Export Formats

| Format | Method | Use Case |
|--------|--------|----------|
| **XML** | GUI or `tmsh save asm policy <name> xml-file <path>` | Full backup, migration, assessment |
| **JSON (Declarative)** | `tmsh save asm policy <name> json-file <path>` (v15.1+) | Automation, CI/CD, NAP compatibility |
| **Compact XML** | GUI export option | Without learning suggestions/history |

The converter targets the **XML export** format, as it is the most widely available (all BIG-IP versions) and contains the complete policy definition.

### Export Command

```bash
tmsh save asm policy /Common/my_policy xml-file /var/tmp/my_policy.xml
tmsh save asm policy /Common/my_policy xml-file /var/tmp/my_policy.xml compact  # without learning data
```

## Top-Level Policy Properties

### Enforcement Mode

The single most critical field. Determines whether the policy can block requests.

| Mode | TMSH Value | Behavior |
|------|------------|----------|
| **Blocking** | `enforcement-mode blocking` | Violations matching block settings result in request rejection |
| **Transparent** | `enforcement-mode transparent` | All violations are logged only; no requests are ever blocked |

**Important nuance:** Even in blocking mode, individual violations can be set to alarm-only. A policy in blocking mode with all violations set to alarm-only effectively behaves like transparent mode. Entities in staging are also alarm-only regardless of policy mode.

### Policy Builder Settings

```
policy-builder {
    learning-mode automatic|manual|disabled
    learning-speed slow|medium|fast
    trusted-traffic-stats-minimum-requests <number>
}
```

| Setting | Description |
|---------|-------------|
| `automatic` | Actively adds/modifies entities based on traffic patterns |
| `manual` | Generates suggestions but does not auto-apply them |
| `disabled` | No learning occurs |

### Encoding

```
encoding utf-8
```

## Entities (Positive Security Model)

Entities are the building blocks of ASM's positive security model. Each entity type has explicit (manually defined), wildcard, and learned states.

### URLs

| Property | Description | Converter Relevance |
|----------|-------------|---------------------|
| `name` | URL path (e.g., `/login`, `/api/*`) | Used for exclusion rule path matching |
| `protocol` | `http` or `https` | N/A for XC (protocol handled at LB level) |
| `type` | `explicit` or `wildcard` | Determines exclusion rule path type (prefix vs regex) |
| `method` | Allowed HTTP methods | Maps to exclusion rule method filter |
| `isAllowed` | Whether URL is allowed | Disallowed URLs have no XC equivalent |
| `attackSignaturesCheck` | Whether signatures are checked | If false, maps to `waf_skip_processing` exclusion |
| `metacharsOnUrlCheck` | Metacharacter checks | No direct XC equivalent |
| `clickjackingProtection` | Clickjacking headers | Handled separately in XC (HTTP LB response headers) |
| `performStaging` | Subject to staging | Informational only (no per-URL staging in XC) |
| `signatureOverrides` | Per-URL signature exceptions | Maps to exclusion rule with path + signature ID |

### Parameters

| Property | Description | Converter Relevance |
|----------|-------------|---------------------|
| `name` | Parameter name | Used for exclusion rule context name |
| `type` | `explicit` or `wildcard` | Determines wildcard matching in context name |
| `valueType` | `alpha`, `numeric`, `alphanumeric`, `auto-detect`, `binary`, `email`, `phone`, `user-input` | **No XC equivalent** — positive security gap |
| `level` | `url` (specific URL) or `global` (all URLs) | Affects exclusion rule path scope |
| `dataType` | Expected data type for validation | **No XC equivalent** |
| `sensitiveParameter` | If true, value is masked in logs | Maps to XC anonymization config |
| `parameterLocation` | `any`, `form-data`, `query-string`, `header`, `cookie`, `path` | Partial map to XC detection context |
| `allowEmptyValue` | Whether empty values are permitted | **No XC equivalent** |
| `checkMaxValueLength` / `maximumLength` | Length enforcement | **No XC equivalent** |
| `performStaging` | Subject to staging | Informational only |
| `attackSignaturesCheck` | Whether signatures check this parameter | If false, maps to exclusion rule |
| `signatureOverrides` | Per-parameter signature exceptions | Maps to exclusion rule with context + signature ID |

### File Types

| Property | Description | Converter Relevance |
|----------|-------------|---------------------|
| `name` | File extension (e.g., `php`, `html`, `jpg`) | Partial map to exclusion rule path regex |
| `allowed` | Whether file type is permitted | **No XC equivalent** (negative security only) |
| `responseCheck` | Inspect responses for this type | **No XC equivalent** |
| `queryStringLength` | Max query string length | **No XC equivalent** |
| `urlLength` | Max URL length | **No XC equivalent** |
| `postDataLength` | Max POST body length | **No XC equivalent** |
| `requestLength` | Max total request length | **No XC equivalent** |

### Cookies

| Property | Description | Converter Relevance |
|----------|-------------|---------------------|
| `name` | Cookie name | Used for exclusion rule context name |
| `type` | `explicit` or `wildcard` | Determines wildcard matching |
| `enforcementType` | `allow` or `enforce` | **No XC equivalent** |
| `attackSignaturesCheck` | Whether signatures check cookie values | Maps to exclusion rule with cookie context |
| `signatureOverrides` | Per-cookie signature exceptions | Maps to exclusion rule with context + signature ID |

### Headers

| Property | Description | Converter Relevance |
|----------|-------------|---------------------|
| `name` | Header name | Used for exclusion rule context name |
| `type` | `explicit` or `wildcard` | Determines wildcard matching |
| `mandatory` | If true, header must be present | **No XC equivalent** |
| `checkSignatures` | Whether attack signatures check this header | Maps to exclusion rule with header context |

### Methods

| Property | Description | Converter Relevance |
|----------|-------------|---------------------|
| `name` | HTTP method (GET, POST, PUT, etc.) | Maps to exclusion rule method filter |
| `actAsMethod` | Which method this acts as for enforcement | **No XC equivalent** |

## Violations

Each violation type has independent `alarm` and `block` flags. This is the core of the alarm-only gap.

### Key Violations (Rapid Deployment Template Defaults)

| Violation | Default Alarm | Default Block | XC Equivalent |
|-----------|:---:|:---:|---|
| `VIOL_ATTACK_SIGNATURE` | Yes | Yes | XC `app_firewall` signature detection |
| `VIOL_EVASION` | Yes | Yes | XC `VIOL_EVASION_*` violations |
| `VIOL_FILETYPE` | Yes | Yes | XC `VIOL_FILETYPE` |
| `VIOL_HTTP_PROTOCOL` | Yes | Yes | XC `VIOL_HTTP_PROTOCOL_*` violations |
| `VIOL_METHOD` | Yes | Yes | XC `VIOL_METHOD` |
| `VIOL_REQUEST_MAX_LENGTH` | Yes | Yes | XC `VIOL_REQUEST_MAX_LENGTH` |
| `VIOL_URL` | Yes | Yes | **No XC equivalent** (positive security) |
| `VIOL_PARAMETER` | Yes | No | **No XC equivalent** (positive security) |
| `VIOL_COOKIE_MODIFIED` | Yes | No | XC `VIOL_COOKIE_MODIFIED` |
| `VIOL_DATA_GUARD` | Yes | No | XC `VIOL_DATA_GUARD` |
| `VIOL_ENCODING` | Yes | No | XC `VIOL_ENCODING` |
| `VIOL_XML_FORMAT` | Yes | No | XC `VIOL_XML_MALFORMED` |
| `VIOL_JSON_FORMAT` | Yes | No | XC `VIOL_JSON_MALFORMED` |

### The Alarm-Only Gap

ASM violations have three effective states:

| State | `alarm` | `block` | Behavior |
|-------|:---:|:---:|----------|
| Full enforcement | true | true | Detect, log, and block |
| Alarm only | true | false | Detect and log, do not block |
| Disabled | false | false | Skip entirely |

XC violations have two states:

| State | Behavior |
|-------|----------|
| Enabled (not in `disabled_violation_types`) | Detect and block (in blocking mode) |
| Disabled (in `disabled_violation_types`) | Skip entirely |

**There is no XC equivalent of alarm-only.** This is the most significant translation gap for mature ASM policies, which typically have many violations and signatures in alarm-only state as a result of tuning.

## Whitelist / Exception Rules

### IP Address Exceptions

```
whitelist-ips {
    <ip> {
        ipAddress <ip>
        ipMask <mask>
        blockRequests never|policy-default
        neverLogRequests true|false
        trustedByPolicyBuilder true|false
        ignoreAnomalies true|false
        ignoreIpReputation true|false
    }
}
```

Maps to XC Service Policy IP allow/deny rules.

### Signature Exceptions (Per-Entity)

```
url /api/v1/data {
    signatureOverrides {
        200001234 { enabled false }
    }
}

parameter my_param {
    signatureOverrides {
        200001234 { enabled false }
    }
}
```

Maps to XC WAF exclusion rules with path/context + signature ID.

## Other Policy Components

### CSRF Protection

```
csrf-protection {
    enabled true|false
    csrf-urls {
        /sensitive-form {
            method POST
            enforcement-action verify-csrf-token
            url /sensitive-form
            requiredParameters { csrf_token }
        }
    }
}
```

Maps to XC HTTP LB CSRF settings (different attachment model).

### Data Guard

```
data-guard {
    enabled true|false
    credit-card-numbers true|false
    us-social-security-numbers true|false
    custom-patterns { <name> { regex "pattern" } }
    exception-urls { /api/safe { } }
}
```

Maps to XC Data Guard on HTTP LB (partial — custom patterns may not translate).

### Geolocation Enforcement

```
geolocation-enforcement {
    disallowed-geolocations {
        "North Korea" { }
        "Iran" { }
    }
}
```

Maps to XC Service Policy geo filtering rules.

### Brute Force Protection

```
brute-force-attack-prevention {
    enabled
    detection-period 600
    maximum-login-attempts 5
    login-url /login.php
}
```

Maps to XC Rate Limiter Policy (partial — ASM has session-aware brute force logic that XC lacks).

### Session Tracking

```
session-tracking {
    session-tracking-status enabled-including-all-resources
    session-hijacking-prevention enabled
}
```

**No XC equivalent.** This is a gap report item.

### Bot Defense

```
security bot-defense profile /Common/my_bot_profile {
    enforcement-mode blocking
    class-overrides {
        malicious-bot { action block }
        benign-bot { action report }
        unknown-bot { action challenge }
    }
}
```

Maps to XC `app_firewall` `bot_protection_setting` (malicious/benign/suspicious with BLOCK/REPORT/IGNORE actions). XC Bot Defense Advanced (Shape) is a separate product.

### IP Intelligence

```
security ip-intelligence policy /Common/my_ip_intel {
    blacklist-categories {
        botnets { action drop }
        scanners { action drop }
    }
}
```

Maps to XC Service Policy IP threat categories.

### Signature Sets

Key signature set categories in ASM:
- Generic Detection Signatures
- High Accuracy Signatures
- OS Command Injection Signatures
- SQL Injection Signatures
- Cross-Site Scripting (XSS) Signatures
- Application-specific sets (Apache, IIS, PHP, Node.js, etc.)
- CVE-based signatures
- Bot Signatures

XC maps these at the accuracy level (`only_high_accuracy`, `high_medium_accuracy`, `high_medium_low_accuracy`) and attack type level (22 discrete attack types that can be individually disabled).
