# REST API Usage

The WaffleIron API is a session-based REST API built on FastAPI. All endpoints are prefixed with `/api/v1`. The API runs on port 8080 (Docker) or 8000 (local dev).

## Session Lifecycle

Each conversion is a server-side session that progresses through states:

```
POST /conversions              →  parsed
GET  /conversions/{id}/analysis     →  analysis computed (lazy, on first access)
PUT  /conversions/{id}/decisions    →  decisions recorded
POST /conversions/{id}/translate    →  XC objects generated
POST /conversions/{id}/push        →  objects pushed to XC
DELETE /conversions/{id}            →  session destroyed
```

Sessions expire after 1 hour by default (configurable via `SESSION_TTL` environment variable).

---

## Conversion Endpoints

### POST /conversions

Upload an AWAF policy file and create a conversion session.

```bash
curl -s -X POST http://localhost:8080/api/v1/conversions \
  -F "file=@policy.xml"
```

**Response (201):**
```json
{
  "id": "a1b2c3d4-...",
  "status": "parsed",
  "policy_name": "my-policy"
}
```

Accepts XML or JSON AWAF policy exports.

### GET /conversions/{id}

Get the current status of a conversion session.

```bash
curl -s http://localhost:8080/api/v1/conversions/$SESSION
```

**Response (200):**
```json
{
  "id": "a1b2c3d4-...",
  "status": "translated",
  "policy_name": "my-policy"
}
```

### GET /conversions/{id}/analysis

Retrieve the policy analysis. Computed lazily on first access.

```bash
curl -s http://localhost:8080/api/v1/conversions/$SESSION/analysis | jq .
```

**Response (200):**
```json
{
  "policy_info": {
    "name": "my-policy",
    "enforcement_mode": "blocking",
    "encoding": "utf-8",
    "signature_accuracy": "high_medium",
    "staging_enabled": false,
    "threat_campaigns_enabled": true,
    "features": {
      "data_guard": true,
      "csrf": false,
      "bot_defense": true,
      "brute_force": false,
      "session_tracking": false,
      "ip_intelligence": true,
      "geolocation": true,
      "blocking_page": true
    },
    "entity_counts": {
      "urls": 12,
      "parameters": 5,
      "file_types": 3,
      "cookies": 0,
      "headers": 0,
      "signature_overrides": 8,
      "violations": 45,
      "whitelist_ips": 2
    },
    "signature_sets": [
      {"name": "High Accuracy Signatures", "enabled": true}
    ]
  },
  "summary": {
    "total": 145,
    "directly_translated": 120,
    "translated_with_loss": 5,
    "decisions_required": 12,
    "cannot_translate": 8
  },
  "alarm_only_signatures": [
    {"sig_id": 200003505, "description": "SQL Injection", "scope": "global"}
  ],
  "alarm_only_violations": [
    {"violation_name": "VIOL_EVASION", "alarm": true, "block": false}
  ],
  "untranslatable": {
    "custom_signature_count": 3,
    "session_tracking_enabled": false,
    "session_hijacking_enabled": false,
    "brute_force_enabled": true,
    "custom_signatures": [...]
  },
  "bot_gaps": [
    {"category": "dos_tool", "asm_action": "challenge", "reason": "XC does not support challenge action"}
  ],
  "blocking_page_gaps": [
    {"variable": "support_id", "reason": "No XC equivalent"}
  ],
  "ip_intel_gaps": [
    {"category": "tor_proxies", "reason": "Category not available in XC"}
  ],
  "warnings": [
    {"resource": "exclusion_rules", "count": 300, "limit": 256, "message": "Exceeds XC limit"}
  ]
}
```

### PUT /conversions/{id}/decisions

Submit user decisions for alarm-only signatures, violations, and bot categories.

```bash
curl -s -X PUT http://localhost:8080/api/v1/conversions/$SESSION/decisions \
  -H "Content-Type: application/json" \
  -d '{
    "alarm_only_signatures": [
      {"sig_id": 200003505, "action": "enforce", "description": "SQL Injection", "scope": "global"},
      {"sig_id": 200004560, "action": "exclude", "description": "XSS", "scope": "/api/*"}
    ],
    "alarm_only_violations": [
      {"violation": "VIOL_EVASION", "action": "enforce"}
    ]
  }'
```

**Actions for signatures:** `enforce` | `exclude` | `defer`
**Actions for violations:** `enforce` | `disable` | `defer`

**Response (200):**
```json
{
  "id": "a1b2c3d4-...",
  "status": "decisions_submitted"
}
```

### POST /conversions/{id}/translate

Translate the policy to XC API objects.

```bash
curl -s -X POST http://localhost:8080/api/v1/conversions/$SESSION/translate \
  -H "Content-Type: application/json" \
  -d '{
    "namespace": "my-namespace",
    "name": "my-policy-xc"
  }'
```

**Request body:**

| Field | Type | Description |
|-------|------|-------------|
| `namespace` | string | Target namespace for all generated objects |
| `name` | string | Optional policy name override |

**Response (200):**
```json
{
  "id": "a1b2c3d4-...",
  "status": "translated",
  "outputs": {
    "app_firewall": { "metadata": {...}, "spec": {...} },
    "exclusion_policy": { "metadata": {...}, "spec": {...} },
    "service_policy": null,
    "http_lb_patch": null
  }
}
```

Null values indicate the policy doesn't require that object type.

### GET /conversions/{id}/outputs

List available output object types after translation.

```bash
curl -s http://localhost:8080/api/v1/conversions/$SESSION/outputs
```

**Response (200):**
```json
{
  "available": ["app_firewall", "exclusion_policy", "service_policy"]
}
```

### GET /conversions/{id}/outputs/{object_type}

Download a specific XC object as JSON.

```bash
curl -s http://localhost:8080/api/v1/conversions/$SESSION/outputs/app_firewall > app_firewall.json
```

Valid object types: `app_firewall`, `exclusion_policy`, `service_policy`, `http_lb_patch`

### GET /conversions/{id}/report

Generate a gap report. Format is selected via the `Accept` header.

```bash
# JSON
curl -s http://localhost:8080/api/v1/conversions/$SESSION/report \
  -H "Accept: application/json" > gap_report.json

# Markdown
curl -s http://localhost:8080/api/v1/conversions/$SESSION/report \
  -H "Accept: text/markdown" > gap_report.md
```

### DELETE /conversions/{id}

Delete a conversion session and free resources.

```bash
curl -s -X DELETE http://localhost:8080/api/v1/conversions/$SESSION
```

**Response:** 204 No Content

---

## XC Integration Endpoints

### GET /xc/status

Check whether XC credentials are configured at the server level (via environment variables).

```bash
curl -s http://localhost:8080/api/v1/xc/status
```

**Response (200):**
```json
{
  "configured": true,
  "tenant_url": "https://tenant.console.ves.volterra.io"
}
```

### POST /xc/connect

Test connectivity to an XC tenant.

```bash
curl -s -X POST http://localhost:8080/api/v1/xc/connect \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_url": "https://tenant.console.ves.volterra.io",
    "api_token": "your-token"
  }'
```

**Response (200):**
```json
{"connected": true}
```

### GET /xc/namespaces

List namespaces from the XC tenant. `shared` is always included at the front.

```bash
curl -s "http://localhost:8080/api/v1/xc/namespaces?tenant_url=https://...&api_token=..."
```

**Response (200):**
```json
{
  "namespaces": ["shared", "production", "staging"]
}
```

If XC credentials are configured at the server level, the query parameters are optional.

### POST /conversions/{id}/push

Push translated objects to an XC tenant.

```bash
curl -s -X POST http://localhost:8080/api/v1/conversions/$SESSION/push \
  -H "Content-Type: application/json" \
  -d '{
    "objects": ["app_firewall", "waf_exclusion_policy", "service_policy"],
    "tenant_url": "https://tenant.console.ves.volterra.io",
    "api_token": "your-token"
  }'
```

**Request body:**

| Field | Type | Description |
|-------|------|-------------|
| `objects` | string[] | Object types to push |
| `tenant_url` | string | Optional — uses server config if omitted |
| `api_token` | string | Optional — uses server config if omitted |

Valid object types: `app_firewall`, `waf_exclusion_policy`, `exclusion_policy`, `service_policy`. The type `http_lb_patch` is accepted but skipped (reference only).

**Response (200):**
```json
{
  "results": [
    {"object_type": "app_firewall", "success": true, "namespace": "my-namespace"},
    {"object_type": "waf_exclusion_policy", "success": true, "namespace": "my-namespace"},
    {"object_type": "service_policy", "success": false, "error": "not available"}
  ]
}
```

### POST /conversions/{id}/push/delete

Delete previously pushed objects from an XC tenant.

```bash
curl -s -X POST http://localhost:8080/api/v1/conversions/$SESSION/push/delete \
  -H "Content-Type: application/json" \
  -d '{
    "objects": ["app_firewall", "waf_exclusion_policy"],
    "tenant_url": "https://tenant.console.ves.volterra.io",
    "api_token": "your-token"
  }'
```

Same request/response format as push.

---

## Health Check

### GET /healthz

```bash
curl -s http://localhost:8080/healthz
```

**Response (200):**
```json
{
  "status": "ok",
  "xc_configured": false
}
```

---

## Full Workflow Example

Complete end-to-end conversion using curl:

```bash
#!/usr/bin/env bash
set -euo pipefail

API="http://localhost:8080/api/v1"

# 1. Upload
SESSION=$(curl -s -X POST "$API/conversions" -F "file=@policy.xml" | jq -r '.id')
echo "Session: $SESSION"

# 2. Analyze
curl -s "$API/conversions/$SESSION/analysis" | jq '.summary'

# 3. Get alarm-only items that need decisions
SIGS=$(curl -s "$API/conversions/$SESSION/analysis" | jq '.alarm_only_signatures')
echo "Alarm-only signatures: $(echo "$SIGS" | jq length)"

# 4. Submit decisions (enforce all)
DECISIONS=$(echo "$SIGS" | jq '[.[] | {sig_id, action: "enforce", description, scope}]')
curl -s -X PUT "$API/conversions/$SESSION/decisions" \
  -H "Content-Type: application/json" \
  -d "{\"alarm_only_signatures\": $DECISIONS}"

# 5. Translate
curl -s -X POST "$API/conversions/$SESSION/translate" \
  -H "Content-Type: application/json" \
  -d '{"namespace": "production", "name": "my-policy"}'

# 6. Download outputs
for obj in app_firewall exclusion_policy service_policy; do
  curl -s "$API/conversions/$SESSION/outputs/$obj" -o "${obj}.json" 2>/dev/null || true
done

# 7. Download gap report
curl -s "$API/conversions/$SESSION/report" -H "Accept: text/markdown" -o gap_report.md

# 8. Push to XC (optional)
curl -s -X POST "$API/conversions/$SESSION/push" \
  -H "Content-Type: application/json" \
  -d '{
    "objects": ["app_firewall", "waf_exclusion_policy", "service_policy"],
    "tenant_url": "https://tenant.console.ves.volterra.io",
    "api_token": "your-token"
  }' | jq .

# 9. Clean up
curl -s -X DELETE "$API/conversions/$SESSION"
```
