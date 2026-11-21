# HTTP API Reference

## Binding and authentication

The API binds to `api.host` from `config/ase.json`, which must be one of
`127.0.0.1`, `::1` or `localhost`. Any other value is rejected during config
validation and again when the socket binds.

Every endpoint except `GET /health` requires:

```
Authorization: Bearer <key>
```

The key is generated on first start at `storage/ase_api.key` with mode `0600`.
Read it with `cat storage/ase_api.key`. Rotate it with
`ASEEngine.api.rotate_api_key()`; the previous key stops working immediately.

## Request rules

| Rule | Behavior on violation |
|---|---|
| Client IP must be loopback | `403 Forbidden` |
| Within rate limit (`api.rate_limit_requests` per window) | `429 Too Many Requests` |
| Valid bearer token | `401 Unauthorized` |
| `Content-Type: application/json` (POST) | `415 Unsupported Media Type` |
| Body ≤ `api.max_body_bytes` | `413 Payload Too Large` |
| Body decodes to a JSON object | `400 Bad Request` |

All responses carry `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Content-Security-Policy: default-src 'none'` and `Cache-Control: no-store`.

## Endpoints

### Public

#### `GET /health`

Liveness only. Returns no engine state.

```json
{"engine": "AKVORIA SECURITY ENGINE", "status": "running", "api": "local"}
```

### Status and diagnostics

| Method | Path | Description |
|---|---|---|
| GET | `/api/status` | Full engine status |
| GET | `/api/health` | Per-subsystem health check |
| GET | `/api/diagnostics` | Diagnostics bundle including `limitations` |
| GET | `/api/config` | Effective config with `api.allow_scan_paths` removed |
| GET | `/api/requests?limit=20` | Recent request audit entries (1–100) |

### Scanning

| Method | Path | Body | Description |
|---|---|---|---|
| POST | `/api/scan` | `{"path": "/abs/path"}` | Scan a file or directory |
| POST | `/api/scan/quick` | — | Scan well-known user folders |
| POST | `/api/scan/full` | `{"paths": ["/a"]}` (optional) | Full scan |
| GET | `/api/scans?limit=20&offset=0&scan_type=custom` | — | Scan history |
| GET | `/api/scans/statistics` | — | Aggregate scan statistics |
| GET | `/api/scans/{id}` | — | One scan with its per-file results |

Scan results carry a `status` from the fixed verdict set, per-file `reasons` and
a `risk_score`. `no_known_indicators` means nothing matched — it is not a
statement that the file is harmless.

### Quarantine

| Method | Path | Body | Description |
|---|---|---|---|
| GET | `/api/quarantine` | — | List quarantined items |
| POST | `/api/quarantine` | `{"path": "...", "authorized": true}` | Quarantine a detected file |
| POST | `/api/quarantine/restore` | `{"quarantine_id": "..."}` | Restore after integrity verification |

`authorized` must be the literal boolean `true`. Omit it and the request is
refused with `403` and the file is left in place. A file with no detection is
also refused.

Restore re-hashes the stored copy. On mismatch it returns `404` with an
integrity message and leaves the quarantine record untouched.

### Alerts and incidents

| Method | Path | Body / Query | Description |
|---|---|---|---|
| GET | `/api/alerts?limit=50&status=open&severity=high` | — | Alert history |
| POST | `/api/alerts/acknowledge` | `{"alert_id": 1, "actor": "name"}` | Acknowledge an alert |
| GET | `/api/incidents?limit=50` | — | Grouped incidents |

Every alert includes `reasons` and a `recommendation`. Acknowledgement is
idempotent per alert: a second acknowledgement returns `404`.

### Threat intelligence

| Method | Path | Body | Description |
|---|---|---|---|
| GET | `/api/intelligence/indicators?type=ip` | — | List indicators |
| POST | `/api/intelligence/indicators` | `{"indicator": "8.8.8.8", "type": "ip", "confidence": 50}` | Add or update |
| DELETE | `/api/intelligence/indicators/{value}` | — | Remove |
| POST | `/api/intelligence/export` | `{"path": "..."}` | Export to JSON |

Indicator values are strictly validated: an invalid IP, domain or SHA-256 is
rejected with `400`.

### Monitoring

| Method | Path | Body | Description |
|---|---|---|---|
| GET | `/api/monitoring` | — | Monitor state, scope and health |
| POST | `/api/monitoring/paths` | `{"paths": ["/dir"]}` | Replace the watch set |

`GET /api/monitoring` returns the scope and the actual resolved roots at the top
level, with the full status nested:

```json
{
  "scope": "configured_directories_only",
  "mode": "polling",
  "roots": ["/home/user/Downloads"],
  "running": true,
  "realtime": { "...": "full status" },
  "health": {"scope": "configured_directories_only", "state": "healthy"}
}
```

`mode` is one of `native`, `polling`, `idle_no_paths` or `stopped`. If the list
is empty, monitoring protects nothing and says so.

### Inventory

| Method | Path | Description |
|---|---|---|
| GET | `/api/processes?limit=100` | Read-only process inventory |
| GET | `/api/network/connections` | Passive connection inventory |
| GET | `/api/network/history?limit=20` | Connection history |
| GET | `/api/events?...` | Persisted security events |
| GET | `/api/scheduler` | Scheduler state |
| GET | `/api/scheduler/history?limit=20` | Task run history |

### Maintenance

| Method | Path | Description |
|---|---|---|
| POST | `/api/diagnostics/backup` | Write a database backup |

## Status codes

| Code | Meaning |
|---|---|
| 200 | Success |
| 201 | Created (quarantine, indicator) |
| 400 | Invalid parameter, JSON or indicator value |
| 401 | Missing or invalid bearer token |
| 403 | Non-loopback client, unauthorized quarantine, path outside allowlist |
| 404 | Unknown endpoint, unknown quarantine id, already-acknowledged alert |
| 405 | Method not supported for this path |
| 413 | Body exceeds the configured limit |
| 415 | Wrong `Content-Type` |
| 429 | Rate limit exceeded |
| 500 | Internal error — body is always generic |

## Example session

```bash
KEY=$(cat storage/ase_api.key)
BASE=http://127.0.0.1:8765

curl -s -H "Authorization: Bearer $KEY" $BASE/api/status | head -20
curl -s -X POST -H "Authorization: Bearer $KEY" \
     -H "Content-Type: application/json" \
     -d '{"path": "/home/user/Downloads"}' $BASE/api/scan
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/alerts?limit=10"
```

## Scan allowlist

Set `api.allow_scan_paths` to restrict which paths the API may scan. When the
list is empty every path the engine process can read is permitted. When it is
populated, a request outside those directories returns `403`. The allowlist is
never returned by `GET /api/config`.
