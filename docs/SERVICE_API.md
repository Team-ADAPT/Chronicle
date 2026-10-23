# Chronicle Security Tool Service Interface

## What this service exposes

A read-only HTTP JSON API at `/api/v1/` that lets external security tools consume Chronicle's detection results programmatically:

- Security alerts with stable IDs, risk scores, severity categories, evidence signals, and human-readable explanations.
- Per-source health status (pipeline, ML models, eBPF collector, risk scoring, PostgreSQL).

## What it does NOT expose

- No write, acknowledge, or delete endpoints.
- No raw event stream (use the existing `/api/events` endpoint in `app.py` for that).
- No PostgreSQL-backed historical retrieval (not yet implemented; the service reads from the in-memory ring buffer only).
- No CORS headers (service is intended for localhost or protected network use only).

---

## Installation

No new dependencies. The service uses Python's standard library (`http.server`, `json`, `socketserver`, `hmac`).

**Python 3.10+ recommended** (3.14 tested).

---

## Start command

```bash
python serve_api.py
```

The service binds to `127.0.0.1:8765` by default.

---

## Configuration (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `CHRONICLE_SERVICE_HOST` | `127.0.0.1` | Bind address. Binding to a non-loopback address requires `CHRONICLE_API_KEY` to be set. |
| `CHRONICLE_SERVICE_PORT` | `8765` | TCP port. |
| `CHRONICLE_API_KEY` | *(unset)* | Optional shared API key. Read at startup, never logged. Required for non-loopback bind. |
| `CHRONICLE_VERBOSE` | *(unset)* | Set to any non-empty value to enable per-request access logs. |

---

## Endpoints

### `GET /api/v1/health`

Reports the real status of each data source.

**Example request**
```
GET /api/v1/health HTTP/1.1
```

**Example response** *(illustrative)*
```json
{
  "status": "ok",
  "sources": {
    "pipeline": "available",
    "ml_models": "available",
    "ebpf_collector": "unavailable_fallback_psutil",
    "risk_scoring": "available",
    "postgresql": "not_implemented"
  },
  "notes": [
    "eBPF requires Linux kernel + BCC; psutil is the macOS fallback.",
    "PostgreSQL storage is not yet implemented; alerts come from the in-memory ring buffer.",
    "Alert IDs are stable within a single service run; cross-restart stability is not guaranteed (no persistent store)."
  ],
  "schema_version": "1.0",
  "request_id": "a1b2c3d4e5f6"
}
```

If the pipeline is unavailable, returns **503** with `"status": "unavailable"`.

**Risk scoring disabled (feature flag off):**
```json
{ "sources": { "risk_scoring": "disabled" } }
```
Risk scoring reports `"disabled"`, not `"available"` or `0`.

---

### `GET /api/v1/alerts`

Returns a paginated list of alerts from the in-memory ring buffer, sorted by timestamp descending (then ID descending for ties).

**Query parameters**

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | integer | 50 | 200 | Number of alerts per page |
| `offset` | integer | 0 | — | Skip first N alerts |
| `severity` | string | — | — | Filter by `Low`, `Medium`, `High`, or `Critical` |
| `source` | string | — | — | Filter by `analytic`, `ml`, `both`, or `none` |

**Example request**
```
GET /api/v1/alerts?limit=2&severity=Critical HTTP/1.1
```

**Example response** *(illustrative)*
```json
{
  "alerts": [
    {
      "id": "ALT-3F9A1B2C",
      "timestamp": "2026-10-17T09:00:00Z",
      "timestamp_source": "ingestion",
      "pid": 1234,
      "comm": "suspicious_proc",
      "riskScore": 82,
      "riskCategory": "Critical",
      "category": "PRIVILEGE_ESCALATION",
      "description": "High-risk behavioral anomaly detected in 'suspicious_proc' (PID 1234).",
      "reasons": ["Analytic rule: unusual privilege escalation attempt."],
      "eval_status": "evaluated",
      "detection_source": "analytic",
      "contributing_signals": [
        {
          "source": "heuristic",
          "name": "privilege_escalation",
          "observed_value": "privilege_escalation",
          "score_contribution": 70.0,
          "description": "Analytic rule: unusual setuid/sudo/prctl invocation sequence..."
        }
      ],
      "dedup_key": "DK-AABBCC112233",
      "dedup_window_seconds": 60,
      "config_version": "1.1.0",
      "status": "ACTIVE"
    }
  ],
  "pagination": { "total": 1, "limit": 2, "offset": 0, "returned": 1 },
  "data_source": "in_memory_ring_buffer",
  "data_source_note": "Results reflect the in-process alert ring buffer (maxlen=100). Historical retrieval from PostgreSQL is not yet implemented.",
  "schema_version": "1.0",
  "request_id": "b2c3d4e5f6a1"
}
```

**Empty result** (no matching alerts): returns `200` with `"alerts": []`.

---

### `GET /api/v1/alerts/{id}`

Returns a single alert by its stable ID (e.g. `ALT-3F9A1B2C`).

> [!WARNING]
> Alert IDs (`ALT-` prefix) are stable within a single service session. **Cross-restart stability is NOT guaranteed** because the service reads from an in-memory buffer with no persistent backing store.

**Example request**
```
GET /api/v1/alerts/ALT-3F9A1B2C HTTP/1.1
```

Returns `404` if the ID is not in the current session buffer.

---

## Error responses

All errors use a consistent envelope:

```json
{
  "error": {
    "code": "INVALID_PARAM",
    "message": "Human-readable description.",
    "request_id": "a1b2c3d4e5f6"
  },
  "schema_version": "1.0"
}
```

| HTTP status | Code | Meaning |
|-------------|------|---------|
| 400 | `INVALID_PARAM` | Bad parameter type, out-of-range value, unknown enum, request body on GET |
| 400 | `BODY_NOT_ALLOWED` | Request body present on a GET request |
| 401 | `UNAUTHORIZED` | Missing or wrong API key |
| 404 | `NOT_FOUND` | Unknown alert ID or route |
| 405 | `METHOD_NOT_ALLOWED` | Non-GET method (service is read-only) |
| 503 | `SOURCE_UNAVAILABLE` | Data source (pipeline) is unavailable |
| 503 | `SOURCE_ERROR` | Failed to read from data source |
| 500 | `INTERNAL_ERROR` | Unexpected internal error; check server logs |

Stack traces, file paths, and environment details are **never** included in error responses. Detailed errors are logged server-side only.

---

## Authentication

**No authentication by default.** The service must run on `localhost` or inside a protected network segment.

**Optional API key:**
Set `CHRONICLE_API_KEY` in the environment before starting. The key is:
- Read once at startup, never logged.
- Compared using constant-time `hmac.compare_digest` to prevent timing attacks.
- **Required** when binding to a non-loopback address (e.g. `0.0.0.0`).

Clients send the key in the `X-Chronicle-API-Key` request header.

> [!CAUTION]
> Do not bind to `0.0.0.0` without setting `CHRONICLE_API_KEY`. The service will refuse to start in this configuration.

---

## Deployment considerations

- The service uses a single-process `ThreadingMixIn` HTTP server. Single worker tested; do not add multiple workers without load testing.
- Default bind: `127.0.0.1` (loopback only).
- No TLS. Place behind a reverse proxy (nginx/caddy) with TLS if exposing beyond localhost.
- No CORS headers; not intended for direct browser consumption.

---

## Data source integration status

| Integration | Status | Evidence |
|-------------|--------|---------|
| In-memory alert ring buffer (`pipeline.active_alerts`) | **PASS** | Tests confirmed; data flows from `RiskEngine.create_alert()` → `ChroniclePipeline.active_alerts` → service response |
| ML models (Isolation Forest + XGBoost) | **PASS** on Linux; **BLOCKED** on macOS without models | `ml_engine.loaded` reported in health |
| eBPF collector | **BLOCKED** on macOS (requires Linux kernel + BCC) | Falls back to psutil; reported as `unavailable_fallback_psutil` in health |
| SQLite (read-only for future extension) | **NOT USED** (DB schema is a subset; in-memory buffer has full schema) | Documented |
| PostgreSQL historical retrieval | **NOT IMPLEMENTED** | Reported in health as `not_implemented` |

---

## Running tests

```bash
# Service API tests only
python3 -m pytest tests/test_service_api.py -v

# Full suite (includes Task 1 + Task 2 regression)
python3 -m pytest tests/ -q

# ML/Task 1 tests
python3 -m pytest ML/tests/ -q
```

---

## Client example

```bash
# With service running on default port:
python examples/client_example.py

# With a different host/port:
CHRONICLE_BASE_URL=http://127.0.0.1:8765 python examples/client_example.py

# With API key:
CHRONICLE_API_KEY=your-key python examples/client_example.py
```
