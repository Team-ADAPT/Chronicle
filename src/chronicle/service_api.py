"""
Chronicle — Read-Only Service Interface for External Security Tools
===================================================================
Exposes Chronicle detection results through a documented, versioned, read-only
HTTP JSON API at the /api/v1/ prefix.

Design constraints
------------------
- Read-only. No write, acknowledge, or delete endpoints.
- Stdlib only (http.server + json). No new dependencies.
- Consumes the Task 2 alert schema (RiskEngine.create_alert) unchanged.
- Does not duplicate risk logic or scoring code.
- Does not add PostgreSQL or persistence; data source is the in-memory pipeline
  ring buffer (ChroniclePipeline.active_alerts, maxlen 100).
- Authentication: none (service must run on localhost or a protected network).
  CHRONICLE_API_KEY env var is optional; if set, checked on every request via
  hmac.compare_digest (constant-time). The service refuses to bind to a
  non-loopback address without a key set.
- Stack traces never leak in responses; logged server-side only.

Endpoints
---------
GET /api/v1/health
GET /api/v1/alerts           ?limit=&offset=&severity=&source=
GET /api/v1/alerts/{id}

Error envelope
--------------
{"error": {"code": "...", "message": "...", "request_id": "..."}}
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import traceback
import uuid
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

# ── Constants ────────────────────────────────────────────────────────────────
API_VERSION = "v1"
PREFIX = f"/api/{API_VERSION}"
SCHEMA_VERSION = "1.0"          # bump when response schema changes
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50
VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
VALID_SOURCES = {"analytic", "ml", "both", "none"}

logger = logging.getLogger("chronicle.service_api")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _request_id() -> str:
    return uuid.uuid4().hex[:12]


def _error_body(code: str, message: str, request_id: str) -> bytes:
    return json.dumps({
        "error": {"code": code, "message": message, "request_id": request_id},
        "schema_version": SCHEMA_VERSION,
    }).encode("utf-8")


def _json_body(payload: Any, request_id: str) -> bytes:
    payload["schema_version"] = SCHEMA_VERSION
    payload["request_id"] = request_id
    return json.dumps(payload).encode("utf-8")


def _get_api_key() -> Optional[str]:
    """Reads the optional API key from the environment. Never logs its value."""
    return os.environ.get("CHRONICLE_API_KEY") or None


def _check_auth(provided: Optional[str], expected: Optional[str]) -> bool:
    """Constant-time comparison when a key is configured. Always passes when no key is set."""
    if expected is None:
        return True
    if provided is None:
        return False
    return hmac.compare_digest(
        hashlib.sha256(provided.encode()).digest(),
        hashlib.sha256(expected.encode()).digest(),
    )


# ── Pipeline accessor (injected at construction) ─────────────────────────────

class _PipelineAccessor:
    """
    Thin adapter over ChroniclePipeline to isolate the service from the live path.
    Only read methods are exposed.
    """

    def __init__(self, pipeline: Any):
        self._pipeline = pipeline

    def is_available(self) -> bool:
        return self._pipeline is not None

    def ml_loaded(self) -> bool:
        try:
            return bool(self._pipeline.ml_engine.loaded)
        except Exception:
            return False

    def ebpf_active(self) -> bool:
        try:
            return bool(self._pipeline.collector.ebpf_enabled)
        except Exception:
            return False

    def risk_scoring_enabled(self) -> bool:
        try:
            return bool(self._pipeline.config.enable_risk_scoring)
        except Exception:
            return True

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Returns all active alerts from the in-memory ring buffer."""
        try:
            return list(self._pipeline.active_alerts)
        except Exception as exc:
            logger.error("Failed to read alert buffer: %s", exc)
            raise

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Searches the in-memory buffer for an alert with the given id.
        ponytail: linear scan over deque maxlen=100 — O(100) is fine here;
                  upgrade to a dict index if buffer grows or hit-rate matters.
        """
        for alert in self._pipeline.active_alerts:
            if alert.get("id") == alert_id:
                return alert
        return None


# ── Request handler ──────────────────────────────────────────────────────────

class SecurityServiceHandler(BaseHTTPRequestHandler):
    """
    Read-only HTTP request handler for the Chronicle security tool service.

    Bound to a ChroniclePipeline instance via the `accessor` class attribute
    (set before the server starts). All mutating methods (POST, PUT, DELETE,
    PATCH) are rejected with 405.
    """

    # Injected by SecurityServiceServer.__init__
    accessor: _PipelineAccessor = None  # type: ignore[assignment]
    _api_key: Optional[str] = None

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Only log when verbose; suppress the per-request noise by default
        if os.environ.get("CHRONICLE_VERBOSE"):
            super().log_message(format, *args)

    # ── Entry points ─────────────────────────────────────────────────────────

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()

    # ── Dispatch ─────────────────────────────────────────────────────────────

    def _dispatch(self, method: str) -> None:
        rid = _request_id()
        try:
            # Reject request bodies on GET/HEAD
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                self._send(400, _error_body(
                    "BODY_NOT_ALLOWED",
                    "Request bodies are not accepted on this endpoint.",
                    rid,
                ))
                return

            # Authentication check
            if not _check_auth(
                self.headers.get("X-Chronicle-API-Key"),
                SecurityServiceHandler._api_key,
            ):
                self._send(401, _error_body(
                    "UNAUTHORIZED",
                    "Missing or invalid API key.",
                    rid,
                ))
                return

            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            qs = parse_qs(parsed.query, keep_blank_values=False)

            # Route
            if path == f"{PREFIX}/health":
                status, body = self._handle_health(rid)
            elif path == f"{PREFIX}/alerts":
                status, body = self._handle_alerts(qs, rid)
            elif path.startswith(f"{PREFIX}/alerts/"):
                alert_id = path[len(f"{PREFIX}/alerts/"):]
                status, body = self._handle_alert_by_id(alert_id, rid)
            else:
                status, body = 404, _error_body(
                    "NOT_FOUND",
                    f"No endpoint matches '{path}'.",
                    rid,
                )

            self._send(status, body)

        except Exception:
            # Last-resort guard: log full trace server-side, return generic 500
            logger.error(
                "Unhandled error [request_id=%s]: %s", rid, traceback.format_exc()
            )
            self._send(500, _error_body(
                "INTERNAL_ERROR",
                "An internal error occurred. Check server logs.",
                rid,
            ))

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # ── Handler methods ───────────────────────────────────────────────────────

    def _handle_health(self, rid: str) -> Tuple[int, bytes]:
        """
        GET /api/v1/health

        Reports the real status of each data source. If risk scoring is
        disabled via feature flag, risk fields are reported as "disabled",
        not as zero or "available".
        """
        acc = SecurityServiceHandler.accessor
        if acc is None or not acc.is_available():
            body = _json_body({
                "status": "unavailable",
                "sources": {
                    "pipeline": "unavailable",
                    "ml_models": "unavailable",
                    "ebpf_collector": "unavailable",
                    "risk_scoring": "unavailable",
                },
            }, rid)
            return 503, body

        try:
            risk_status = "available" if acc.risk_scoring_enabled() else "disabled"
            ebpf_status = "available" if acc.ebpf_active() else "unavailable_fallback_psutil"
            ml_status = "available" if acc.ml_loaded() else "unavailable"
            body = _json_body({
                "status": "ok",
                "sources": {
                    "pipeline": "available",
                    "ml_models": ml_status,
                    "ebpf_collector": ebpf_status,
                    "risk_scoring": risk_status,
                    "postgresql": "not_implemented",
                },
                "notes": [
                    "eBPF requires Linux kernel + BCC; psutil is the macOS fallback.",
                    "PostgreSQL storage is not yet implemented; alerts come from the in-memory ring buffer.",
                    "Alert IDs are stable within a single service run; cross-restart stability is not guaranteed (no persistent store).",
                ],
            }, rid)
            return 200, body
        except Exception:
            logger.error("Health check error: %s", traceback.format_exc())
            return 503, _error_body("SOURCE_ERROR", "Health check failed.", rid)

    def _handle_alerts(self, qs: Dict[str, List[str]], rid: str) -> Tuple[int, bytes]:
        """
        GET /api/v1/alerts

        Parameters
        ----------
        limit   : int, 1..MAX_PAGE_SIZE, default DEFAULT_PAGE_SIZE
        offset  : int, >= 0, default 0
        severity: str, one of Low|Medium|High|Critical
        source  : str, one of analytic|ml|both|none

        Sorted by timestamp desc, then id desc (deterministic).
        Returns 200 with empty list when no alerts match.
        Returns 503 when the data source is unavailable.
        """
        acc = SecurityServiceHandler.accessor
        if acc is None or not acc.is_available():
            return 503, _error_body("SOURCE_UNAVAILABLE", "Alert data source is unavailable.", rid)

        # ── Parameter validation ─────────────────────────────────────────
        try:
            limit = int(qs.get("limit", [str(DEFAULT_PAGE_SIZE)])[0])
        except (ValueError, TypeError):
            return 400, _error_body("INVALID_PARAM", "'limit' must be an integer.", rid)
        if not (1 <= limit <= MAX_PAGE_SIZE):
            return 400, _error_body(
                "INVALID_PARAM",
                f"'limit' must be between 1 and {MAX_PAGE_SIZE}.",
                rid,
            )

        try:
            offset = int(qs.get("offset", ["0"])[0])
        except (ValueError, TypeError):
            return 400, _error_body("INVALID_PARAM", "'offset' must be an integer.", rid)
        if offset < 0:
            return 400, _error_body("INVALID_PARAM", "'offset' must be >= 0.", rid)

        severity_filter: Optional[str] = None
        if "severity" in qs:
            severity_filter = qs["severity"][0]
            if severity_filter not in VALID_SEVERITIES:
                return 400, _error_body(
                    "INVALID_PARAM",
                    f"'severity' must be one of: {', '.join(sorted(VALID_SEVERITIES))}.",
                    rid,
                )

        source_filter: Optional[str] = None
        if "source" in qs:
            source_filter = qs["source"][0]
            if source_filter not in VALID_SOURCES:
                return 400, _error_body(
                    "INVALID_PARAM",
                    f"'source' must be one of: {', '.join(sorted(VALID_SOURCES))}.",
                    rid,
                )

        # ── Fetch & filter ───────────────────────────────────────────────
        try:
            alerts = acc.get_alerts()
        except Exception:
            return 503, _error_body("SOURCE_ERROR", "Failed to read alert buffer.", rid)

        if severity_filter:
            alerts = [a for a in alerts if a.get("riskCategory") == severity_filter]
        if source_filter:
            alerts = [a for a in alerts if a.get("detection_source") == source_filter]

        # Deterministic sort: timestamp desc, then id desc
        alerts = sorted(
            alerts,
            key=lambda a: (a.get("timestamp", ""), a.get("id", "")),
            reverse=True,
        )

        total = len(alerts)
        page = alerts[offset: offset + limit]

        body = _json_body({
            "alerts": page,
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "returned": len(page),
            },
            "data_source": "in_memory_ring_buffer",
            "data_source_note": (
                "Results reflect the in-process alert ring buffer (maxlen=100). "
                "Historical retrieval from PostgreSQL is not yet implemented."
            ),
        }, rid)
        return 200, body

    def _handle_alert_by_id(self, alert_id: str, rid: str) -> Tuple[int, bytes]:
        """
        GET /api/v1/alerts/{id}

        Returns the full alert dict for the given stable alert ID.
        Returns 404 if not found in the ring buffer.
        Returns 503 if the data source is unavailable.

        Note: IDs use the ALT- prefix produced by RiskEngine.make_alert_id().
        Stability across restarts is NOT guaranteed (no persistent store).
        """
        # Basic format validation — reject obviously malformed IDs early
        if not alert_id or len(alert_id) > 64 or not alert_id.replace("-", "").isalnum():
            return 400, _error_body(
                "INVALID_PARAM",
                "Alert ID must be alphanumeric with hyphens, max 64 characters.",
                rid,
            )

        acc = SecurityServiceHandler.accessor
        if acc is None or not acc.is_available():
            return 503, _error_body("SOURCE_UNAVAILABLE", "Alert data source is unavailable.", rid)

        try:
            alert = acc.get_alert_by_id(alert_id)
        except Exception:
            return 503, _error_body("SOURCE_ERROR", "Failed to read alert buffer.", rid)

        if alert is None:
            return 404, _error_body(
                "NOT_FOUND",
                f"No alert with id '{alert_id}' found in the current session buffer.",
                rid,
            )

        body = _json_body({"alert": alert, "data_source": "in_memory_ring_buffer"}, rid)
        return 200, body

    def _method_not_allowed(self) -> None:
        rid = _request_id()
        self._send(405, _error_body(
            "METHOD_NOT_ALLOWED",
            "This service is read-only. Only GET requests are accepted.",
            rid,
        ))
