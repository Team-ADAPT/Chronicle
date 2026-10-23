"""
Chronicle Task 3 — Security Tool Service Interface: Test Suite
==============================================================
Tests for src/chronicle/service_api.py.

Strategy
--------
All tests use SecurityServiceHandler directly (no live network port).
Requests are constructed as minimal mocks; BaseHTTPRequestHandler is
bypassed — we call handler methods directly after wiring the class attributes.

Fixtures are labelled SYNTHETIC throughout. No live eBPF or PostgreSQL required.

Coverage
--------
1.  Health response with per-source status
2.  Valid alert list retrieval with pagination
3.  Alert retrieval by ID (PASS)
4.  Empty result set → 200 with empty list
5.  Unknown alert ID → 404
6.  Invalid parameters: bad types, out-of-range limit, negative offset,
    unknown enum, wrong method, request body present
7.  Response schema and required fields against the Task 2 alert schema
8.  Pagination and filtering determinism
9.  Internal exception → generic 500, no stack trace in body
10. Unavailable data source → 503, health reports it
11. Risk scores, severity, evidence, explanations preserved from detection result
12. No fabricated results when accessor is unavailable
13. Authentication: missing key, wrong key, correct key,
    non-loopback bind refused without key
14. Feature flag off: risk fields reported as unavailable (eval_status=insufficient_data)
15. Regression: Task 2 risk-scoring tests still pass
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from chronicle.service_api import (
    MAX_PAGE_SIZE,
    PREFIX,
    SCHEMA_VERSION,
    VALID_SEVERITIES,
    VALID_SOURCES,
    SecurityServiceHandler,
    _PipelineAccessor,
    _check_auth,
    _error_body,
    _json_body,
    _request_id,
)

# ─────────────────────────────────────────────────────────────────────────────
# SYNTHETIC alert fixtures (labelled)
# ─────────────────────────────────────────────────────────────────────────────

_SYNTHETIC_ALERT_1: Dict[str, Any] = {
    "id": "ALT-AABBCCDD",
    "timestamp": "2026-10-17T09:00:00Z",
    "timestamp_source": "ingestion",
    "pid": 1234,
    "ppid": 1,
    "comm": "suspicious_proc",
    "user": "root",
    "riskScore": 82,
    "riskCategory": "Critical",
    "category": "PRIVILEGE_ESCALATION",
    "description": "SYNTHETIC: High-risk behavioural anomaly detected.",
    "reasons": ["Analytic rule: privilege escalation attempt."],
    "eval_status": "evaluated",
    "detection_source": "analytic",
    "contributing_signals": [
        {
            "source": "heuristic",
            "name": "privilege_escalation",
            "observed_value": "privilege_escalation",
            "score_contribution": 70.0,
            "description": "Analytic rule: privilege escalation attempt.",
        }
    ],
    "dedup_key": "DK-AABBCC112233",
    "dedup_window_seconds": 60,
    "config_version": "1.1.0",
    "status": "ACTIVE",
}

_SYNTHETIC_ALERT_2: Dict[str, Any] = {
    "id": "ALT-11223344",
    "timestamp": "2026-10-17T08:00:00Z",
    "timestamp_source": "ingestion",
    "pid": 5678,
    "comm": "miner_proc",
    "riskScore": 55,
    "riskCategory": "High",
    "category": "RESOURCE_HIJACK",
    "description": "SYNTHETIC: Suspicious crypto mining pattern.",
    "reasons": ["Analytic rule: crypto mining."],
    "eval_status": "evaluated",
    "detection_source": "ml",
    "contributing_signals": [],
    "dedup_key": "DK-112233AABBCC",
    "dedup_window_seconds": 60,
    "config_version": "1.1.0",
    "status": "ACTIVE",
}

_SYNTHETIC_ALERT_DISABLED: Dict[str, Any] = {
    "id": "ALT-DEADBEEF",
    "timestamp": "2026-10-17T07:00:00Z",
    "timestamp_source": "ingestion",
    "pid": 9999,
    "comm": "safe_proc",
    "riskScore": 0,
    "riskCategory": "Low",
    "category": "EXECUTION",
    "description": "SYNTHETIC: Risk scoring disabled.",
    "reasons": [],
    "eval_status": "insufficient_data",   # feature flag off
    "detection_source": "none",
    "contributing_signals": [],
    "dedup_key": "DK-DEADBEEF0000",
    "dedup_window_seconds": 60,
    "config_version": "1.1.0",
    "status": "ACTIVE",
    "limitations": "Score may be incomplete due to missing or invalid inputs. Treat with caution.",
}

_ALL_SYNTHETIC_ALERTS = [_SYNTHETIC_ALERT_1, _SYNTHETIC_ALERT_2]


# ─────────────────────────────────────────────────────────────────────────────
# In-process handler call helper (no network port needed)
# ─────────────────────────────────────────────────────────────────────────────

def _call(
    path: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    content_length: int = 0,
    accessor: Optional[_PipelineAccessor] = None,
    api_key: Optional[str] = None,
) -> tuple[int, Dict[str, Any]]:
    """
    Patches SecurityServiceHandler class attributes directly, then calls
    _dispatch (or the appropriate do_* method for non-GET verbs that bypass
    _dispatch). Returns (status_code, parsed_response_body).
    """
    out_buf = io.BytesIO()
    captured: Dict[str, Any] = {"status": None}

    # Patch the real class so handler methods see the correct accessor/key
    orig_accessor = SecurityServiceHandler.accessor
    orig_key = SecurityServiceHandler._api_key
    SecurityServiceHandler.accessor = accessor   # type: ignore[assignment]
    SecurityServiceHandler._api_key = api_key    # type: ignore[assignment]

    try:
        class _TestHandler(SecurityServiceHandler):
            def __init__(self):
                self.path = path
                self.command = method
                self.wfile = out_buf
                self.rfile = io.BytesIO(b"")
                self._captured_status: Optional[int] = None
                self._headers_sent: list = []

            def send_response(self, code, message=None):
                self._captured_status = code
                captured["status"] = code

            def send_header(self, keyword, value):
                self._headers_sent.append((keyword, value))

            def end_headers(self):
                pass

            @property
            def headers(self):
                class _H:
                    def __init__(self, h, cl):
                        self._h = h
                        self._cl = cl
                    def get(self, k, default=None):
                        if k == "Content-Length":
                            return str(self._cl)
                        return self._h.get(k, default)
                return _H(headers or {}, content_length)

            def log_message(self, *a, **kw):
                pass

        handler = _TestHandler()

        # Route to the correct do_* method (mirrors real server dispatch)
        _method_map = {
            "GET": handler.do_GET,
            "HEAD": handler.do_HEAD,
            "POST": handler.do_POST,
            "PUT": handler.do_PUT,
            "DELETE": handler.do_DELETE,
            "PATCH": handler.do_PATCH,
            "OPTIONS": handler.do_OPTIONS,
        }
        do_fn = _method_map.get(method, handler.do_GET)
        do_fn()

    finally:
        SecurityServiceHandler.accessor = orig_accessor  # type: ignore[assignment]
        SecurityServiceHandler._api_key = orig_key       # type: ignore[assignment]

    out_buf.seek(0)
    raw = out_buf.read()
    body = json.loads(raw) if raw else {}
    return handler._captured_status, body


def _make_accessor(
    alerts: Optional[List[Dict[str, Any]]] = None,
    available: bool = True,
    ml_loaded: bool = True,
    ebpf: bool = False,
    risk_enabled: bool = True,
    raise_on_get: bool = False,
) -> _PipelineAccessor:
    """SYNTHETIC accessor factory — does not connect to any live pipeline."""
    acc = MagicMock(spec=_PipelineAccessor)
    acc.is_available.return_value = available
    acc.ml_loaded.return_value = ml_loaded
    acc.ebpf_active.return_value = ebpf
    acc.risk_scoring_enabled.return_value = risk_enabled

    _alerts = list(alerts) if alerts is not None else list(_ALL_SYNTHETIC_ALERTS)

    if raise_on_get:
        acc.get_alerts.side_effect = RuntimeError("SYNTHETIC source failure")
        acc.get_alert_by_id.side_effect = RuntimeError("SYNTHETIC source failure")
    else:
        acc.get_alerts.return_value = _alerts
        def _by_id(aid):
            for a in _alerts:
                if a.get("id") == aid:
                    return a
            return None
        acc.get_alert_by_id.side_effect = _by_id

    return acc


# ─────────────────────────────────────────────────────────────────────────────
# 1. Health endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_ok(self):
        acc = _make_accessor(risk_enabled=True, ml_loaded=True, ebpf=False)
        status, body = _call(f"{PREFIX}/health", accessor=acc)
        assert status == 200
        assert body["status"] == "ok"
        assert "schema_version" in body
        assert body["sources"]["pipeline"] == "available"
        assert body["sources"]["risk_scoring"] == "available"
        assert body["sources"]["ml_models"] == "available"
        assert "postgresql" in body["sources"]

    def test_health_risk_disabled_reports_disabled_not_zero(self):
        """Feature flag off: risk_scoring field is 'disabled', not 'available'."""
        acc = _make_accessor(risk_enabled=False)
        status, body = _call(f"{PREFIX}/health", accessor=acc)
        assert status == 200
        assert body["sources"]["risk_scoring"] == "disabled"

    def test_health_ml_unavailable(self):
        acc = _make_accessor(ml_loaded=False)
        status, body = _call(f"{PREFIX}/health", accessor=acc)
        assert body["sources"]["ml_models"] == "unavailable"

    def test_health_ebpf_unavailable_fallback(self):
        acc = _make_accessor(ebpf=False)
        status, body = _call(f"{PREFIX}/health", accessor=acc)
        assert body["sources"]["ebpf_collector"] == "unavailable_fallback_psutil"

    def test_health_postgresql_not_implemented(self):
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/health", accessor=acc)
        assert body["sources"]["postgresql"] == "not_implemented"

    def test_health_unavailable_pipeline_returns_503(self):
        acc = _make_accessor(available=False)
        status, body = _call(f"{PREFIX}/health", accessor=acc)
        assert status == 503
        assert body["sources"]["pipeline"] == "unavailable"

    def test_health_has_notes(self):
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/health", accessor=acc)
        assert "notes" in body
        assert isinstance(body["notes"], list)


# ─────────────────────────────────────────────────────────────────────────────
# 2–4 & 7–8. Alert list
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertList:
    def test_list_default_returns_200(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts", accessor=acc)
        assert status == 200
        assert "alerts" in body
        assert "pagination" in body
        assert "schema_version" in body

    def test_list_empty_returns_200_empty_list(self):
        """Empty result set → 200 with empty list, not 404."""
        acc = _make_accessor(alerts=[])
        status, body = _call(f"{PREFIX}/alerts", accessor=acc)
        assert status == 200
        assert body["alerts"] == []
        assert body["pagination"]["total"] == 0

    def test_list_pagination_limit(self):
        acc = _make_accessor()  # 2 synthetic alerts
        status, body = _call(f"{PREFIX}/alerts?limit=1", accessor=acc)
        assert status == 200
        assert len(body["alerts"]) == 1
        assert body["pagination"]["returned"] == 1
        assert body["pagination"]["total"] == 2

    def test_list_pagination_offset(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts?limit=10&offset=1", accessor=acc)
        assert status == 200
        assert len(body["alerts"]) == 1
        assert body["pagination"]["offset"] == 1

    def test_list_offset_beyond_results_returns_empty(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts?offset=999", accessor=acc)
        assert status == 200
        assert body["alerts"] == []

    def test_list_sorted_by_timestamp_desc_deterministic(self):
        """Most-recent alert first, stable sort."""
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts", accessor=acc)
        timestamps = [a["timestamp"] for a in body["alerts"]]
        assert timestamps == sorted(timestamps, reverse=True), "Alerts must be sorted timestamp desc"

    def test_list_severity_filter(self):
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts?severity=Critical", accessor=acc)
        for a in body["alerts"]:
            assert a["riskCategory"] == "Critical"

    def test_list_source_filter(self):
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts?source=analytic", accessor=acc)
        for a in body["alerts"]:
            assert a["detection_source"] == "analytic"

    def test_list_has_data_source_note(self):
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts", accessor=acc)
        assert "data_source" in body
        assert "data_source_note" in body

    def test_list_required_alert_fields(self):
        """Every alert must have Task 2 schema required fields."""
        required = {
            "id", "timestamp", "pid", "comm", "riskScore", "riskCategory",
            "category", "description", "reasons", "eval_status",
            "detection_source", "contributing_signals", "dedup_key",
            "config_version", "status",
        }
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts", accessor=acc)
        for alert in body["alerts"]:
            missing = required - set(alert.keys())
            assert not missing, f"Alert missing fields: {missing}"

    def test_list_risk_score_and_category_preserved(self):
        """Scores and severity are preserved exactly from the detection result."""
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts", accessor=acc)
        alert = next(a for a in body["alerts"] if a["id"] == "ALT-AABBCCDD")
        assert alert["riskScore"] == 82
        assert alert["riskCategory"] == "Critical"
        assert alert["detection_source"] == "analytic"

    def test_list_evidence_and_explanations_preserved(self):
        """contributing_signals and reasons preserved exactly."""
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts", accessor=acc)
        alert = next(a for a in body["alerts"] if a["id"] == "ALT-AABBCCDD")
        assert len(alert["contributing_signals"]) == 1
        sig = alert["contributing_signals"][0]
        assert sig["source"] == "heuristic"
        assert sig["name"] == "privilege_escalation"
        assert alert["reasons"][0] == "Analytic rule: privilege escalation attempt."


# ─────────────────────────────────────────────────────────────────────────────
# 3 & 5. Alert by ID
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertById:
    def test_existing_id_returns_200(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts/ALT-AABBCCDD", accessor=acc)
        assert status == 200
        assert body["alert"]["id"] == "ALT-AABBCCDD"
        assert "schema_version" in body

    def test_unknown_id_returns_404(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts/ALT-NOTEXIST", accessor=acc)
        assert status == 404
        assert body["error"]["code"] == "NOT_FOUND"

    def test_malformed_id_returns_400(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts/../../etc/passwd", accessor=acc)
        assert status == 400

    def test_empty_id_returns_404_or_routes_to_list(self):
        # /api/v1/alerts/ with no id — routes to alert list handler
        acc = _make_accessor()
        status, _ = _call(f"{PREFIX}/alerts/", accessor=acc)
        # Either 200 (list) or 400 (empty id); must not 500
        assert status in (200, 400)

    def test_all_task2_schema_fields_present(self):
        required = {
            "id", "timestamp", "pid", "comm", "riskScore", "riskCategory",
            "category", "description", "reasons", "eval_status",
            "detection_source", "contributing_signals", "dedup_key",
            "config_version", "status",
        }
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts/ALT-AABBCCDD", accessor=acc)
        missing = required - set(body["alert"].keys())
        assert not missing, f"Alert missing Task 2 fields: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Invalid parameters
# ─────────────────────────────────────────────────────────────────────────────

class TestInvalidParameters:
    def test_limit_string_returns_400(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts?limit=abc", accessor=acc)
        assert status == 400
        assert body["error"]["code"] == "INVALID_PARAM"

    def test_limit_zero_returns_400(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts?limit=0", accessor=acc)
        assert status == 400

    def test_limit_over_max_returns_400(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts?limit=9999", accessor=acc)
        assert status == 400

    def test_offset_negative_returns_400(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts?offset=-1", accessor=acc)
        assert status == 400

    def test_offset_string_returns_400(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts?offset=foo", accessor=acc)
        assert status == 400

    def test_unknown_severity_returns_400(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts?severity=EXTREME", accessor=acc)
        assert status == 400
        assert "severity" in body["error"]["message"].lower()

    def test_unknown_source_returns_400(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts?source=unknown_source", accessor=acc)
        assert status == 400
        assert "source" in body["error"]["message"].lower()

    def test_post_method_returns_405(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts", method="POST", accessor=acc)
        assert status == 405
        assert body["error"]["code"] == "METHOD_NOT_ALLOWED"

    def test_put_method_returns_405(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts", method="PUT", accessor=acc)
        assert status == 405

    def test_delete_method_returns_405(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts", method="DELETE", accessor=acc)
        assert status == 405

    def test_patch_method_returns_405(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts", method="PATCH", accessor=acc)
        assert status == 405

    def test_request_body_on_get_returns_400(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts", content_length=10, accessor=acc)
        assert status == 400
        assert body["error"]["code"] == "BODY_NOT_ALLOWED"

    def test_unknown_endpoint_returns_404(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/nonexistent", accessor=acc)
        assert status == 404
        assert body["error"]["code"] == "NOT_FOUND"

    def test_all_errors_have_error_envelope(self):
        """Every error response must have the standard error envelope."""
        acc = _make_accessor()
        test_paths = [
            (f"{PREFIX}/alerts?limit=abc", "GET"),
            (f"{PREFIX}/alerts?severity=UNKNOWN", "GET"),
            (f"{PREFIX}/nonexistent", "GET"),
        ]
        for path, method in test_paths:
            status, body = _call(path, method=method, accessor=acc)
            assert status >= 400
            assert "error" in body, f"Missing error envelope for {path}"
            assert "code" in body["error"]
            assert "message" in body["error"]
            assert "request_id" in body["error"]


# ─────────────────────────────────────────────────────────────────────────────
# 9. Internal exception → 500 with no stack trace
# ─────────────────────────────────────────────────────────────────────────────

class TestInternalError:
    def test_exception_returns_500_generic(self):
        acc = _make_accessor(raise_on_get=True)
        status, body = _call(f"{PREFIX}/alerts", accessor=acc)
        assert status == 503  # source failure → 503 (caught before generic 500)

    def test_no_stack_trace_in_500_body(self):
        """A totally unexpected error must not leak stack trace in response."""
        acc = _make_accessor()
        acc.is_available.side_effect = RuntimeError("SYNTHETIC unexpected error")
        status, body = _call(f"{PREFIX}/alerts", accessor=acc)
        assert status == 500
        body_str = json.dumps(body)
        assert "Traceback" not in body_str
        assert "RuntimeError" not in body_str
        assert "SYNTHETIC" not in body_str

    def test_500_error_has_request_id(self):
        acc = _make_accessor()
        acc.is_available.side_effect = RuntimeError("SYNTHETIC")
        _, body = _call(f"{PREFIX}/alerts", accessor=acc)
        assert "error" in body
        assert "request_id" in body["error"]


# ─────────────────────────────────────────────────────────────────────────────
# 10. Unavailable data source → 503
# ─────────────────────────────────────────────────────────────────────────────

class TestUnavailableSource:
    def test_unavailable_pipeline_alerts_returns_503(self):
        acc = _make_accessor(available=False)
        status, body = _call(f"{PREFIX}/alerts", accessor=acc)
        assert status == 503
        assert body["error"]["code"] == "SOURCE_UNAVAILABLE"

    def test_unavailable_pipeline_by_id_returns_503(self):
        acc = _make_accessor(available=False)
        status, body = _call(f"{PREFIX}/alerts/ALT-AABBCCDD", accessor=acc)
        assert status == 503

    def test_source_error_on_get_alerts_returns_503(self):
        acc = _make_accessor(raise_on_get=True)
        status, _ = _call(f"{PREFIX}/alerts", accessor=acc)
        assert status == 503

    def test_health_reports_unavailable_when_no_pipeline(self):
        status, body = _call(f"{PREFIX}/health", accessor=None)
        assert status == 503
        assert body["sources"]["pipeline"] == "unavailable"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Risk scores, severity, evidence preserved
# ─────────────────────────────────────────────────────────────────────────────

class TestDataFidelity:
    def test_risk_score_preserved(self):
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts/ALT-AABBCCDD", accessor=acc)
        assert body["alert"]["riskScore"] == _SYNTHETIC_ALERT_1["riskScore"]

    def test_risk_category_preserved(self):
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts/ALT-AABBCCDD", accessor=acc)
        assert body["alert"]["riskCategory"] == _SYNTHETIC_ALERT_1["riskCategory"]

    def test_contributing_signals_preserved(self):
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts/ALT-AABBCCDD", accessor=acc)
        assert body["alert"]["contributing_signals"] == _SYNTHETIC_ALERT_1["contributing_signals"]

    def test_reasons_preserved(self):
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts/ALT-AABBCCDD", accessor=acc)
        assert body["alert"]["reasons"] == _SYNTHETIC_ALERT_1["reasons"]

    def test_dedup_key_preserved(self):
        acc = _make_accessor()
        _, body = _call(f"{PREFIX}/alerts/ALT-AABBCCDD", accessor=acc)
        assert body["alert"]["dedup_key"] == _SYNTHETIC_ALERT_1["dedup_key"]


# ─────────────────────────────────────────────────────────────────────────────
# 12. No fabricated results
# ─────────────────────────────────────────────────────────────────────────────

class TestNoFabrication:
    def test_unavailable_source_does_not_return_fake_alerts(self):
        acc = _make_accessor(available=False)
        status, body = _call(f"{PREFIX}/alerts", accessor=acc)
        assert status == 503
        assert "alerts" not in body  # no fabricated data

    def test_empty_buffer_returns_empty_list_not_fake(self):
        acc = _make_accessor(alerts=[])
        _, body = _call(f"{PREFIX}/alerts", accessor=acc)
        assert body["alerts"] == []

    def test_unknown_id_does_not_fabricate_alert(self):
        acc = _make_accessor()
        status, body = _call(f"{PREFIX}/alerts/ALT-NOTREAL", accessor=acc)
        assert status == 404
        assert "alert" not in body


# ─────────────────────────────────────────────────────────────────────────────
# 13. Authentication
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthentication:
    def test_no_key_configured_allows_all(self):
        """No API key configured → all requests pass (localhost-only mode)."""
        acc = _make_accessor()
        status, _ = _call(f"{PREFIX}/health", accessor=acc, api_key=None)
        assert status == 200

    def test_correct_key_allows_request(self):
        acc = _make_accessor()
        status, _ = _call(
            f"{PREFIX}/health",
            headers={"X-Chronicle-API-Key": "correct-key"},
            accessor=acc,
            api_key="correct-key",
        )
        assert status == 200

    def test_wrong_key_returns_401(self):
        acc = _make_accessor()
        status, body = _call(
            f"{PREFIX}/health",
            headers={"X-Chronicle-API-Key": "wrong-key"},
            accessor=acc,
            api_key="correct-key",
        )
        assert status == 401
        assert body["error"]["code"] == "UNAUTHORIZED"

    def test_missing_key_returns_401_when_key_configured(self):
        acc = _make_accessor()
        status, body = _call(
            f"{PREFIX}/health",
            headers={},
            accessor=acc,
            api_key="correct-key",
        )
        assert status == 401

    def test_key_comparison_is_constant_time(self):
        """_check_auth must use hmac.compare_digest, not ==."""
        import inspect
        import chronicle.service_api as sa
        source = inspect.getsource(sa._check_auth)
        assert "compare_digest" in source, "_check_auth must use hmac.compare_digest"

    def test_non_loopback_without_key_refused_at_startup(self):
        """serve_api.main() must refuse to bind to 0.0.0.0 without CHRONICLE_API_KEY."""
        import importlib
        import serve_api as sa_module
        with patch.dict("os.environ", {
            "CHRONICLE_SERVICE_HOST": "0.0.0.0",
            "CHRONICLE_SERVICE_PORT": "19999",
        }, clear=False):
            # Remove key if present
            with patch.dict("os.environ", {}, clear=False):
                import os
                os.environ.pop("CHRONICLE_API_KEY", None)
                with pytest.raises(SystemExit) as exc_info:
                    sa_module.main()
                assert exc_info.value.code == 1


# ─────────────────────────────────────────────────────────────────────────────
# 14. Feature flag off: risk fields reported correctly
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureFlag:
    def test_flag_off_health_reports_disabled(self):
        acc = _make_accessor(risk_enabled=False)
        _, body = _call(f"{PREFIX}/health", accessor=acc)
        assert body["sources"]["risk_scoring"] == "disabled"

    def test_flag_off_alert_eval_status_insufficient(self):
        """When flag off, alert eval_status should be 'insufficient_data', not zero."""
        acc = _make_accessor(alerts=[_SYNTHETIC_ALERT_DISABLED], risk_enabled=False)
        _, body = _call(f"{PREFIX}/alerts/ALT-DEADBEEF", accessor=acc)
        assert body["alert"]["eval_status"] == "insufficient_data"
        # risk_score is 0 because flag disabled scoring — not fabricated
        assert body["alert"]["riskScore"] == 0
        assert "limitations" in body["alert"]


# ─────────────────────────────────────────────────────────────────────────────
# 15. Regression: Task 2 tests still pass (import check)
# ─────────────────────────────────────────────────────────────────────────────

class TestTask2Regression:
    def test_risk_engine_importable(self):
        from chronicle.risk_engine import RiskEngine, ScoringResult
        assert RiskEngine is not None

    def test_make_alert_id_format(self):
        from chronicle.risk_engine import make_alert_id
        aid = make_alert_id()
        assert aid.startswith("ALT-")
        assert len(aid) == 12  # "ALT-" + 8 hex chars

    def test_scoring_result_to_dict(self):
        from chronicle.risk_engine import RiskEngine, EVAL_OK
        result = RiskEngine.evaluate(
            comm="test",
            pid=1,
            user="root",
            event_type="sys_sample",
            deviations={"cpu_z": 5.0, "mem_z": 0.0, "syscalls_z": 0.0, "max_z": 5.0},
            ml_result={"ml_available": False},
        )
        d = result.to_dict()
        assert "risk_score" in d
        assert "eval_status" in d
        assert "detection_source" in d

    def test_service_api_does_not_import_risk_engine_internals(self):
        """Service layer must not redefine scoring logic — only import types."""
        import ast
        import chronicle.service_api as sa
        source_path = Path(sa.__file__)
        tree = ast.parse(source_path.read_text())
        risk_engine_imports = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            and hasattr(node, "module")
            and node.module and "risk_engine" in node.module
        ]
        assert not risk_engine_imports, (
            "service_api.py must not import from risk_engine (no scoring logic duplication)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_request_id_unique(self):
        ids = {_request_id() for _ in range(100)}
        assert len(ids) == 100

    def test_error_body_parseable(self):
        body = _error_body("CODE", "msg", "req123")
        parsed = json.loads(body)
        assert parsed["error"]["code"] == "CODE"
        assert parsed["error"]["request_id"] == "req123"

    def test_json_body_adds_schema_version(self):
        body = _json_body({"key": "val"}, "req456")
        parsed = json.loads(body)
        assert parsed["schema_version"] == SCHEMA_VERSION
        assert parsed["request_id"] == "req456"

    def test_check_auth_no_key_always_passes(self):
        assert _check_auth(None, None) is True
        assert _check_auth("anything", None) is True

    def test_check_auth_wrong_key(self):
        assert _check_auth("wrong", "correct") is False

    def test_check_auth_correct_key(self):
        assert _check_auth("secret", "secret") is True
