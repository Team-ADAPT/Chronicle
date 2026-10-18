"""
Chronicle - REST API Handler Module
Exposes endpoints for real-time telemetry streaming, alerts, profiles,
simulation injection, and process termination.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from chronicle.pipeline import ChroniclePipeline


class ChronicleAPIHandler:
    """Dispatches HTTP requests to the ChroniclePipeline."""

    def __init__(self, pipeline: ChroniclePipeline):
        self.pipeline = pipeline

    def handle_request(self, method: str, path: str, body_bytes: bytes = b"") -> Tuple[int, str, bytes]:
        """
        Handles an incoming HTTP API request.
        Returns: (status_code, content_type, response_body_bytes)
        """
        parsed = urlparse(path)
        route = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        headers = "application/json"

        # Parse JSON body if present
        data: Dict[str, Any] = {}
        if body_bytes:
            try:
                data = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                return 400, headers, json.dumps({"error": "Malformed JSON in request body"}).encode("utf-8")

        try:
            if method == "GET":
                if route == "/api/status":
                    res = {
                        "status": "healthy",
                        "version": "0.2.0",
                        "ebpf_active": self.pipeline.collector.ebpf_enabled,
                        "ml_loaded": self.pipeline.ml_engine.loaded,
                        "events_processed": self.pipeline.total_events_processed,
                        "anomalies_detected": self.pipeline.total_anomalies_detected,
                    }
                    return 200, headers, json.dumps(res).encode("utf-8")

                elif route == "/api/events":
                    try:
                        limit = max(1, min(1000, int(query.get("limit", [100])[0])))
                    except (ValueError, TypeError):
                        limit = 100
                    events = self.pipeline.get_events(limit=limit)
                    return 200, headers, json.dumps(events).encode("utf-8")

                elif route == "/api/alerts":
                    try:
                        limit = max(1, min(1000, int(query.get("limit", [50])[0])))
                    except (ValueError, TypeError):
                        limit = 50
                    alerts = self.pipeline.get_alerts(limit=limit)
                    return 200, headers, json.dumps(alerts).encode("utf-8")

                elif route == "/api/profiles":
                    profiles = self.pipeline.get_profiles()
                    return 200, headers, json.dumps(profiles).encode("utf-8")

                elif route == "/api/stats":
                    stats = self.pipeline.get_stats()
                    return 200, headers, json.dumps(stats).encode("utf-8")

            elif method == "POST":
                if route == "/api/simulate":
                    scenario = data.get("scenario") or "interactive_shell_from_daemon"
                    enriched = self.pipeline.inject_simulation(scenario)
                    return 200, headers, json.dumps({"status": "success", "event": enriched}).encode("utf-8")

                elif route == "/api/kill":
                    try:
                        pid = int(data.get("pid", 0))
                    except (ValueError, TypeError):
                        pid = 0
                    if pid <= 0:
                        return 400, headers, json.dumps({"error": "Invalid or missing PID"}).encode("utf-8")
                    terminated = self.pipeline.kill_process(pid)
                    return 200, headers, json.dumps({"status": "success", "terminated": terminated, "pid": pid}).encode("utf-8")

                elif route == "/api/alerts/ack":
                    alert_id = str(data.get("id") or "")
                    self.pipeline.acknowledge_alert(alert_id)
                    return 200, headers, json.dumps({"status": "success", "id": alert_id}).encode("utf-8")

                elif route == "/api/alerts/ack-all":
                    acknowledged_count = self.pipeline.acknowledge_all_alerts()
                    return 200, headers, json.dumps({
                        "status": "success",
                        "acknowledged_count": acknowledged_count,
                    }).encode("utf-8")

            return 404, headers, json.dumps({"error": "Endpoint not found", "route": route}).encode("utf-8")

        except Exception as exc:
            return 500, headers, json.dumps({"error": str(exc)}).encode("utf-8")
