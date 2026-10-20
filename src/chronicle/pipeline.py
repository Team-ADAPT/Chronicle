"""
Chronicle - Telemetry & Detection Pipeline Orchestrator
Connects eBPF/psutil telemetry collection, historical baselines (DBMS),
in-process ML detection (Isolation Forest / XGBoost), and risk scoring.
"""
from __future__ import annotations

import collections
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from chronicle.config import ChronicleConfig
from chronicle.collector import TelemetryCollector, classify_process_cluster
from chronicle.ml_detector import MLDetectionEngine
from chronicle.risk_engine import RiskEngine, ScoringResult
from chronicle.storage import ChronicleDatabase, ProcessProfile

logger = logging.getLogger("chronicle.pipeline")


class ChroniclePipeline:
    """The central orchestrator linking the OS observer, DBMS memory, and ML detector."""

    def __init__(self, config: Optional[ChronicleConfig] = None):
        self.config = config or ChronicleConfig()
        self.db = ChronicleDatabase(self.config.db_path)
        self.ml_engine = MLDetectionEngine(self.config.ml_models_dir)
        self.collector = TelemetryCollector(enable_ebpf=self.config.enable_ebpf)

        self._lock = threading.Lock()
        self.is_running = False
        self._thread: Optional[threading.Thread] = None

        # In-memory fast ring-buffers for real-time UI streaming
        self.recent_events: collections.deque[Dict[str, Any]] = collections.deque(maxlen=self.config.max_recent_events)
        self.active_alerts: collections.deque[Dict[str, Any]] = collections.deque(maxlen=self.config.max_active_alerts)
        
        # Historical process profiles (in-memory cache backed by DB)
        self.profiles: Dict[str, ProcessProfile] = {}
        self._seed_baseline_profiles()

        # Telemetry statistics counters
        self.total_events_processed = 0
        self.total_anomalies_detected = 0
        self.total_invalid_events = 0
        self.total_scoring_failures = 0

    def _seed_baseline_profiles(self) -> None:
        """Establish baseline profiles from initial live host process inspection."""
        try:
            initial_procs = self.collector.sample_active_processes(limit=40)
            for p in initial_procs:
                comm = p["comm"]
                prof = ProcessProfile(comm=comm, user=p["user"])
                prof.update(cpu=p["cpu"], mem=p["mem"], syscalls=p["syscalls"], event_type="sys_sample")
                self.profiles[comm] = prof
        except Exception as exc:
            logger.debug("Baseline profile initialization: %s", exc)

    def process_raw_event(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a single raw telemetry event through:
        1. Input validation (invalid events are counted, not discarded)
        2. Historical profile deviation analysis (Z-score)
        3. ML anomaly & attack inference (Isolation Forest + XGBoost)
        4. Risk scoring and explainability generation (gated by feature flag)
        5. Storage & alert generation

        Per-event exceptions are caught so that one malformed event cannot
        halt processing of subsequent valid events.
        """
        try:
            return self._process_event_inner(ev)
        except Exception as exc:
            logger.warning("Unhandled error processing event %s: %s", ev.get("id"), exc)
            with self._lock:
                self.total_invalid_events += 1
            # Return a minimal safe record so callers don't crash
            return {
                "id": ev.get("id", "unknown"),
                "timestamp": ev.get("timestamp", ""),
                "pid": ev.get("pid", 0),
                "ppid": ev.get("ppid", 1),
                "comm": ev.get("comm", "unknown"),
                "user": ev.get("user", "system"),
                "eventType": ev.get("eventType", "sys_sample"),
                "cpu": 0.0,
                "mem": 0.0,
                "syscalls": 0,
                "riskScore": 0,
                "status": "SAFE",
                "anomalyDetails": f"Event processing failed: {exc}",
                "deviation": "N/A",
                "mlScore": 0.0,
                "xgbAttackProb": 0.0,
                "terminated": False,
                "eval_status": "scoring_error",
            }

    def _process_event_inner(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        """Inner implementation of process_raw_event."""
        comm = ev.get("comm") or "unknown"
        pid = ev.get("pid", 0)
        user = ev.get("user", "system")
        cpu = ev.get("cpu", 0.0)
        mem = ev.get("mem", 0.0)
        syscalls = ev.get("syscalls", 0)
        seq = ev.get("syscall_sequence", ["read", "write"])
        heuristics = ev.get("heuristic_flags", [])
        event_ts = ev.get("timestamp") or datetime.now(timezone.utc).strftime("%H:%M:%S")
        ppid = ev.get("ppid", 1)

        # 1. Historical Baseline Comparison
        with self._lock:
            prof = self.profiles.setdefault(comm, ProcessProfile(comm=comm, user=user))
            deviations = prof.evaluate_deviations(cpu=cpu, mem=mem, syscalls=syscalls)
            prof.update(cpu=cpu, mem=mem, syscalls=syscalls, event_type=ev.get("eventType", "sys_sample"))

        # 2. Machine Learning Anomaly Detection
        ml_result = self.ml_engine.predict_sequence(seq)
        if ml_result.get("error"):
            with self._lock:
                self.total_scoring_failures += 1

        # 3. Contextual Risk & Explainability Evaluation (feature-flag gated)
        scoring_result: ScoringResult = RiskEngine.evaluate(
            comm=comm,
            pid=pid,
            user=user,
            event_type=ev.get("eventType", "sys_sample"),
            deviations=deviations,
            ml_result=ml_result,
            heuristic_flags=heuristics,
            event_timestamp=event_ts,
            ppid=ppid,
            enabled=self.config.enable_risk_scoring,
        )

        if scoring_result.eval_status == "scoring_error":
            with self._lock:
                self.total_scoring_failures += 1

        risk_score = scoring_result.risk_score
        status = scoring_result.status

        # Enriched event record (backward-compatible fields + new eval fields)
        enriched = {
            "id": ev.get("id") or f"evt-{uuid.uuid4().hex[:8]}",
            "timestamp": event_ts,
            "pid": pid,
            "ppid": ppid,
            "comm": comm,
            "user": user,
            "cluster": ev.get("cluster") or classify_process_cluster(comm, user),
            "eventType": ev.get("eventType", "sys_sample"),
            "cpu": cpu,
            "mem": mem,
            "net_kb": float(ev.get("net_kb", ev.get("netKb", 0.0)) or 0.0),
            "syscalls": syscalls,
            "riskScore": risk_score,
            "riskCategory": scoring_result.risk_category,
            "status": status,
            "eval_status": scoring_result.eval_status,
            "anomalyDetails": scoring_result.anomaly_details,
            "deviation": f"Max Z: {deviations.get('max_z', 0.0)}σ",
            "mlScore": ml_result.get("if_score", 0.0),
            "xgbAttackProb": ml_result.get("xgb_prob", 0.0),
            "detection_source": scoring_result.detection_source,
            "terminated": False,
        }

        with self._lock:
            self.recent_events.appendleft(enriched)
            self.total_events_processed += 1

            # 4. Alert Generation (only for genuine high-risk or heuristic/ML attacks)
            # Statistical drift alone (Medium risk < 50) is logged as normal telemetry, not a security alert.
            is_security_alert = (
                self.config.enable_risk_scoring
                and scoring_result.eval_status == "evaluated"
                and (
                    status == "ANOMALOUS"
                    or risk_score >= 50
                    or len(heuristics) > 0
                    or ml_result.get("xgb_attack", False)
                )
            )
            if is_security_alert:
                self.total_anomalies_detected += 1
                alert = RiskEngine.create_alert(
                    comm=comm,
                    pid=pid,
                    risk_score=risk_score,
                    category=scoring_result.category,
                    reasons=scoring_result.reasons,
                    description=ev.get("description", ""),
                    scoring_result=scoring_result,
                    event_id=ev.get("id"),
                    event_timestamp=event_ts,
                    ppid=ppid,
                    user=user,
                )
                self.active_alerts.appendleft(alert)
                try:
                    self.db.insert_alert(alert)
                except Exception as exc:
                    logger.warning("DB insert alert error: %s", exc)

            try:
                self.db.insert_event(enriched)
            except Exception as exc:
                logger.warning("DB insert event error: %s", exc)

        return enriched

    def start(self) -> None:
        """Starts the background telemetry collection worker thread."""
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="ChroniclePipelineWorker")
            self._thread.start()
            logger.info("Chronicle background telemetry pipeline started.")

    def stop(self) -> None:
        """Stops the pipeline gracefully."""
        with self._lock:
            self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("Chronicle background telemetry pipeline stopped.")

    def _worker_loop(self) -> None:
        """Background sampling loop for real Linux kernel eBPF and host telemetry."""
        while self.is_running:
            try:
                # 1. If kernel eBPF probes are active on Linux, poll kernel perf buffer
                if self.collector.ebpf_enabled:
                    kernel_events = self.collector.poll_kernel_events(timeout_ms=120)
                    for ev in kernel_events:
                        self.process_raw_event(ev)

                # 2. Sample live host processes currently active on machine
                live_proc_events = self.collector.sample_active_processes(limit=12)
                for ev in live_proc_events:
                    self.process_raw_event(ev)

                # 3. Record real host system metrics
                sys_metrics = self.collector.get_system_metrics()
                normalcy = self.get_normalcy_percent()
                sys_metrics["normalcy_percent"] = normalcy
                self.db.insert_system_metric(sys_metrics)
            except Exception as exc:
                logger.warning("Error in pipeline worker loop: %s", exc)

            time.sleep(self.config.sample_interval)

    def inject_simulation(self, scenario_key: str) -> Dict[str, Any]:
        """Manually injects an attack simulation event through the full pipeline."""
        raw_event = self.collector.generate_attack_event(scenario_key)
        enriched = self.process_raw_event(raw_event)
        return enriched

    def kill_process(self, pid: int) -> bool:
        """Terminates a process or marks it terminated in the feed."""
        if pid <= 0:
            return False

        terminated = False
        try:
            p = psutil.Process(pid)
            p.terminate()
            terminated = True
        except Exception:
            pass

        with self._lock:
            for ev in self.recent_events:
                if ev.get("pid") == pid:
                    ev["terminated"] = True
                    ev["status"] = "SAFE"
                    ev["riskScore"] = 5
                    ev["anomalyDetails"] = "Process terminated via simulated SIGKILL."
        return terminated

    def acknowledge_alert(self, alert_id: str) -> None:
        with self._lock:
            self.db.update_alert_status(alert_id, "ACKNOWLEDGED")
            for a in self.active_alerts:
                if a["id"] == alert_id:
                    a["status"] = "ACKNOWLEDGED"

    def acknowledge_all_alerts(self) -> int:
        with self._lock:
            acknowledged_count = self.db.update_active_alerts_status("ACKNOWLEDGED")
            for alert in self.active_alerts:
                if alert["status"] == "ACTIVE":
                    alert["status"] = "ACKNOWLEDGED"
            return acknowledged_count

    def get_normalcy_percent(self) -> int:
        with self._lock:
            if not self.recent_events:
                return 96
            anom_count = sum(1 for e in self.recent_events if e["status"] == "ANOMALOUS")
            total = len(self.recent_events)
            pct = 100 - int((anom_count / total) * 100)
            return max(50, min(99, pct))

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.recent_events)[:limit]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.active_alerts)[:limit]

    def get_profiles(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {k: v.to_dict() for k, v in self.profiles.items()}

    def get_stats(self) -> Dict[str, Any]:
        sys_metrics = self.collector.get_system_metrics()
        normalcy = self.get_normalcy_percent()
        with self._lock:
            total_active_alerts = sum(1 for a in self.active_alerts if a["status"] == "ACTIVE")
            active_anomalies = sum(1 for e in self.recent_events if e["status"] == "ANOMALOUS")
            active_suspicious = sum(1 for e in self.recent_events if e["status"] == "SUSPICIOUS")

        sys_metrics["normalcy_percent"] = normalcy
        sys_metrics["active_alerts_count"] = total_active_alerts
        sys_metrics["anomalous_processes_count"] = active_anomalies
        sys_metrics["suspicious_processes_count"] = active_suspicious
        sys_metrics["ebpf_active"] = self.collector.ebpf_enabled
        sys_metrics["ml_models_loaded"] = self.ml_engine.loaded
        sys_metrics["risk_scoring_enabled"] = self.config.enable_risk_scoring
        sys_metrics["total_invalid_events"] = self.total_invalid_events
        sys_metrics["total_scoring_failures"] = self.total_scoring_failures
        return sys_metrics

    def get_process_history(self, comm: str, pid: Optional[int] = None, days: int = 7, limit: int = 200) -> Dict[str, Any]:
        """Queries historical process telemetry directly from the local SQLite database."""
        return self.db.get_process_history(comm=comm, pid=pid, days=days, limit=limit)
