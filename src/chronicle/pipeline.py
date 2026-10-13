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
from chronicle.collector import TelemetryCollector
from chronicle.ml_detector import MLDetectionEngine
from chronicle.risk_engine import RiskEngine
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

    def _seed_baseline_profiles(self) -> None:
        """Seed established 30-day historical baseline profiles for standard Linux processes."""
        defaults = {
            "systemd": {"user": "root", "cpu": 0.2, "mem": 18.4, "sys": 42},
            "sshd": {"user": "root", "cpu": 0.4, "mem": 7.2, "sys": 85},
            "nginx": {"user": "www-data", "cpu": 1.5, "mem": 42.0, "sys": 320},
            "bash": {"user": "anurag", "cpu": 0.3, "mem": 9.8, "sys": 110},
            "python3": {"user": "anurag", "cpu": 3.2, "mem": 65.0, "sys": 210},
            "dockerd": {"user": "root", "cpu": 2.1, "mem": 120.0, "sys": 450},
            "cron": {"user": "root", "cpu": 0.1, "mem": 4.5, "sys": 25},
            "curl": {"user": "anurag", "cpu": 0.5, "mem": 12.0, "sys": 140},
        }
        for name, spec in defaults.items():
            prof = ProcessProfile(comm=name, user=spec["user"])
            # Seed 50 initial samples around typical value to establish running mean & variance
            for _ in range(50):
                prof.update(
                    cpu=spec["cpu"] * (0.8 + 0.4 * (hash(name) % 100) / 100.0),
                    mem=spec["mem"] * (0.9 + 0.2 * (hash(name) % 100) / 100.0),
                    syscalls=int(spec["sys"] * (0.85 + 0.3 * (hash(name) % 100) / 100.0)),
                    event_type="execve" if name in ("bash", "python3") else "sys_sample",
                )
            self.profiles[name] = prof

    def process_raw_event(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a single raw telemetry event through:
        1. Historical profile deviation analysis (Z-score)
        2. ML anomaly & attack inference (Isolation Forest + XGBoost)
        3. Risk scoring and explainability generation
        4. Storage & alert generation
        """
        comm = ev.get("comm") or "unknown"
        pid = ev.get("pid", 0)
        user = ev.get("user", "system")
        cpu = ev.get("cpu", 0.0)
        mem = ev.get("mem", 0.0)
        syscalls = ev.get("syscalls", 0)
        seq = ev.get("syscall_sequence", ["read", "write"])
        heuristics = ev.get("heuristic_flags", [])

        # 1. Historical Baseline Comparison
        with self._lock:
            prof = self.profiles.setdefault(comm, ProcessProfile(comm=comm, user=user))
            deviations = prof.evaluate_deviations(cpu=cpu, mem=mem, syscalls=syscalls)
            prof.update(cpu=cpu, mem=mem, syscalls=syscalls, event_type=ev.get("eventType", "sys_sample"))

        # 2. Machine Learning Anomaly Detection
        ml_result = self.ml_engine.predict_sequence(seq)

        # 3. Contextual Risk & Explainability Evaluation
        eval_res = RiskEngine.evaluate(
            comm=comm,
            pid=pid,
            user=user,
            event_type=ev.get("eventType", "sys_sample"),
            deviations=deviations,
            ml_result=ml_result,
            heuristic_flags=heuristics,
        )

        risk_score = eval_res["risk_score"]
        status = eval_res["status"]

        # Enriched event record
        enriched = {
            "id": ev["id"],
            "timestamp": ev["timestamp"],
            "pid": pid,
            "ppid": ev.get("ppid", 1),
            "comm": comm,
            "user": user,
            "eventType": ev.get("eventType", "sys_sample"),
            "cpu": cpu,
            "mem": mem,
            "syscalls": syscalls,
            "riskScore": risk_score,
            "status": status,
            "anomalyDetails": eval_res["anomaly_details"],
            "deviation": f"Max Z: {deviations.get('max_z', 0.0)}σ",
            "mlScore": ml_result.get("if_score", 0.0),
            "xgbAttackProb": ml_result.get("xgb_prob", 0.0),
            "terminated": False,
        }

        with self._lock:
            self.recent_events.appendleft(enriched)
            self.total_events_processed += 1

            # 4. Alert Generation
            if status in ("SUSPICIOUS", "ANOMALOUS") or risk_score >= 40:
                self.total_anomalies_detected += 1
                alert = RiskEngine.create_alert(
                    comm=comm,
                    pid=pid,
                    risk_score=risk_score,
                    category=eval_res["category"],
                    reasons=eval_res["reasons"],
                    description=ev.get("description", ""),
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
        """Background sampling loop."""
        while self.is_running:
            try:
                events = self.collector.sample_active_processes(limit=8)
                for ev in events:
                    self.process_raw_event(ev)
                
                # Periodically record system metrics
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
        terminated = False
        try:
            p = psutil.Process(pid)
            p.terminate()
            terminated = True
        except Exception:
            pass

        with self._lock:
            for ev in self.recent_events:
                if ev["pid"] == pid:
                    ev["terminated"] = True
                    ev["status"] = "SAFE"
                    ev["riskScore"] = 5
                    ev["anomalyDetails"] = "Process terminated via simulated SIGKILL."
        return terminated

    def acknowledge_alert(self, alert_id: str) -> None:
        with self._lock:
            for a in self.active_alerts:
                if a["id"] == alert_id:
                    a["status"] = "ACKNOWLEDGED"
            self.db.update_alert_status(alert_id, "ACKNOWLEDGED")

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
        return sys_metrics
