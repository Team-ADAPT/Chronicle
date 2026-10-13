"""
Chronicle - Storage & Historical Profiler Module (DBMS Layer)
Implements local SQLite database storage and Welford's online algorithm
for persistent process-specific behavioural baselines.
"""
from __future__ import annotations

import json
import math
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class OnlineMetric:
    """Welford's algorithm for numerically stable running mean and standard deviation."""
    __slots__ = ("count", "mean", "m2", "min_val", "max_val")

    def __init__(self, count: int = 0, mean: float = 0.0, m2: float = 0.0, min_val: float = float("inf"), max_val: float = float("-inf")):
        self.count = count
        self.mean = mean
        self.m2 = m2
        self.min_val = min_val if min_val != float("inf") else 0.0
        self.max_val = max_val if max_val != float("-inf") else 0.0

    def update(self, x: float) -> None:
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.m2 += delta * delta2
        if self.count == 1:
            self.min_val = x
            self.max_val = x
        else:
            if x < self.min_val:
                self.min_val = x
            if x > self.max_val:
                self.max_val = x

    @property
    def variance(self) -> float:
        return self.m2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, x: float, min_std: float = 0.01) -> float:
        s = max(self.std, min_std)
        return abs(x - self.mean) / s

    def ratio(self, x: float) -> float:
        return x / self.mean if self.mean > 1e-6 else (1.0 if x == 0 else float("inf"))

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "mean": round(self.mean, 4),
            "m2": round(self.m2, 4),
            "std": round(self.std, 4),
            "min_val": round(self.min_val, 4),
            "max_val": round(self.max_val, 4),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "OnlineMetric":
        return cls(
            count=d.get("count", 0),
            mean=d.get("mean", 0.0),
            m2=d.get("m2", 0.0),
            min_val=d.get("min_val", 0.0),
            max_val=d.get("max_val", 0.0),
        )


class ProcessProfile:
    """Historical behavioural baseline for a process identity."""

    def __init__(self, comm: str, user: str = "root", path: str = ""):
        self.comm = comm
        self.user = user
        self.path = path or f"/usr/bin/{comm}"
        self.cpu = OnlineMetric()
        self.mem = OnlineMetric()
        self.syscalls = OnlineMetric()
        self.file_ops = OnlineMetric()
        self.net_conns = OnlineMetric()
        self.typical_events: set[str] = set()
        self.sample_count: int = 0
        self.cluster: str = self._assign_cluster(comm)

    @staticmethod
    def _assign_cluster(comm: str) -> str:
        if comm in ("systemd", "systemd-udevd", "journald", "init", "kthreadd"):
            return "systemd"
        if comm in ("nginx", "apache2", "sshd", "caddy", "envoy"):
            return "nginx"
        if comm in ("bash", "sh", "zsh", "python3", "python", "node", "ruby"):
            return "bash"
        if comm in ("dockerd", "containerd", "docker", "podman", "kubelet"):
            return "dockerd"
        return "systemd"

    def update(self, cpu: float, mem: float, syscalls: int, event_type: str = "telemetry", file_ops: int = 0, net_conns: int = 0) -> None:
        self.sample_count += 1
        self.cpu.update(cpu)
        self.mem.update(mem)
        self.syscalls.update(float(syscalls))
        self.file_ops.update(float(file_ops))
        self.net_conns.update(float(net_conns))
        if event_type:
            self.typical_events.add(event_type)

    def evaluate_deviations(self, cpu: float, mem: float, syscalls: int) -> Dict[str, Any]:
        """Calculates Z-scores and deviations before updating baselines."""
        cpu_z = self.cpu.z_score(cpu, min_std=0.2) if self.cpu.count >= 2 else 0.0
        mem_z = self.mem.z_score(mem, min_std=1.0) if self.mem.count >= 2 else 0.0
        sys_z = self.syscalls.z_score(float(syscalls), min_std=5.0) if self.syscalls.count >= 2 else 0.0
        
        max_z = max(cpu_z, mem_z, sys_z)
        return {
            "cpu_z": round(cpu_z, 2),
            "mem_z": round(mem_z, 2),
            "syscalls_z": round(sys_z, 2),
            "max_z": round(max_z, 2),
            "cpu_deviation": round(cpu - self.cpu.mean, 2),
            "mem_deviation": round(mem - self.mem.mean, 2),
            "syscalls_deviation": round(syscalls - self.syscalls.mean, 2),
        }

    def to_dict(self) -> dict:
        return {
            "comm": self.comm,
            "user": self.user,
            "path": self.path,
            "avgCpu": round(self.cpu.mean, 2),
            "stdCpu": round(self.cpu.std, 2),
            "avgMem": round(self.mem.mean, 2),
            "stdMem": round(self.mem.std, 2),
            "avgSyscalls": round(self.syscalls.mean, 1),
            "stdSyscalls": round(self.syscalls.std, 1),
            "cluster": self.cluster,
            "sampleCount": self.sample_count,
            "typicalEvents": list(self.typical_events) if self.typical_events else ["execve", "fork"],
        }


class ChronicleDatabase:
    """SQLite local database for structured historical telemetry and alerting."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS process_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                pid INTEGER NOT NULL,
                ppid INTEGER,
                comm TEXT NOT NULL,
                user TEXT NOT NULL,
                event_type TEXT NOT NULL,
                cpu REAL NOT NULL,
                mem REAL NOT NULL,
                syscalls INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                anomaly_details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_events_pid ON process_events(pid);
            CREATE INDEX IF NOT EXISTS idx_events_comm ON process_events(comm);
            CREATE INDEX IF NOT EXISTS idx_events_time ON process_events(timestamp);

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                pid INTEGER NOT NULL,
                comm TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                reasons TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                cpu_percent REAL NOT NULL,
                mem_used_mb REAL NOT NULL,
                mem_total_mb REAL NOT NULL,
                syscall_rate REAL NOT NULL,
                normalcy_percent REAL NOT NULL,
                process_count INTEGER NOT NULL
            );
            """)

    def insert_event(self, ev: Dict[str, Any]) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO process_events 
            (id, timestamp, pid, ppid, comm, user, event_type, cpu, mem, syscalls, risk_score, status, anomaly_details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ev["id"], ev["timestamp"], ev["pid"], ev.get("ppid", 1),
                ev["comm"], ev["user"], ev["eventType"], ev["cpu"], ev["mem"],
                ev["syscalls"], ev["riskScore"], ev["status"], ev.get("anomalyDetails", "")
            ))

    def insert_alert(self, alert: Dict[str, Any]) -> None:
        reasons_json = json.dumps(alert.get("reasons", [])) if isinstance(alert.get("reasons"), list) else str(alert.get("reasons", ""))
        with self._lock, self._get_connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO alerts 
            (id, timestamp, pid, comm, risk_score, category, description, reasons, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["id"], alert["timestamp"], alert["pid"], alert["comm"],
                alert["riskScore"], alert["category"], alert["description"],
                reasons_json, alert.get("status", "ACTIVE")
            ))

    def update_alert_status(self, alert_id: str, new_status: str) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))

    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock, self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM process_events ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_active_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock, self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM alerts WHERE status = 'ACTIVE' ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            res = []
            for r in rows:
                d = dict(r)
                try:
                    d["reasons"] = json.loads(d["reasons"])
                except Exception:
                    pass
                res.append(d)
            return res

    def insert_system_metric(self, metrics: Dict[str, Any]) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute("""
            INSERT INTO system_metrics (timestamp, cpu_percent, mem_used_mb, mem_total_mb, syscall_rate, normalcy_percent, process_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                metrics["timestamp"], metrics["cpu_percent"], metrics["mem_used_mb"],
                metrics["mem_total_mb"], metrics["syscall_rate"], metrics["normalcy_percent"],
                metrics["process_count"]
            ))
