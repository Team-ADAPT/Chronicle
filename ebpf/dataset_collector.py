#!/usr/bin/env python3
"""
CHRONICLE — An Intelligent Historical Behaviour Analysis System
Linux Behavioural Telemetry Collector

This program collects Linux host behavioural telemetry (system, process,
network, disk, and — where eBPF/BCC is available — kernel-level syscall,
file and process-lifecycle events), maintains lightweight historical
behavioural profiles per process, computes current-vs-historical deviation
features, and writes everything to a local CSV dataset suitable for later
ML experimentation (XGBoost / Isolation Forest / Random Forest).

IMPORTANT DESIGN NOTES
-----------------------
* psutil is used for system/process/network/disk *statistics*.
* BCC/eBPF is used for kernel-level *events* (execve, fork/clone, exit,
  file open/unlink, socket connect). These are two different sources and
  are never conflated: psutil alone CANNOT see raw syscalls.
* No file contents, keystrokes, passwords, packet payloads, environment
  variables, clipboard, screenshots, or audio/video are ever collected.
* The collector performs NO classification, NO ML training, and makes NO
  network connections of its own. All data stays local.
* Everything lives in this single file, but is organised internally into
  cohesion-focused classes that mirror a modular architecture so that the
  CSV writer can later be swapped for a PostgreSQL writer with minimal
  change to the rest of the pipeline.

Run with:
    sudo python3 dataset_collector.py --interval 5 --window 60 --label BENIGN

Stop with Ctrl+C or SIGTERM. Shutdown is graceful: the queue is flushed,
CSV files are closed cleanly, and final statistics are printed.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import json
import logging
import math
import os
import platform
import queue
import signal
import socket as pysocket
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:
    print("FATAL: psutil is required. Install with: pip install psutil", file=sys.stderr)
    sys.exit(1)

# BCC/eBPF is optional. The collector must degrade gracefully without it.
try:
    from bcc import BPF  # type: ignore
    _BCC_IMPORT_OK = True
except Exception:
    BPF = None  # type: ignore
    _BCC_IMPORT_OK = False


# =====================================================================
# 1. CONFIGURATION
# =====================================================================

@dataclass
class Configuration:
    """All tunable behaviour lives here. CLI flags override these defaults."""

    # Sampling / windowing
    sample_interval: float = 5.0          # seconds, system/process/network/disk polling
    feature_window: float = 60.0          # seconds, behavioural aggregation window

    # Output
    output_directory: str = "chronicle_data"
    single_csv: bool = True
    max_rows_per_file: int = 1_000_000
    profiles_file: str = "chronicle_profiles.json"

    # Queueing / memory protection
    max_queue_size: int = 200_000
    writer_batch_size: int = 500
    writer_flush_interval: float = 2.0

    # Privacy
    hash_file_paths: bool = True
    hash_ip_addresses: bool = False
    store_command_line: bool = False

    # Component toggles
    enable_ebpf: bool = True
    enable_process_monitoring: bool = True
    enable_network_monitoring: bool = True
    enable_disk_monitoring: bool = True
    enable_feature_aggregation: bool = True

    # Disk protection
    min_free_disk_gb: float = 5.0
    disk_check_interval: float = 30.0

    # Labeling
    session_label: str = "UNKNOWN"          # BENIGN | ATTACK | UNKNOWN
    attack_scenario: Optional[str] = None
    attack_id: Optional[str] = None

    # Logging
    log_level: str = "INFO"
    stats_report_interval: float = 60.0

    # Historical profile persistence
    profile_persist_interval: float = 120.0
    profile_max_processes: int = 5000       # bound the profile store size


def build_config_from_cli(argv: Optional[List[str]] = None) -> Configuration:
    parser = argparse.ArgumentParser(
        description="Chronicle Linux Behavioural Telemetry Collector"
    )
    parser.add_argument("--interval", type=float, default=None, help="System/process sample interval (seconds)")
    parser.add_argument("--window", type=float, default=None, help="Behavioural feature window (seconds)")
    parser.add_argument("--output", type=str, default=None, help="Output directory")
    parser.add_argument("--no-ebpf", action="store_true", help="Disable eBPF collection")
    parser.add_argument("--no-processes", action="store_true", help="Disable per-process monitoring")
    parser.add_argument("--no-network", action="store_true", help="Disable network monitoring")
    parser.add_argument("--no-features", action="store_true", help="Disable behavioural feature aggregation")
    parser.add_argument("--unhashed-paths", action="store_true", help="Store raw file paths instead of hashes")
    parser.add_argument("--command-line", action="store_true", help="Store sanitized command-line strings")
    parser.add_argument("--label", type=str, default=None, choices=["BENIGN", "ATTACK", "UNKNOWN"])
    parser.add_argument("--attack-scenario", type=str, default=None)
    parser.add_argument("--attack-id", type=str, default=None)
    parser.add_argument("--log-level", type=str, default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args(argv)

    cfg = Configuration()
    if args.interval is not None:
        cfg.sample_interval = args.interval
    if args.window is not None:
        cfg.feature_window = args.window
    if args.output is not None:
        cfg.output_directory = args.output
    if args.no_ebpf:
        cfg.enable_ebpf = False
    if args.no_processes:
        cfg.enable_process_monitoring = False
    if args.no_network:
        cfg.enable_network_monitoring = False
    if args.no_features:
        cfg.enable_feature_aggregation = False
    if args.unhashed_paths:
        cfg.hash_file_paths = False
    if args.command_line:
        cfg.store_command_line = True
    if args.label is not None:
        cfg.session_label = args.label
    if args.attack_scenario is not None:
        cfg.attack_scenario = args.attack_scenario
    if args.attack_id is not None:
        cfg.attack_id = args.attack_id
    if args.log_level is not None:
        cfg.log_level = args.log_level
    return cfg


# =====================================================================
# 2. UTILITIES
# =====================================================================

def utc_now_iso() -> str:
    """UTC ISO-8601 timestamp, e.g. 2026-09-15T12:35:42.123456+00:00"""
    return datetime.now(timezone.utc).isoformat()


def make_session_id() -> str:
    return f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"


def get_host_id() -> str:
    """Stable-ish local host identifier that avoids exposing raw hostnames
    beyond what the machine itself already exposes locally."""
    try:
        machine_id_path = Path("/etc/machine-id")
        if machine_id_path.exists():
            return machine_id_path.read_text().strip()
    except Exception:
        pass
    return hashlib.sha256(pysocket.gethostname().encode("utf-8")).hexdigest()[:32]


class PrivacyManager:
    """Central place for all privacy-preserving transforms. Nothing outside
    this class should decide how to hash/redact sensitive fields."""

    def __init__(self, cfg: Configuration):
        self.cfg = cfg

    def transform_path(self, path: Optional[str]) -> Optional[str]:
        if path is None:
            return None
        if self.cfg.hash_file_paths:
            return "h_" + hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()
        return path

    def transform_ip(self, ip: Optional[str]) -> Optional[str]:
        if ip is None:
            return None
        if self.cfg.hash_ip_addresses:
            return "h_" + hashlib.sha256(ip.encode("utf-8")).hexdigest()[:16]
        return ip

    def sanitize_cmdline(self, cmdline: List[str]) -> Optional[str]:
        """Only used if STORE_COMMAND_LINE is enabled. Redacts tokens that
        look like secrets (key=value pairs, tokens, long hex/base64-looking
        strings) and never returns anything if the feature is disabled."""
        if not self.cfg.store_command_line:
            return None
        redacted = []
        secret_markers = ("password", "passwd", "secret", "token", "apikey", "api_key", "key=")
        for tok in cmdline:
            low = tok.lower()
            if any(m in low for m in secret_markers) or "=" in tok and len(tok) > 20:
                redacted.append("[REDACTED]")
            else:
                redacted.append(tok)
        joined = " ".join(redacted)
        return joined[:512]  # bound length


# =====================================================================
# 3. ONLINE STATISTICS (Welford) + HISTORICAL PROFILES
# =====================================================================

@dataclass
class OnlineStat:
    """Numerically stable running mean/variance via Welford's algorithm."""
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    minimum: float = math.inf
    maximum: float = -math.inf

    def update(self, x: float) -> None:
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.m2 += delta * delta2
        self.minimum = min(self.minimum, x)
        self.maximum = max(self.maximum, x)

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance) if self.variance > 0 else 0.0

    def z_score(self, x: float) -> float:
        if self.count < 2 or self.std == 0:
            return 0.0
        return (x - self.mean) / self.std

    def ratio(self, x: float) -> float:
        if self.mean == 0:
            return 0.0 if x == 0 else float("inf")
        return x / self.mean

    def to_dict(self) -> Dict[str, float]:
        return {
            "count": self.count, "mean": self.mean, "m2": self.m2,
            "minimum": self.minimum if self.minimum != math.inf else 0.0,
            "maximum": self.maximum if self.maximum != -math.inf else 0.0,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "OnlineStat":
        s = OnlineStat()
        s.count = int(d.get("count", 0))
        s.mean = float(d.get("mean", 0.0))
        s.m2 = float(d.get("m2", 0.0))
        s.minimum = float(d.get("minimum", math.inf))
        s.maximum = float(d.get("maximum", -math.inf))
        return s


# Metrics tracked historically per process (keyed by process name, since
# PIDs are ephemeral and behavioural baselines are meaningful per program).
HISTORICAL_METRICS = (
    "syscall_count", "file_event_count", "network_connection_count",
    "child_process_count", "cpu_mean", "memory_mean",
    "disk_read_bytes", "disk_write_bytes",
    "network_bytes_sent", "network_bytes_received",
    "unique_destinations", "unique_ports", "unique_files",
)


class StatisticsManager:
    """Maintains bounded, persistent historical behavioural baselines per
    process name. Never stores raw historical events — only compact
    running statistics (Welford's algorithm)."""

    def __init__(self, cfg: Configuration, profiles_path: Path, logger: logging.Logger):
        self.cfg = cfg
        self.path = profiles_path
        self.logger = logger
        self._lock = threading.Lock()
        self.profiles: Dict[str, Dict[str, OnlineStat]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
            for proc_name, metrics in raw.items():
                self.profiles[proc_name] = {
                    m: OnlineStat.from_dict(v) for m, v in metrics.items()
                }
            self.logger.info("Loaded historical profiles for %d processes", len(self.profiles))
        except Exception as exc:
            self.logger.warning("Could not load historical profiles (%s); starting fresh", exc)

    def persist(self) -> None:
        with self._lock:
            self._evict_if_needed()
            serializable = {
                proc: {m: s.to_dict() for m, s in metrics.items()}
                for proc, metrics in self.profiles.items()
            }
        try:
            tmp_path = self.path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(serializable))
            tmp_path.replace(self.path)
        except Exception as exc:
            self.logger.warning("Failed to persist historical profiles: %s", exc)

    def _evict_if_needed(self) -> None:
        """Bound the profile store: drop the least-observed processes first."""
        if len(self.profiles) <= self.cfg.profile_max_processes:
            return
        by_activity = sorted(
            self.profiles.items(),
            key=lambda kv: sum(s.count for s in kv[1].values()),
        )
        to_drop = len(self.profiles) - self.cfg.profile_max_processes
        for proc_name, _ in by_activity[:to_drop]:
            del self.profiles[proc_name]

    def update_and_compare(self, process_name: str, window_metrics: Dict[str, float]) -> Dict[str, Dict[str, float]]:
        """Update the historical baseline for a process with this window's
        values, and return deviation features computed BEFORE the update
        (so 'current vs historical' is meaningful and not self-referential
        for the very first observation)."""
        with self._lock:
            proc_profile = self.profiles.setdefault(process_name, {})
            result: Dict[str, Dict[str, float]] = {}
            for metric, current_value in window_metrics.items():
                stat = proc_profile.setdefault(metric, OnlineStat())
                historical_mean = stat.mean
                historical_std = stat.std
                z = stat.z_score(current_value)
                ratio = stat.ratio(current_value)
                deviation = current_value - historical_mean
                result[metric] = {
                    "current_value": current_value,
                    "historical_mean": historical_mean,
                    "historical_std": historical_std,
                    "deviation": deviation,
                    "ratio_to_historical_mean": ratio if math.isfinite(ratio) else 0.0,
                    "z_score": z,
                }
                stat.update(current_value)
            return result


# =====================================================================
# 4. BOUNDED EVENT QUEUE + DROP COUNTER
# =====================================================================

class BoundedEventQueue:
    """Wraps a bounded Queue. Never grows unbounded; on overflow, events
    are dropped and counted rather than crashing or consuming unlimited
    RAM."""

    def __init__(self, maxsize: int, logger: logging.Logger):
        self._q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=maxsize)
        self.logger = logger
        self.received = 0
        self.dropped = 0
        self._lock = threading.Lock()

    def put(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self.received += 1
        try:
            self._q.put_nowait(event)
        except queue.Full:
            with self._lock:
                self.dropped += 1

    def get(self, timeout: float) -> Optional[Dict[str, Any]]:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def qsize(self) -> int:
        return self._q.qsize()


# =====================================================================
# 5. CSV SCHEMA + DATASET WRITER (abstraction ready for PostgreSQL swap)
# =====================================================================

CSV_FIELDS = [
    "timestamp", "host_id", "event_type", "dataset_session_id",
    "session_label", "attack_scenario", "attack_id",
    "pid", "ppid", "process_name", "executable", "username", "uid", "gid",
    "syscall", "syscall_category", "syscall_result",
    "file_operation", "file_path",
    "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "connection_status",
    "cpu_percent", "memory_percent", "memory_rss", "memory_vms", "threads",
    "system_cpu_percent", "system_memory_percent", "swap_percent",
    "disk_read_bytes", "disk_write_bytes",
    "network_bytes_sent", "network_bytes_received",
    "network_packets_sent", "network_packets_received",
    "window_duration",
    "syscall_count", "file_event_count", "network_connection_count", "child_process_count",
    "unique_files", "unique_destinations", "unique_ports",
    "historical_mean", "historical_std", "deviation", "historical_ratio", "z_score",
    "host_os", "kernel_version",
    "command_line",
]


class DatasetWriterBase:
    """Abstract-ish base so a PostgreSQLWriter can later implement the
    same interface (write_row / flush / close) with no changes needed to
    producers of events."""

    def write_row(self, row: Dict[str, Any]) -> None:
        raise NotImplementedError

    def flush(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class CSVDatasetWriter(DatasetWriterBase):
    """Buffered, batched, rotating CSV writer. Never keeps the whole
    dataset in RAM — only a small write buffer."""

    def __init__(self, cfg: Configuration, output_dir: Path, logger: logging.Logger):
        self.cfg = cfg
        self.output_dir = output_dir
        self.logger = logger
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.rows_written = 0
        self._file_index = 1
        self._rows_in_current_file = 0
        self._fh = None
        self._writer = None
        self._open_new_file()

    def _current_path(self) -> Path:
        if self.cfg.single_csv:
            stem = "chronicle_dataset"
        else:
            stem = "chronicle_dataset"
        return self.output_dir / f"{stem}_{self._file_index:04d}.csv"

    def _open_new_file(self) -> None:
        path = self._current_path()
        is_new = not path.exists()
        self._fh = open(path, "a", newline="", buffering=1)
        self._writer = csv.DictWriter(self._fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        if is_new:
            self._writer.writeheader()
        self._rows_in_current_file = 0
        self.logger.info("Writing dataset to %s", path)

    def write_row(self, row: Dict[str, Any]) -> None:
        with self._lock:
            self._buffer.append(row)
            if len(self._buffer) >= self.cfg.writer_batch_size:
                self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._buffer:
            return
        for row in self._buffer:
            if self._rows_in_current_file >= self.cfg.max_rows_per_file:
                self._fh.close()
                self._file_index += 1
                self._open_new_file()
            self._writer.writerow(row)
            self._rows_in_current_file += 1
            self.rows_written += 1
        self._buffer.clear()
        self._fh.flush()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def close(self) -> None:
        with self._lock:
            self._flush_locked()
            if self._fh:
                self._fh.close()


# =====================================================================
# 6. RESOURCE MONITOR (self-overhead measurement)
# =====================================================================

class ResourceMonitor:
    """Tracks the collector's own CPU/RAM overhead using lightweight
    psutil calls against its own process — never by spawning external
    monitoring processes."""

    def __init__(self):
        self._proc = psutil.Process(os.getpid())
        self._proc.cpu_percent(interval=None)  # prime the internal counter

    def snapshot(self) -> Tuple[float, float]:
        cpu = self._proc.cpu_percent(interval=None)
        rss_mb = self._proc.memory_info().rss / (1024 * 1024)
        return cpu, rss_mb


# =====================================================================
# 7. HOST-LEVEL STATIC INFO
# =====================================================================

@dataclass
class HostInfo:
    host_id: str
    hostname: str
    os_name: str
    distro: str
    kernel_version: str
    cpu_count: int
    python_version: str

    @staticmethod
    def collect() -> "HostInfo":
        distro = "unknown"
        try:
            os_release = Path("/etc/os-release")
            if os_release.exists():
                data = dict(
                    line.split("=", 1) for line in os_release.read_text().splitlines() if "=" in line
                )
                distro = data.get("PRETTY_NAME", "unknown").strip('"')
        except Exception:
            pass
        return HostInfo(
            host_id=get_host_id(),
            hostname=pysocket.gethostname(),
            os_name=platform.system(),
            distro=distro,
            kernel_version=platform.release(),
            cpu_count=psutil.cpu_count(logical=True) or 1,
            python_version=platform.python_version(),
        )


# =====================================================================
# 8. SYSTEM COLLECTOR (psutil)
# =====================================================================

class SystemCollector:
    """Periodic host-wide telemetry: CPU, memory, swap, disk IO counters."""

    def __init__(self, cfg: Configuration, host: HostInfo, out_queue: BoundedEventQueue, logger: logging.Logger):
        self.cfg = cfg
        self.host = host
        self.out_queue = out_queue
        self.logger = logger
        self._last_disk_io = psutil.disk_io_counters()
        self._last_net_io = psutil.net_io_counters()
        self._last_sample_time = time.monotonic()

    def collect_once(self) -> Dict[str, Any]:
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()
        try:
            load1, load5, load15 = os.getloadavg()
        except (OSError, AttributeError):
            load1 = load5 = load15 = 0.0

        disk_io = psutil.disk_io_counters()
        net_io = psutil.net_io_counters()
        now = time.monotonic()
        elapsed = max(now - self._last_sample_time, 1e-6)

        disk_read_bytes = getattr(disk_io, "read_bytes", 0)
        disk_write_bytes = getattr(disk_io, "write_bytes", 0)
        net_sent = getattr(net_io, "bytes_sent", 0)
        net_recv = getattr(net_io, "bytes_recv", 0)

        self._last_disk_io = disk_io
        self._last_net_io = net_io
        self._last_sample_time = now

        event = {
            "timestamp": utc_now_iso(),
            "host_id": self.host.host_id,
            "event_type": "SYSTEM_METRIC",
            "host_os": self.host.os_name,
            "kernel_version": self.host.kernel_version,
            "system_cpu_percent": psutil.cpu_percent(interval=None),
            "system_memory_percent": vm.percent,
            "swap_percent": sm.percent,
            "disk_read_bytes": disk_read_bytes,
            "disk_write_bytes": disk_write_bytes,
            "network_bytes_sent": net_sent,
            "network_bytes_received": net_recv,
        }
        return event

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.out_queue.put(self.collect_once())
            except Exception as exc:
                self.logger.error("SystemCollector error: %s", exc)
            stop_event.wait(self.cfg.sample_interval)


# =====================================================================
# 9. PROCESS COLLECTOR (psutil) — periodic snapshot + lifecycle fallback
# =====================================================================

class ProcessCollector:
    """Periodic per-process telemetry, plus PROCESS_START/PROCESS_EXIT
    detection via snapshot diffing. This is a fallback path used whenever
    eBPF process-lifecycle events are unavailable; when eBPF is active it
    supplies more precise/faster lifecycle events and this collector's
    lifecycle detection simply becomes redundant confirmation."""

    def __init__(self, cfg: Configuration, host: HostInfo, out_queue: BoundedEventQueue,
                 privacy: PrivacyManager, logger: logging.Logger):
        self.cfg = cfg
        self.host = host
        self.out_queue = out_queue
        self.privacy = privacy
        self.logger = logger
        self._known_pids: Dict[int, Dict[str, Any]] = {}

    def _safe_process_info(self, proc: "psutil.Process") -> Optional[Dict[str, Any]]:
        try:
            with proc.oneshot():
                info = {
                    "pid": proc.pid,
                    "ppid": proc.ppid(),
                    "process_name": proc.name(),
                    "executable": self._safe(proc.exe),
                    "username": self._safe(proc.username),
                    "uid": proc.uids().real if hasattr(proc, "uids") else None,
                    "gid": proc.gids().real if hasattr(proc, "gids") else None,
                    "status": self._safe(proc.status),
                    "create_time": proc.create_time(),
                    "cpu_percent": proc.cpu_percent(interval=None),
                    "memory_percent": proc.memory_percent(),
                    "threads": proc.num_threads(),
                }
                try:
                    mem = proc.memory_info()
                    info["memory_rss"] = mem.rss
                    info["memory_vms"] = mem.vms
                except Exception:
                    info["memory_rss"] = None
                    info["memory_vms"] = None
                try:
                    info["open_files"] = len(proc.open_files())
                except Exception:
                    info["open_files"] = None
                if self.cfg.store_command_line:
                    try:
                        info["command_line"] = self.privacy.sanitize_cmdline(proc.cmdline())
                    except Exception:
                        info["command_line"] = None
                else:
                    info["command_line"] = None
                return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as exc:
            self.logger.debug("ProcessCollector unexpected error for pid=%s: %s", proc.pid, exc)
            return None

    @staticmethod
    def _safe(fn):
        try:
            return fn()
        except Exception:
            return None

    def collect_once(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        current_pids = set()
        for proc in psutil.process_iter():
            info = self._safe_process_info(proc)
            if info is None:
                continue
            pid = info["pid"]
            current_pids.add(pid)

            if pid not in self._known_pids:
                # New process observed -> PROCESS_START (fallback path)
                events.append({
                    "timestamp": utc_now_iso(),
                    "host_id": self.host.host_id,
                    "event_type": "PROCESS_START",
                    "pid": pid, "ppid": info["ppid"],
                    "process_name": info["process_name"],
                    "executable": info["executable"],
                    "username": info["username"],
                    "uid": info["uid"], "gid": info["gid"],
                })

            events.append({
                "timestamp": utc_now_iso(),
                "host_id": self.host.host_id,
                "event_type": "PROCESS_METRIC",
                "pid": pid, "ppid": info["ppid"],
                "process_name": info["process_name"],
                "executable": info["executable"],
                "username": info["username"],
                "uid": info["uid"], "gid": info["gid"],
                "cpu_percent": info["cpu_percent"],
                "memory_percent": info["memory_percent"],
                "memory_rss": info["memory_rss"],
                "memory_vms": info["memory_vms"],
                "threads": info["threads"],
                "command_line": info.get("command_line"),
            })

            # Track relationship for graph reconstruction (deduplicated by
            # (ppid, pid) pair since that uniquely identifies the edge).
            self._known_pids[pid] = info

        # Anything previously known but now gone => PROCESS_EXIT
        vanished = set(self._known_pids.keys()) - current_pids
        for pid in vanished:
            old = self._known_pids.pop(pid, {})
            events.append({
                "timestamp": utc_now_iso(),
                "host_id": self.host.host_id,
                "event_type": "PROCESS_EXIT",
                "pid": pid,
                "process_name": old.get("process_name"),
            })
        return events

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                for event in self.collect_once():
                    self.out_queue.put(event)
            except Exception as exc:
                self.logger.error("ProcessCollector error: %s", exc)
            stop_event.wait(self.cfg.sample_interval)


# =====================================================================
# 10. NETWORK COLLECTOR (psutil)
# =====================================================================

class NetworkCollector:
    """Periodic connection-level telemetry via psutil. No payloads are
    ever touched — only connection tuples and status."""

    PROTO_MAP = {
        pysocket.SOCK_STREAM: "TCP",
        pysocket.SOCK_DGRAM: "UDP",
    }

    def __init__(self, cfg: Configuration, host: HostInfo, out_queue: BoundedEventQueue,
                 privacy: PrivacyManager, logger: logging.Logger):
        self.cfg = cfg
        self.host = host
        self.out_queue = out_queue
        self.privacy = privacy
        self.logger = logger
        self._seen_conns: set = set()

    def collect_once(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            conns = []
        except Exception as exc:
            self.logger.debug("NetworkCollector error: %s", exc)
            conns = []

        current_keys = set()
        for c in conns:
            if not c.raddr:
                continue  # only remote/established-style connections are behaviourally interesting
            proto = self.PROTO_MAP.get(c.type, "OTHER")
            src_ip, src_port = (c.laddr.ip, c.laddr.port) if c.laddr else (None, None)
            dst_ip, dst_port = c.raddr.ip, c.raddr.port
            key = (c.pid, proto, src_ip, src_port, dst_ip, dst_port)
            current_keys.add(key)
            is_new = key not in self._seen_conns
            self._seen_conns.add(key)

            process_name = None
            if c.pid:
                try:
                    process_name = psutil.Process(c.pid).name()
                except Exception:
                    process_name = None

            events.append({
                "timestamp": utc_now_iso(),
                "host_id": self.host.host_id,
                "event_type": "NETWORK_CONNECT" if is_new else "NETWORK_STATUS",
                "pid": c.pid,
                "process_name": process_name,
                "protocol": proto,
                "src_ip": self.privacy.transform_ip(src_ip),
                "src_port": src_port,
                "dst_ip": self.privacy.transform_ip(dst_ip),
                "dst_port": dst_port,
                "connection_status": c.status,
            })

        # Bound memory of the seen-connection set.
        if len(self._seen_conns) > 100_000:
            self._seen_conns = current_keys
        return events

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                for event in self.collect_once():
                    self.out_queue.put(event)
            except Exception as exc:
                self.logger.error("NetworkCollector error: %s", exc)
            stop_event.wait(self.cfg.sample_interval)


# =====================================================================
# 11. DISK COLLECTOR (psutil, system-wide; per-process disk IO where available)
# =====================================================================

class DiskCollector:
    """System-wide and (where the platform allows) per-process disk IO
    rate telemetry."""

    def __init__(self, cfg: Configuration, host: HostInfo, out_queue: BoundedEventQueue, logger: logging.Logger):
        self.cfg = cfg
        self.host = host
        self.out_queue = out_queue
        self.logger = logger
        self._last_counters = psutil.disk_io_counters()
        self._last_time = time.monotonic()

    def collect_once(self) -> Dict[str, Any]:
        counters = psutil.disk_io_counters()
        now = time.monotonic()
        elapsed = max(now - self._last_time, 1e-6)

        read_rate = 0.0
        write_rate = 0.0
        if counters and self._last_counters:
            read_rate = (counters.read_bytes - self._last_counters.read_bytes) / elapsed
            write_rate = (counters.write_bytes - self._last_counters.write_bytes) / elapsed

        self._last_counters = counters
        self._last_time = now

        return {
            "timestamp": utc_now_iso(),
            "host_id": self.host.host_id,
            "event_type": "DISK_METRIC",
            "disk_read_bytes": getattr(counters, "read_bytes", 0),
            "disk_write_bytes": getattr(counters, "write_bytes", 0),
        }

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.out_queue.put(self.collect_once())
            except Exception as exc:
                self.logger.error("DiskCollector error: %s", exc)
            stop_event.wait(self.cfg.sample_interval)


# =====================================================================
# 12. EBPF COLLECTOR (BCC) — kernel-level syscall/file/process events
# =====================================================================

# A compact BPF C program tracing security-relevant tracepoints. Only
# metadata useful for behavioural analysis is captured — never syscall
# argument buffers/contents beyond short, fixed-size path snippets, and
# file paths are hashed downstream by PrivacyManager before ever reaching
# the CSV, per configuration.
_BPF_PROGRAM = r"""
#include <linux/sched.h>

#define ARGSIZE  200

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
};

struct exit_event_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};

struct file_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
    u8 op;   // 0=open 1=unlink
};

struct net_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
    u8 op;   // 0=connect
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(exit_events);
BPF_PERF_OUTPUT(file_events);
BPF_PERF_OUTPUT(net_events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename),
                               (void *)args->filename);
    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct exit_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    exit_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct file_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.op = 0;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename),
                             (void *)args->filename);
    file_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct file_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.op = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename),
                             (void *)args->pathname);
    file_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct net_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.op = 0;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    net_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


class EBPFCollector:
    """Wraps a BCC BPF program for kernel-level process/file/network
    events. Fully optional: any failure to load simply disables this
    component and the rest of the collector continues unaffected."""

    def __init__(self, cfg: Configuration, host: HostInfo, out_queue: BoundedEventQueue,
                 privacy: PrivacyManager, logger: logging.Logger):
        self.cfg = cfg
        self.host = host
        self.out_queue = out_queue
        self.privacy = privacy
        self.logger = logger
        self.enabled = False
        self._bpf = None
        self._proc_name_cache: Dict[int, str] = {}

        if not cfg.enable_ebpf:
            self.logger.info("eBPF collection disabled by configuration.")
            return
        if not _BCC_IMPORT_OK:
            self.logger.warning("BCC not importable — eBPF/kernel telemetry disabled. "
                                 "Falling back to psutil-only collection.")
            return
        if os.geteuid() != 0:
            self.logger.warning("Not running as root — eBPF requires root. Disabling eBPF collection.")
            return
        try:
            self._bpf = BPF(text=_BPF_PROGRAM)
            self._bpf["exec_events"].open_perf_buffer(self._on_exec, page_cnt=64)
            self._bpf["exit_events"].open_perf_buffer(self._on_exit, page_cnt=64)
            self._bpf["file_events"].open_perf_buffer(self._on_file, page_cnt=64)
            self._bpf["net_events"].open_perf_buffer(self._on_net, page_cnt=64)
            self.enabled = True
            self.logger.info("eBPF collector attached (execve/exit/openat/unlinkat/connect).")
        except Exception as exc:
            self.logger.warning("Failed to attach eBPF program (%s). Continuing without kernel "
                                 "telemetry; psutil-based collection remains active.", exc)
            self._bpf = None
            self.enabled = False

    def _emit(self, event: Dict[str, Any]) -> None:
        event.setdefault("timestamp", utc_now_iso())
        event.setdefault("host_id", self.host.host_id)
        self.out_queue.put(event)

    def _on_exec(self, cpu, data, size) -> None:
        try:
            event = self._bpf["exec_events"].event(data)
            filename = event.filename.decode("utf-8", "replace")
            self._proc_name_cache[event.pid] = event.comm.decode("utf-8", "replace")
            self._emit({
                "event_type": "SYSCALL",
                "syscall": "execve",
                "syscall_category": "PROCESS",
                "pid": event.pid, "ppid": event.ppid, "uid": event.uid,
                "process_name": event.comm.decode("utf-8", "replace"),
                "file_path": self.privacy.transform_path(filename),
                "syscall_result": "success",
            })
        except Exception as exc:
            self.logger.debug("exec event decode error: %s", exc)

    def _on_exit(self, cpu, data, size) -> None:
        try:
            event = self._bpf["exit_events"].event(data)
            self._emit({
                "event_type": "PROCESS_EXIT",
                "pid": event.pid, "ppid": event.ppid,
                "process_name": event.comm.decode("utf-8", "replace"),
            })
            self._proc_name_cache.pop(event.pid, None)
        except Exception as exc:
            self.logger.debug("exit event decode error: %s", exc)

    def _on_file(self, cpu, data, size) -> None:
        try:
            event = self._bpf["file_events"].event(data)
            filename = event.filename.decode("utf-8", "replace")
            op = "OPEN" if event.op == 0 else "DELETE"
            self._emit({
                "event_type": "FILE_" + op,
                "syscall": "openat" if event.op == 0 else "unlinkat",
                "syscall_category": "FILE",
                "pid": event.pid, "uid": event.uid,
                "process_name": event.comm.decode("utf-8", "replace"),
                "file_operation": op,
                "file_path": self.privacy.transform_path(filename),
                "syscall_result": "attempted",
            })
        except Exception as exc:
            self.logger.debug("file event decode error: %s", exc)

    def _on_net(self, cpu, data, size) -> None:
        try:
            event = self._bpf["net_events"].event(data)
            self._emit({
                "event_type": "NETWORK_CONNECT",
                "syscall": "connect",
                "syscall_category": "NETWORK",
                "pid": event.pid, "uid": event.uid,
                "process_name": event.comm.decode("utf-8", "replace"),
                "syscall_result": "attempted",
            })
        except Exception as exc:
            self.logger.debug("net event decode error: %s", exc)

    def run_forever(self, stop_event: threading.Event) -> None:
        if not self.enabled or self._bpf is None:
            return
        while not stop_event.is_set():
            try:
                self._bpf.perf_buffer_poll(timeout=500)
            except Exception as exc:
                self.logger.error("eBPF polling error (continuing): %s", exc)
                time.sleep(1.0)


# =====================================================================
# 13. BEHAVIOUR AGGREGATOR — raw events -> per-process windowed features
# =====================================================================

class _WindowAccumulator:
    """Mutable per-process accumulator for one behavioural window."""

    __slots__ = (
        "syscall_count", "file_event_count", "network_connection_count",
        "child_process_count", "cpu_samples", "memory_samples",
        "disk_read_bytes", "disk_write_bytes",
        "network_bytes_sent", "network_bytes_received",
        "unique_files", "unique_destinations", "unique_ports",
    )

    def __init__(self):
        self.syscall_count = 0
        self.file_event_count = 0
        self.network_connection_count = 0
        self.child_process_count = 0
        self.cpu_samples: List[float] = []
        self.memory_samples: List[float] = []
        self.disk_read_bytes = 0.0
        self.disk_write_bytes = 0.0
        self.network_bytes_sent = 0.0
        self.network_bytes_received = 0.0
        self.unique_files: set = set()
        self.unique_destinations: set = set()
        self.unique_ports: set = set()


class BehaviourAggregator:
    """Consumes normalized events and, every `feature_window` seconds,
    emits one BEHAVIOURAL_FEATURE row per active process, including
    current-vs-historical deviation features from StatisticsManager."""

    def __init__(self, cfg: Configuration, host: HostInfo, out_queue: BoundedEventQueue,
                 stats: StatisticsManager, logger: logging.Logger):
        self.cfg = cfg
        self.host = host
        self.out_queue = out_queue
        self.stats = stats
        self.logger = logger
        self._lock = threading.Lock()
        self._acc: Dict[str, _WindowAccumulator] = {}
        self._window_start = time.monotonic()

    def observe(self, event: Dict[str, Any]) -> None:
        """Feed a single (already-written) event into the current window's
        accumulators. Cheap, O(1) amortized work — safe to call from the
        writer thread's hot path."""
        proc_name = event.get("process_name")
        if not proc_name:
            return
        etype = event.get("event_type", "")

        with self._lock:
            acc = self._acc.setdefault(proc_name, _WindowAccumulator())

            if etype == "SYSCALL":
                acc.syscall_count += 1
            elif etype.startswith("FILE_"):
                acc.file_event_count += 1
                fp = event.get("file_path")
                if fp:
                    acc.unique_files.add(fp)
            elif etype in ("NETWORK_CONNECT", "NETWORK_STATUS"):
                acc.network_connection_count += 1
                dst = event.get("dst_ip")
                port = event.get("dst_port")
                if dst:
                    acc.unique_destinations.add(dst)
                if port:
                    acc.unique_ports.add(port)
            elif etype == "PROCESS_START":
                acc.child_process_count += 1
            elif etype == "PROCESS_METRIC":
                cpu = event.get("cpu_percent")
                mem = event.get("memory_percent")
                if isinstance(cpu, (int, float)):
                    acc.cpu_samples.append(cpu)
                if isinstance(mem, (int, float)):
                    acc.memory_samples.append(mem)
            elif etype == "DISK_METRIC":
                pass  # system-wide, not attributable per-process here
            elif etype == "NETWORK_STATUS_BYTES":
                acc.network_bytes_sent += event.get("network_bytes_sent", 0) or 0
                acc.network_bytes_received += event.get("network_bytes_received", 0) or 0

    def flush_window(self, session: "SessionInfo") -> int:
        """Compute and emit one BEHAVIOURAL_FEATURE row per process,
        compare against history, and reset accumulators. Returns the
        number of feature rows emitted."""
        now = time.monotonic()
        with self._lock:
            window_duration = now - self._window_start
            acc_snapshot = self._acc
            self._acc = {}
            self._window_start = now

        emitted = 0
        for proc_name, acc in acc_snapshot.items():
            cpu_mean = sum(acc.cpu_samples) / len(acc.cpu_samples) if acc.cpu_samples else 0.0
            mem_mean = sum(acc.memory_samples) / len(acc.memory_samples) if acc.memory_samples else 0.0

            window_metrics = {
                "syscall_count": float(acc.syscall_count),
                "file_event_count": float(acc.file_event_count),
                "network_connection_count": float(acc.network_connection_count),
                "child_process_count": float(acc.child_process_count),
                "cpu_mean": cpu_mean,
                "memory_mean": mem_mean,
                "disk_read_bytes": acc.disk_read_bytes,
                "disk_write_bytes": acc.disk_write_bytes,
                "network_bytes_sent": acc.network_bytes_sent,
                "network_bytes_received": acc.network_bytes_received,
                "unique_destinations": float(len(acc.unique_destinations)),
                "unique_ports": float(len(acc.unique_ports)),
                "unique_files": float(len(acc.unique_files)),
            }

            deviations = self.stats.update_and_compare(proc_name, window_metrics)

            # Emit one row focused on network deviation as the headline
            # z-score/ratio (network is typically the highest-signal
            # behavioural dimension), while carrying all raw window
            # counts as well. Consumers can recompute other deviations
            # from historical_mean/std of any metric they care about by
            # joining on process_name across windows if desired.
            headline = deviations.get("network_connection_count", {})

            row = {
                "timestamp": utc_now_iso(),
                "host_id": self.host.host_id,
                "event_type": "BEHAVIOURAL_FEATURE",
                "dataset_session_id": session.session_id,
                "session_label": session.label,
                "attack_scenario": session.attack_scenario,
                "attack_id": session.attack_id,
                "process_name": proc_name,
                "window_duration": round(window_duration, 3),
                "syscall_count": acc.syscall_count,
                "file_event_count": acc.file_event_count,
                "network_connection_count": acc.network_connection_count,
                "child_process_count": acc.child_process_count,
                "unique_files": len(acc.unique_files),
                "unique_destinations": len(acc.unique_destinations),
                "unique_ports": len(acc.unique_ports),
                "cpu_percent": round(cpu_mean, 3),
                "memory_percent": round(mem_mean, 3),
                "disk_read_bytes": acc.disk_read_bytes,
                "disk_write_bytes": acc.disk_write_bytes,
                "network_bytes_sent": acc.network_bytes_sent,
                "network_bytes_received": acc.network_bytes_received,
                "historical_mean": round(headline.get("historical_mean", 0.0), 4),
                "historical_std": round(headline.get("historical_std", 0.0), 4),
                "deviation": round(headline.get("deviation", 0.0), 4),
                "historical_ratio": round(headline.get("ratio_to_historical_mean", 0.0), 4),
                "z_score": round(headline.get("z_score", 0.0), 4),
                "host_os": session.host.os_name,
                "kernel_version": session.host.kernel_version,
            }
            self.out_queue.put(row)
            emitted += 1
        return emitted


# =====================================================================
# 14. SESSION INFO
# =====================================================================

@dataclass
class SessionInfo:
    session_id: str
    label: str
    attack_scenario: Optional[str]
    attack_id: Optional[str]
    host: HostInfo
    collection_start: str
    collection_end: Optional[str] = None


# =====================================================================
# 15. STARTUP CHECKS
# =====================================================================

def run_startup_checks(cfg: Configuration, host: HostInfo, logger: logging.Logger) -> None:
    print("Chronicle Collector")
    print("--------------------")
    print(f"OS:          {host.distro or host.os_name}")
    print(f"Kernel:      {host.kernel_version}")
    print(f"Python:      {host.python_version}")
    print(f"psutil:      OK ({psutil.__version__})")
    print(f"BCC:         {'OK' if _BCC_IMPORT_OK else 'NOT AVAILABLE'}")
    print(f"Root:        {'YES' if os.geteuid() == 0 else 'NO'}")
    print(f"Output:      {cfg.output_directory}/")

    if host.os_name != "Linux":
        logger.warning("Chronicle is designed for Linux. Some features may not work on %s.", host.os_name)

    if not _BCC_IMPORT_OK:
        print("eBPF unavailable — syscall/file kernel telemetry disabled.")
    elif os.geteuid() != 0:
        print("Root privileges required for eBPF — syscall/file kernel telemetry disabled.")
    else:
        print("eBPF: OK")

    try:
        usage = psutil.disk_usage(str(Path(cfg.output_directory).resolve().parent))
        free_gb = usage.free / (1024 ** 3)
        print(f"Free disk:   {free_gb:.1f} GB")
        if free_gb < cfg.min_free_disk_gb:
            logger.warning("Free disk space (%.1f GB) is below the configured minimum (%.1f GB).",
                            free_gb, cfg.min_free_disk_gb)
    except Exception:
        pass
    print()


# =====================================================================
# 16. MAIN COLLECTOR ORCHESTRATOR
# =====================================================================

class ChronicleCollector:
    def __init__(self, cfg: Configuration):
        self.cfg = cfg
        self.logger = self._setup_logging()
        self.host = HostInfo.collect()
        self.session = SessionInfo(
            session_id=make_session_id(),
            label=cfg.session_label,
            attack_scenario=cfg.attack_scenario,
            attack_id=cfg.attack_id,
            host=self.host,
            collection_start=utc_now_iso(),
        )

        self.output_dir = Path(cfg.output_directory)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.privacy = PrivacyManager(cfg)
        self.queue = BoundedEventQueue(cfg.max_queue_size, self.logger)
        self.writer = CSVDatasetWriter(cfg, self.output_dir, self.logger)
        self.stats_mgr = StatisticsManager(cfg, self.output_dir / cfg.profiles_file, self.logger)
        self.aggregator = BehaviourAggregator(cfg, self.host, self.queue, self.stats_mgr, self.logger)
        self.resource_monitor = ResourceMonitor()

        self.system_collector = SystemCollector(cfg, self.host, self.queue, self.logger)
        self.process_collector = ProcessCollector(cfg, self.host, self.queue, self.privacy, self.logger)
        self.network_collector = NetworkCollector(cfg, self.host, self.queue, self.privacy, self.logger)
        self.disk_collector = DiskCollector(cfg, self.host, self.queue, self.logger)
        self.ebpf_collector = EBPFCollector(cfg, self.host, self.queue, self.privacy, self.logger)

        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._start_time = time.monotonic()
        self._rows_seen_for_features = 0

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("chronicle")
        logger.setLevel(getattr(logging, self.cfg.log_level, logging.INFO))
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(asctime)s %(message)s", "%H:%M:%S"))
        logger.handlers.clear()
        logger.addHandler(handler)
        return logger

    # -- thread bodies -------------------------------------------------

    def _writer_loop(self) -> None:
        """Drains the bounded queue, writes rows to CSV, and feeds the
        BehaviourAggregator so windowed features can be computed without
        a second pass over the data."""
        last_flush = time.monotonic()
        while not self._stop_event.is_set() or self.queue.qsize() > 0:
            event = self.queue.get(timeout=0.5)
            if event is None:
                if time.monotonic() - last_flush > self.cfg.writer_flush_interval:
                    self.writer.flush()
                    last_flush = time.monotonic()
                continue

            row = self._normalize_row(event)
            self.writer.write_row(row)
            if self.cfg.enable_feature_aggregation:
                self.aggregator.observe(row)

            if time.monotonic() - last_flush > self.cfg.writer_flush_interval:
                self.writer.flush()
                last_flush = time.monotonic()

    def _normalize_row(self, event: Dict[str, Any]) -> Dict[str, Any]:
        row = {field_name: None for field_name in CSV_FIELDS}
        row.update(event)
        row["dataset_session_id"] = row.get("dataset_session_id") or self.session.session_id
        row["session_label"] = row.get("session_label") or self.session.label
        row["attack_scenario"] = row.get("attack_scenario") or self.session.attack_scenario
        row["attack_id"] = row.get("attack_id") or self.session.attack_id
        row["host_os"] = row.get("host_os") or self.host.os_name
        row["kernel_version"] = row.get("kernel_version") or self.host.kernel_version
        row.setdefault("timestamp", utc_now_iso())
        return row

    def _feature_window_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.wait(self.cfg.feature_window):
            try:
                emitted = self.aggregator.flush_window(self.session)
                self.logger.debug("Feature window flushed: %d process rows emitted.", emitted)
            except Exception as exc:
                self.logger.error("BehaviourAggregator error: %s", exc)

    def _profile_persist_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.wait(self.cfg.profile_persist_interval):
            self.stats_mgr.persist()

    def _disk_space_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.wait(self.cfg.disk_check_interval):
            try:
                usage = psutil.disk_usage(str(self.output_dir.resolve()))
                free_gb = usage.free / (1024 ** 3)
                if free_gb < self.cfg.min_free_disk_gb:
                    self.logger.warning("WARNING: Disk space below configured limit.")
                    self.logger.warning("Collection stopped to protect the system.")
                    self._stop_event.set()
                    break
            except Exception as exc:
                self.logger.debug("Disk space check failed: %s", exc)

    def _stats_report_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.wait(self.cfg.stats_report_interval):
            self._print_report()

    def _print_report(self) -> None:
        runtime = time.monotonic() - self._start_time
        hours, rem = divmod(int(runtime), 3600)
        minutes, seconds = divmod(rem, 60)
        cpu, ram_mb = self.resource_monitor.snapshot()
        events_per_sec = self.queue.received / runtime if runtime > 0 else 0.0
        try:
            n_procs = len(psutil.pids())
        except Exception:
            n_procs = 0

        self.logger.info(
            "Runtime: %dh %dm%s | Events received: %d | written: %d | dropped: %d | "
            "processes: %d | events/sec: %.1f | Collector CPU: %.1f%% RAM: %.1f MB",
            hours, minutes, f"{seconds}s", self.queue.received, self.writer.rows_written,
            self.queue.dropped, n_procs, events_per_sec, cpu, ram_mb,
        )

    # -- lifecycle -------------------------------------------------------

    def start(self) -> None:
        run_startup_checks(self.cfg, self.host, self.logger)
        self.logger.info("Session %s starting (label=%s)", self.session.session_id, self.session.label)

        thread_specs = [
            ("writer", self._writer_loop),
            ("system", self.system_collector.run_forever),
            ("disk", self.disk_collector.run_forever if self.cfg.enable_disk_monitoring else None),
            ("process", self.process_collector.run_forever if self.cfg.enable_process_monitoring else None),
            ("network", self.network_collector.run_forever if self.cfg.enable_network_monitoring else None),
            ("ebpf", self.ebpf_collector.run_forever),
            ("features", self._feature_window_loop if self.cfg.enable_feature_aggregation else None),
            ("profiles", self._profile_persist_loop),
            ("diskspace", self._disk_space_loop),
            ("statsreport", self._stats_report_loop),
        ]

        for name, target in thread_specs:
            if target is None:
                continue
            if name == "writer":
                t = threading.Thread(target=target, name=name, daemon=True)
            else:
                t = threading.Thread(target=target, args=(self._stop_event,), name=name, daemon=True)
            t.start()
            self._threads.append(t)

        self.logger.info("Collection running. Press Ctrl+C to stop.")

    def stop(self) -> None:
        if self._stop_event.is_set():
            return
        self.logger.info("Shutdown requested — stopping collection...")
        self._stop_event.set()

        # Give the eBPF/system/network/process loops a brief moment to
        # notice the stop event, then drain and flush.
        for t in self._threads:
            if t.name != "writer":
                t.join(timeout=3.0)

        # Writer thread drains any remaining queued events before exiting.
        writer_thread = next((t for t in self._threads if t.name == "writer"), None)
        if writer_thread:
            writer_thread.join(timeout=10.0)

        self.writer.close()
        self.stats_mgr.persist()
        self.session.collection_end = utc_now_iso()

        self._print_final_summary()

    def _print_final_summary(self) -> None:
        runtime = time.monotonic() - self._start_time
        print()
        print("Chronicle collection stopped.")
        print(f"Session:          {self.session.session_id}")
        print(f"Collection start: {self.session.collection_start}")
        print(f"Collection end:   {self.session.collection_end}")
        print(f"Runtime:          {runtime:.1f}s")
        print(f"Events received:  {self.queue.received:,}")
        print(f"Events written:   {self.writer.rows_written:,}")
        print(f"Events dropped:   {self.queue.dropped:,}")
        print(f"Output directory: {self.output_dir.resolve()}")


# =====================================================================
# 17. ENTRYPOINT
# =====================================================================

def main() -> None:
    cfg = build_config_from_cli()
    collector = ChronicleCollector(cfg)

    def _handle_signal(signum, frame):
        collector.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    collector.start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        collector.stop()


if __name__ == "__main__":
    main()
