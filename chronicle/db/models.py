"""
Data models for Chronicle telemetry, behavioural windows, baselines, and detections.
Handles conversion to/from database records and collector CSV rows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Union


def parse_datetime(val: Any) -> Optional[datetime]:
    """Parse string, timestamp float, or datetime into a timezone-aware UTC datetime."""
    if val is None or val == "":
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(val, tz=timezone.utc)
    if isinstance(val, str):
        val = val.strip()
        if not val:
            return None
        # Handle trailing Z or offsets
        if val.endswith("Z"):
            val = val[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(val)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            # Fallback for epoch seconds stored as string
            try:
                sec = float(val)
                return datetime.fromtimestamp(sec, tz=timezone.utc)
            except ValueError:
                return None
    return None


def to_iso(dt: Optional[datetime]) -> Optional[str]:
    """Serialize datetime to ISO-8601 string."""
    if dt is None:
        return None
    return dt.isoformat()


def safe_int(val: Any, default: int = 0) -> int:
    try:
        if val is None or val == "":
            return default
        return int(val)
    except (ValueError, TypeError):
        return default


def safe_float(val: Any, default: float = 0.0) -> float:
    try:
        if val is None or val == "":
            return default
        return float(val)
    except (ValueError, TypeError):
        return default


@dataclass
class ProcessInstance:
    instance_id: str
    profile_id: str
    pid: int
    comm: str
    start_time: datetime
    ppid: Optional[int] = None
    parent_instance_id: Optional[str] = None
    executable: Optional[str] = None
    executable_hash: Optional[str] = None
    uid: Optional[int] = None
    end_time: Optional[datetime] = None
    exit_code: Optional[int] = None
    preexisting: bool = False
    windows_written: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "ProcessInstance":
        meta = row.get("metadata")
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        elif not isinstance(meta, dict):
            meta = {}

        return cls(
            instance_id=row["instance_id"],
            profile_id=row.get("profile_id", ""),
            pid=row["pid"],
            comm=row["comm"],
            ppid=row.get("ppid"),
            parent_instance_id=row.get("parent_instance_id") or None,
            executable=row.get("executable"),
            executable_hash=row.get("executable_hash"),
            uid=row.get("uid"),
            start_time=parse_datetime(row["start_time"]) or datetime.now(timezone.utc),
            end_time=parse_datetime(row.get("end_time")),
            exit_code=row.get("exit_code"),
            preexisting=bool(row.get("preexisting", False)),
            windows_written=row.get("windows_written", 0),
            metadata=meta,
            created_at=parse_datetime(row.get("created_at")),
            updated_at=parse_datetime(row.get("updated_at")),
        )

    @classmethod
    def from_collector_csv(cls, d: Mapping[str, str]) -> "ProcessInstance":
        pre = d.get("preexisting", "0")
        is_pre = pre in ("1", "true", "True")
        return cls(
            instance_id=d["instance_id"],
            profile_id=d.get("profile_id", ""),
            pid=safe_int(d["pid"]),
            ppid=safe_int(d["ppid"]) if d.get("ppid") else None,
            parent_instance_id=d.get("parent_instance_id") or None,
            comm=d.get("comm", ""),
            executable=d.get("executable") or None,
            executable_hash=d.get("executable_hash") or None,
            uid=safe_int(d["uid"]) if d.get("uid") else None,
            start_time=parse_datetime(d["start_time"]) or datetime.now(timezone.utc),
            end_time=parse_datetime(d.get("end_time")),
            exit_code=safe_int(d["exit_code"]) if d.get("exit_code") != "" else None,
            preexisting=is_pre,
            windows_written=safe_int(d.get("windows_written", 0)),
        )


@dataclass
class TelemetryEvent:
    timestamp: datetime
    event_type: str
    instance_id: Optional[str] = None
    pid: Optional[int] = None
    event_id: Optional[int] = None
    event_uuid: Optional[str] = None
    syscall_category: Optional[str] = None
    file_identifier: Optional[str] = None
    network_identifier: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "TelemetryEvent":
        p = row.get("payload")
        if isinstance(p, str):
            try:
                p = json.loads(p)
            except Exception:
                p = {}
        elif not isinstance(p, dict):
            p = {}

        return cls(
            event_id=row.get("event_id"),
            event_uuid=row.get("event_uuid"),
            instance_id=row.get("instance_id"),
            pid=row.get("pid"),
            timestamp=parse_datetime(row["timestamp"]) or datetime.now(timezone.utc),
            event_type=row["event_type"],
            syscall_category=row.get("syscall_category"),
            file_identifier=row.get("file_identifier"),
            network_identifier=row.get("network_identifier"),
            payload=p,
            created_at=parse_datetime(row.get("created_at")),
        )

    @classmethod
    def from_collector_csv(cls, d: Mapping[str, str]) -> "TelemetryEvent":
        meta = d.get("metadata", "")
        payload = {}
        if meta:
            try:
                payload = json.loads(meta)
            except Exception:
                payload = {"raw": meta}

        return cls(
            event_id=safe_int(d["event_id"]) if d.get("event_id") else None,
            instance_id=d.get("instance_id") or None,
            pid=safe_int(d["pid"]) if d.get("pid") else None,
            timestamp=parse_datetime(d["timestamp"]) or datetime.now(timezone.utc),
            event_type=d["event_type"],
            syscall_category=d.get("syscall_category") or None,
            file_identifier=d.get("file_identifier") or None,
            network_identifier=d.get("network_identifier") or None,
            payload=payload,
        )


@dataclass
class BehaviourWindow:
    window_index: int
    profile_id: str
    start_time: datetime
    end_time: datetime
    duration_s: float
    window_id: Optional[int] = None
    instance_id: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    comm: Optional[str] = None
    executable: Optional[str] = None

    # Syscall counts
    syscall_count: int = 0
    syscalls_file: int = 0
    syscalls_network: int = 0
    syscalls_process: int = 0
    syscalls_memory: int = 0
    syscalls_ipc: int = 0
    syscalls_other: int = 0
    syscalls_sensitive: int = 0
    distinct_syscalls: int = 0

    # File metrics
    file_read_count: int = 0
    file_write_count: int = 0
    file_open_count: int = 0
    file_open_write_count: int = 0
    file_create_count: int = 0
    file_delete_count: int = 0
    file_rename_count: int = 0
    unique_files: int = 0
    bytes_read: int = 0
    bytes_written: int = 0

    # Network metrics
    network_count: int = 0
    net_connect_count: int = 0
    net_accept_count: int = 0
    unique_dest_ips: int = 0
    unique_dest_ports: int = 0
    tcp_tx_bytes: int = 0
    tcp_rx_bytes: int = 0
    udp_tx_bytes: int = 0

    # Process relations
    child_process_count: int = 0
    thread_create_count: int = 0
    exec_count: int = 0

    # Resources
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    memory_rss_bytes: int = 0
    memory_vms_bytes: int = 0
    memory_percent: float = 0.0
    num_threads: int = 0
    num_fds: int = 0
    disk_read_bytes: int = 0
    disk_write_bytes: int = 0
    ctx_switches_voluntary: int = 0
    ctx_switches_involuntary: int = 0

    # Bookkeeping
    alive_at_end: int = 1
    label: str = "unlabeled"
    label_binary: Optional[int] = None
    scenario: str = "ambient"
    experiment_id: Optional[str] = None

    feature_data: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0"
    created_at: Optional[datetime] = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "BehaviourWindow":
        feat = row.get("feature_data")
        if isinstance(feat, str):
            try:
                feat = json.loads(feat)
            except Exception:
                feat = {}
        elif not isinstance(feat, dict):
            feat = {}

        return cls(
            window_id=row.get("window_id"),
            window_index=row["window_index"],
            instance_id=row.get("instance_id"),
            profile_id=row.get("profile_id", ""),
            pid=row.get("pid"),
            ppid=row.get("ppid"),
            comm=row.get("comm"),
            executable=row.get("executable"),
            start_time=parse_datetime(row["start_time"]) or datetime.now(timezone.utc),
            end_time=parse_datetime(row["end_time"]) or datetime.now(timezone.utc),
            duration_s=safe_float(row["duration_s"]),
            syscall_count=row.get("syscall_count", 0),
            syscalls_file=row.get("syscalls_file", 0),
            syscalls_network=row.get("syscalls_network", 0),
            syscalls_process=row.get("syscalls_process", 0),
            syscalls_memory=row.get("syscalls_memory", 0),
            syscalls_ipc=row.get("syscalls_ipc", 0),
            syscalls_other=row.get("syscalls_other", 0),
            syscalls_sensitive=row.get("syscalls_sensitive", 0),
            distinct_syscalls=row.get("distinct_syscalls", 0),
            file_read_count=row.get("file_read_count", 0),
            file_write_count=row.get("file_write_count", 0),
            file_open_count=row.get("file_open_count", 0),
            file_open_write_count=row.get("file_open_write_count", 0),
            file_create_count=row.get("file_create_count", 0),
            file_delete_count=row.get("file_delete_count", 0),
            file_rename_count=row.get("file_rename_count", 0),
            unique_files=row.get("unique_files", 0),
            bytes_read=row.get("bytes_read", 0),
            bytes_written=row.get("bytes_written", 0),
            network_count=row.get("network_count", 0),
            net_connect_count=row.get("net_connect_count", 0),
            net_accept_count=row.get("net_accept_count", 0),
            unique_dest_ips=row.get("unique_dest_ips", 0),
            unique_dest_ports=row.get("unique_dest_ports", 0),
            tcp_tx_bytes=row.get("tcp_tx_bytes", 0),
            tcp_rx_bytes=row.get("tcp_rx_bytes", 0),
            udp_tx_bytes=row.get("udp_tx_bytes", 0),
            child_process_count=row.get("child_process_count", 0),
            thread_create_count=row.get("thread_create_count", 0),
            exec_count=row.get("exec_count", 0),
            cpu_usage=safe_float(row.get("cpu_usage", 0.0)),
            memory_usage=safe_float(row.get("memory_usage", 0.0)),
            memory_rss_bytes=row.get("memory_rss_bytes", 0),
            memory_vms_bytes=row.get("memory_vms_bytes", 0),
            memory_percent=safe_float(row.get("memory_percent", 0.0)),
            num_threads=row.get("num_threads", 0),
            num_fds=row.get("num_fds", 0),
            disk_read_bytes=row.get("disk_read_bytes", 0),
            disk_write_bytes=row.get("disk_write_bytes", 0),
            ctx_switches_voluntary=row.get("ctx_switches_voluntary", 0),
            ctx_switches_involuntary=row.get("ctx_switches_involuntary", 0),
            alive_at_end=row.get("alive_at_end", 1),
            label=row.get("label", "unlabeled"),
            label_binary=row.get("label_binary"),
            scenario=row.get("scenario", "ambient"),
            experiment_id=row.get("experiment_id"),
            feature_data=feat,
            schema_version=row.get("schema_version", "1.0"),
            created_at=parse_datetime(row.get("created_at")),
        )

    @classmethod
    def from_collector_csv(cls, d: Mapping[str, str]) -> "BehaviourWindow":
        lbin = safe_int(d["label_binary"]) if d.get("label_binary") not in ("", None) else None
        return cls(
            window_id=safe_int(d["window_id"]) if d.get("window_id") else None,
            window_index=safe_int(d.get("window_index", 0)),
            instance_id=d.get("instance_id") or None,
            profile_id=d.get("profile_id", ""),
            pid=safe_int(d["pid"]) if d.get("pid") else None,
            ppid=safe_int(d["ppid"]) if d.get("ppid") else None,
            comm=d.get("comm"),
            executable=d.get("executable"),
            start_time=parse_datetime(d["start_time"]) or datetime.now(timezone.utc),
            end_time=parse_datetime(d["end_time"]) or datetime.now(timezone.utc),
            duration_s=safe_float(d.get("duration_s", 0.0)),
            syscall_count=safe_int(d.get("syscall_count", 0)),
            syscalls_file=safe_int(d.get("syscalls_file", 0)),
            syscalls_network=safe_int(d.get("syscalls_network", 0)),
            syscalls_process=safe_int(d.get("syscalls_process", 0)),
            syscalls_memory=safe_int(d.get("syscalls_memory", 0)),
            syscalls_ipc=safe_int(d.get("syscalls_ipc", 0)),
            syscalls_other=safe_int(d.get("syscalls_other", 0)),
            syscalls_sensitive=safe_int(d.get("syscalls_sensitive", 0)),
            distinct_syscalls=safe_int(d.get("distinct_syscalls", 0)),
            file_read_count=safe_int(d.get("file_read_count", 0)),
            file_write_count=safe_int(d.get("file_write_count", 0)),
            file_open_count=safe_int(d.get("file_open_count", 0)),
            file_open_write_count=safe_int(d.get("file_open_write_count", 0)),
            file_create_count=safe_int(d.get("file_create_count", 0)),
            file_delete_count=safe_int(d.get("file_delete_count", 0)),
            file_rename_count=safe_int(d.get("file_rename_count", 0)),
            unique_files=safe_int(d.get("unique_files", 0)),
            bytes_read=safe_int(d.get("bytes_read", 0)),
            bytes_written=safe_int(d.get("bytes_written", 0)),
            network_count=safe_int(d.get("network_count", 0)),
            net_connect_count=safe_int(d.get("net_connect_count", 0)),
            net_accept_count=safe_int(d.get("net_accept_count", 0)),
            unique_dest_ips=safe_int(d.get("unique_dest_ips", 0)),
            unique_dest_ports=safe_int(d.get("unique_dest_ports", 0)),
            tcp_tx_bytes=safe_int(d.get("tcp_tx_bytes", 0)),
            tcp_rx_bytes=safe_int(d.get("tcp_rx_bytes", 0)),
            udp_tx_bytes=safe_int(d.get("udp_tx_bytes", 0)),
            child_process_count=safe_int(d.get("child_process_count", 0)),
            thread_create_count=safe_int(d.get("thread_create_count", 0)),
            exec_count=safe_int(d.get("exec_count", 0)),
            cpu_usage=safe_float(d.get("cpu_usage", 0.0)),
            memory_usage=safe_float(d.get("memory_usage", 0.0)),
            memory_rss_bytes=safe_int(d.get("memory_rss_bytes", 0)),
            memory_vms_bytes=safe_int(d.get("memory_vms_bytes", 0)),
            memory_percent=safe_float(d.get("memory_percent", 0.0)),
            num_threads=safe_int(d.get("num_threads", 0)),
            num_fds=safe_int(d.get("num_fds", 0)),
            disk_read_bytes=safe_int(d.get("disk_read_bytes", 0)),
            disk_write_bytes=safe_int(d.get("disk_write_bytes", 0)),
            ctx_switches_voluntary=safe_int(d.get("ctx_switches_voluntary", 0)),
            ctx_switches_involuntary=safe_int(d.get("ctx_switches_involuntary", 0)),
            alive_at_end=safe_int(d.get("alive_at_end", 1)),
            label=d.get("label", "unlabeled"),
            label_binary=lbin,
            scenario=d.get("scenario", "ambient"),
            experiment_id=d.get("experiment_id"),
        )


@dataclass
class SystemMetric:
    window_index: int
    start_time: datetime
    end_time: datetime
    duration_s: float
    metric_id: Optional[int] = None
    cpu_percent_total: float = 0.0
    cpu_user: float = 0.0
    cpu_system: float = 0.0
    cpu_idle: float = 0.0
    cpu_iowait: float = 0.0
    cpu_steal: float = 0.0
    cpu_core_max: float = 0.0
    load_1m: float = 0.0
    load_5m: float = 0.0
    load_15m: float = 0.0
    mem_total: int = 0
    mem_used: int = 0
    mem_available: int = 0
    mem_percent: float = 0.0
    swap_used: int = 0
    swap_percent: float = 0.0
    disk_root_percent: float = 0.0
    disk_used_percent_max: float = 0.0
    disk_read_bytes: int = 0
    disk_write_bytes: int = 0
    net_bytes_sent: int = 0
    net_bytes_recv: int = 0
    net_packets_sent: int = 0
    net_packets_recv: int = 0
    conn_established: int = 0
    conn_listen: int = 0
    conn_total: int = 0
    process_count: int = 0
    tracked_instances: int = 0
    events_received: int = 0
    events_lost: int = 0
    label: str = "unlabeled"
    label_binary: Optional[int] = None
    scenario: str = "ambient"
    experiment_id: Optional[str] = None
    raw_metrics: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "SystemMetric":
        raw = row.get("raw_metrics")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        elif not isinstance(raw, dict):
            raw = {}

        return cls(
            metric_id=row.get("metric_id"),
            window_index=safe_int(row.get("window_index", 0)),
            start_time=parse_datetime(row.get("start_time")) or datetime.now(timezone.utc),
            end_time=parse_datetime(row.get("end_time")) or datetime.now(timezone.utc),
            duration_s=safe_float(row.get("duration_s", 0.0)),
            cpu_percent_total=safe_float(row.get("cpu_percent_total", 0.0)),
            cpu_user=safe_float(row.get("cpu_user", 0.0)),
            cpu_system=safe_float(row.get("cpu_system", 0.0)),
            cpu_idle=safe_float(row.get("cpu_idle", 0.0)),
            cpu_iowait=safe_float(row.get("cpu_iowait", 0.0)),
            cpu_steal=safe_float(row.get("cpu_steal", 0.0)),
            cpu_core_max=safe_float(row.get("cpu_core_max", 0.0)),
            load_1m=safe_float(row.get("load_1m", 0.0)),
            load_5m=safe_float(row.get("load_5m", 0.0)),
            load_15m=safe_float(row.get("load_15m", 0.0)),
            mem_total=safe_int(row.get("mem_total", 0)),
            mem_used=safe_int(row.get("mem_used", 0)),
            mem_available=safe_int(row.get("mem_available", 0)),
            mem_percent=safe_float(row.get("mem_percent", 0.0)),
            swap_used=safe_int(row.get("swap_used", 0)),
            swap_percent=safe_float(row.get("swap_percent", 0.0)),
            disk_root_percent=safe_float(row.get("disk_root_percent", 0.0)),
            disk_used_percent_max=safe_float(row.get("disk_used_percent_max", 0.0)),
            disk_read_bytes=safe_int(row.get("disk_read_bytes", 0)),
            disk_write_bytes=safe_int(row.get("disk_write_bytes", 0)),
            net_bytes_sent=safe_int(row.get("net_bytes_sent", 0)),
            net_bytes_recv=safe_int(row.get("net_bytes_recv", 0)),
            net_packets_sent=safe_int(row.get("net_packets_sent", 0)),
            net_packets_recv=safe_int(row.get("net_packets_recv", 0)),
            conn_established=safe_int(row.get("conn_established", 0)),
            conn_listen=safe_int(row.get("conn_listen", 0)),
            conn_total=safe_int(row.get("conn_total", 0)),
            process_count=safe_int(row.get("process_count", 0)),
            tracked_instances=safe_int(row.get("tracked_instances", 0)),
            events_received=safe_int(row.get("events_received", 0)),
            events_lost=safe_int(row.get("events_lost", 0)),
            label=row.get("label", "unlabeled"),
            label_binary=safe_int(row["label_binary"]) if row.get("label_binary") not in ("", None) else None,
            scenario=row.get("scenario", "ambient"),
            experiment_id=row.get("experiment_id"),
            raw_metrics=raw,
            created_at=parse_datetime(row.get("created_at")),
        )

    @classmethod
    def from_collector_csv(cls, d: Mapping[str, str]) -> "SystemMetric":
        lbin = safe_int(d["label_binary"]) if d.get("label_binary") not in ("", None) else None
        raw = d.get("raw_metrics")
        raw_dict = {}
        if isinstance(raw, str) and raw:
            try:
                raw_dict = json.loads(raw)
            except Exception:
                raw_dict = {"raw": raw}
        elif isinstance(raw, dict):
            raw_dict = raw
        return cls(
            window_index=safe_int(d.get("window_index", 0)),
            start_time=parse_datetime(d["start_time"]) or datetime.now(timezone.utc),
            end_time=parse_datetime(d["end_time"]) or datetime.now(timezone.utc),
            duration_s=safe_float(d.get("duration_s", 0.0)),
            cpu_percent_total=safe_float(d.get("cpu_percent_total", 0.0)),
            cpu_user=safe_float(d.get("cpu_user", 0.0)),
            cpu_system=safe_float(d.get("cpu_system", 0.0)),
            cpu_idle=safe_float(d.get("cpu_idle", 0.0)),
            cpu_iowait=safe_float(d.get("cpu_iowait", 0.0)),
            cpu_steal=safe_float(d.get("cpu_steal", 0.0)),
            cpu_core_max=safe_float(d.get("cpu_core_max", 0.0)),
            load_1m=safe_float(d.get("load_1m", 0.0)),
            load_5m=safe_float(d.get("load_5m", 0.0)),
            load_15m=safe_float(d.get("load_15m", 0.0)),
            mem_total=safe_int(d.get("mem_total", 0)),
            mem_used=safe_int(d.get("mem_used", 0)),
            mem_available=safe_int(d.get("mem_available", 0)),
            mem_percent=safe_float(d.get("mem_percent", 0.0)),
            swap_used=safe_int(d.get("swap_used", 0)),
            swap_percent=safe_float(d.get("swap_percent", 0.0)),
            disk_root_percent=safe_float(d.get("disk_root_percent", 0.0)),
            disk_used_percent_max=safe_float(d.get("disk_used_percent_max", 0.0)),
            disk_read_bytes=safe_int(d.get("disk_read_bytes", 0)),
            disk_write_bytes=safe_int(d.get("disk_write_bytes", 0)),
            net_bytes_sent=safe_int(d.get("net_bytes_sent", 0)),
            net_bytes_recv=safe_int(d.get("net_bytes_recv", 0)),
            net_packets_sent=safe_int(d.get("net_packets_sent", 0)),
            net_packets_recv=safe_int(d.get("net_packets_recv", 0)),
            conn_established=safe_int(d.get("conn_established", 0)),
            conn_listen=safe_int(d.get("conn_listen", 0)),
            conn_total=safe_int(d.get("conn_total", 0)),
            process_count=safe_int(d.get("process_count", 0)),
            tracked_instances=safe_int(d.get("tracked_instances", 0)),
            events_received=safe_int(d.get("events_received", 0)),
            events_lost=safe_int(d.get("events_lost", 0)),
            label=d.get("label", "unlabeled"),
            label_binary=lbin,
            scenario=d.get("scenario", "ambient"),
            experiment_id=d.get("experiment_id"),
            raw_metrics=raw_dict,
        )


@dataclass
class ProcessProfile:
    profile_id: str
    comm: str
    executable: Optional[str] = None
    executable_hash: Optional[str] = None
    profile_version: int = 1
    observations_count: int = 0
    time_period_start: Optional[datetime] = None
    time_period_end: Optional[datetime] = None
    baseline_stats: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "ProcessProfile":
        bs = row.get("baseline_stats")
        if isinstance(bs, str):
            try:
                bs = json.loads(bs)
            except Exception:
                bs = {}
        elif not isinstance(bs, dict):
            bs = {}

        return cls(
            profile_id=row["profile_id"],
            comm=row["comm"],
            executable=row.get("executable"),
            executable_hash=row.get("executable_hash"),
            profile_version=row.get("profile_version", 1),
            observations_count=row.get("observations_count", 0),
            time_period_start=parse_datetime(row.get("time_period_start")),
            time_period_end=parse_datetime(row.get("time_period_end")),
            baseline_stats=bs,
            created_at=parse_datetime(row.get("created_at")),
            updated_at=parse_datetime(row.get("updated_at")),
        )


@dataclass
class DetectionRecord:
    detector_name: str
    detection_id: Optional[int] = None
    timestamp: Optional[datetime] = None
    instance_id: Optional[str] = None
    window_id: Optional[int] = None
    anomaly_score: Optional[float] = None
    risk_score: Optional[float] = None
    is_anomaly: bool = True
    mitre_technique: Optional[str] = None
    scenario: Optional[str] = None
    description: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "DetectionRecord":
        det = row.get("details")
        if isinstance(det, str):
            try:
                det = json.loads(det)
            except Exception:
                det = {}
        elif not isinstance(det, dict):
            det = {}

        return cls(
            detection_id=row.get("detection_id"),
            timestamp=parse_datetime(row.get("timestamp")) or datetime.now(timezone.utc),
            instance_id=row.get("instance_id"),
            window_id=row.get("window_id"),
            detector_name=row["detector_name"],
            anomaly_score=row.get("anomaly_score"),
            risk_score=row.get("risk_score"),
            is_anomaly=bool(row.get("is_anomaly", True)),
            mitre_technique=row.get("mitre_technique"),
            scenario=row.get("scenario"),
            description=row.get("description"),
            details=det,
            created_at=parse_datetime(row.get("created_at")),
        )
