"""
Persistent telemetry repository for Chronicle.
Provides clean data access for process instances, events, behaviour windows,
system metrics, baseline profiles, and anomaly detections.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from chronicle.db.connection import Database
from chronicle.db.models import (
    BehaviourWindow,
    DetectionRecord,
    ProcessInstance,
    ProcessProfile,
    SystemMetric,
    TelemetryEvent,
)
from chronicle.db.privacy import redact_string, sanitize_dict

logger = logging.getLogger("chronicle.db.repository")


class TelemetryRepository:
    """PostgreSQL and SQLite data access layer for Chronicle telemetry and historical baselines."""

    def __init__(self, database: Optional[Database] = None, enable_privacy_filter: bool = True):
        self.db = database or Database()
        self.enable_privacy_filter = enable_privacy_filter

    # -------------------------------------------------------------------------
    # Process Instances
    # -------------------------------------------------------------------------
    def register_process(self, inst: ProcessInstance) -> str:
        """Insert or update a process instance record."""
        sql = """
            INSERT INTO process_instances (
                instance_id, profile_id, pid, ppid, parent_instance_id,
                comm, executable, executable_hash, uid, start_time,
                end_time, exit_code, preexisting, windows_written, metadata, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
            )
            ON CONFLICT (instance_id) DO UPDATE SET
                end_time = EXCLUDED.end_time,
                exit_code = EXCLUDED.exit_code,
                windows_written = EXCLUDED.windows_written,
                executable = COALESCE(EXCLUDED.executable, process_instances.executable),
                executable_hash = COALESCE(EXCLUDED.executable_hash, process_instances.executable_hash),
                metadata = process_instances.metadata || EXCLUDED.metadata,
                updated_at = CURRENT_TIMESTAMP
            RETURNING instance_id;
        """
        meta = sanitize_dict(inst.metadata) if self.enable_privacy_filter else inst.metadata
        params = (
            inst.instance_id,
            inst.profile_id,
            inst.pid,
            inst.ppid,
            inst.parent_instance_id,
            inst.comm,
            inst.executable,
            inst.executable_hash,
            inst.uid,
            inst.start_time,
            inst.end_time,
            inst.exit_code,
            inst.preexisting,
            inst.windows_written,
            json.dumps(meta),
        )
        with self.db.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return row["instance_id"] if isinstance(row, dict) else row[0]

    def register_processes_batch(self, instances: Sequence[ProcessInstance]) -> int:
        """Batch upsert multiple process instances inside a single transaction."""
        if not instances:
            return 0

        sql = """
            INSERT INTO process_instances (
                instance_id, profile_id, pid, ppid, parent_instance_id,
                comm, executable, executable_hash, uid, start_time,
                end_time, exit_code, preexisting, windows_written, metadata, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
            )
            ON CONFLICT (instance_id) DO UPDATE SET
                end_time = EXCLUDED.end_time,
                exit_code = EXCLUDED.exit_code,
                windows_written = EXCLUDED.windows_written,
                executable = COALESCE(EXCLUDED.executable, process_instances.executable),
                executable_hash = COALESCE(EXCLUDED.executable_hash, process_instances.executable_hash),
                metadata = process_instances.metadata || EXCLUDED.metadata,
                updated_at = CURRENT_TIMESTAMP;
        """
        rows = [
            (
                i.instance_id,
                i.profile_id,
                i.pid,
                i.ppid,
                i.parent_instance_id,
                i.comm,
                i.executable,
                i.executable_hash,
                i.uid,
                i.start_time,
                i.end_time,
                i.exit_code,
                i.preexisting,
                i.windows_written,
                json.dumps(sanitize_dict(i.metadata) if self.enable_privacy_filter else i.metadata),
            )
            for i in instances
        ]
        with self.db.cursor() as cur:
            cur.executemany(sql, rows)
            return len(rows)

    def update_process_exit(
        self, instance_id: str, end_time: datetime, exit_code: Optional[int] = None
    ) -> bool:
        """Record process termination timestamp and optional exit code."""
        sql = """
            UPDATE process_instances
            SET end_time = %s,
                exit_code = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = %s;
        """
        with self.db.cursor() as cur:
            cur.execute(sql, (end_time, exit_code, instance_id))
            return cur.rowcount > 0

    def get_process(self, instance_id: str) -> Optional[ProcessInstance]:
        """Fetch a single process instance by its unique UUID identity."""
        sql = "SELECT * FROM process_instances WHERE instance_id = %s;"
        with self.db.cursor() as cur:
            cur.execute(sql, (instance_id,))
            row = cur.fetchone()
            return ProcessInstance.from_row(row) if row else None

    def get_processes_by_pid(self, pid: int, active_only: bool = False) -> List[ProcessInstance]:
        """Fetch process instances sharing a PID, distinguishing reused PIDs by start time."""
        if active_only:
            sql = "SELECT * FROM process_instances WHERE pid = %s AND end_time IS NULL ORDER BY start_time DESC;"
            params = (pid,)
        else:
            sql = "SELECT * FROM process_instances WHERE pid = %s ORDER BY start_time DESC;"
            params = (pid,)

        with self.db.cursor() as cur:
            cur.execute(sql, params)
            return [ProcessInstance.from_row(r) for r in cur.fetchall()]

    def get_processes_by_comm(self, comm: str, limit: int = 50) -> List[ProcessInstance]:
        """Fetch process instances matching a process name."""
        sql = "SELECT * FROM process_instances WHERE comm = %s ORDER BY start_time DESC LIMIT %s;"
        with self.db.cursor() as cur:
            cur.execute(sql, (comm, limit))
            return [ProcessInstance.from_row(r) for r in cur.fetchall()]

    # -------------------------------------------------------------------------
    # Telemetry Events
    # -------------------------------------------------------------------------
    def insert_event(self, event: TelemetryEvent) -> int:
        """Insert a single telemetry event."""
        sql = """
            INSERT INTO telemetry_events (
                event_uuid, instance_id, pid, timestamp, event_type,
                syscall_category, file_identifier, network_identifier, payload
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING event_id;
        """
        file_id = (
            redact_string(event.file_identifier)
            if (self.enable_privacy_filter and event.file_identifier)
            else event.file_identifier
        )
        payload = sanitize_dict(event.payload) if self.enable_privacy_filter else event.payload
        params = (
            event.event_uuid,
            event.instance_id,
            event.pid,
            event.timestamp,
            event.event_type,
            event.syscall_category,
            file_id,
            event.network_identifier,
            json.dumps(payload),
        )
        with self.db.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return row["event_id"] if isinstance(row, dict) else row[0]

    def insert_events_batch(self, events: Sequence[TelemetryEvent]) -> int:
        """Batch insert telemetry events inside a single transaction."""
        if not events:
            return 0

        sql = """
            INSERT INTO telemetry_events (
                event_uuid, instance_id, pid, timestamp, event_type,
                syscall_category, file_identifier, network_identifier, payload
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        rows = [
            (
                e.event_uuid,
                e.instance_id,
                e.pid,
                e.timestamp,
                e.event_type,
                e.syscall_category,
                redact_string(e.file_identifier) if (self.enable_privacy_filter and e.file_identifier) else e.file_identifier,
                e.network_identifier,
                json.dumps(sanitize_dict(e.payload) if self.enable_privacy_filter else e.payload),
            )
            for e in events
        ]
        with self.db.cursor() as cur:
            cur.executemany(sql, rows)
            return len(rows)

    def get_events_by_process(
        self,
        instance_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 200,
    ) -> List[TelemetryEvent]:
        """Retrieve telemetry events belonging to a process instance."""
        clauses = ["instance_id = %s"]
        params: List[Any] = [instance_id]

        if start_time:
            clauses.append("timestamp >= %s")
            params.append(start_time)
        if end_time:
            clauses.append("timestamp <= %s")
            params.append(end_time)

        sql = f"""
            SELECT * FROM telemetry_events
            WHERE {' AND '.join(clauses)}
            ORDER BY timestamp ASC
            LIMIT %s;
        """
        params.append(limit)

        with self.db.cursor() as cur:
            cur.execute(sql, tuple(params))
            return [TelemetryEvent.from_row(r) for r in cur.fetchall()]

    def get_events_by_timerange(
        self,
        start_time: datetime,
        end_time: datetime,
        event_types: Optional[Sequence[str]] = None,
        limit: int = 200,
    ) -> List[TelemetryEvent]:
        """Retrieve telemetry events across processes within a time window."""
        clauses = ["timestamp >= %s", "timestamp <= %s"]
        params: List[Any] = [start_time, end_time]

        if event_types:
            clauses.append("event_type = ANY(%s)")
            params.append(list(event_types))

        sql = f"""
            SELECT * FROM telemetry_events
            WHERE {' AND '.join(clauses)}
            ORDER BY timestamp ASC
            LIMIT %s;
        """
        params.append(limit)

        with self.db.cursor() as cur:
            cur.execute(sql, tuple(params))
            return [TelemetryEvent.from_row(r) for r in cur.fetchall()]

    def get_recent_events(self, limit: int = 100) -> List[TelemetryEvent]:
        """Retrieve the latest telemetry events observed on the host."""
        sql = "SELECT * FROM telemetry_events ORDER BY timestamp DESC LIMIT %s;"
        with self.db.cursor() as cur:
            cur.execute(sql, (limit,))
            return [TelemetryEvent.from_row(r) for r in cur.fetchall()]

    # -------------------------------------------------------------------------
    # Behaviour Windows
    # -------------------------------------------------------------------------
    def insert_window(self, win: BehaviourWindow) -> int:
        """Insert a single behaviour window record."""
        sql = """
            INSERT INTO behaviour_windows (
                window_index, instance_id, profile_id, pid, ppid, comm, executable,
                start_time, end_time, duration_s,
                syscall_count, syscalls_file, syscalls_network, syscalls_process,
                syscalls_memory, syscalls_ipc, syscalls_other, syscalls_sensitive, distinct_syscalls,
                file_read_count, file_write_count, file_open_count, file_open_write_count,
                file_create_count, file_delete_count, file_rename_count, unique_files,
                bytes_read, bytes_written,
                network_count, net_connect_count, net_accept_count, unique_dest_ips, unique_dest_ports,
                tcp_tx_bytes, tcp_rx_bytes, udp_tx_bytes,
                child_process_count, thread_create_count, exec_count,
                cpu_usage, memory_usage, memory_rss_bytes, memory_vms_bytes, memory_percent,
                num_threads, num_fds, disk_read_bytes, disk_write_bytes,
                ctx_switches_voluntary, ctx_switches_involuntary,
                alive_at_end, label, label_binary, scenario, experiment_id,
                feature_data, schema_version
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s
            ) RETURNING window_id;
        """
        params = (
            win.window_index, win.instance_id, win.profile_id, win.pid, win.ppid, win.comm, win.executable,
            win.start_time, win.end_time, win.duration_s,
            win.syscall_count, win.syscalls_file, win.syscalls_network, win.syscalls_process,
            win.syscalls_memory, win.syscalls_ipc, win.syscalls_other, win.syscalls_sensitive, win.distinct_syscalls,
            win.file_read_count, win.file_write_count, win.file_open_count, win.file_open_write_count,
            win.file_create_count, win.file_delete_count, win.file_rename_count, win.unique_files,
            win.bytes_read, win.bytes_written,
            win.network_count, win.net_connect_count, win.net_accept_count, win.unique_dest_ips, win.unique_dest_ports,
            win.tcp_tx_bytes, win.tcp_rx_bytes, win.udp_tx_bytes,
            win.child_process_count, win.thread_create_count, win.exec_count,
            win.cpu_usage, win.memory_usage, win.memory_rss_bytes, win.memory_vms_bytes, win.memory_percent,
            win.num_threads, win.num_fds, win.disk_read_bytes, win.disk_write_bytes,
            win.ctx_switches_voluntary, win.ctx_switches_involuntary,
            win.alive_at_end, win.label, win.label_binary, win.scenario, win.experiment_id,
            json.dumps(win.feature_data), win.schema_version,
        )
        with self.db.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return row["window_id"] if isinstance(row, dict) else row[0]

    def insert_windows_batch(self, windows: Sequence[BehaviourWindow]) -> int:
        """Batch insert multiple behaviour window records."""
        if not windows:
            return 0

        sql = """
            INSERT INTO behaviour_windows (
                window_index, instance_id, profile_id, pid, ppid, comm, executable,
                start_time, end_time, duration_s,
                syscall_count, syscalls_file, syscalls_network, syscalls_process,
                syscalls_memory, syscalls_ipc, syscalls_other, syscalls_sensitive, distinct_syscalls,
                file_read_count, file_write_count, file_open_count, file_open_write_count,
                file_create_count, file_delete_count, file_rename_count, unique_files,
                bytes_read, bytes_written,
                network_count, net_connect_count, net_accept_count, unique_dest_ips, unique_dest_ports,
                tcp_tx_bytes, tcp_rx_bytes, udp_tx_bytes,
                child_process_count, thread_create_count, exec_count,
                cpu_usage, memory_usage, memory_rss_bytes, memory_vms_bytes, memory_percent,
                num_threads, num_fds, disk_read_bytes, disk_write_bytes,
                ctx_switches_voluntary, ctx_switches_involuntary,
                alive_at_end, label, label_binary, scenario, experiment_id,
                feature_data, schema_version
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s
            );
        """
        rows = [
            (
                w.window_index, w.instance_id, w.profile_id, w.pid, w.ppid, w.comm, w.executable,
                w.start_time, w.end_time, w.duration_s,
                w.syscall_count, w.syscalls_file, w.syscalls_network, w.syscalls_process,
                w.syscalls_memory, w.syscalls_ipc, w.syscalls_other, w.syscalls_sensitive, w.distinct_syscalls,
                w.file_read_count, w.file_write_count, w.file_open_count, w.file_open_write_count,
                w.file_create_count, w.file_delete_count, w.file_rename_count, w.unique_files,
                w.bytes_read, w.bytes_written,
                w.network_count, w.net_connect_count, w.net_accept_count, w.unique_dest_ips, w.unique_dest_ports,
                w.tcp_tx_bytes, w.tcp_rx_bytes, w.udp_tx_bytes,
                w.child_process_count, w.thread_create_count, w.exec_count,
                w.cpu_usage, w.memory_usage, w.memory_rss_bytes, w.memory_vms_bytes, w.memory_percent,
                w.num_threads, w.num_fds, w.disk_read_bytes, w.disk_write_bytes,
                w.ctx_switches_voluntary, w.ctx_switches_involuntary,
                w.alive_at_end, w.label, w.label_binary, w.scenario, w.experiment_id,
                json.dumps(w.feature_data), w.schema_version,
            )
            for w in windows
        ]
        with self.db.cursor() as cur:
            cur.executemany(sql, rows)
            return len(rows)

    def get_windows_by_process(
        self,
        instance_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[BehaviourWindow]:
        """Fetch behaviour windows for a given process instance."""
        clauses = ["instance_id = %s"]
        params: List[Any] = [instance_id]

        if start_time:
            clauses.append("start_time >= %s")
            params.append(start_time)
        if end_time:
            clauses.append("end_time <= %s")
            params.append(end_time)

        sql = f"""
            SELECT * FROM behaviour_windows
            WHERE {' AND '.join(clauses)}
            ORDER BY start_time ASC
            LIMIT %s;
        """
        params.append(limit)

        with self.db.cursor() as cur:
            cur.execute(sql, tuple(params))
            return [BehaviourWindow.from_row(r) for r in cur.fetchall()]

    def get_windows_by_profile(
        self,
        profile_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 2000,
    ) -> List[BehaviourWindow]:
        """Fetch historical behaviour windows for a given program profile."""
        clauses = ["profile_id = %s"]
        params: List[Any] = [profile_id]

        if start_time:
            clauses.append("start_time >= %s")
            params.append(start_time)
        if end_time:
            clauses.append("end_time <= %s")
            params.append(end_time)

        sql = f"""
            SELECT * FROM behaviour_windows
            WHERE {' AND '.join(clauses)}
            ORDER BY start_time ASC
            LIMIT %s;
        """
        params.append(limit)

        with self.db.cursor() as cur:
            cur.execute(sql, tuple(params))
            return [BehaviourWindow.from_row(r) for r in cur.fetchall()]

    def get_recent_windows(self, limit: int = 100) -> List[BehaviourWindow]:
        """Retrieve recent behaviour windows."""
        sql = "SELECT * FROM behaviour_windows ORDER BY start_time DESC LIMIT %s;"
        with self.db.cursor() as cur:
            cur.execute(sql, (limit,))
            return [BehaviourWindow.from_row(r) for r in cur.fetchall()]

    # -------------------------------------------------------------------------
    # System Metrics
    # -------------------------------------------------------------------------
    def insert_system_metrics_batch(self, metrics: Sequence[SystemMetric]) -> int:
        """Batch insert system metric observations."""
        if not metrics:
            return 0

        sql = """
            INSERT INTO system_metrics (
                window_index, start_time, end_time, duration_s,
                cpu_percent_total, cpu_user, cpu_system, cpu_idle, cpu_iowait, cpu_steal, cpu_core_max,
                load_1m, load_5m, load_15m,
                mem_total, mem_used, mem_available, mem_percent, swap_used, swap_percent,
                disk_root_percent, disk_used_percent_max, disk_read_bytes, disk_write_bytes,
                net_bytes_sent, net_bytes_recv, net_packets_sent, net_packets_recv,
                conn_established, conn_listen, conn_total,
                process_count, tracked_instances, events_received, events_lost,
                label, label_binary, scenario, experiment_id, raw_metrics
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s
            );
        """
        rows = [
            (
                m.window_index, m.start_time, m.end_time, m.duration_s,
                m.cpu_percent_total, m.cpu_user, m.cpu_system, m.cpu_idle, m.cpu_iowait, m.cpu_steal, m.cpu_core_max,
                m.load_1m, m.load_5m, m.load_15m,
                m.mem_total, m.mem_used, m.mem_available, m.mem_percent, m.swap_used, m.swap_percent,
                m.disk_root_percent, m.disk_used_percent_max, m.disk_read_bytes, m.disk_write_bytes,
                m.net_bytes_sent, m.net_bytes_recv, m.net_packets_sent, m.net_packets_recv,
                m.conn_established, m.conn_listen, m.conn_total,
                m.process_count, m.tracked_instances, m.events_received, m.events_lost,
                m.label, m.label_binary, m.scenario, m.experiment_id, json.dumps(m.raw_metrics),
            )
            for m in metrics
        ]
        with self.db.cursor() as cur:
            cur.executemany(sql, rows)
            return len(rows)

    def get_recent_system_metrics(self, limit: int = 50) -> List[SystemMetric]:
        """Fetch latest system metric records."""
        sql = "SELECT * FROM system_metrics ORDER BY start_time DESC LIMIT %s;"
        with self.db.cursor() as cur:
            cur.execute(sql, (limit,))
            return [SystemMetric.from_row(r) for r in cur.fetchall()]

    def get_recent_system_activity(self, limit: int = 100) -> Dict[str, Any]:
        """Fetch an activity overview aggregating recent counts and system stats."""
        with self.db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM process_instances WHERE end_time IS NULL;")
            active_procs = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) AS c FROM telemetry_events;")
            total_events = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) AS c FROM behaviour_windows;")
            total_windows = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) AS c FROM detections WHERE is_anomaly = TRUE;")
            total_anomalies = cur.fetchone()["c"]

            cur.execute("""
                SELECT comm, COUNT(*) as window_count, ROUND(AVG(cpu_usage)::numeric, 2) as avg_cpu
                FROM behaviour_windows
                GROUP BY comm
                ORDER BY window_count DESC
                LIMIT 10;
            """)
            top_comms = [dict(r) for r in cur.fetchall()]

            return {
                "active_processes": active_procs,
                "total_telemetry_events": total_events,
                "total_behaviour_windows": total_windows,
                "total_anomalies": total_anomalies,
                "top_active_programs": top_comms,
            }

    # -------------------------------------------------------------------------
    # Process Profiles (Historical Baselines)
    # -------------------------------------------------------------------------
    def save_profile(self, profile: ProcessProfile) -> None:
        """Create or update a program-level behavioural profile."""
        sql = """
            INSERT INTO process_profiles (
                profile_id, comm, executable, executable_hash,
                profile_version, observations_count,
                time_period_start, time_period_end, baseline_stats, updated_at
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s,
                %s, %s, %s, CURRENT_TIMESTAMP
            )
            ON CONFLICT (profile_id, profile_version) DO UPDATE SET
                comm = EXCLUDED.comm,
                executable = COALESCE(EXCLUDED.executable, process_profiles.executable),
                executable_hash = COALESCE(EXCLUDED.executable_hash, process_profiles.executable_hash),
                observations_count = EXCLUDED.observations_count,
                time_period_start = EXCLUDED.time_period_start,
                time_period_end = EXCLUDED.time_period_end,
                baseline_stats = EXCLUDED.baseline_stats,
                updated_at = CURRENT_TIMESTAMP;
        """
        params = (
            profile.profile_id,
            profile.comm,
            profile.executable,
            profile.executable_hash,
            profile.profile_version,
            profile.observations_count,
            profile.time_period_start,
            profile.time_period_end,
            json.dumps(profile.baseline_stats),
        )
        with self.db.cursor() as cur:
            cur.execute(sql, params)

    def get_profile(
        self, profile_id: str, version: Optional[int] = None
    ) -> Optional[ProcessProfile]:
        """Fetch a behaviour profile by profile_id and optional version."""
        if version is not None:
            sql = "SELECT * FROM process_profiles WHERE profile_id = %s AND profile_version = %s;"
            params = (profile_id, version)
        else:
            sql = "SELECT * FROM process_profiles WHERE profile_id = %s ORDER BY profile_version DESC LIMIT 1;"
            params = (profile_id,)

        with self.db.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return ProcessProfile.from_row(row) if row else None

    def get_profiles_by_comm(self, comm: str) -> List[ProcessProfile]:
        """Fetch profiles matching program comm name."""
        sql = "SELECT * FROM process_profiles WHERE comm = %s ORDER BY profile_version DESC;"
        with self.db.cursor() as cur:
            cur.execute(sql, (comm,))
            return [ProcessProfile.from_row(r) for r in cur.fetchall()]

    def list_profiles(self, limit: int = 100) -> List[ProcessProfile]:
        """List stored program profiles."""
        sql = "SELECT * FROM process_profiles ORDER BY updated_at DESC LIMIT %s;"
        with self.db.cursor() as cur:
            cur.execute(sql, (limit,))
            return [ProcessProfile.from_row(r) for r in cur.fetchall()]

    # -------------------------------------------------------------------------
    # Detections
    # -------------------------------------------------------------------------
    def insert_detection(self, det: DetectionRecord) -> int:
        """Insert a model or rule detection output."""
        sql = """
            INSERT INTO detections (
                timestamp, instance_id, window_id, detector_name,
                anomaly_score, risk_score, is_anomaly, mitre_technique,
                scenario, description, details
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING detection_id;
        """
        params = (
            det.timestamp,
            det.instance_id,
            det.window_id,
            det.detector_name,
            det.anomaly_score,
            det.risk_score,
            det.is_anomaly,
            det.mitre_technique,
            det.scenario,
            det.description,
            json.dumps(det.details),
        )
        with self.db.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return row["detection_id"] if isinstance(row, dict) else row[0]

    def insert_detections_batch(self, detections: Sequence[DetectionRecord]) -> int:
        """Batch insert anomaly detections."""
        if not detections:
            return 0

        sql = """
            INSERT INTO detections (
                timestamp, instance_id, window_id, detector_name,
                anomaly_score, risk_score, is_anomaly, mitre_technique,
                scenario, description, details
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        rows = [
            (
                d.timestamp,
                d.instance_id,
                d.window_id,
                d.detector_name,
                d.anomaly_score,
                d.risk_score,
                d.is_anomaly,
                d.mitre_technique,
                d.scenario,
                d.description,
                json.dumps(d.details),
            )
            for d in detections
        ]
        with self.db.cursor() as cur:
            cur.executemany(sql, rows)
            return len(rows)

    def get_recent_detections(self, limit: int = 50) -> List[DetectionRecord]:
        """Fetch latest detections ordered by timestamp descending."""
        sql = "SELECT * FROM detections ORDER BY timestamp DESC LIMIT %s;"
        with self.db.cursor() as cur:
            cur.execute(sql, (limit,))
            return [DetectionRecord.from_row(r) for r in cur.fetchall()]

    def get_detections_by_instance(self, instance_id: str) -> List[DetectionRecord]:
        """Fetch all detections associated with a given process instance."""
        sql = "SELECT * FROM detections WHERE instance_id = %s ORDER BY timestamp ASC;"
        with self.db.cursor() as cur:
            cur.execute(sql, (instance_id,))
            return [DetectionRecord.from_row(r) for r in cur.fetchall()]
