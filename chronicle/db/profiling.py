"""
Historical process behaviour profiling and baseline builder.
Aggregates historical behaviour windows for a given program profile to establish
statistical norms (mean, standard deviation, percentiles) and evaluate deviations.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from chronicle.db.models import BehaviourWindow, ProcessProfile
from chronicle.db.repository import TelemetryRepository


def mean_and_std(values: List[float]) -> Tuple[float, float]:
    """Compute mean and population standard deviation."""
    if not values:
        return 0.0, 0.0
    n = len(values)
    avg = sum(values) / n
    if n <= 1:
        return round(avg, 4), 0.0
    var = sum((x - avg) ** 2 for x in values) / n
    return round(avg, 4), round(math.sqrt(var), 4)


class ProfileManager:
    """Computes program-level behavioural baselines and evaluates live windows against history."""

    def __init__(self, repository: TelemetryRepository):
        self.repo = repository

    def build_profile_from_history(
        self,
        profile_id: str,
        comm: Optional[str] = None,
        min_observations: int = 5,
        version: int = 1,
    ) -> Optional[ProcessProfile]:
        """Aggregate behaviour windows for profile_id and persist a ProcessProfile."""
        windows = self.repo.get_windows_by_profile(profile_id)
        if len(windows) < min_observations:
            return None

        program_comm = comm or next((w.comm for w in windows if w.comm), "unknown")
        program_exe = next((w.executable for w in windows if w.executable), None)

        cpus = [w.cpu_usage for w in windows]
        mems = [w.memory_usage for w in windows]
        syscalls = [float(w.syscall_count) for w in windows]
        file_reads = [float(w.bytes_read) for w in windows]
        file_writes = [float(w.bytes_written) for w in windows]
        net_tx = [float(w.tcp_tx_bytes + w.udp_tx_bytes) for w in windows]
        net_rx = [float(w.tcp_rx_bytes) for w in windows]
        sensitive = [float(w.syscalls_sensitive) for w in windows]

        avg_cpu, std_cpu = mean_and_std(cpus)
        avg_mem, std_mem = mean_and_std(mems)
        avg_sys, std_sys = mean_and_std(syscalls)
        avg_rd, std_rd = mean_and_std(file_reads)
        avg_wr, std_wr = mean_and_std(file_writes)
        avg_tx, std_tx = mean_and_std(net_tx)
        avg_rx, std_rx = mean_and_std(net_rx)

        typical_events: List[str] = []
        if sum(w.file_open_count for w in windows) > 0:
            typical_events.append("file_open")
        if sum(w.file_write_count for w in windows) > 0:
            typical_events.append("file_modify")
        if sum(w.net_connect_count for w in windows) > 0:
            typical_events.append("socket_connect")
        if sum(w.child_process_count for w in windows) > 0:
            typical_events.append("fork")
        if sum(w.exec_count for w in windows) > 0:
            typical_events.append("execve")

        baseline_stats = {
            "avgCpu": avg_cpu,
            "stdCpu": std_cpu,
            "maxCpu": max(cpus) if cpus else 0.0,
            "avgMem": avg_mem,
            "stdMem": std_mem,
            "maxMem": max(mems) if mems else 0.0,
            "avgSyscalls": avg_sys,
            "stdSyscalls": std_sys,
            "maxSyscalls": max(syscalls) if syscalls else 0.0,
            "avgBytesRead": avg_rd,
            "stdBytesRead": std_rd,
            "maxBytesRead": max(file_reads) if file_reads else 0.0,
            "avgBytesWritten": avg_wr,
            "stdBytesWritten": std_wr,
            "maxBytesWritten": max(file_writes) if file_writes else 0.0,
            "avgNetTx": avg_tx,
            "stdNetTx": std_tx,
            "maxNetTx": max(net_tx) if net_tx else 0.0,
            "avgNetRx": avg_rx,
            "stdNetRx": std_rx,
            "maxNetRx": max(net_rx) if net_rx else 0.0,
            "maxSensitiveSyscalls": max(sensitive) if sensitive else 0.0,
            "typicalEvents": typical_events,
            "sampleCount": len(windows),
        }

        start_times = [w.start_time for w in windows if w.start_time]
        end_times = [w.end_time for w in windows if w.end_time]

        profile = ProcessProfile(
            profile_id=profile_id,
            comm=program_comm,
            executable=program_exe,
            profile_version=version,
            observations_count=len(windows),
            time_period_start=min(start_times) if start_times else None,
            time_period_end=max(end_times) if end_times else None,
            baseline_stats=baseline_stats,
        )

        self.repo.save_profile(profile)
        return profile

    @staticmethod
    def evaluate_window_deviation(
        win: BehaviourWindow, profile: ProcessProfile, threshold_z: float = 3.0
    ) -> Dict[str, Any]:
        """Compare a behaviour window against historical baseline, calculating Z-scores and anomaly risks."""
        b = profile.baseline_stats
        reasons: List[str] = []

        def z_score(actual: float, mean: float, std: float) -> float:
            if std <= 0.001:
                if actual <= mean:
                    return 0.0
                effective_std = max(0.1 * abs(mean), 1.0)
                return round((actual - mean) / effective_std, 2)
            return round((actual - mean) / std, 2)

        z_cpu = z_score(win.cpu_usage, b.get("avgCpu", 0.0), b.get("stdCpu", 0.0))
        z_mem = z_score(win.memory_usage, b.get("avgMem", 0.0), b.get("stdMem", 0.0))
        z_sys = z_score(float(win.syscall_count), b.get("avgSyscalls", 0.0), b.get("stdSyscalls", 0.0))

        if z_cpu >= threshold_z:
            reasons.append(f"CPU usage {win.cpu_usage:.1f}% is {z_cpu}x standard deviations above historical mean")
        if z_mem >= threshold_z:
            reasons.append(f"Memory {win.memory_usage:.1f}MB is {z_mem}x standard deviations above baseline")
        if z_sys >= threshold_z:
            reasons.append(f"Syscall burst {win.syscall_count} is {z_sys}x standard deviations above baseline")

        # Unprecedented outbound network socket
        if win.net_connect_count > 0 and "socket_connect" not in b.get("typicalEvents", []):
            reasons.append(f"Unprecedented outbound socket connection initiated by {win.comm}")

        # Sensitive syscall spike
        if win.syscalls_sensitive > 0 and b.get("maxSensitiveSyscalls", 0.0) == 0.0:
            reasons.append(f"Unprecedented privileged/sensitive syscall invocation ({win.syscalls_sensitive})")

        # Risk score calculation (0 to 100)
        max_z = max(0.0, z_cpu, z_mem, z_sys)
        risk = min(100.0, max_z * 20.0 + (len(reasons) * 15.0))
        is_anomaly = bool(reasons or risk >= 75.0)

        return {
            "is_anomaly": is_anomaly,
            "risk_score": round(risk, 1),
            "z_scores": {"cpu": z_cpu, "memory": z_mem, "syscalls": z_sys},
            "reasons": reasons,
            "profile_observations": profile.observations_count,
        }
