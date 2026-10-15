"""
Chronicle - Historical Process Behaviour Profiling and Advanced Behavioural Baselining.
=======================================================================================
Implements robust statistical baselines per program (profile_id) separate from individual
process instances, resistant to outliers (Median, IQR, NMAD), handling cold-starts, zero
variance, missing values, and temporal data isolation without synthetic data.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from chronicle.db.models import (
    BehaviourWindow,
    DeviationResult,
    ProcessInstance,
    ProcessLifecycleSummary,
    ProcessProfile,
    ProgramHistorySummary,
    safe_float,
    safe_int,
    to_iso,
)
from chronicle.db.repository import TelemetryRepository


# -----------------------------------------------------------------------------
# Real Telemetry Features Produced by Chronicle eBPF Collector (eBPF + psutil)
# -----------------------------------------------------------------------------
FEATURE_REGISTRY: Dict[str, Dict[str, Any]] = {
    # 1. Syscall metrics
    "syscall_count": {"category": "syscall", "floor": 5.0, "weight": 1.0, "label": "Syscall frequency"},
    "distinct_syscalls": {"category": "syscall", "floor": 1.0, "weight": 1.0, "label": "Syscall diversity"},
    "syscalls_file": {"category": "syscall", "floor": 2.0, "weight": 0.8, "label": "File syscalls"},
    "syscalls_network": {"category": "syscall", "floor": 1.0, "weight": 1.2, "label": "Network syscalls"},
    "syscalls_process": {"category": "syscall", "floor": 1.0, "weight": 1.2, "label": "Process control syscalls"},
    "syscalls_memory": {"category": "syscall", "floor": 1.0, "weight": 0.8, "label": "Memory syscalls"},
    "syscalls_ipc": {"category": "syscall", "floor": 1.0, "weight": 0.8, "label": "IPC syscalls"},
    "syscalls_other": {"category": "syscall", "floor": 1.0, "weight": 0.5, "label": "Other syscalls"},
    "syscalls_sensitive": {"category": "security", "floor": 0.5, "weight": 2.5, "label": "Sensitive/privileged syscalls"},

    # 2. File activity metrics
    "file_read_count": {"category": "file", "floor": 1.0, "weight": 0.8, "label": "File read operations"},
    "file_write_count": {"category": "file", "floor": 1.0, "weight": 1.0, "label": "File write operations"},
    "file_open_count": {"category": "file", "floor": 1.0, "weight": 0.8, "label": "File open operations"},
    "file_open_write_count": {"category": "file", "floor": 1.0, "weight": 1.2, "label": "File open-write operations"},
    "file_create_count": {"category": "file", "floor": 0.5, "weight": 1.2, "label": "File create operations"},
    "file_delete_count": {"category": "security", "floor": 0.5, "weight": 2.0, "label": "File delete operations"},
    "file_rename_count": {"category": "file", "floor": 0.5, "weight": 1.2, "label": "File rename operations"},
    "unique_files": {"category": "file", "floor": 1.0, "weight": 1.0, "label": "Distinct files accessed"},
    "bytes_read": {"category": "file", "floor": 1024.0, "weight": 0.7, "label": "Bytes read"},
    "bytes_written": {"category": "file", "floor": 1024.0, "weight": 0.9, "label": "Bytes written"},

    # 3. Network activity metrics
    "network_count": {"category": "network", "floor": 1.0, "weight": 1.0, "label": "Network operations"},
    "net_connect_count": {"category": "security", "floor": 0.5, "weight": 2.2, "label": "Outbound socket connects"},
    "net_accept_count": {"category": "network", "floor": 0.5, "weight": 1.2, "label": "Inbound socket accepts"},
    "unique_dest_ips": {"category": "network", "floor": 0.5, "weight": 1.5, "label": "Distinct destination IPs"},
    "unique_dest_ports": {"category": "network", "floor": 0.5, "weight": 1.2, "label": "Distinct destination ports"},
    "tcp_tx_bytes": {"category": "network", "floor": 512.0, "weight": 0.9, "label": "TCP transmitted bytes"},
    "tcp_rx_bytes": {"category": "network", "floor": 512.0, "weight": 0.7, "label": "TCP received bytes"},
    "udp_tx_bytes": {"category": "network", "floor": 512.0, "weight": 1.2, "label": "UDP transmitted bytes"},

    # 4. Process relations
    "child_process_count": {"category": "security", "floor": 0.5, "weight": 2.0, "label": "Child processes spawned"},
    "thread_create_count": {"category": "security", "floor": 1.0, "weight": 1.0, "label": "Threads created"},
    "exec_count": {"category": "security", "floor": 0.5, "weight": 2.5, "label": "Binary execve invocations"},

    # 5. Resource metrics
    "cpu_usage": {"category": "resource", "floor": 0.5, "weight": 1.2, "label": "CPU usage (%)"},
    "memory_usage": {"category": "resource", "floor": 1.0, "weight": 1.0, "label": "Memory usage (MB)"},
    "memory_rss_bytes": {"category": "resource", "floor": 1048576.0, "weight": 0.8, "label": "Resident memory (RSS)"},
    "memory_vms_bytes": {"category": "resource", "floor": 2097152.0, "weight": 0.6, "label": "Virtual memory (VMS)"},
    "memory_percent": {"category": "resource", "floor": 0.5, "weight": 1.0, "label": "Memory percentage"},
    "num_threads": {"category": "resource", "floor": 1.0, "weight": 0.8, "label": "Thread count"},
    "num_fds": {"category": "resource", "floor": 1.0, "weight": 0.8, "label": "Open file descriptors"},
    "disk_read_bytes": {"category": "resource", "floor": 4096.0, "weight": 0.6, "label": "Disk read bytes"},
    "disk_write_bytes": {"category": "resource", "floor": 4096.0, "weight": 0.7, "label": "Disk write bytes"},
    "ctx_switches_voluntary": {"category": "resource", "floor": 10.0, "weight": 0.5, "label": "Voluntary context switches"},
    "ctx_switches_involuntary": {"category": "resource", "floor": 5.0, "weight": 0.7, "label": "Involuntary context switches"},
    "duration_s": {"category": "resource", "floor": 0.1, "weight": 0.3, "label": "Window duration (s)"},
}


# -----------------------------------------------------------------------------
# Robust Statistical Utilities
# -----------------------------------------------------------------------------
def mean_and_std(values: Sequence[float]) -> Tuple[float, float]:
    """Compute mean and population standard deviation."""
    if not values:
        return 0.0, 0.0
    n = len(values)
    avg = sum(values) / n
    if n <= 1:
        return round(avg, 4), 0.0
    var = sum((x - avg) ** 2 for x in values) / n
    return round(avg, 4), round(math.sqrt(var), 4)


def compute_percentiles(values: Sequence[float], percentiles: Sequence[float] = (25.0, 50.0, 75.0, 90.0, 95.0, 99.0)) -> Dict[float, float]:
    """Calculate exact or interpolated percentiles for a list of values."""
    if not values:
        return {p: 0.0 for p in percentiles}
    sorted_v = sorted(values)
    n = len(sorted_v)
    res = {}
    for p in percentiles:
        if n == 1:
            res[p] = round(sorted_v[0], 4)
            continue
        k = (p / 100.0) * (n - 1)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            res[p] = round(sorted_v[int(k)], 4)
        else:
            d = k - f
            interpolated = sorted_v[f] + d * (sorted_v[c] - sorted_v[f])
            res[p] = round(interpolated, 4)
    return res


def compute_median_and_mad(values: Sequence[float]) -> Tuple[float, float, float]:
    """
    Compute Median, Median Absolute Deviation (MAD), and Normalized MAD (NMAD).
    NMAD (1.4826 * MAD) is an unbiased, outlier-resistant estimator of standard deviation.
    """
    if not values:
        return 0.0, 0.0, 0.0
    sorted_v = sorted(values)
    n = len(sorted_v)
    if n % 2 == 1:
        med = sorted_v[n // 2]
    else:
        med = (sorted_v[n // 2 - 1] + sorted_v[n // 2]) / 2.0

    abs_devs = sorted([abs(x - med) for x in values])
    if n % 2 == 1:
        mad = abs_devs[n // 2]
    else:
        mad = (abs_devs[n // 2 - 1] + abs_devs[n // 2]) / 2.0

    nmad = 1.4826 * mad
    return round(med, 4), round(mad, 4), round(nmad, 4)


def compute_feature_baseline(values: Sequence[float], noise_floor: float = 1.0) -> Dict[str, Any]:
    """
    Compute comprehensive robust statistics for a behavioural feature:
    mean, std, min, max, median, MAD, NMAD, percentiles (p25, p75, p90, p95, p99),
    IQR, and effective scaling denominator for deviation scoring.
    """
    if not values:
        return {
            "count": 0,
            "mean": 0.0,
            "std": 0.0,
            "min": 0.0,
            "max": 0.0,
            "median": 0.0,
            "mad": 0.0,
            "nmad": 0.0,
            "iqr": 0.0,
            "p25": 0.0,
            "p50": 0.0,
            "p75": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "noise_floor": noise_floor,
            "effective_scale": noise_floor,
        }

    n = len(values)
    avg, std = mean_and_std(values)
    med, mad, nmad = compute_median_and_mad(values)
    pcts = compute_percentiles(values, (25.0, 50.0, 75.0, 90.0, 95.0, 99.0))
    iqr = round(max(0.0, pcts[75.0] - pcts[25.0]), 4)

    # Effective scale prevents division by zero when variance is zero (e.g. constant 0 or 1)
    effective_scale = max(nmad, std, 0.05 * abs(med), noise_floor)

    return {
        "count": n,
        "mean": avg,
        "std": std,
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "median": med,
        "mad": mad,
        "nmad": nmad,
        "iqr": iqr,
        "p25": pcts[25.0],
        "p50": pcts[50.0],
        "p75": pcts[75.0],
        "p90": pcts[90.0],
        "p95": pcts[95.0],
        "p99": pcts[99.0],
        "noise_floor": noise_floor,
        "effective_scale": round(effective_scale, 4),
    }


def calculate_maturity(observations_count: int, instances_count: int = 1) -> Tuple[str, float]:
    """
    Determine baseline maturity level and confidence score.

    Tiers:
      • COLD_START (< 5 windows or 0 instances):
          Confidence 0.1 - 0.4. Low sample size; deviation signals are conservative
          and suppressed to avoid false alarms.
      • LEARNING (5 - 29 windows):
          Confidence 0.45 - 0.79. Baselining in progress; risk scaled by confidence.
      • MATURE (>= 30 windows):
          Confidence 0.8 - 1.0. Full statistical baseline enforcement.
    """
    if observations_count < 5 or instances_count < 1:
        conf = min(0.40, max(0.10, observations_count * 0.08))
        return "COLD_START", round(conf, 2)
    elif observations_count < 30:
        progress = (observations_count - 5) / 25.0
        instance_factor = min(0.10, (instances_count - 1) * 0.02)
        conf = 0.45 + (0.30 * progress) + instance_factor
        return "LEARNING", round(min(0.79, conf), 2)
    else:
        instance_factor = min(0.10, (instances_count - 1) * 0.02)
        obs_factor = min(0.10, (observations_count - 30) / 100.0)
        conf = 0.80 + obs_factor + instance_factor
        return "MATURE", round(min(1.0, conf), 2)


# -----------------------------------------------------------------------------
# ProfileManager
# -----------------------------------------------------------------------------
class ProfileManager:
    """
    Computes and manages program-level behavioural baselines and evaluates live observations
    against historical profiles using robust statistical modeling.
    """

    def __init__(self, repository: TelemetryRepository):
        self.repo = repository

    def build_profile_from_history(
        self,
        profile_id: str,
        comm: Optional[str] = None,
        min_observations: int = 5,
        version: int = 1,
        as_of: Optional[datetime] = None,
        clean_only: bool = True,
        allow_cold_start: bool = False,
    ) -> Optional[ProcessProfile]:
        """
        Aggregate historical behaviour windows for a profile_id and persist a ProcessProfile.
        
        Args:
            profile_id: Program identity hash.
            comm: Optional process command name override.
            min_observations: Minimum windows required to persist/return a profile.
            version: Profile version integer.
            as_of: Upper temporal bound (prevents future data leakage into baselines).
            clean_only: If True, excludes malicious/attack windows from baseline (anti-poisoning).
            allow_cold_start: If True, returns a profile even if below min_observations.

        Returns:
            ProcessProfile if sufficient observations exist, else None.
        """
        # Fetch historical windows adhering to temporal and clean-data constraints
        windows = self.repo.get_windows_by_profile_range(
            profile_id=profile_id,
            end_time=as_of,
            clean_only=clean_only,
            limit=5000,
        )

        n_obs = len(windows)
        if n_obs < min_observations and not allow_cold_start:
            return None

        # Distinct instances contributing to this program baseline
        instances_count = self.repo.count_instances_by_profile(profile_id)
        if instances_count == 0 and n_obs > 0:
            instances_count = len({w.instance_id for w in windows if w.instance_id})

        program_comm = comm or next((w.comm for w in windows if w.comm), "unknown")
        program_exe = next((w.executable for w in windows if w.executable), None)

        # 1. Compute robust statistics for all registered collector features
        feature_stats: Dict[str, Any] = {}
        for feat_name, meta in FEATURE_REGISTRY.items():
            vals = [float(getattr(w, feat_name, 0.0) or 0.0) for w in windows]
            feature_stats[feat_name] = compute_feature_baseline(vals, noise_floor=meta["floor"])

        # 2. Derive typical qualitative events seen historically
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
        if sum(w.file_delete_count for w in windows) > 0:
            typical_events.append("file_delete")

        # 3. Determine baseline maturity and confidence
        maturity, confidence = calculate_maturity(n_obs, instances_count)

        # 4. Synthesize complete baseline_stats dictionary with legacy + robust fields
        cpus = [w.cpu_usage for w in windows]
        mems = [w.memory_usage for w in windows]
        syscalls = [float(w.syscall_count) for w in windows]
        file_reads = [float(w.bytes_read) for w in windows]
        file_writes = [float(w.bytes_written) for w in windows]
        net_tx = [float(w.tcp_tx_bytes + w.udp_tx_bytes) for w in windows]
        net_rx = [float(w.tcp_rx_bytes) for w in windows]
        sensitive = [float(w.syscalls_sensitive) for w in windows]

        baseline_stats: Dict[str, Any] = {
            # Metadata & Maturity
            "maturity": maturity,
            "confidence": confidence,
            "instances_count": instances_count,
            "sampleCount": n_obs,
            "typicalEvents": typical_events,
            "clean_only": clean_only,
            "computed_at": datetime.now(timezone.utc).isoformat(),
            # Full robust multi-feature statistics
            "features": feature_stats,
            # Legacy fields for backward compatibility with existing tests and dashboards
            "avgCpu": feature_stats["cpu_usage"]["mean"],
            "stdCpu": feature_stats["cpu_usage"]["std"],
            "maxCpu": feature_stats["cpu_usage"]["max"],
            "avgMem": feature_stats["memory_usage"]["mean"],
            "stdMem": feature_stats["memory_usage"]["std"],
            "maxMem": feature_stats["memory_usage"]["max"],
            "avgSyscalls": feature_stats["syscall_count"]["mean"],
            "stdSyscalls": feature_stats["syscall_count"]["std"],
            "maxSyscalls": feature_stats["syscall_count"]["max"],
            "avgBytesRead": feature_stats["bytes_read"]["mean"],
            "stdBytesRead": feature_stats["bytes_read"]["std"],
            "maxBytesRead": feature_stats["bytes_read"]["max"],
            "avgBytesWritten": feature_stats["bytes_written"]["mean"],
            "stdBytesWritten": feature_stats["bytes_written"]["std"],
            "maxBytesWritten": feature_stats["bytes_written"]["max"],
            "avgNetTx": feature_stats["tcp_tx_bytes"]["mean"],
            "stdNetTx": feature_stats["tcp_tx_bytes"]["std"],
            "maxNetTx": max(net_tx) if net_tx else 0.0,
            "avgNetRx": feature_stats["tcp_rx_bytes"]["mean"],
            "stdNetRx": feature_stats["tcp_rx_bytes"]["std"],
            "maxNetRx": max(net_rx) if net_rx else 0.0,
            "maxSensitiveSyscalls": max(sensitive) if sensitive else 0.0,
        }

        start_times = [w.start_time for w in windows if w.start_time]
        end_times = [w.end_time for w in windows if w.end_time]

        profile = ProcessProfile(
            profile_id=profile_id,
            comm=program_comm,
            executable=program_exe,
            profile_version=version,
            observations_count=n_obs,
            time_period_start=min(start_times) if start_times else None,
            time_period_end=max(end_times) if end_times else None,
            baseline_stats=baseline_stats,
        )

        self.repo.save_profile(profile)
        return profile

    def update_profile_incrementally(
        self,
        profile_id: str,
        new_windows: Sequence[BehaviourWindow],
        filter_anomalies: bool = True,
    ) -> ProcessProfile:
        """
        Incrementally incorporate newly arrived behaviour windows into a program profile
        without re-scanning full historical telemetry. Transaction-safe.
        """
        if not new_windows:
            existing = self.repo.get_profile(profile_id)
            if existing:
                return existing
            return self.build_profile_from_history(profile_id, allow_cold_start=True)

        # Filter out anomalous/malicious windows if requested
        if filter_anomalies:
            clean_windows = [
                w for w in new_windows
                if (w.label_binary is None or w.label_binary == 0) and (w.label not in ("malicious", "attack"))
            ]
        else:
            clean_windows = list(new_windows)

        if not clean_windows:
            existing = self.repo.get_profile(profile_id)
            return existing or self.build_profile_from_history(profile_id, allow_cold_start=True)

        existing = self.repo.get_profile(profile_id)
        if existing is None or not existing.baseline_stats.get("features"):
            # No prior profile: build from all available history
            return self.build_profile_from_history(profile_id, allow_cold_start=True)

        # Incremental statistics update using Welford parallel combination
        b = existing.baseline_stats
        features = b.get("features", {})
        old_n = existing.observations_count
        new_n = len(clean_windows)
        total_n = old_n + new_n

        for feat_name, meta in FEATURE_REGISTRY.items():
            new_vals = [float(getattr(w, feat_name, 0.0) or 0.0) for w in clean_windows]
            new_avg, new_std = mean_and_std(new_vals)
            new_min = min(new_vals)
            new_max = max(new_vals)

            old_feat = features.get(feat_name)
            if not old_feat:
                features[feat_name] = compute_feature_baseline(new_vals, noise_floor=meta["floor"])
                continue

            old_avg = old_feat.get("mean", 0.0)
            old_std = old_feat.get("std", 0.0)
            old_var = old_std ** 2
            new_var = new_std ** 2

            # Combined mean
            delta = new_avg - old_avg
            comb_mean = old_avg + (delta * new_n / total_n)

            # Combined variance (Chan et al. parallel formula)
            comb_var = (
                (old_n * old_var) + (new_n * new_var) + (delta ** 2 * old_n * new_n / total_n)
            ) / total_n
            comb_std = math.sqrt(max(0.0, comb_var))

            # Approximation for median and scale
            comb_min = min(old_feat.get("min", new_min), new_min)
            comb_max = max(old_feat.get("max", new_max), new_max)
            med_estimate = round((comb_mean + old_feat.get("median", comb_mean)) / 2.0, 4)
            scale = max(comb_std, meta["floor"])

            old_feat.update({
                "count": total_n,
                "mean": round(comb_mean, 4),
                "std": round(comb_std, 4),
                "min": round(comb_min, 4),
                "max": round(comb_max, 4),
                "median": med_estimate,
                "effective_scale": round(scale, 4),
            })

        # Update typical events
        typical = set(b.get("typicalEvents", []))
        if any(w.file_open_count > 0 for w in clean_windows): typical.add("file_open")
        if any(w.file_write_count > 0 for w in clean_windows): typical.add("file_modify")
        if any(w.net_connect_count > 0 for w in clean_windows): typical.add("socket_connect")
        if any(w.child_process_count > 0 for w in clean_windows): typical.add("fork")
        if any(w.exec_count > 0 for w in clean_windows): typical.add("execve")

        # Instances count
        distinct_new_instances = len({w.instance_id for w in clean_windows if w.instance_id})
        instances_count = max(b.get("instances_count", 1), distinct_new_instances)

        maturity, confidence = calculate_maturity(total_n, instances_count)

        b["maturity"] = maturity
        b["confidence"] = confidence
        b["sampleCount"] = total_n
        b["typicalEvents"] = list(typical)
        b["instances_count"] = instances_count
        b["computed_at"] = datetime.now(timezone.utc).isoformat()

        # Update legacy fields
        b["avgCpu"] = features["cpu_usage"]["mean"]
        b["stdCpu"] = features["cpu_usage"]["std"]
        b["maxCpu"] = features["cpu_usage"]["max"]
        b["avgMem"] = features["memory_usage"]["mean"]
        b["stdMem"] = features["memory_usage"]["std"]
        b["maxMem"] = features["memory_usage"]["max"]
        b["avgSyscalls"] = features["syscall_count"]["mean"]
        b["stdSyscalls"] = features["syscall_count"]["std"]
        b["maxSyscalls"] = features["syscall_count"]["max"]

        new_starts = [w.start_time for w in clean_windows if w.start_time]
        new_ends = [w.end_time for w in clean_windows if w.end_time]
        t_start = min(filter(None, [existing.time_period_start] + new_starts), default=None)
        t_end = max(filter(None, [existing.time_period_end] + new_ends), default=None)

        updated_profile = ProcessProfile(
            profile_id=profile_id,
            comm=existing.comm,
            executable=existing.executable,
            executable_hash=existing.executable_hash,
            profile_version=existing.profile_version,
            observations_count=total_n,
            time_period_start=t_start,
            time_period_end=t_end,
            baseline_stats=b,
        )
        self.repo.save_profile(updated_profile)
        return updated_profile

    def recompute_profile(
        self,
        profile_id: str,
        clean_only: bool = True,
        min_observations: int = 5,
    ) -> Optional[ProcessProfile]:
        """Idempotently recompute an existing baseline profile from all historical data."""
        return self.build_profile_from_history(
            profile_id=profile_id,
            clean_only=clean_only,
            min_observations=min_observations,
        )

    def recompute_all_profiles(
        self,
        min_observations: int = 5,
        clean_only: bool = True,
    ) -> Dict[str, Optional[ProcessProfile]]:
        """Recompute profiles for all distinct program profiles identified in storage."""
        profile_ids = self.repo.get_distinct_profile_ids()
        results: Dict[str, Optional[ProcessProfile]] = {}
        for pid in profile_ids:
            results[pid] = self.recompute_profile(pid, clean_only=clean_only, min_observations=min_observations)
        return results

    def build_instance_history_summary(self, instance_id: str) -> Optional[ProcessLifecycleSummary]:
        """Generate a complete process-history profile for a single process lifetime."""
        return self.repo.get_process_lifecycle_summary(instance_id)

    def evaluate_window_deviation(
        self,
        win: BehaviourWindow,
        profile: ProcessProfile,
        threshold_z: float = 3.0,
    ) -> DeviationResult:
        """
        Compare an observed behaviour window against historical baseline, calculating
        both classical Z-scores and robust outlier-resistant modified Z-scores.
        
        Handles:
          • Cold-start / low confidence: dampens deviation scores conservatively to prevent false positives.
          • Zero variance: scales using feature noise floor.
          • Outliers in history: uses Median and NMAD rather than mean/std.
          • Unprecedented events: flags novel outbound sockets, sensitive syscalls, or fork bursts.
        """
        b = profile.baseline_stats
        features = b.get("features", {})
        maturity = b.get("maturity", "COLD_START" if profile.observations_count < 5 else "MATURE")
        confidence = float(b.get("confidence", 0.3 if maturity == "COLD_START" else 0.85))
        reasons: List[str] = []
        unprecedented: List[str] = []
        robust_devs: Dict[str, Dict[str, Any]] = {}
        category_risks: Dict[str, float] = {
            "resource": 0.0,
            "syscall": 0.0,
            "security": 0.0,
            "file": 0.0,
            "network": 0.0,
        }

        # Helper to compute robust score
        def calc_robust_score(actual: float, f_stats: Dict[str, Any], meta: Dict[str, Any]) -> Tuple[float, float, bool]:
            med = f_stats.get("median", f_stats.get("mean", 0.0))
            scale = f_stats.get("effective_scale", max(f_stats.get("std", 0.0), meta["floor"]))
            if scale <= 0.001:
                scale = meta["floor"]

            # Robust score (deviation relative to median and robust scale)
            mod_z = (actual - med) / scale
            
            # Classical z-score for comparison
            std = f_stats.get("std", scale)
            std = std if std > 0.001 else scale
            z_classic = (actual - f_stats.get("mean", med)) / std

            is_deviant = mod_z >= threshold_z
            return round(mod_z, 2), round(z_classic, 2), is_deviant

        # Evaluate all features present in the registry
        for feat_name, meta in FEATURE_REGISTRY.items():
            actual = float(getattr(win, feat_name, 0.0) or 0.0)
            f_stats = features.get(feat_name, {})
            if not f_stats:
                continue

            mod_z, z_classic, is_dev = calc_robust_score(actual, f_stats, meta)
            robust_devs[feat_name] = {
                "actual": actual,
                "median": f_stats.get("median", 0.0),
                "mean": f_stats.get("mean", 0.0),
                "effective_scale": f_stats.get("effective_scale", meta["floor"]),
                "robust_score": mod_z,
                "z_classic": z_classic,
                "is_deviant": is_dev,
            }

            # If deviant above threshold, calculate risk contribution
            if is_dev and actual > f_stats.get("median", 0.0):
                cat = meta["category"]
                weight = meta["weight"]
                cat_risk = min(40.0, (mod_z - threshold_z + 1.0) * 10.0 * weight)
                category_risks[cat] = max(category_risks[cat], cat_risk)

                if mod_z >= threshold_z:
                    reasons.append(
                        f"{meta['label']} {actual:.1f} is {mod_z:.1f}σ above historical baseline "
                        f"(baseline: {f_stats.get('median', 0.0):.1f} ± {f_stats.get('effective_scale', 0.0):.1f})"
                    )

        # 2. Check for unprecedented security-sensitive events
        typical = set(b.get("typicalEvents", []))
        
        # Unprecedented outbound network socket
        if win.net_connect_count > 0:
            if "socket_connect" not in typical or features.get("net_connect_count", {}).get("max", 0.0) == 0:
                unprecedented.append("socket_connect")
                category_risks["security"] = max(category_risks["security"], 45.0)
                reasons.append(f"Unprecedented outbound socket connection initiated by {win.comm} (norm is 0)")

        # Unprecedented sensitive syscall spike (ptrace, bpf, init_module)
        if win.syscalls_sensitive > 0:
            if b.get("maxSensitiveSyscalls", 0.0) == 0.0 or features.get("syscalls_sensitive", {}).get("max", 0.0) == 0:
                unprecedented.append("sensitive_syscall")
                category_risks["security"] = max(category_risks["security"], 50.0)
                reasons.append(f"Unprecedented privileged/sensitive syscall invocation ({win.syscalls_sensitive})")

        # Unprecedented child process execution
        if win.exec_count > 0 and "execve" not in typical and features.get("exec_count", {}).get("max", 0.0) == 0:
            unprecedented.append("execve")
            category_risks["security"] = max(category_risks["security"], 40.0)
            reasons.append(f"Unprecedented child binary execution (execve) spawned by {win.comm}")

        # Unprecedented mass file delete
        if win.file_delete_count > 5 and features.get("file_delete_count", {}).get("max", 0.0) == 0:
            unprecedented.append("file_delete")
            category_risks["security"] = max(category_risks["security"], 40.0)
            reasons.append(f"Unprecedented mass file deletion burst ({win.file_delete_count} files removed)")

        # 3. Handle baseline maturity & confidence
        raw_composite_risk = min(
            100.0,
            category_risks["security"] * 1.2
            + category_risks["syscall"] * 0.8
            + category_risks["resource"] * 0.6
            + category_risks["network"] * 0.7
            + category_risks["file"] * 0.6
        )

        if maturity == "COLD_START":
            # Suppress false positives on new programs: scale down by confidence and cap
            calibrated_risk = min(30.0, raw_composite_risk * confidence)
            if reasons and not unprecedented:
                reasons = [
                    f"Baseline in COLD_START ({profile.observations_count} observations); "
                    f"deviation signals are conservative: {r}" for r in reasons
                ]
            is_anomaly = bool(unprecedented and calibrated_risk >= 25.0)
        elif maturity == "LEARNING":
            calibrated_risk = min(95.0, raw_composite_risk * confidence)
            is_anomaly = bool(calibrated_risk >= 50.0 or unprecedented)
        else:
            # Mature baseline
            calibrated_risk = min(99.0, raw_composite_risk)
            is_anomaly = bool(reasons or calibrated_risk >= 60.0 or unprecedented)

        # Legacy 3-key z_scores dictionary for backward compatibility
        z_cpu = robust_devs.get("cpu_usage", {}).get("z_classic", 0.0)
        z_mem = robust_devs.get("memory_usage", {}).get("z_classic", 0.0)
        z_sys = robust_devs.get("syscall_count", {}).get("z_classic", 0.0)

        # Backward compatibility check for tests expecting specific legacy messages
        if z_cpu >= threshold_z and not any("CPU usage" in r for r in reasons):
            reasons.append(f"CPU usage {win.cpu_usage:.1f}% is {z_cpu}x standard deviations above historical mean")
        if z_mem >= threshold_z and not any("Memory" in r for r in reasons):
            reasons.append(f"Memory {win.memory_usage:.1f}MB is {z_mem}x standard deviations above baseline")
        if z_sys >= threshold_z and not any("Syscall burst" in r for r in reasons):
            reasons.append(f"Syscall burst {win.syscall_count} is {z_sys}x standard deviations above baseline")

        return DeviationResult(
            is_anomaly=is_anomaly,
            risk_score=round(calibrated_risk, 1),
            confidence=round(confidence, 2),
            maturity=maturity,
            reasons=reasons,
            z_scores={"cpu": z_cpu, "memory": z_mem, "syscalls": z_sys},
            robust_deviations=robust_devs,
            risk_contributions={k: round(v, 1) for k, v in category_risks.items()},
            unprecedented_events=unprecedented,
            profile_observations=profile.observations_count,
            instances_in_baseline=profile.instances_count,
            details={
                "threshold_z": threshold_z,
                "raw_risk": round(raw_composite_risk, 1),
                "deviant_features_count": sum(1 for d in robust_devs.values() if d.get("is_deviant")),
            },
        )

    def get_deviation_features(
        self,
        win: BehaviourWindow,
        profile: ProcessProfile,
    ) -> Dict[str, float]:
        """
        Extract numerical deviation feature vector suitable for downstream ML anomaly detection
        or risk scoring models while strictly preserving standard numerical schemas.
        """
        features = profile.baseline_stats.get("features", {})
        vec: Dict[str, float] = {}
        for feat_name, meta in FEATURE_REGISTRY.items():
            actual = float(getattr(win, feat_name, 0.0) or 0.0)
            f_stats = features.get(feat_name, {})
            scale = f_stats.get("effective_scale", meta["floor"])
            med = f_stats.get("median", 0.0)
            dev = (actual - med) / (scale if scale > 0.001 else meta["floor"])
            vec[f"dev_{feat_name}"] = round(dev, 4)
        return vec
