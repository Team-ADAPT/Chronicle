"""
Chronicle - Configuration module.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _resolve_data_dir() -> Path:
    env_dir = os.environ.get("CHRONICLE_DATA_DIR")
    if env_dir:
        p = Path(env_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    # Standard candidate in repo / package root
    default_dir = Path(__file__).resolve().parents[2] / "data"
    try:
        default_dir.mkdir(parents=True, exist_ok=True)
        test_file = default_dir / ".write_test"
        test_file.touch()
        test_file.unlink()
        return default_dir
    except (OSError, PermissionError):
        pass

    # Safe fallback to user local directory
    user_dir = Path.home() / ".local" / "share" / "chronicle"
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir


def _resolve_db_path() -> Path:
    env_path = os.environ.get("CHRONICLE_DB_PATH")
    if env_path:
        p = Path(env_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    return _resolve_data_dir() / "chronicle.db"


@dataclass
class ChronicleConfig:
    # Base paths
    root_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])
    data_dir: Path = field(default_factory=_resolve_data_dir)
    db_path: Path = field(default_factory=_resolve_db_path)
    profiles_path: Path = field(default_factory=lambda: _resolve_data_dir() / "profiles.json")

    # ML Models directory
    ml_models_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2] / "ML" / "models")

    # Telemetry sampling & windows (seconds)
    sample_interval: float = 2.0
    feature_window: float = 30.0

    # Privacy options (air-gapped local processing)
    hash_file_paths: bool = True
    hash_ips: bool = False
    anonymize_cmdlines: bool = False

    # eBPF options
    enable_ebpf: bool = True
    fallback_psutil: bool = True

    # Statistical / Risk thresholds (passed to RiskEngine; override here to
    # change scoring behaviour without editing risk_engine.py constants)
    z_score_suspicious_threshold: float = 2.0
    z_score_anomalous_threshold: float = 3.5
    ml_anomaly_threshold: float = -0.05
    xgboost_attack_threshold: float = 0.50

    # ── Risk scoring feature flag ──────────────────────────────────────────
    # Set to False to disable risk scoring and alert generation entirely.
    # When disabled, events are still collected and stored with risk_score=0
    # and eval_status="insufficient_data" so that existing consumers continue
    # to receive events in the same format.
    enable_risk_scoring: bool = True

    # Ring buffer limits
    max_recent_events: int = 500
    max_active_alerts: int = 100

    def __post_init__(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
