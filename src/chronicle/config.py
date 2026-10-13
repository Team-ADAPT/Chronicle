"""
Chronicle - Configuration module.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ChronicleConfig:
    # Base paths
    root_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])
    data_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2] / "data")
    db_path: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2] / "data" / "chronicle.db")
    profiles_path: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2] / "data" / "profiles.json")
    
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
    
    # Statistical / Risk thresholds
    z_score_suspicious_threshold: float = 2.0
    z_score_anomalous_threshold: float = 3.5
    ml_anomaly_threshold: float = -0.05
    xgboost_attack_threshold: float = 0.50
    
    # Ring buffer limits
    max_recent_events: int = 500
    max_active_alerts: int = 100
    
    def __post_init__(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
