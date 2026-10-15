"""
Chronicle - Intelligent Host Behaviour Analysis & Activity Monitor
Database, Telemetry, and Baselining Layer.
"""

__version__ = "0.2.0"

from pathlib import Path
_src_chronicle = Path(__file__).resolve().parent.parent / "src" / "chronicle"
if _src_chronicle.is_dir() and str(_src_chronicle) not in __path__:
    __path__.append(str(_src_chronicle))

from chronicle.db.config import DatabaseConfig, RetentionConfig
from chronicle.db.connection import Database
from chronicle.db.models import (
    BehaviourWindow,
    DetectionRecord,
    DeviationResult,
    ProcessInstance,
    ProcessLifecycleSummary,
    ProcessProfile,
    ProgramHistorySummary,
    SystemMetric,
    TelemetryEvent,
)
from chronicle.db.repository import TelemetryRepository

__all__ = [
    "__version__",
    "Database",
    "DatabaseConfig",
    "RetentionConfig",
    "TelemetryRepository",
    "ProcessInstance",
    "TelemetryEvent",
    "BehaviourWindow",
    "SystemMetric",
    "ProcessProfile",
    "DetectionRecord",
    "ProcessLifecycleSummary",
    "DeviationResult",
    "ProgramHistorySummary",
]
