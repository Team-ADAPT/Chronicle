"""
Bridge module enabling imports from src.chronicle.db
"""

from pathlib import Path

_root_db = Path(__file__).resolve().parent.parent.parent.parent / "chronicle" / "db"
if _root_db.is_dir() and str(_root_db) not in __path__:
    __path__.append(str(_root_db))

from chronicle.db.config import DatabaseConfig, RetentionConfig
from chronicle.db.connection import Database
from chronicle.db.models import (
    BehaviourWindow,
    DetectionRecord,
    ProcessInstance,
    ProcessProfile,
    SystemMetric,
    TelemetryEvent,
)
from chronicle.db.profiling import ProfileManager
from chronicle.db.repository import TelemetryRepository
from chronicle.db.retention import RetentionManager

__all__ = [
    "Database",
    "DatabaseConfig",
    "RetentionConfig",
    "TelemetryRepository",
    "ProfileManager",
    "RetentionManager",
    "ProcessInstance",
    "TelemetryEvent",
    "BehaviourWindow",
    "SystemMetric",
    "ProcessProfile",
    "DetectionRecord",
]
