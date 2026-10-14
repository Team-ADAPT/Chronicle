"""
Bridge module enabling imports from src.chronicle.db
"""

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
