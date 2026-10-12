"""
Chronicle - Intelligent Host Behaviour Analysis & Activity Monitor
Database, Telemetry, and Baselining Layer.
"""

__version__ = "0.2.0"

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
]
