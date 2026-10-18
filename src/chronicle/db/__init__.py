"""
Chronicle PostgreSQL Database Layer.
"""

from chronicle.db.config import DatabaseConfig, RetentionConfig
from chronicle.db.connection import (
    Database,
    DatabaseConfigurationError,
    DatabaseConnectionError,
    DatabaseError,
)
from chronicle.db.migrations import discover_migrations, run_migrations
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
from chronicle.db.profiling import ProfileManager
from chronicle.db.repository import TelemetryRepository
from chronicle.db.retention import RetentionManager

__all__ = [
    "Database",
    "DatabaseConfig",
    "RetentionConfig",
    "DatabaseError",
    "DatabaseConfigurationError",
    "DatabaseConnectionError",
    "TelemetryRepository",
    "ProfileManager",
    "RetentionManager",
    "run_migrations",
    "discover_migrations",
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
