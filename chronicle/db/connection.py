"""
PostgreSQL connection and session management using psycopg (version 3).
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

try:
    import psycopg
    from psycopg import Connection, Cursor
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None  # type: ignore
    dict_row = None  # type: ignore
    Connection = Any  # type: ignore
    Cursor = Any  # type: ignore


from chronicle.db.config import DatabaseConfig

logger = logging.getLogger("chronicle.db.connection")


class DatabaseError(Exception):
    """Base exception for all Chronicle database operations."""
    pass


class DatabaseConfigurationError(DatabaseError):
    """Raised when database settings are missing or invalid."""
    pass


class DatabaseConnectionError(DatabaseError):
    """Raised when connecting to the PostgreSQL server fails."""
    pass


class Database:
    """Manages connections, transaction lifecycles, and health checks for Chronicle."""

    def __init__(self, config: Optional[DatabaseConfig] = None):
        if psycopg is None:
            raise DatabaseError(
                "psycopg (v3) is required for Chronicle database access.\n"
                "Install it via: pip install 'psycopg[binary]>=3.1.0'"
            )
        self.config = config or DatabaseConfig.from_env()

    def connect(self) -> Connection:
        """Create a new PostgreSQL connection with dict_row row factory."""
        if not self.config.is_configured():
            raise DatabaseConfigurationError(
                "PostgreSQL is not configured. Set DATABASE_URL or CHRONICLE_DB_* environment variables."
            )

        enforce_local = os.getenv("CHRONICLE_ENFORCE_LOCAL_DB", "1").lower() in ("1", "true", "yes", "on")
        if enforce_local and not self.config.is_local():
            raise DatabaseConfigurationError(
                f"Privacy enforcement blocked non-local database connection: {self.config.masked_conninfo()}.\n"
                "Chronicle is configured with user-side privacy enforcement (CHRONICLE_ENFORCE_LOCAL_DB=1).\n"
                "All telemetry and database storage must remain strictly on the user's local machine "
                "(localhost, 127.0.0.1, ::1, or local UNIX domain socket).\n"
                "If you intentionally operate an external database within a private trusted network, set CHRONICLE_ENFORCE_LOCAL_DB=0."
            )

        if not self.config.is_local():
            logger.warning(
                "[chronicle privacy] Database target is a remote host [%s]. Ensure this meets your local privacy policy.",
                self.config.masked_conninfo(),
            )

        try:
            conn = psycopg.connect(self.config.conninfo(), row_factory=dict_row)
            return conn
        except Exception as e:
            logger.error("Failed to connect to PostgreSQL [%s]: %s", self.config.masked_conninfo(), e)
            raise DatabaseConnectionError(f"Could not connect to PostgreSQL: {e}") from e

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        """Context manager providing a managed connection with transaction boundary."""
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def cursor(self) -> Iterator[Cursor]:
        """Context manager yielding a cursor inside a managed transaction."""
        with self.connection() as conn:
            with conn.cursor() as cur:
                yield cur

    def check_health(self) -> Dict[str, Any]:
        """Verify connectivity and return server metadata."""
        if not self.config.is_configured():
            return {
                "status": "unconfigured",
                "message": "DATABASE_URL is not set.",
                "connected": False,
            }

        start = time.perf_counter()
        try:
            with self.cursor() as cur:
                cur.execute("SELECT version(), current_database(), current_user;")
                row = cur.fetchone()
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
                return {
                    "status": "healthy",
                    "connected": True,
                    "is_local": self.config.is_local(),
                    "latency_ms": latency_ms,
                    "database": row["current_database"] if row else None,
                    "user": row["current_user"] if row else None,
                    "server_version": row["version"] if row else None,
                }
        except Exception as e:
            return {
                "status": "error",
                "connected": False,
                "error": str(e),
                "target": self.config.masked_conninfo(),
            }
