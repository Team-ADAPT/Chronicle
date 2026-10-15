"""
Dual-engine database connection and session management for Chronicle.
Supports PostgreSQL (using psycopg v3) with automatic, zero-dependency SQLite fallback
for single-machine Linux desktop execution as required by Project.md.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import date, datetime
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

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
    """Raised when connecting to the database server fails."""
    pass


class RowDict(dict):
    """Dictionary representing a database row, supporting both key and index access."""

    def __init__(self, mapping: Dict[str, Any], values: Sequence[Any]):
        super().__init__(mapping)
        self._values = list(values)

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


def _sqlite_row_factory(cursor: sqlite3.Cursor, row: Tuple[Any, ...]) -> RowDict:
    """Row factory converting SQLite tuples into RowDict instances with dict & index access."""
    col_names = [col[0] for col in cursor.description]
    mapping = {col_names[idx]: val for idx, val in enumerate(row)}
    return RowDict(mapping, row)


class SQLiteCursorWrapper:
    """
    Transparent cursor wrapper adapting psycopg-style SQL statements and parameters
    for Python's built-in sqlite3 database engine.
    """

    def __init__(self, raw_cursor: sqlite3.Cursor):
        self._cur = raw_cursor

    @property
    def rowcount(self) -> int:
        return self._cur.rowcount

    @property
    def lastrowid(self) -> Optional[int]:
        return self._cur.lastrowid

    @property
    def description(self) -> Any:
        return self._cur.description

    def close(self) -> None:
        self._cur.close()

    def _adapt_sql(self, sql: str) -> str:
        """Translate PostgreSQL query specifics into SQLite syntax."""
        # 1. Adapt metadata JSON concatenation: process_instances.metadata || EXCLUDED.metadata
        s = re.sub(
            r"(\w+\.metadata)\s*\|\|\s*(EXCLUDED\.metadata)",
            r"json_patch(\1, \2)",
            sql,
            flags=re.IGNORECASE,
        )
        # 2. Remove PostgreSQL-specific typecasts (e.g. ::numeric, ::jsonb)
        s = re.sub(r"::(?:numeric|jsonb|text|int|bigint)\b", "", s, flags=re.IGNORECASE)
        # 3. Replace parameter placeholders %s with ?
        s = s.replace("%s", "?")
        return s

    def _adapt_param_value(self, val: Any) -> Any:
        """Serialize parameter values for SQLite storage."""
        if val is None:
            return None
        if isinstance(val, (datetime, date)):
            return val.isoformat()
        if isinstance(val, bool):
            return 1 if val else 0
        return val

    def _adapt_params(self, params: Any) -> Any:
        if params is None:
            return None
        if isinstance(params, (list, tuple)):
            return tuple(self._adapt_param_value(v) for v in params)
        if isinstance(params, dict):
            return {k: self._adapt_param_value(v) for k, v in params.items()}
        return params

    def execute(self, sql: str, params: Any = None) -> "SQLiteCursorWrapper":
        adapted_sql = self._adapt_sql(sql)
        adapted_params = self._adapt_params(params)
        if adapted_params is None:
            self._cur.execute(adapted_sql)
        else:
            self._cur.execute(adapted_sql, adapted_params)
        return self

    def executemany(self, sql: str, seq_of_params: Any) -> "SQLiteCursorWrapper":
        adapted_sql = self._adapt_sql(sql)
        adapted_seq = [self._adapt_params(p) for p in seq_of_params]
        self._cur.executemany(adapted_sql, adapted_seq)
        return self

    def fetchone(self) -> Optional[RowDict]:
        return self._cur.fetchone()

    def fetchall(self) -> List[RowDict]:
        return self._cur.fetchall()

    def fetchmany(self, size: int = 1) -> List[RowDict]:
        return self._cur.fetchmany(size)


class Database:
    """
    Manages connections, transactions, and dual-engine storage (PostgreSQL / SQLite).
    Guarantees seamless offline/single-machine operation without external daemon setup.
    """

    def __init__(self, config: Optional[DatabaseConfig] = None):
        self.config = config or DatabaseConfig.from_env()
        self.engine = self._resolve_engine()

    def _resolve_engine(self) -> str:
        """Resolve database engine to either 'postgresql' or 'sqlite'."""
        requested = self.config.effective_engine()
        if requested == "postgresql":
            if psycopg is None:
                if self.config.engine == "postgresql":
                    raise DatabaseError(
                        "psycopg (v3) is required for explicit PostgreSQL access.\n"
                        "Install it via: pip install 'psycopg[binary]>=3.1.0'"
                    )
                logger.info(
                    "[chronicle db] psycopg is not installed. Falling back to local SQLite storage (%s) as per Project.md.",
                    self.config.sqlite_path,
                )
                return "sqlite"
            return "postgresql"
        return "sqlite"

    def connect(self) -> Any:
        """Create a new database connection according to the active engine."""
        if self.engine == "postgresql":
            return self._connect_postgresql()
        return self._connect_sqlite()

    def _connect_postgresql(self) -> Connection:
        if not self.config.is_postgres_configured():
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

    def _connect_sqlite(self) -> sqlite3.Connection:
        from chronicle.db.privacy import enforce_private_permissions

        db_path = self.config.sqlite_path
        parent_dir = os.path.dirname(os.path.abspath(db_path))
        if parent_dir and not os.path.exists(parent_dir):
            try:
                os.makedirs(parent_dir, mode=0o700, exist_ok=True)
                os.chmod(parent_dir, 0o700)
            except OSError:
                pass

        # Set umask 0o077 so newly created files, WAL, and SHM are owner-only rw-------
        old_umask = os.umask(0o077)
        try:
            conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10.0)
            conn.row_factory = _sqlite_row_factory
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
        except Exception as e:
            logger.error("Failed to initialize SQLite database [%s]: %s", db_path, e)
            raise DatabaseConnectionError(f"Could not connect to SQLite: {e}") from e
        finally:
            os.umask(old_umask)

        # Enforce POSIX 0600 on database and aux files
        enforce_private_permissions(db_path)
        return conn

    @contextmanager
    def connection(self) -> Iterator[Any]:
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
    def cursor(self) -> Iterator[Any]:
        """Context manager yielding a cursor inside a managed transaction."""
        with self.connection() as conn:
            if self.engine == "sqlite":
                cur = conn.cursor()
                try:
                    yield SQLiteCursorWrapper(cur)
                finally:
                    cur.close()
            else:
                with conn.cursor() as cur:
                    yield cur

    def check_health(self) -> Dict[str, Any]:
        """Verify connectivity and return engine metadata with privacy audit."""
        from chronicle.db.privacy import audit_storage_privacy

        start = time.perf_counter()

        if self.engine == "sqlite":
            try:
                with self.cursor() as cur:
                    cur.execute("SELECT sqlite_version();")
                    row = cur.fetchone()
                    version = row[0] if row else "unknown"
                    latency_ms = round((time.perf_counter() - start) * 1000, 2)
                    privacy_info = audit_storage_privacy("sqlite", self.config.sqlite_path, True)
                    return {
                        "status": "healthy",
                        "connected": True,
                        "engine": "sqlite",
                        "is_local": True,
                        "database": self.config.sqlite_path,
                        "latency_ms": latency_ms,
                        "server_version": f"SQLite {version}",
                        "privacy": privacy_info,
                    }
            except Exception as e:
                return {
                    "status": "error",
                    "connected": False,
                    "engine": "sqlite",
                    "error": str(e),
                    "target": self.config.sqlite_path,
                }

        # PostgreSQL health check
        if not self.config.is_postgres_configured():
            return {
                "status": "unconfigured",
                "message": "DATABASE_URL is not set.",
                "connected": False,
                "engine": "postgresql",
            }

        try:
            with self.cursor() as cur:
                cur.execute("SELECT version(), current_database(), current_user;")
                row = cur.fetchone()
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
                return {
                    "status": "healthy",
                    "connected": True,
                    "engine": "postgresql",
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
                "engine": "postgresql",
                "error": str(e),
                "target": self.config.masked_conninfo(),
            }
