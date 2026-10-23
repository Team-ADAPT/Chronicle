"""
Configuration management for Chronicle PostgreSQL storage and retention rules.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import urlparse


@dataclass
class DatabaseConfig:
    """Database connection settings, supporting PostgreSQL (DATABASE_URL) or SQLite fallback."""
    database_url: Optional[str] = None
    host: Optional[str] = None
    port: int = 5432
    dbname: Optional[str] = None
    user: Optional[str] = None
    password: Optional[str] = None
    sslmode: str = "prefer"
    pool_min: int = 1
    pool_max: int = 10
    connect_timeout: float = 10.0
    engine: str = "auto"  # "auto", "postgresql", "sqlite"
    sqlite_path: str = "chronicle.db"

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "DatabaseConfig":
        """Construct configuration from environment variables."""
        e = env if env is not None else os.environ

        engine = e.get("CHRONICLE_DB_ENGINE", "auto").lower()
        sqlite_path = e.get("CHRONICLE_SQLITE_PATH", "chronicle.db")

        raw_url = e.get("DATABASE_URL") or e.get("CHRONICLE_DATABASE_URL")
        if raw_url:
            parsed = urlparse(raw_url)
            port_val = parsed.port if parsed.port is not None else 5432
            db_name = parsed.path.lstrip("/") if parsed.path else None
            return cls(
                database_url=raw_url,
                host=parsed.hostname,
                port=port_val,
                dbname=db_name,
                user=parsed.username,
                password=parsed.password,
                sslmode=e.get("CHRONICLE_DB_SSLMODE", "prefer"),
                pool_min=int(e.get("CHRONICLE_DB_POOL_MIN", "1")),
                pool_max=int(e.get("CHRONICLE_DB_POOL_MAX", "10")),
                connect_timeout=float(e.get("CHRONICLE_DB_TIMEOUT", "10.0")),
                engine=engine,
                sqlite_path=sqlite_path,
            )

        host = e.get("CHRONICLE_DB_HOST") or e.get("PGHOST")
        dbname = e.get("CHRONICLE_DB_NAME") or e.get("PGDATABASE")
        user = e.get("CHRONICLE_DB_USER") or e.get("PGUSER")
        password = e.get("CHRONICLE_DB_PASSWORD") or e.get("PGPASSWORD")
        port_str = e.get("CHRONICLE_DB_PORT") or e.get("PGPORT", "5432")

        try:
            port = int(port_str)
        except ValueError:
            port = 5432

        return cls(
            database_url=None,
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password,
            sslmode=e.get("CHRONICLE_DB_SSLMODE", "prefer"),
            pool_min=int(e.get("CHRONICLE_DB_POOL_MIN", "1")),
            pool_max=int(e.get("CHRONICLE_DB_POOL_MAX", "10")),
            connect_timeout=float(e.get("CHRONICLE_DB_TIMEOUT", "10.0")),
            engine=engine,
            sqlite_path=sqlite_path,
        )

    def is_configured(self) -> bool:
        """Return True if sufficient settings exist to connect to a database."""
        if self.engine == "sqlite":
            return True
        if self.database_url:
            return True
        if self.host and self.dbname:
            return True
        # In auto mode, SQLite fallback ensures the database is always operational
        return self.engine == "auto"

    def is_postgres_configured(self) -> bool:
        """Return True if explicit PostgreSQL credentials/URL are configured."""
        if self.database_url:
            return True
        return bool(self.host and self.dbname)

    def effective_engine(self) -> str:
        """Determine whether PostgreSQL or SQLite should be utilized."""
        if self.engine == "sqlite":
            return "sqlite"
        if self.engine == "postgresql":
            return "postgresql"
        # auto mode: use postgresql only if configured
        return "postgresql" if self.is_postgres_configured() else "sqlite"

    def is_local(self) -> bool:
        """Return True if connection targets the user's local machine."""
        if self.effective_engine() == "sqlite":
            return True
        if self.database_url:
            try:
                parsed = urlparse(self.database_url)
                hostname = parsed.hostname
                if not hostname:
                    return True
                return hostname.lower() in ("localhost", "127.0.0.1", "::1")
            except Exception:
                return False
        if not self.host:
            # Empty host connects to local UNIX domain socket (/var/run/postgresql or /tmp)
            return True
        return self.host.lower() in ("localhost", "127.0.0.1", "::1") or self.host.startswith("/")

    def conninfo(self) -> str:
        """Return a libpq connection string suitable for psycopg."""
        if self.database_url:
            return self.database_url

        parts = []
        if self.host:
            parts.append(f"host={self.host}")
        if self.port:
            parts.append(f"port={self.port}")
        if self.dbname:
            parts.append(f"dbname={self.dbname}")
        if self.user:
            parts.append(f"user={self.user}")
        if self.password:
            parts.append(f"password={self.password}")
        if self.sslmode:
            parts.append(f"sslmode={self.sslmode}")
        if self.connect_timeout:
            parts.append(f"connect_timeout={int(self.connect_timeout)}")

        return " ".join(parts)

    def masked_conninfo(self) -> str:
        """Return safe string with password scrubbed for logging and diagnostics."""
        if self.effective_engine() == "sqlite":
            return f"sqlite:///{self.sqlite_path}"

        if self.database_url:
            try:
                p = urlparse(self.database_url)
                if p.password:
                    safe_netloc = p.netloc.replace(f":{p.password}@", ":***@")
                    return p._replace(netloc=safe_netloc).geturl()
            except Exception:
                return "<DATABASE_URL masked>"
            return self.database_url

        parts = []
        if self.host:
            parts.append(f"host={self.host}")
        if self.port:
            parts.append(f"port={self.port}")
        if self.dbname:
            parts.append(f"dbname={self.dbname}")
        if self.user:
            parts.append(f"user={self.user}")
        if self.password:
            parts.append("password=***")
        if self.sslmode:
            parts.append(f"sslmode={self.sslmode}")
        return " ".join(parts)

    def __repr__(self) -> str:
        return f"DatabaseConfig({self.masked_conninfo()})"


@dataclass
class RetentionConfig:
    """Configurable retention policies for telemetry, windows, metrics, and profiles."""
    events_days: int = 7
    windows_days: int = 30
    metrics_days: int = 30
    detections_days: Optional[int] = 90
    dead_procs_days: int = 30
    preserve_flagged_detections: bool = True

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "RetentionConfig":
        """Load retention policy configuration from environment variables."""
        e = env if env is not None else os.environ

        def parse_days(key: str, default: int) -> int:
            val = e.get(key)
            if val is not None and val.strip():
                try:
                    return max(1, int(val.strip()))
                except ValueError:
                    pass
            return default

        def parse_opt_days(key: str, default: Optional[int]) -> Optional[int]:
            val = e.get(key)
            if val is not None:
                cleaned = val.strip().lower()
                if cleaned in ("0", "none", "unlimited", "forever"):
                    return None
                try:
                    return max(1, int(cleaned))
                except ValueError:
                    pass
            return default

        preserve = e.get("CHRONICLE_RETENTION_PRESERVE_DETECTIONS", "true").lower() in ("1", "true", "yes")

        return cls(
            events_days=parse_days("CHRONICLE_RETENTION_EVENTS_DAYS", 7),
            windows_days=parse_days("CHRONICLE_RETENTION_WINDOWS_DAYS", 30),
            metrics_days=parse_days("CHRONICLE_RETENTION_METRICS_DAYS", 30),
            detections_days=parse_opt_days("CHRONICLE_RETENTION_DETECTIONS_DAYS", 90),
            dead_procs_days=parse_days("CHRONICLE_RETENTION_DEAD_PROCS_DAYS", 30),
            preserve_flagged_detections=preserve,
        )
