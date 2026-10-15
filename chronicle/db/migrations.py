"""
Versioned schema migration runner for Chronicle dual-engine storage (PostgreSQL / SQLite).
Discovers and applies SQL migration files in sequence, tracking applied state.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from chronicle.db.connection import Database

logger = logging.getLogger("chronicle.db.migrations")
SQL_DIR = Path(__file__).resolve().parent / "sql"


@dataclass
class Migration:
    version: int
    name: str
    filepath: Path

    def read_sql(self) -> str:
        return self.filepath.read_text(encoding="utf-8")


def discover_migrations(sql_dir: Optional[Path] = None) -> List[Migration]:
    """Scan sql_dir for files matching <version>_<name>.sql and return sorted list."""
    directory = sql_dir or SQL_DIR
    if not directory.is_dir():
        return []

    migrations: List[Migration] = []
    pattern = re.compile(r"^(\d+)_(.+)\.sql$")

    for entry in directory.iterdir():
        if not entry.is_file():
            continue
        m = pattern.match(entry.name)
        if m:
            version = int(m.group(1))
            name = m.group(2)
            migrations.append(Migration(version=version, name=name, filepath=entry))

    migrations.sort(key=lambda x: x.version)
    return migrations


def get_applied_versions(conn) -> Set[int]:
    """Return set of migration versions already applied to the database."""
    if isinstance(conn, sqlite3.Connection):
        cur = conn.cursor()
        try:
            cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations';")
            if not cur.fetchone():
                return set()
            cur.execute("SELECT version FROM schema_migrations ORDER BY version;")
            rows = cur.fetchall()
            return {r[0] for r in rows}
        finally:
            cur.close()

    with conn.cursor() as cur:
        # PostgreSQL check
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'schema_migrations'
            );
        """)
        row = cur.fetchone()
        exists = row["exists"] if isinstance(row, dict) else row[0]
        if not exists:
            return set()

        cur.execute("SELECT version FROM schema_migrations ORDER BY version;")
        rows = cur.fetchall()
        if rows and isinstance(rows[0], dict):
            return {r["version"] for r in rows}
        return {r[0] for r in rows}


def apply_migration(conn, migration: Migration) -> None:
    """Execute a single migration file and record it in schema_migrations."""
    sql = migration.read_sql()
    logger.info("Applying migration %03d: %s", migration.version, migration.name)

    if isinstance(conn, sqlite3.Connection):
        conn.executescript(sql)
        conn.execute(
            """
            INSERT INTO schema_migrations (version, name, applied_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT (version) DO NOTHING;
            """,
            (migration.version, migration.name),
        )
        return

    with conn.cursor() as cur:
        cur.execute(sql)
        cur.execute(
            """
            INSERT INTO schema_migrations (version, name, applied_at)
            VALUES (%s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (version) DO NOTHING;
            """,
            (migration.version, migration.name),
        )


def run_migrations(
    database: Optional[Database] = None, sql_dir: Optional[Path] = None
) -> List[Migration]:
    """Run all unapplied migrations against the target database (PostgreSQL or SQLite)."""
    db = database or Database()
    directory = sql_dir or SQL_DIR
    applied: List[Migration] = []

    with db.connection() as conn:
        already_applied = get_applied_versions(conn)

        if db.engine == "sqlite":
            sqlite_file = directory / "sqlite_schema.sql"
            all_migrations = discover_migrations(directory)
            if not already_applied:
                if sqlite_file.is_file():
                    logger.info("Applying full SQLite schema from %s", sqlite_file)
                    conn.executescript(sqlite_file.read_text(encoding="utf-8"))
                    for m in all_migrations:
                        conn.execute(
                            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT (version) DO NOTHING;",
                            (m.version, m.name),
                        )
                        applied.append(m)
                    if not all_migrations:
                        conn.execute(
                            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (1, 'sqlite_initial_schema', CURRENT_TIMESTAMP) ON CONFLICT (version) DO NOTHING;"
                        )
                        applied.append(Migration(1, "sqlite_initial_schema", sqlite_file))
                return applied
            else:
                # Tables exist, check if newer migrations exist
                for m in all_migrations:
                    if m.version not in already_applied:
                        # Attempt applying
                        apply_migration(conn, m)
                        applied.append(m)
                return applied

        # PostgreSQL execution
        all_migrations = discover_migrations(directory)
        for migration in all_migrations:
            if migration.version not in already_applied:
                apply_migration(conn, migration)
                applied.append(migration)

    return applied


def get_migration_status(database: Optional[Database] = None) -> Dict[str, Any]:
    """Return current migration state and pending migrations."""
    db = database or Database()
    all_migrations = discover_migrations()

    try:
        with db.connection() as conn:
            applied = get_applied_versions(conn)
            pending = [m for m in all_migrations if m.version not in applied]
            return {
                "latest_applied_version": max(applied) if applied else 0,
                "applied_count": len(applied),
                "pending_count": len(pending),
                "pending_migrations": [f"{m.version:03d}_{m.name}" for m in pending],
            }
    except Exception as e:
        return {
            "error": str(e),
            "pending_count": len(all_migrations),
            "all_migrations": [f"{m.version:03d}_{m.name}" for m in all_migrations],
        }


def main():
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    try:
        applied = run_migrations()
        if applied:
            print(f"Successfully applied {len(applied)} migration(s):")
            for m in applied:
                print(f"  • {m.version:03d}_{m.name}")
        else:
            print("Database schema is up to date (0 pending migrations).")
    except Exception as err:
        print(f"Migration failed: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
