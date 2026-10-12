"""
CLI entry point for Chronicle database operations:
  python -m chronicle.db migrate
  python -m chronicle.db status
  python -m chronicle.db retention [--dry-run]
  python -m chronicle.db ingest <experiment_dir>
"""

import argparse
import logging
import os
import sys

from chronicle.db.config import DatabaseConfig
from chronicle.db.connection import Database
from chronicle.db.ingest import ingest_experiment
from chronicle.db.migrations import get_migration_status, run_migrations
from chronicle.db.retention import RetentionManager


def main():
    parser = argparse.ArgumentParser(
        prog="python -m chronicle.db",
        description="Chronicle PostgreSQL database management utility",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # migrate
    subparsers.add_parser("migrate", help="Run all pending schema migrations")

    # status
    subparsers.add_parser("status", help="Check database connectivity and migration status")

    # retention
    ret_parser = subparsers.add_parser("retention", help="Run retention policy cleanup")
    ret_parser.add_argument("--dry-run", action="store_true", help="Report records without deleting")

    # ingest
    ingest_parser = subparsers.add_parser("ingest", help="Ingest eBPF collector dataset folder")
    ingest_parser.add_argument("path", help="Path to experiment run directory")
    ingest_parser.add_argument("--batch-size", type=int, default=1000, help="Batch insertion size")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    cfg = DatabaseConfig.from_env()

    if args.command == "status":
        print("Chronicle PostgreSQL Status:")
        print(f"  • Configured: {cfg.is_configured()}")
        print(f"  • Connection: {cfg.masked_conninfo()}")
        if not cfg.is_configured():
            print("  • Notice: DATABASE_URL is not set.")
            sys.exit(0)
        locality = "User-Side Local (100% Private)" if cfg.is_local() else "Remote Server"
        enforce_local = os.getenv("CHRONICLE_ENFORCE_LOCAL_DB", "1").lower() in ("1", "true", "yes", "on")
        privacy_status = "Active (Remote connections blocked)" if enforce_local else "Permissive"

        print(f"  • Locality:   {locality}")
        print(f"  • Privacy:    {privacy_status}")

        db = Database(cfg)
        health = db.check_health()
        print(f"  • Connected:  {health.get('connected')}")
        if health.get("connected"):
            print(f"  • Latency:    {health.get('latency_ms')} ms")
            print(f"  • Database:   {health.get('database')}")
            mig_stat = get_migration_status(db)
            print(f"  • Migrations: {mig_stat.get('applied_count')} applied, {mig_stat.get('pending_count')} pending")
        else:
            print(f"  • Error:      {health.get('error')}")
            sys.exit(1)

    elif args.command == "migrate":
        if not cfg.is_configured():
            print("Error: DATABASE_URL is not set.", file=sys.stderr)
            sys.exit(1)
        db = Database(cfg)
        applied = run_migrations(db)
        if applied:
            print(f"Applied {len(applied)} migration(s):")
            for m in applied:
                print(f"  • {m.version:03d}_{m.name}")
        else:
            print("Database schema is up to date (0 pending migrations).")

    elif args.command == "retention":
        if not cfg.is_configured():
            print("Error: DATABASE_URL is not set.", file=sys.stderr)
            sys.exit(1)
        db = Database(cfg)
        mgr = RetentionManager(db)
        res = mgr.purge_expired_data(dry_run=args.dry_run)
        mode = "[DRY-RUN]" if args.dry_run else "[EXECUTED]"
        print(f"Chronicle Retention Cleanup {mode}:")
        for tbl, count in res.items():
            print(f"  • {tbl}: {count} rows")

    elif args.command == "ingest":
        if not cfg.is_configured():
            print("Error: DATABASE_URL is not set.", file=sys.stderr)
            sys.exit(1)
        counts = ingest_experiment(args.path, batch_size=args.batch_size)
        print("Ingestion complete:")
        for k, v in counts.items():
            print(f"  • {k}: {v} records")


if __name__ == "__main__":
    main()
