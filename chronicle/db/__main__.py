"""
CLI entry point for Chronicle dual-engine database operations:
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
        description="Chronicle PostgreSQL & SQLite database management utility",
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
    ingest_parser.add_argument("--auto-profile", action="store_true", help="Automatically compute baselines after ingestion")
    ingest_parser.add_argument("--min-obs", type=int, default=5, help="Minimum observations required for baseline maturity")

    # profile
    prof_parser = subparsers.add_parser("profile", help="Compute or recompute behavioural baselines for programs")
    prof_parser.add_argument("--profile-id", default=None, help="Specific program profile_id to compute (default: all)")
    prof_parser.add_argument("--min-obs", type=int, default=5, help="Minimum observations required for baseline maturity")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    cfg = DatabaseConfig.from_env()

    if args.command == "status":
        db = Database(cfg)
        health = db.check_health()
        engine_label = "PostgreSQL" if db.engine == "postgresql" else "SQLite (Local Fallback)"

        print(f"Chronicle Storage Status [{engine_label}]:")
        print(f"  • Engine:     {db.engine.upper()}")
        print(f"  • Connection: {cfg.masked_conninfo()}")

        locality = "User-Side Local (100% Private)" if cfg.is_local() else "Remote Server"
        enforce_local = os.getenv("CHRONICLE_ENFORCE_LOCAL_DB", "1").lower() in ("1", "true", "yes", "on")
        privacy_status = "Active (Remote connections blocked)" if enforce_local else "Permissive"

        print(f"  • Locality:   {locality}")
        print(f"  • Privacy:    {privacy_status}")
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
        db = Database(cfg)
        applied = run_migrations(db)
        engine_label = db.engine.upper()
        if applied:
            print(f"Applied {len(applied)} {engine_label} migration(s):")
            for m in applied:
                print(f"  • {m.version:03d}_{m.name}")
        else:
            print(f"Database schema ({engine_label}) is up to date (0 pending migrations).")

    elif args.command == "retention":
        db = Database(cfg)
        mgr = RetentionManager(db)
        res = mgr.purge_expired_data(dry_run=args.dry_run)
        mode = "[DRY-RUN]" if args.dry_run else "[EXECUTED]"
        print(f"Chronicle Retention Cleanup {mode} ({db.engine.upper()}):")
        for tbl, count in res.items():
            print(f"  • {tbl}: {count} rows")

    elif args.command == "ingest":
        db = Database(cfg)
        run_migrations(db)
        from chronicle.db.repository import TelemetryRepository
        repo = TelemetryRepository(db)
        counts = ingest_experiment(
            args.path,
            repository=repo,
            batch_size=args.batch_size,
            auto_profile=args.auto_profile,
            min_observations=args.min_obs,
        )
        print(f"Ingestion complete ({db.engine.upper()}):")
        for k, v in counts.items():
            print(f"  • {k}: {v} records")

    elif args.command == "profile":
        db = Database(cfg)
        run_migrations(db)
        from chronicle.db.profiling import ProfileManager
        from chronicle.db.repository import TelemetryRepository
        repo = TelemetryRepository(db)
        pm = ProfileManager(repo)

        if args.profile_id:
            prof = pm.recompute_profile(args.profile_id, min_observations=args.min_obs)
            if prof:
                print(f"Profile {prof.profile_id} ({prof.comm}):")
                print(f"  • Maturity:      {prof.maturity}")
                print(f"  • Confidence:    {prof.confidence:.2f}")
                print(f"  • Observations:  {prof.observations_count}")
                print(f"  • Instances:     {prof.instances_count}")
            else:
                print(f"Insufficient history for profile '{args.profile_id}' (minimum {args.min_obs} required).")
        else:
            results = pm.recompute_all_profiles(min_observations=args.min_obs)
            print(f"Chronicle Program Baselining ({db.engine.upper()}):")
            for pid, prof in results.items():
                if prof:
                    print(f"  • {pid} ({prof.comm}): {prof.maturity} (conf: {prof.confidence:.2f}, n={prof.observations_count})")
                else:
                    print(f"  • {pid}: Insufficient history")

if __name__ == "__main__":
    main()
