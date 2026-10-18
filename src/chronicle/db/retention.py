"""
Configurable retention manager for Chronicle historical telemetry data.
Safely purges expired events, windows, system metrics, and dead process records
while strictly respecting foreign-key integrity and preserving detection records.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from chronicle.db.config import RetentionConfig
from chronicle.db.connection import Database

logger = logging.getLogger("chronicle.db.retention")


class RetentionManager:
    """Enforces configurable retention policies over historical telemetry and metrics."""

    def __init__(self, database: Optional[Database] = None, config: Optional[RetentionConfig] = None):
        self.db = database or Database()
        self.config = config or RetentionConfig.from_env()

    def purge_expired_data(
        self,
        now: Optional[datetime] = None,
        dry_run: bool = False,
    ) -> Dict[str, int]:
        """
        Execute retention cleanup in safe dependency order.

        Order of operations:
        1. Expired telemetry events (preserving windows/instances linked to flagged detections)
        2. Expired behaviour windows (preserving windows directly linked to detections)
        3. Expired system metrics
        4. Expired detections (if detections_days is configured)
        5. Exited process instances that have no remaining events, windows, or detections.
        """
        ref_time = now or datetime.now(timezone.utc)
        cutoff_events = ref_time - timedelta(days=self.config.events_days)
        cutoff_windows = ref_time - timedelta(days=self.config.windows_days)
        cutoff_metrics = ref_time - timedelta(days=self.config.metrics_days)
        cutoff_dead_procs = ref_time - timedelta(days=self.config.dead_procs_days)
        cutoff_detections = (
            ref_time - timedelta(days=self.config.detections_days)
            if self.config.detections_days is not None
            else None
        )

        logger.info(
            "Starting retention cleanup (dry_run=%s). Cutoffs: events=%s, windows=%s, metrics=%s, procs=%s",
            dry_run,
            cutoff_events.isoformat(),
            cutoff_windows.isoformat(),
            cutoff_metrics.isoformat(),
            cutoff_dead_procs.isoformat(),
        )

        results: Dict[str, int] = {
            "telemetry_events": 0,
            "behaviour_windows": 0,
            "system_metrics": 0,
            "detections": 0,
            "process_instances": 0,
        }

        with self.db.cursor() as cur:
            # 1. Telemetry Events
            if self.config.preserve_flagged_detections:
                if cutoff_detections is not None:
                    event_where = """
                        timestamp < %s
                        AND (
                            instance_id IS NULL
                            OR instance_id NOT IN (
                                SELECT DISTINCT instance_id FROM detections
                                WHERE is_anomaly = TRUE AND timestamp >= %s AND instance_id IS NOT NULL
                            )
                        )
                    """
                    event_params = (cutoff_events, cutoff_detections)
                else:
                    event_where = """
                        timestamp < %s
                        AND (
                            instance_id IS NULL
                            OR instance_id NOT IN (
                                SELECT DISTINCT instance_id FROM detections
                                WHERE is_anomaly = TRUE AND instance_id IS NOT NULL
                            )
                        )
                    """
                    event_params = (cutoff_events,)
            else:
                event_where = "timestamp < %s"
                event_params = (cutoff_events,)

            if dry_run:
                cur.execute(f"SELECT COUNT(*) AS c FROM telemetry_events WHERE {event_where};", event_params)
                results["telemetry_events"] = cur.fetchone()["c"]
            else:
                cur.execute(f"DELETE FROM telemetry_events WHERE {event_where};", event_params)
                results["telemetry_events"] = cur.rowcount

            # 2. Behaviour Windows
            if self.config.preserve_flagged_detections:
                if cutoff_detections is not None:
                    win_where = """
                        end_time < %s
                        AND window_id NOT IN (
                            SELECT window_id FROM detections WHERE window_id IS NOT NULL
                        )
                        AND (
                            instance_id IS NULL
                            OR instance_id NOT IN (
                                SELECT DISTINCT instance_id FROM detections
                                WHERE is_anomaly = TRUE AND timestamp >= %s AND instance_id IS NOT NULL
                            )
                        )
                    """
                    win_params = (cutoff_windows, cutoff_detections)
                else:
                    win_where = """
                        end_time < %s
                        AND window_id NOT IN (
                            SELECT window_id FROM detections WHERE window_id IS NOT NULL
                        )
                        AND (
                            instance_id IS NULL
                            OR instance_id NOT IN (
                                SELECT DISTINCT instance_id FROM detections
                                WHERE is_anomaly = TRUE AND instance_id IS NOT NULL
                            )
                        )
                    """
                    win_params = (cutoff_windows,)
            else:
                win_where = "end_time < %s"
                win_params = (cutoff_windows,)

            if dry_run:
                cur.execute(f"SELECT COUNT(*) AS c FROM behaviour_windows WHERE {win_where};", win_params)
                results["behaviour_windows"] = cur.fetchone()["c"]
            else:
                cur.execute(f"DELETE FROM behaviour_windows WHERE {win_where};", win_params)
                results["behaviour_windows"] = cur.rowcount

            # 3. System Metrics
            if dry_run:
                cur.execute("SELECT COUNT(*) AS c FROM system_metrics WHERE end_time < %s;", (cutoff_metrics,))
                results["system_metrics"] = cur.fetchone()["c"]
            else:
                cur.execute("DELETE FROM system_metrics WHERE end_time < %s;", (cutoff_metrics,))
                results["system_metrics"] = cur.rowcount

            # 4. Detections
            if cutoff_detections is not None:
                if dry_run:
                    cur.execute("SELECT COUNT(*) AS c FROM detections WHERE timestamp < %s;", (cutoff_detections,))
                    results["detections"] = cur.fetchone()["c"]
                else:
                    cur.execute("DELETE FROM detections WHERE timestamp < %s;", (cutoff_detections,))
                    results["detections"] = cur.rowcount

            # 5. Dead Process Instances
            # Only remove terminated processes with end_time < cutoff AND no child references AND no remaining events/windows/detections
            proc_where = """
                end_time IS NOT NULL
                AND end_time < %s
                AND instance_id NOT IN (
                    SELECT parent_instance_id FROM process_instances WHERE parent_instance_id IS NOT NULL
                )
                AND instance_id NOT IN (
                    SELECT DISTINCT instance_id FROM telemetry_events WHERE instance_id IS NOT NULL
                )
                AND instance_id NOT IN (
                    SELECT DISTINCT instance_id FROM behaviour_windows WHERE instance_id IS NOT NULL
                )
                AND instance_id NOT IN (
                    SELECT DISTINCT instance_id FROM detections WHERE instance_id IS NOT NULL
                )
            """
            proc_params = (cutoff_dead_procs,)

            if dry_run:
                cur.execute(f"SELECT COUNT(*) AS c FROM process_instances WHERE {proc_where};", proc_params)
                results["process_instances"] = cur.fetchone()["c"]
            else:
                cur.execute(f"DELETE FROM process_instances WHERE {proc_where};", proc_params)
                results["process_instances"] = cur.rowcount

        action = "Would delete" if dry_run else "Deleted"
        logger.info(
            "Retention run complete: %s %d events, %d windows, %d metrics, %d detections, %d procs",
            action,
            results["telemetry_events"],
            results["behaviour_windows"],
            results["system_metrics"],
            results["detections"],
            results["process_instances"],
        )
        return results


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Chronicle PostgreSQL retention cleanup runner")
    parser.add_argument("--dry-run", action="store_true", help="Report records eligible for cleanup without deleting")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    mgr = RetentionManager()
    try:
        res = mgr.purge_expired_data(dry_run=args.dry_run)
        mode = "[DRY-RUN]" if args.dry_run else "[EXECUTED]"
        print(f"Chronicle Retention Cleanup {mode}:")
        for tbl, count in res.items():
            print(f"  • {tbl}: {count} rows")
    except Exception as e:
        print(f"Retention cleanup error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
