"""
Ingestion utilities for loading Chronicle eBPF collector runs directly into PostgreSQL.
Reads process_instances.csv, telemetry_events.csv, behaviour_windows.csv,
and system_metrics.csv from an experiment output directory.
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Dict, Optional, Union

from chronicle.db.models import (
    BehaviourWindow,
    ProcessInstance,
    SystemMetric,
    TelemetryEvent,
)
from chronicle.db.repository import TelemetryRepository

logger = logging.getLogger("chronicle.db.ingest")


def ingest_experiment(
    run_dir: Union[str, Path],
    repository: Optional[TelemetryRepository] = None,
    batch_size: int = 1000,
) -> Dict[str, int]:
    """Import an eBPF collector experiment directory into PostgreSQL."""
    directory = Path(run_dir)
    if not directory.is_dir():
        raise FileNotFoundError(f"Experiment directory not found: {directory}")

    repo = repository or TelemetryRepository()
    results = {
        "process_instances": 0,
        "telemetry_events": 0,
        "behaviour_windows": 0,
        "system_metrics": 0,
    }

    # 1. Process Instances (must precede events and windows for foreign-key resolution)
    inst_csv = directory / "process_instances.csv"
    if inst_csv.is_file():
        logger.info("Ingesting process instances from %s", inst_csv)
        instances = []
        with open(inst_csv, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                instances.append(ProcessInstance.from_collector_csv(row))
                if len(instances) >= batch_size:
                    repo.register_processes_batch(instances)
                    results["process_instances"] += len(instances)
                    instances = []
        if instances:
            repo.register_processes_batch(instances)
            results["process_instances"] += len(instances)

    # 2. Telemetry Events
    events_csv = directory / "telemetry_events.csv"
    if events_csv.is_file():
        logger.info("Ingesting telemetry events from %s", events_csv)
        events = []
        with open(events_csv, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(TelemetryEvent.from_collector_csv(row))
                if len(events) >= batch_size:
                    repo.insert_events_batch(events)
                    results["telemetry_events"] += len(events)
                    events = []
        if events:
            repo.insert_events_batch(events)
            results["telemetry_events"] += len(events)

    # 3. Behaviour Windows
    win_csv = directory / "behaviour_windows.csv"
    if win_csv.is_file():
        logger.info("Ingesting behaviour windows from %s", win_csv)
        windows = []
        with open(win_csv, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                windows.append(BehaviourWindow.from_collector_csv(row))
                if len(windows) >= batch_size:
                    repo.insert_windows_batch(windows)
                    results["behaviour_windows"] += len(windows)
                    windows = []
        if windows:
            repo.insert_windows_batch(windows)
            results["behaviour_windows"] += len(windows)

    # 4. System Metrics
    sys_csv = directory / "system_metrics.csv"
    if sys_csv.is_file():
        logger.info("Ingesting system metrics from %s", sys_csv)
        metrics = []
        with open(sys_csv, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                metrics.append(SystemMetric.from_collector_csv(row))
                if len(metrics) >= batch_size:
                    repo.insert_system_metrics_batch(metrics)
                    results["system_metrics"] += len(metrics)
                    metrics = []
        if metrics:
            repo.insert_system_metrics_batch(metrics)
            results["system_metrics"] += len(metrics)

    logger.info("Ingestion complete for %s: %s", directory.name, results)
    return results


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Ingest Chronicle collector datasets into PostgreSQL")
    parser.add_argument("path", help="Path to experiment directory (contains process_instances.csv, etc.)")
    parser.add_argument("--batch-size", type=int, default=1000, help="Batch insertion size")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    try:
        counts = ingest_experiment(args.path, batch_size=args.batch_size)
        print("Dataset ingested successfully:")
        for k, v in counts.items():
            print(f"  • {k}: {v} records")
    except Exception as e:
        print(f"Ingestion failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
