# Chronicle — Automation & Utility Scripts

This directory contains development, testing, database administration, and packaging helper scripts for Chronicle.

---

## 1. Available Scripts

| Script | Purpose |
| --- | --- |
| `scripts/run_dev.sh` | Launches Chronicle in development mode (starts pipeline, API, and desktop UI). |
| `scripts/run_tests.sh` | Executes the complete test suite (pipeline, database storage, and ML inference). |
| `scripts/db_manage.sh` | Convenience wrapper around the `python -m chronicle.db` CLI for migrations, health checks, and baselining. |
| `packaging/build_deb.sh` | Builds the standalone Debian (`.deb`) installer package for Linux distribution. |
| `Dataset/dataset_collector.py` | Automated workload simulator and telemetry dataset generator. |

---

## 2. Usage Examples

### 2.1 Launching Chronicle in Development Mode
```bash
chmod +x scripts/run_dev.sh
./scripts/run_dev.sh

# Or launch directly with app.py
python3 app.py --window
```

### 2.2 Running Tests
```bash
chmod +x scripts/run_tests.sh
./scripts/run_tests.sh
```

### 2.3 Database Management
```bash
chmod +x scripts/db_manage.sh

# Check database health & migration status
./scripts/db_manage.sh status

# Run schema migrations
./scripts/db_manage.sh migrate

# Recompute historical behavioural baselines
./scripts/db_manage.sh profile
```
