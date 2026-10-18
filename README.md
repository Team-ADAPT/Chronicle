# Chronicle

<p align="center">
  <img src="ui/assets/icon.png" alt="Chronicle Logo" width="160" />
</p>

<p align="center">
  <strong>Intelligent Host Behaviour Analysis & Activity Monitoring System</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python: 3.10+" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20eBPF-orange.svg" alt="Platform: Linux" />
  <img src="https://img.shields.io/badge/Tests-110%20Passed-brightgreen.svg" alt="Tests" />
  <img src="https://img.shields.io/badge/ML-XGBoost%20%7C%20Isolation%20Forest-purple.svg" alt="ML Models" />
  <img src="https://img.shields.io/badge/DBMS-SQLite%20%7C%20PostgreSQL-indigo.svg" alt="DBMS Dual Engine" />
</p>

---

> **Core Philosophy:** *"The Operating System observes, the DBMS remembers, Machine Learning detects."*

**Chronicle** is a Linux-based host behavioural analysis and security monitoring system built on a fundamental principle: **individual events lack context; historical behaviour reveals anomalies**. Rather than evaluating isolated system calls or brief observation windows, Chronicle persistently monitors host activity, builds process-specific historical baselines, and detects threats using statistical baselines and in-process machine learning.

---

## 📑 Table of Contents

- [System Architecture](#system-architecture)
- [Key Features](#key-features)
- [Project Directory Layout](#project-directory-layout)
- [Quickstart Guide](#quickstart-guide)
- [Database Management CLI](#database-management-cli)
- [Telemetry Collection (eBPF)](#telemetry-collection-ebpf)
- [Machine Learning & Retraining](#machine-learning--retraining)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Debian Packaging](#debian-packaging)
- [Privacy & Security Guarantees](#privacy--security-guarantees)
- [Documentation Index](#documentation-index)
- [License & Credits](#license--credits)

---

## 🏛️ System Architecture

Chronicle connects kernel observation, relational persistence, in-process machine learning, explainable risk scoring, and desktop presentation into an integrated pipeline:

```text
               ┌────────────────────────────────────────────────────────┐
               │                   Linux Host Kernel                    │
               └───────────────────────────┬────────────────────────────┘
                                           │
                        Kernel Probes & Tracepoints (BCC)
                        [sys_enter_execve, fork, openat, connect]
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │          Telemetry Collector & Normalizer             │
               │   • 5-second behaviour window aggregation              │
               │   • Zero-crash psutil fallback for unprivileged hosts  │
               │   • Privacy sanitizer (token / password redaction)     │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │              Chronicle DBMS Memory Layer               │
               │   • Dual-Engine: SQLite (default) + PostgreSQL 14+     │
               │   • Automated versioned schema migrations              │
               │   • Process instances (UUID surrogate keys)            │
               │   • Configurable time/count data retention manager     │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │            Historical Profiling Engine                 │
               │   • Process-specific running baselines (CPU, Mem, Sys) │
               │   • Welford's algorithm + Outlier-resistant NMAD / IQR │
               │   • Real-time Z-score deviation calculation            │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │         In-Process Machine Learning Engine             │
               │   • Supervised XGBoost Classifier (ADFA-LD & PLAID)    │
               │   • Unsupervised Isolation Forest Anomaly Detector     │
               │   • Exact 401/442 feature vector extraction            │
               │   • Automated ModelRegistry with candidate promotion   │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │            Contextual Risk & Alert Engine              │
               │   • Transparent 0–100 multi-category risk score        │
               │   • Explainable diagnostic evidence reasons            │
               │   • Windowed temporal alert deduplication (120s)       │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │               Chronicle Desktop Interface              │
               │   • Native WebKit window (pywebview) + Web UI fallback │
               │   • Real-time process stream, baseline graphs & triage │
               │   • Local REST API (http://127.0.0.1:8000/api/)        │
               └────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Features

- **Kernel-Level eBPF Telemetry:** Real-time capture of process executions (`execve`), system call histograms, file modifications (`openat`, `unlinkat`), and network connections (`connect`).
- **Resilient psutil Fallback:** When running without `root` or on development machines, automatically switches to `psutil` sampling with zero crashes.
- **Relational DBMS Storage:** Dual-engine storage with PostgreSQL for high-throughput server deployments and zero-dependency embedded SQLite for single-user desktop monitoring.
- **Robust Behavioural Baselining:** Long-term statistical profiles per program identity (CPU, memory, syscall rates) using Welford's algorithm and Median Absolute Deviation resistant to poisoning.
- **In-Process Machine Learning:** Pre-trained XGBoost and Isolation Forest models executing directly in Python with sub-millisecond inference latencies.
- **Explainable Risk Scoring:** Computes calibrated 0–100 risk scores backed by verifiable evidence strings (e.g., *"Syscall burst 5.2σ above baseline; interactive shell spawned from daemon"*).
- **Automated Model Retraining:** Staged model registry with schema verification, candidate gates, atomic promotion, and instantaneous rollback.
- **Strict Privacy Enforcement:** 100% of telemetry stays local. Automatic redaction of passwords, tokens, API keys, and sensitive environment variables; file permissions hardened to `0600` (owner-only).
- **Native Desktop Application:** Standalone desktop UI powered by `pywebview` with light/dark theme support, live KPI counters, and interactive alert management.
- **Debian (.deb) Distribution:** Automated packaging scripts generating standalone Debian packages registered with the Linux desktop applications menu.

---

## 📁 Project Directory Layout

```text
Chronicle/
├── app.py                      # Main desktop launcher (native pywebview / browser mode)
├── pyproject.toml              # Modern PEP 517/518 build metadata & tool configs
├── requirements.txt            # Python runtime & test dependencies
├── .editorconfig               # Consistent cross-editor formatting rules
├── .gitignore                  # Git ignore rules for caches, databases, and artifacts
├── LICENSE                     # MIT Open Source License
├── CONTRIBUTING.md             # Contribution guidelines & conventional commits
├── README.md                   # Project overview and documentation index
│
├── src/                        # Canonical Chronicle Python package
│   └── chronicle/              # Core application & library modules
│       ├── api.py              # Local REST API endpoints handler
│       ├── collector.py        # Live eBPF & psutil kernel observer
│       ├── config.py           # Application & pipeline configuration
│       ├── ml_detector.py      # In-process Scikit-learn/XGBoost inference engine
│       ├── pipeline.py         # End-to-end telemetry orchestrator
│       ├── risk_engine.py      # Contextual risk scoring & explainable alerting
│       ├── storage.py          # Lightweight fast SQLite storage & Welford profiler
│       └── db/                 # Full relational DBMS persistence subsystem
│           ├── config.py       # Database connection & retention settings
│           ├── connection.py   # PostgreSQL & SQLite connection manager
│           ├── ingest.py       # eBPF dataset ingestion pipeline
│           ├── migrations.py   # Versioned SQL migration runner
│           ├── models.py       # Dataclasses and relational entity definitions
│           ├── privacy.py      # Local data redaction & permission enforcement
│           ├── profiling.py    # Historical profile baseline manager
│           ├── repository.py   # Query repository for events, profiles, detections
│           ├── retention.py    # Automated database retention & pruning
│           ├── __main__.py     # Database administration CLI entrypoint
│           └── sql/            # Versioned migration scripts (001, 002, 003)
├── ebpf/                       # Linux kernel telemetry collection layer
│   ├── collector.py            # Standalone eBPF telemetry collector (BCC)
│   ├── dataset_collector.py    # Behavioural telemetry & workload simulator
│   └── README.md               # Kernel probe hooks and architecture reference
│
├── database/                   # DBMS specifications
│   ├── schema.sql              # Consolidated master DDL schema
│   └── README.md               # Relational data model & DBMS principles
│
├── ML/                         # Machine learning subsystem
│   ├── src/                    # Data loaders, feature extractors, training scripts
│   │   ├── model_registry.py   # Candidate staging, promotion, and rollback
│   │   ├── retrain_pipeline.py # Automated retraining pipeline CLI
│   │   └── validate_training_data.py # Schema & data quality validator
│   ├── models/                 # Pre-trained XGBoost & Isolation Forest models
│   ├── results/                # Confusion matrices, ROC curves, metrics JSON
│   └── tests/                  # Model reloading, schema isolation & retraining tests
│
├── ui/                         # Desktop monitoring interface assets
│   ├── index.html              # Modern dashboard layout (Overview, Process, Alerts)
│   ├── style.css               # Design system with responsive themes
│   ├── app.js                  # Frontend interactivity & real-time telemetry polling
│   └── assets/                 # Icons and visual assets
│
├── packaging/                  # Linux distribution packaging
│   ├── build_deb.sh            # Debian (.deb) package build automation
│   ├── chronicle.desktop       # FreeDesktop application launcher entry
│   └── DEBIAN/                 # Debian package control configuration
│
├── scripts/                    # Automation helper scripts
│   ├── run_dev.sh              # Start Chronicle in development mode
│   ├── run_tests.sh            # Run complete unit and integration test suites
│   ├── db_manage.sh            # Database administration CLI wrapper
│   └── README.md               # Script usage documentation
│
├── tests/                      # Core test suites
│   ├── test_chronicle_pipeline.py  # End-to-end pipeline & API integration tests
│   ├── test_db_storage.py          # Database storage, migrations & privacy tests
│   ├── test_risk_scoring_alerts.py # Risk scoring, deduplication & alert tests
│   └── README.md                   # Test runner guide and instructions
│
└── docs/                       # Comprehensive documentation suite
    ├── README.md               # Documentation directory index
    ├── architecture.md         # Detailed system architecture specification
    ├── proposal.md             # Formal project proposal & objectives
    ├── project_specification.md# Full academic & course specifications
    ├── task_ledger.md          # Work-done ledger and milestone audit
    ├── commit_roadmap.md       # Step-by-step commit history and viva guide
    └── project_summary.md      # Project development summary and history
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites & Installation

Clone the repository and install runtime dependencies:

```bash
git clone https://github.com/Team-ADAPT/Chronicle.git
cd Chronicle

# Create and activate virtual environment (optional but recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies (or install editable package via pyproject.toml)
pip install -r requirements.txt
pip install -e .
```

### 2. Launch the Application

Launch Chronicle with the native desktop window (`pywebview`):

```bash
# Option A: Using the developer script
./scripts/run_dev.sh

# Option B: Direct Python execution
python3 app.py --window
```

To run in headless / browser mode:

```bash
python3 app.py --no-window --port 8080
# Open http://127.0.0.1:8080 in your browser
```

---

## 🗄️ Database Management CLI

Chronicle provides a built-in database administration CLI supporting both SQLite and PostgreSQL:

```bash
# Inspect database health, latency, engine, and migration status
./scripts/db_manage.sh status

# Run pending schema migrations
./scripts/db_manage.sh migrate

# Recompute historical behavioural baselines from telemetry
./scripts/db_manage.sh profile --min-obs 5

# Execute retention cleanup (dry-run mode available)
./scripts/db_manage.sh retention --dry-run

# Ingest an external eBPF collector dataset with automatic baseline calculation
./scripts/db_manage.sh ingest /path/to/collector_run/ --auto-profile
```

---

## 🔍 Telemetry Collection (eBPF)

The standalone telemetry collector runs at kernel level to capture high-volume tracepoints:

```bash
# Run benign desktop baseline collection (5-second windows)
sudo python3 ebpf/collector.py \
  --label benign \
  --scenario normal_desktop \
  --duration 300 \
  --window 5

# Run security workload simulation with raw syscall tracing and salted hashing
sudo python3 ebpf/collector.py \
  --label malicious \
  --scenario ransomware_sim \
  --duration 180 \
  --window 5 \
  --trace-syscalls \
  --hash-paths
```

> **Requirements for native eBPF:** Linux kernel >= 5.5, BCC tools, and kernel headers (`sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)`). When run without root, Chronicle automatically falls back to `psutil`.

---

## 🧠 Machine Learning & Retraining

Chronicle evaluates syscall-level process sequences using models trained on standard benchmarks:

| Dataset | Primary Model | Attack Recall | Accuracy | Features |
| :--- | :--- | :---: | :---: | :---: |
| **ADFA-LD** | Supervised XGBoost | **93.29%** | **97.65%** | 442 Linux Syscall Traces |
| **PLAID** | Supervised XGBoost | **100.00%** | **99.60%** | 401 Process Features |
| **Baseline** | Isolation Forest | 88.40% | 91.20% | Unsupervised Anomaly Scoring |

### Automated Model Retraining Pipeline

Chronicle includes a safe, automated retraining workflow with candidate evaluation and rollback:

```bash
# 1. Validate incoming dataset quality and schema conformity
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --data path/to/adfa.csv --validate-only

# 2. Retrain and evaluate candidate against production baseline
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --data path/to/adfa.csv

# 3. Retrain with automatic atomic promotion upon passing acceptance gates
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --data path/to/adfa.csv --promote

# 4. Instant rollback to previous archived model if regression is observed
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --rollback
```

---

## 🧪 Testing & Quality Assurance

Chronicle maintains comprehensive test coverage across pipeline orchestration, relational DBMS storage, risk scoring, and ML validation:

```bash
# Run the complete test suite
./scripts/run_tests.sh

# Or directly with pytest
pytest tests/ -v
```

All 90 core integration and unit tests execute in ~3 seconds.

To run the machine learning retraining and validation suite:

```bash
PYTHONPATH=ML/src:src:. pytest ML/tests/test_retrain_pipeline.py -v
```

---

## 📦 Debian Packaging

Chronicle packages into a native `.deb` archive for one-click installation on Ubuntu, Debian, or Linux Mint:

```bash
# Build the .deb installer
bash packaging/build_deb.sh

# Install the generated package
sudo dpkg -i packaging/output/chronicle_0.2.0-1_amd64.deb

# Launch Chronicle from the application menu or terminal
chronicle
```

---

## 🔒 Privacy & Security Guarantees

1. **100% Local Processing:** Telemetry is processed and analyzed strictly on the local machine; no data is transmitted to external servers.
2. **Credential Sanitization:** Process arguments and command-lines are scrubbed for sensitive keys (`password`, `token`, `secret`, `api_key`, `auth`).
3. **Hardened File Permissions:** Database and profile files are automatically hardened to `0600` (read/write by owner only) with parent directories restricted to `0700`.
4. **Local Binding:** The internal REST API server binds strictly to `127.0.0.1` and blocks non-local network access.

---

## 📖 Documentation Index

Detailed architectural and academic specifications are available in the [`docs/`](docs/) directory:

- [System Architecture Specification](docs/architecture.md)
- [PBL Project Proposal](docs/proposal.md)
- [Comprehensive Project Specification](docs/project_specification.md)
- [Task & Work-Done Ledger](docs/task_ledger.md)
- [Commit History & Roadmap](docs/commit_roadmap.md)
- [Project Summary & History](docs/project_summary.md)
- [DBMS Relational Schema & Specifications](database/README.md)
- [eBPF Observation Layer Reference](ebpf/README.md)
- [Research & ML Evaluation Framework](research/README.md)

---

## 📜 License & Credits

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Developed as a Project-Based Learning (PBL) initiative by **Team ADAPT**:
- **Department of Computer Science & Engineering**
- **Graphic Era (Deemed to be University), Dehradun**
- **Academic Session 2026–27**
