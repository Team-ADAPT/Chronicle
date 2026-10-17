# Chronicle

<p align="center">
  <img src="ui/assets/icon.png" alt="Chronicle" width="180" />
</p>

<p align="center">
  <strong>Intelligent Host Behaviour Analysis and Activity Monitoring</strong>
</p>

<p align="center">
  Chronicle combines local Linux telemetry, historical process baselines, and machine-learning models to help identify unusual or potentially malicious behaviour.
</p>

> **Current status:** Chronicle features an end-to-end working pipeline: Linux eBPF kernel telemetry collection, a dual-engine relational DBMS (PostgreSQL + SQLite) with automated migrations and retention, a robust historical behavioural profiling engine, embedded Scikit-learn/XGBoost ML anomaly detectors, an explainable risk scoring engine, a lightweight native desktop UI (`pywebview`), and Debian (`.deb`) packaging.

---

## Overview

Chronicle is a host behavioural analysis and threat-detection system designed around a foundational principle: **individual events lack context; historical behaviour reveals anomalies**. Rather than judging process actions in isolation or over brief observation windows, Chronicle persistently tracks process lifecycles, file and network events, resource usage, and syscall patterns, storing structured telemetry locally and comparing active executions against long-term historical baselines.

The system is designed around a strict local-first, privacy-preserving workflow:

1. **Observe:** Capture host kernel activity via eBPF probes with seamless fallback to `psutil`.
2. **Normalize & Scrub:** Clean telemetry events into structured 5-second behaviour windows while redacting credentials and sensitive user data.
3. **Persist:** Store structured telemetry, windows, metrics, and profiles in a local PostgreSQL or SQLite database.
4. **Profile:** Build outlier-resistant historical baselines (Median, NMAD, IQR) per program identity across multiple executions.
5. **Detect:** Evaluate feature deviations using embedded Scikit-learn / XGBoost models alongside statistical anomaly checks.
6. **Score & Explain:** Combine multi-category evidence into an explainable 0–100 risk score.
7. **Present:** Surface real-time processes, baselines, and alerts in a native Linux desktop application (`pywebview`).

---

## Key Features

- **Linux eBPF Telemetry Collection:** Real-time kernel probes for process execution, lifecycle, file activity, network connections, syscall counts, and I/O statistics.
- **Relational DBMS & History Layer:** PostgreSQL and SQLite dual-engine storage with automatic schema migrations, foreign keys, and indexes for fast temporal queries.
- **Robust Behavioural Baselines:** Outlier-resistant statistical profiling (Median, NMAD) handling cold-starts, concept drift, and baseline anti-poisoning.
- **Privacy-Preserving Local-First Design:** 100% of telemetry and analysis stays on the host; automatic credential sanitization (`password`, `token`, `secret`, `api_key`).
- **In-Process Machine Learning:** Embedded XGBoost and Isolation Forest models running directly in Python without remote API dependencies.
- **Explainable Risk Scoring:** Transparent 0–100 risk scores with granular diagnostic evidence (e.g., "Network activity 4.2× historical baseline").
- **Native Desktop Dashboard:** Lightweight WebKit desktop application (`pywebview`) featuring Overview, Process, Historical Baseline, and Alert Investigation views.
- **Debian (.deb) Packaging:** Complete packaging pipeline for one-command installation (`dpkg -i`) and Linux application menu integration.

---

## Architecture

```text
Linux Host
    │
    ▼
eBPF / C Kernel Probes (BCC)
    │
    ▼
Collection & Normalization
    │
    ▼
Privacy Sanitization Layer
    │
    ▼
Local Database Storage (PostgreSQL / SQLite)
    │
    ▼
Historical Behaviour Profiles (Median, NMAD, Z-scores)
    │
    ▼
Feature Extraction (Historical vs Live Deltas)
    │
    ▼
In-Process ML Detection (Isolation Forest & XGBoost)
    │
    ▼
Risk Scoring & Explanation (0-100 Score + Evidence)
    │
    ▼
Chronicle Desktop App (pywebview / WebKit Window)
```

---

## Repository Structure

```text
Chronicle/
├── README.md                 # Project overview and quickstart guide
├── CONTRIBUTING.md           # Conventional Commits and development workflow
├── LICENSE                   # MIT open-source license
├── Project.md                # Full academic & architectural specification
├── SUMMARY.md                # Project development summary and progress report
├── requirements.txt          # Python dependency specifications
│
├── docs/                     # Specifications and architectural documentation
│   ├── proposal.md           # Formal PBL project proposal
│   └── architecture.md       # Detailed system architecture and dataflows
│
├── src/                      # Canonical Python package
│   └── chronicle/            # Collector, pipeline orchestrator, ML detector, risk engine, API
│       ├── api.py            # Local REST API handler
│       ├── collector.py      # Kernel eBPF & psutil telemetry collector
│       ├── config.py         # System configuration
│       ├── ml_detector.py    # In-process Scikit-learn/XGBoost inference engine
│       ├── pipeline.py       # Central orchestrator connecting OS, DBMS, ML, and UI
│       ├── risk_engine.py    # Contextual risk scoring and explainable alerting
│       └── storage.py        # Lightweight local cache storage
│
├── chronicle/                # Database and History Repository layer
│   └── db/                   # Connection pool, models, repository, profiling, privacy, migrations
│       ├── connection.py     # Dual-engine PostgreSQL & SQLite connection manager
│       ├── models.py         # Relational data classes and lifecycle models
│       ├── privacy.py        # Sensitive data redaction and path masking
│       ├── profiling.py      # Robust statistical baselining engine
│       ├── repository.py     # Data access layer for telemetry, profiles, and detections
│       ├── retention.py      # Automated database pruning and retention
│       └── sql/              # Versioned migration scripts
│
├── database/                 # DBMS specifications and master schema
│   ├── schema.sql            # Consolidated master DDL schema
│   └── README.md             # Relational model and DBMS documentation
│
├── ebpf/                     # Kernel observation layer documentation
│   └── README.md             # eBPF/BCC probes, event structures, and kernel hooks
│
├── research/                 # Academic and ML research documentation
│   └── README.md             # Model A vs Model B evaluation framework and benchmarks
│
├── tests/                    # Comprehensive unit and integration test suites
│   ├── test_chronicle_pipeline.py  # Pipeline, ML inference, and API tests
│   ├── test_db_storage.py          # Database storage, profiling, and privacy tests
│   └── README.md                   # Test runner guide and coverage breakdown
│
├── scripts/                  # Automation and utility scripts
│   ├── run_dev.sh            # Launch Chronicle desktop app in dev mode
│   ├── run_tests.sh          # Execute complete test suite
│   ├── db_manage.sh          # Database administration CLI wrapper
│   └── README.md             # Scripts documentation
│
├── ML/                       # Machine learning datasets, models, and evaluations
│   ├── src/                  # Dataset loaders, feature engineering, and training scripts
│   ├── models/               # Serialized models (.joblib) and feature schemas
│   ├── results/              # Confusion matrices, classification reports, and metrics
│   └── tests/                # Model reloading and validation tests
│
├── ui/                       # Modern desktop web application assets
│   ├── index.html            # Main dashboard HTML (Overview, Process, Baseline, Alert views)
│   ├── style.css             # Vanilla CSS design system with light/dark themes
│   └── app.js                # Frontend reactivity, charts, and API polling
│
├── packaging/                # Linux distribution packaging assets
│   ├── build_deb.sh          # Debian (.deb) package builder
│   ├── chronicle.desktop     # Linux desktop launcher entry
│   └── DEBIAN/               # Package control metadata
│
└── app.py                    # Main executable entry point (native window / web mode)
```

---

## Quickstart Guide

### 1. Installation

Clone the repository and install runtime dependencies:

```bash
git clone https://github.com/Team-ADAPT/Chronicle.git
cd Chronicle

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Run the Desktop Application

Launch Chronicle with the native desktop window (`pywebview`):

```bash
# Launch via helper script
./scripts/run_dev.sh

# Or directly with Python
python3 app.py --window
```

To run in headless / browser-only mode:

```bash
python3 app.py --no-window --port 8080
# Open http://localhost:8080 in your browser
```

### 3. Run the Test Suites

Execute all pipeline and database tests:

```bash
./scripts/run_tests.sh
```

### 4. Database Administration

```bash
# Check database health & migration status
./scripts/db_manage.sh status

# Apply schema migrations
./scripts/db_manage.sh migrate

# Recompute historical behavioural baselines
./scripts/db_manage.sh profile
```

---

## Requirements

### Runtime Dashboard & Pipeline
- Python 3.9 or newer (tested on Python 3.10, 3.11, 3.12, 3.13)
- Linux (Debian, Ubuntu, Linux Mint, etc.), macOS, or Windows for desktop monitoring
- SQLite is built into Python; PostgreSQL 14+ is optional for enterprise server deployments

### Linux Kernel eBPF Telemetry
- Linux kernel 5.5 or newer with BCC support
- Root / `CAP_BPF` privileges (when unprivileged, Chronicle automatically falls back to `psutil`)
- Install kernel headers on Ubuntu/Debian:
  ```bash
  sudo apt update
  sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) python3-psutil
  ```

---

## Quick Start

### Run the dashboard

From the repository root:

```bash
python3 app.py
```

The default mode starts a local web server at `http://127.0.0.1:8000` and opens it in the default browser. To disable automatic browser opening:

```bash
python3 app.py --no-browser
```

To force the native desktop window mode when `pywebview` is installed:

```bash
python3 app.py --window
```

Use a custom development port:

```bash
python3 app.py --port 8080 --no-browser
```

---

## eBPF Data Collection

The collector writes a labelled dataset folder containing telemetry, process, behaviour-window, syscall, and system-metric outputs.

Run it as root on a Linux host:

```bash
sudo python3 eBPF_collector.py \
  --label benign \
  --scenario idle_desktop \
  --duration 300 \
  --window 5
```

Run a labelled collection for a security scenario:

```bash
sudo python3 eBPF_collector.py \
  --label malicious \
  --scenario ransomware_sim \
  --duration 180 \
  --window 5 \
  --trace-syscalls \
  --hash-paths
```

### Important collector options

| Option | Purpose |
|---|---|
| `--out` | Output directory root; a timestamped experiment is created beneath it |
| `--label` | Benign, malicious, or a custom workload label |
| `--scenario` | Human-readable scenario name recorded in metadata |
| `--duration` | Collection time in seconds; use `0` to run until interrupted |
| `--window` | Behaviour-window length in seconds |
| `--include-idle` | Include fully idle processes |
| `--only-comm` | Restrict collection to selected process names |
| `--exclude-comm` | Exclude selected process names |
| `--trace-syscalls` | Save raw syscall sequences; this is high-volume |
| `--hash-paths` | Store salted hashes instead of raw paths |
| `--perf-pages` | Size of the eBPF perf buffer per CPU |
| `--quiet` | Suppress non-essential collector output |

The command stops cleanly with `Ctrl+C` or `SIGTERM`. Each experiment includes `metadata.json` plus the collected CSV files.

---

## Machine Learning

Chronicle evaluates syscall-level process traces using two public research datasets:

- **ADFA-LD:** 5,951 traces, 746 attack traces, 442 engineered features.
- **PLAID:** 40,817 traces, 1,252 attack traces, 401 engineered features.

The current ML workflow is implemented in `ML/src/` and includes:

- Dataset loading and sequence validation
- Syscall feature extraction and schema management
- Training and evaluation for XGBoost
- Training and evaluation for Isolation Forest
- Cross-dataset transfer analysis
- Model persistence and metric export

### Build the ADFA-LD dataset

```bash
python3 ML/src/build_dataset.py
```

### Build the PLAID dataset

```bash
python3 ML/src/build_plaid_dataset.py
```

### Train the models

```bash
python3 ML/src/train_xgboost.py
python3 ML/src/train_isolation_forest.py
```

```bash
python3 ML/src/train_plaid_xgboost.py
python3 ML/src/train_plaid_isolation_forest.py
```

### Run model evaluation

```bash
python3 ML/src/cross_dataset_eval.py
```

### Automated Model Retraining & Validation

Chronicle provides an automated retraining workflow with strict schema validation, candidate evaluation, side-by-side baseline comparison, acceptance gates, candidate staging in a model registry, and safe atomic promotion with rollback:

```bash
# Validate input dataset quality and schema conformity
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --data ML/DATA/processed/adfa_features.csv --validate-only

# Retrain and evaluate candidate model against approved baseline
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --data ML/DATA/processed/adfa_features.csv

# Retrain with automatic promotion upon passing acceptance thresholds
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --data ML/DATA/processed/adfa_features.csv --promote

# Roll back to the previously approved model
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --rollback
```

See [ML/README.md](file:///Users/divyanshimac/chronicle/ML/README.md) for full architecture, acceptance thresholds, schema isolation rules, and registry details.

### Current evaluation results

| Dataset | Primary model | Attack recall | Accuracy | Notes |
|---|---|---:|---:|---|
| ADFA-LD | XGBoost | 93.29% | 97.65% | 442 features; supervised detector is primary |
| PLAID | XGBoost | 100.00% | 99.60% | 401 features; 0 false negatives in the test set |

Isolation Forest is currently a complementary detector. Its attack recall is substantially lower on both datasets and is not the primary production detection path.

> The datasets and model artifacts are not automatically downloaded by the repository. The required dataset files must be obtained separately and placed in the expected `ML/DATA/` locations.

---

## Model and Results Artifacts

Generated artifacts are stored under `ML/models/` and `ML/results/`:

- Trained joblib models
- Feature-column schemas and training configuration
- Classification reports
- Confusion matrices and feature-importance plots
- JSON metrics
- Cross-dataset comparison results

See `ML/results/ADFA_LD_RESULTS.md` and `ML/results/PLAID_RESULTS.md` for detailed research findings and artifact descriptions.

---

## Testing

Run the complete test suite from the repository root:

```bash
python3 -m pytest ML/tests/ -v
```

The current test suite covers dataset discovery, preprocessing, feature extraction, processed data integrity, model serialization, prediction behavior, and metrics. Test data and trained model assets are required for the full pipeline tests.

---

## Debian Packaging

A Debian package tree and build script are provided in `packaging/`.

Build the package on a Debian or Ubuntu system:

```bash
bash packaging/build_deb.sh
```

The script creates an architecture-specific `.deb` package and installs the application under `/opt/chronicle` with a launcher in `/usr/local/bin/chronicle`.

The package metadata is defined in `packaging/DEBIAN/control` and the application desktop entry is provided in `packaging/chronicle.desktop`.

---

## Privacy and Security

Chronicle follows a local-first design:

- Telemetry is processed on the monitored system where possible.
- Raw file paths may optionally be replaced with salted hashes.
- User content is not intentionally collected as part of the telemetry schema.
- Network activity is recorded as process-level metadata and connection information.
- The dashboard runs as a local web service by default and binds to `127.0.0.1`.

This is an experimental research system. It is not a hardened endpoint security product and should not be used as the sole control for production security monitoring.

---

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting changes.

Recommended workflow:

```bash
git checkout -b feat/your-change
git add .
git commit -m "feat(scope): add your change"
git push origin feat/your-change
```

Before opening a pull request:

1. Run the relevant tests.
2. Update documentation for user-facing changes.
3. Avoid committing datasets, credentials, generated telemetry, or personal files.
4. Keep security-sensitive changes focused and clearly documented.
5. Follow the Conventional Commits conventions in `CONTRIBUTING.md`.

---

## Roadmap

### Completed

- Local dashboard and native-window launch modes
- Linux eBPF telemetry collection
- ADFA-LD and PLAID feature pipelines
- XGBoost and Isolation Forest models
- Evaluation reports and model artifacts
- Debian packaging scaffold
- Automated model retraining and validation workflow

### In progress

- Persistent database storage and event retention
- Full process-history profiling
- Risk-scoring integration with telemetry results
- Explainable alert generation
- Production-grade security and performance hardening
- Deployment and distribution improvements

### Planned

- A complete real-time collector and dashboard integration
- PostgreSQL-backed storage
- Advanced behavioural baselining
- API or service interfaces for security tooling
- A formal public license and release process

---

## License

No explicit license has been assigned to this repository yet. The project is currently distributed without a stated open-source license. Review the repository and obtain permission before reuse or redistribution that would otherwise require licensing terms.

---

## Project Team

**Team ADAPT**

Chronicle is being developed as a Project Based Learning initiative.
