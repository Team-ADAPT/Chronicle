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

> **Current status:** The repository contains a functional local dashboard, a Linux eBPF telemetry collector, ML training pipelines, and evaluation artifacts. Database persistence, deployment integration, and production hardening are still under development.

---

## Overview

Chronicle is a research-oriented security project for understanding how a process behaves over time, rather than judging individual events in isolation. It records process lifecycle activity, file and network events, resource usage, and syscall patterns, then compares current activity with historical baselines.

The system is designed around a local-first workflow:

1. Observe host activity with eBPF and system-level telemetry.
2. Normalize events into behaviour windows and process profiles.
3. Extract structured features for machine-learning analysis.
4. Combine supervised and unsupervised detectors with contextual risk indicators.
5. Present findings through a local web or desktop interface.

---

## Key Features

- **Linux eBPF telemetry collection** for process execution, file activity, network connections, syscall counts, and I/O statistics.
- **Behaviour-window aggregation** with process, system, and event-level metrics.
- **Privacy-conscious collection** using local processing and optional hashed file paths.
- **Historical baselines** for process families and workload profiles.
- **Interactive dashboard** with live activity, anomaly scenarios, process inspection, filters, and theme selection.
- **Supervised detection** using XGBoost for ADFA-LD and PLAID datasets.
- **Unsupervised detection** using Isolation Forest as a complementary detector.
- **Cross-dataset evaluation** for measuring feature and model transfer limitations.
- **Debian package scaffolding** for distributing the local application.

---

## Architecture

```text
Linux host
    │
    ▼
eBPF probes and psutil telemetry
    │
    ▼
Normalization and privacy filtering
    │
    ▼
Process instances + telemetry events
    │
    ▼
Behaviour windows and feature extraction
    │
    ▼
XGBoost / Isolation Forest analysis
    │
    ▼
Risk scoring and explainable findings
    │
    ▼
Chronicle dashboard
```

The implementation is currently split into three main areas:

- **Runtime:** the desktop entry point and browser interface in `app.py` and `ui/`.
- **Telemetry:** the eBPF collector in `eBPF_collector.py`.
- **Machine learning:** dataset loaders, feature engineering, training scripts, models, metrics, and tests under `ML/`.

---

## Repository Structure

```text
Chronicle/
├── app.py                    # Local web and native-window entry point
├── eBPF_collector.py         # Linux eBPF telemetry collection pipeline
├── ui/                       # Web dashboard assets
├── ML/
│   ├── src/                  # Dataset, preprocessing, feature, and training code
│   ├── models/               # Trained models and feature schemas
│   ├── results/              # Evaluation reports and metrics
│   └── tests/                # Pipeline and model tests
├── packaging/                # Debian package build assets
├── CONTRIBUTING.md           # Contribution conventions
└── README.md                 # Project documentation
```

---

## Requirements

### Runtime dashboard

- Python 3.9 or newer
- A modern Linux, macOS, or Windows environment for the browser-based interface
- No privileged system access is required for the dashboard itself

### Linux eBPF collector

- Linux kernel 5.5 or newer; earlier kernels may work for selected probes
- Root privileges
- Python 3 with `psutil`
- BCC, the Python BCC bindings, and matching kernel headers

Install the Linux dependencies on Ubuntu or Debian:

```bash
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) python3-psutil
```

Install the Python runtime dependencies for the dashboard and ML scripts:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install pandas numpy scikit-learn xgboost joblib matplotlib pytest pywebview
```

> The project does not currently provide a consolidated dependency file. The required packages may vary by operating system and dataset workflow.

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
- Automated model retraining and validation
- API or service interfaces for security tooling
- A formal public license and release process

---

## License

No explicit license has been assigned to this repository yet. The project is currently distributed without a stated open-source license. Review the repository and obtain permission before reuse or redistribution that would otherwise require licensing terms.

---

## Project Team

**Team ADAPT**

Chronicle is being developed as a Project Based Learning initiative.
