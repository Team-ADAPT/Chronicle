<div align="center">

  <img src="ui/assets/icon.png" alt="Chronicle Logo" width="140" style="border-radius: 20px; box-shadow: 0 8px 24px rgba(0,0,0,0.15);" />

  # CHRONICLE
  ### Intelligent Host Behaviour Analysis & Security Telemetry Platform

  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
  [![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
  [![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-E95420?style=for-the-badge&logo=linux&logoColor=white)](ebpf/)
  [![Test Suite](https://img.shields.io/badge/Tests-92%20Passing-10B981?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
  [![ML Engine](https://img.shields.io/badge/ML-XGBoost%20%7C%20Isolation%20Forest-8B5CF6?style=for-the-badge&logo=scikit-learn&logoColor=white)](ML/)
  [![Privacy](https://img.shields.io/badge/Privacy-100%25%20Air--Gapped-EC4899?style=for-the-badge)](README.md#privacy--security-guarantees)

  <p align="center">
    <strong>A high-throughput, air-gapped host behaviour analysis system linking kernel-level eBPF observation, relational DBMS historical baselines, in-process machine learning, and explainable contextual risk scoring.</strong>
  </p>

  <p align="center">
    <a href="#-quickstart">Quickstart</a> •
    <a href="#-key-capabilities">Capabilities</a> •
    <a href="#-system-architecture">Architecture</a> •
    <a href="#-interactive-dashboard--process-inspection">UI & Telemetry</a> •
    <a href="#-threat-detection--ml-benchmarks">ML Models</a> •
    <a href="#-database-cli">Database CLI</a> •
    <a href="#-testing--verification">Tests</a>
  </p>

</div>

---

> ### 💡 Core Philosophy
> *"The Operating System observes, the DBMS remembers, Machine Learning detects."*
>
> Isolated events lack context; historical behaviour reveals anomalies. Rather than relying on rigid static signatures or evaluating events in a vacuum, **Chronicle** builds rolling process-specific behavioural baselines ($\mu \pm 3.5\sigma$), quantifies operational drift, and executes sub-millisecond in-process ML inference to unmask sophisticated living-off-the-land attacks, crypto-miners, and rogue daemon child-shells.

---

## ⚡ Key Capabilities

- **🔍 Dual-Engine Telemetry Collection**
  - **Kernel eBPF Probes (BCC):** High-throughput capture of `sys_enter_execve`, `fork`, `exit`, `openat`, `unlinkat`, and IPv4/IPv6 socket connections (`tcp_v4_connect`, `inet_csk_accept`).
  - **Zero-Crash Host Fallback (psutil):** Seamless, unprivileged cross-platform fallback with persistent process handle caching for real-time, non-zero CPU delta measurements.

- **🧠 Dual-Layer Machine Learning**
  - **Supervised XGBoost Classifier:** Pre-trained on 442 Linux syscall traces (ADFA-LD) and 401 behavioral features (PLAID) achieving **>97.6% accuracy** and **100% attack recall**.
  - **Unsupervised Isolation Forest:** Real-time anomaly detection scoring on active syscall sequences without external cloud dependencies.

- **📈 Rolling Statistical Envelopes (Welford's Algorithm)**
  - Online running mean ($\mu$) and variance ($\sigma^2$) tracking per binary identity.
  - Multi-tier Gaussian deviations, warmup burn-in cycles (`count < 3`), noise-clamped envelopes (`< 4% CPU` bounded to `< 1.5σ`), and outlier-resistant baselines.

- **🚨 Explainable, Calibrated Risk Scoring (0–100)**
  - Dynamic baseline activity scoring (`4–35 / 100`) for normal execution combined with multi-signal fusion for anomalies.
  - Transparent MITRE-aligned diagnostic evidence strings (e.g., `RESOURCE_HIJACK`, `COMMAND_AND_CONTROL`, `EXECUTION`) with temporal windowed deduplication (120s).

- **🗄️ Relational DBMS Persistence & Historical Deep-Dive**
  - Dual-engine relational persistence: Zero-configuration embedded **SQLite** with instant migrations, plus optional **PostgreSQL 14+** support for high-throughput enterprise infrastructure.
  - **Process Historical Inspector:** Interactive multi-day modal tracking CPU, RAM, Network KB/s, Syscall frequency, and Risk Score curves with instant CSV report export.

- **🔒 Strict Local Privacy (Air-Gapped by Design)**
  - **0 Bytes external egress:** 100% of telemetry, models, and databases stay strictly on the local machine.
  - Automated regex credential sanitization (`password`, `token`, `secret`, `api_key`).
  - File permissions automatically locked to `0600` (owner read/write only).

- **🕒 Localized Timezone Support**
  - Native support for **Indian Standard Time (IST, UTC+05:30)** across backend collectors, telemetry ingestion, historical query windows, and live UI clocks.

---

## 🏛️ System Architecture

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         Linux / Host OS Kernel                              │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
           eBPF Probes & Tracepoints    │   psutil Process Iteration
           [execve, fork, openat, tcp]  │   [Cached PID Handles, Memory, CPU]
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                Chronicle Telemetry Collector & Normalizer                   │
 │   • 5-second observation window aggregator                                  │
 │   • Dynamic process cluster classifier (systemd, nginx, bash, dockerd)      │
 │   • Zero-sleep CPU delta tracking via self._proc_cache                      │
 │   • Automatic token & credential sanitization                               │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                      Chronicle DBMS Persistence Layer                       │
 │   • SQLite (default) / PostgreSQL 14+ with versioned migrations             │
 │   • Multi-day process history retention & automated pruning                 │
 │   • Online statistical baseline profiling (Welford's algorithm)             │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                     In-Process Machine Learning Engine                      │
 │   • Supervised XGBoost Classifier (ADFA-LD & PLAID syscall sequences)       │
 │   • Unsupervised Isolation Forest anomaly detector (< 0.8ms latency)        │
 │   • Automated ModelRegistry with candidate staging & atomic rollback        │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                  Contextual Risk & Alert Reasoning Engine                   │
 │   • Calibrated 0–100 composite risk scoring with noise suppression          │
 │   • MITRE-aligned category categorization & evidence diagnostics            │
 │   • 120-second temporal alert deduplication window                          │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                     Chronicle Modern Desktop Interface                      │
 │   • Live telemetry feed, health donut gauge, and Z-score deviation charts   │
 │   • Process Inspection & Historical Deep-Dive Modal with CSV export         │
 │   • Interactive Attack Simulator (Webshell, Ransomware, Crypto, PrivEsc)    │
 │   • REST API: http://127.0.0.1:8000/api/ (Status, Events, Alerts, History)  │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🖥️ Interactive Dashboard & Process Inspection

Chronicle features a retro-modern visual control center designed for security operations and systems auditing:

```text
+--------------------------------------------------------------------------------------------------+
|  🐧 CHRONICLE  •  Host Behaviour Analysis System                     [● 100% Air-Gapped] [01:14 IST] |
+--------------------+---------------------+---------------------+---------------------------------+
| CPU UTILIZATION    | HOST RAM FOOTPRINT  | KERNEL SYSCALLS     | HOST NORMALCY                   |
| 14.8%              | 6.4 GB / 8.0 GB     | 7,861 calls/s       | 99% (0 Active Alerts)           |
| 495 Active Procs   | Swap: 0% • Buffer   | eBPF Probes: OK     | In-Process Isolation Forest     |
+--------------------+---------------------+---------------------+---------------------------------+
| PROCESS CLUSTERS:  [🐧 systemd: 87]  [🌐 nginx: 52]  [💻 bash: 316]  [🐳 dockerd: 39]             |
+--------------------------------------------------------------------------------------------------+
| LIVE TELEMETRY STREAM & BEHAVIOURAL PROFILES                                                    |
| Comm             PID    User    Type        CPU     Memory   Syscalls  Status        Actions     |
| Google Chrome    34877  Anurag  sys_sample  1.2%    124 MB   79        SAFE • 6      [Inspect] [Hist] |
| Spotify          45554  Anurag  sys_sample  2.3%    56 MB    86        SAFE • 9      [Inspect] [Hist] |
| Electron         39380  Anurag  sys_sample  3.1%    111 MB   92        SAFE • 13     [Inspect] [Hist] |
| nginx (sim)      3812   www-data execve     18.4%   48 MB    1,420     ANOMALOUS • 75 [Kill] [Alert] |
+--------------------------------------------------------------------------------------------------+
```

### 🔍 Historical Process Inspection Modal
Clicking **History** on any process opens the historical telemetry viewer:
- **Interactive Multi-Day Graph:** Toggle between **CPU (%)**, **Memory (MB)**, **Network (KB/s)**, **Syscall Rate**, and **Anomaly Risk Score**.
- **Historical Point Table:** Shows past execution checkpoints, Z-score variance, and status tags.
- **One-Click CSV Export:** Downloads raw historical telemetry data formatted for security audits.

---

## 🚀 Quickstart

### 1. Prerequisites & Installation

Clone the repository and install dependencies in a virtual environment:

```bash
git clone https://github.com/Team-ADAPT/Chronicle.git
cd Chronicle

# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package dependencies
pip install -r requirements.txt
pip install -e .
```

### 2. Launching Chronicle

Start the desktop application:

```bash
# Option A: Standalone browser dashboard (default on port 8000)
python3 app.py

# Option B: Run on a custom port without auto-launching browser
python3 app.py --port 8080 --no-browser

# Option C: Native desktop window mode (pywebview)
python3 app.py --window
```

Visit **[http://127.0.0.1:8000](http://127.0.0.1:8000)** to view the live dashboard.

---

## 🧪 Interactive Security Simulations

Chronicle includes a built-in attack injection framework to verify machine learning detection and alerting in real time:

| Scenario Alias | Behavioral Signature | Detection Technique | Typical Risk |
| :--- | :--- | :--- | :---: |
| **`webshell`** | `nginx` spawning interactive `/bin/sh` or `/bin/bash` | Heuristic + XGBoost Syscall Sequence | **75 / 100** |
| **`crypto`** | Prolonged high-CPU compute burst with thread affinity | Statistical Z-Score ($\Delta > 4.5\sigma$) | **88 / 100** |
| **`ransomware`** | Rapid recursive directory traversals & `unlinkat` spikes | High-frequency IOPS deviation | **92 / 100** |
| **`reverseshell`** | Outbound reverse TCP connection socket from worker | Kernel tracepoint `tcp_v4_connect` | **85 / 100** |
| **`privesc`** | Unprivileged process escalating to `UID 0` (`setuid`) | Heuristic Privilege Escalation rule | **95 / 100** |

Trigger attacks via the dashboard simulation panel or directly via the REST API:

```bash
# Inject a webshell anomaly
curl -X POST http://127.0.0.1:8000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"scenario": "webshell"}'
```

---

## 🧠 Threat Detection & ML Benchmarks

Chronicle pairs statistical anomaly models with supervised classifiers trained on standardized academic benchmarks:

| Benchmark Dataset | Architecture | Accuracy | Attack Recall | Inference Latency | Features |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **ADFA-LD** | Supervised XGBoost | **97.65%** | **93.29%** | **< 0.8 ms** | 442 Linux Syscall Traces |
| **PLAID** | Supervised XGBoost | **99.60%** | **100.00%** | **< 0.6 ms** | 401 Process Features |
| **Online Baseline** | Isolation Forest | **91.20%** | **88.40%** | **< 0.5 ms** | Real-time sequence vectors |

### Automated Model Retraining Pipeline

Chronicle includes a safe, automated retraining workflow with schema verification, acceptance gates, and atomic rollback:

```bash
# 1. Validate dataset format and schema consistency
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --data path/to/dataset.csv --validate-only

# 2. Train candidate model and evaluate metrics
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --data path/to/dataset.csv

# 3. Train and atomically promote model upon passing acceptance gates
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --data path/to/dataset.csv --promote

# 4. Instant rollback to previous archived model if regression is detected
python3 ML/src/retrain_pipeline.py --dataset adfa --model-type xgboost --rollback
```

---

## 🗄️ Database CLI

Chronicle provides a database management utility supporting both SQLite and PostgreSQL:

```bash
# Inspect database engine, health, table statistics, and migration status
./scripts/db_manage.sh status

# Run versioned relational migrations
./scripts/db_manage.sh migrate

# Recompute 30-day behavioural baselines from telemetry logs
./scripts/db_manage.sh profile --min-obs 5

# Prune stale telemetry records based on retention policy
./scripts/db_manage.sh retention --dry-run
```

---

## 🔌 REST API Reference

The local HTTP daemon (`http://127.0.0.1:8000/api`) provides real-time JSON endpoints:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | System health, eBPF probe status, total events, and anomaly counts |
| `GET` | `/api/stats` | Live CPU %, memory breakdown, thread counts, and cluster distributions |
| `GET` | `/api/events?limit=80` | Ring-buffer telemetry event stream with Z-scores and risk ratings |
| `GET` | `/api/alerts?limit=40` | Active and triaged security alerts with explainable reasoning |
| `GET` | `/api/history?comm=name&days=7` | Multi-day historical telemetry timeline for a specific binary |
| `POST` | `/api/simulate` | Injects synthetic behavioral scenarios (`webshell`, `crypto`, etc.) |
| `POST` | `/api/kill` | Sends `SIGKILL` to terminate an active process by PID |

---

## 🧪 Testing & Verification

Chronicle maintains a comprehensive test suite covering the entire pipeline:

```bash
# Run all unit, integration, and risk-scoring tests
pytest tests/ -v
```

```text
============================== test session starts ==============================
collected 92 items

tests/test_chronicle_pipeline.py .........                               [  9%]
tests/test_db_storage.py ..........                                      [ 20%]
tests/test_risk_scoring_alerts.py ...................................... [ 61%]
...................................                                      [100%]

============================== 92 passed in 3.61s ==============================
```

---

## 📦 Debian (.deb) Packaging

Package Chronicle for native distribution on Ubuntu, Debian, or Linux Mint:

```bash
# Build the standalone Debian package
bash packaging/build_deb.sh

# Install the generated .deb package
sudo dpkg -i packaging/output/chronicle_0.2.0-1_amd64.deb

# Launch Chronicle from your system applications menu or terminal
chronicle
```

---

## 🔒 Privacy & Security Guarantees

1. **100% Local & Air-Gapped:** Zero telemetry leaves the host machine. No third-party analytical SDKs, remote trackers, or cloud dependencies.
2. **Credential Redaction:** Automatic inline scrubbing of command lines and environment variables for patterns matching passwords, API tokens, and secret keys.
3. **Restricted File Permissions:** All local database files and profile caches are explicitly chmod-hardened to `0600` (read/write by owner only).
4. **Loopback Binding:** The internal API server binds exclusively to `127.0.0.1`, ignoring external network interfaces.

---

## 📁 Repository Structure

```text
Chronicle/
├── app.py                      # Main application launcher (native WebKit / browser)
├── pyproject.toml              # PEP 517/518 build specification & tool configs
├── requirements.txt            # Python dependencies
├── src/chronicle/              # Core application package
│   ├── api.py                  # Local REST API dispatcher
│   ├── collector.py            # eBPF kernel observer & psutil telemetry collector
│   ├── config.py               # Runtime configuration & feature flags
│   ├── ml_detector.py          # In-process Scikit-learn & XGBoost detector
│   ├── pipeline.py             # Telemetry & detection pipeline orchestrator
│   ├── risk_engine.py          # Contextual 0-100 risk scoring & explainable alerts
│   ├── storage.py              # SQLite DBMS storage & Welford profiler
│   └── db/                     # Relational persistence subsystem (PostgreSQL/SQLite)
├── ebpf/                       # Linux kernel tracepoints & standalone collectors
├── ML/                         # Retraining pipeline, model registry & benchmarks
├── ui/                         # Modern desktop interface (HTML5, CSS3, ES6)
├── packaging/                  # Debian (.deb) package scripts and desktop launchers
├── scripts/                    # Automation utilities (db_manage, run_tests, run_dev)
├── tests/                      # 92 unit and integration tests
└── docs/                       # Architectural specifications & academic ledger
```

---

## 📜 License & Credits

Chronicle is licensed under the **[MIT License](LICENSE)**.

Developed as a Project-Based Learning (PBL) initiative by **Team ADAPT**:
- **Department of Computer Science & Engineering**
- **Graphic Era (Deemed to be University), Dehradun**
- **Academic Session 2026–27**
