# Chronicle — Project Summary & Audit Ledger

## Executive Overview
**Chronicle** is an Intelligent Host Behaviour Analysis and Activity Monitoring system that unifies local Linux telemetry, historical process baselines, and in-process machine learning to detect anomalous and malicious execution patterns.

> **Foundational Axiom:** *"The Operating System observes, the DBMS remembers, Machine Learning detects."*

Traditional host intrusion detection evaluates isolated system calls or brief observation windows, causing either high false alarms on legitimate workload spikes or blindspots during slow, stealthy attacks. Chronicle addresses this limitation by continuously tracking process lifecycles, maintaining structured historical behavioral profiles in a local DBMS, and detecting significant deviations using statistical profiling and machine-learning anomaly detection.

---

## Key Subsystems & Architecture

### 1. Runtime Desktop Interface (`app.py` & `ui/`)
- **Native Desktop Application:** Standalone desktop app powered by `pywebview` (WebKit engine) with zero external server dependencies.
- **Embedded Web Server:** Threaded local HTTP server binding strictly to `127.0.0.1:8000` for zero-leak privacy.
- **Interactive Triage UI:** Responsive dashboard featuring:
  - **Overview Stream:** Real-time KPI telemetry cards, live process throughput, and anomaly indicators.
  - **Process Inspection:** Detailed process drawer showing memory, CPU, PID lineage, and syscall rates.
  - **Historical Baselines:** Visual 30-day baseline comparisons against running averages.
  - **Alert Management:** Explainable alert cards with severity grading, root-cause evidence, and one-click mitigation.
- **Contributors:**
  - the-wilful-youth: UI layout enhancements and light/dark theme graph illumination
  - Anurag: Core launcher integration, threading, and packaging

### 2. Linux Kernel Telemetry Observer (`ebpf/collector.py` & `src/chronicle/collector.py`)
- **Kernel Probes (eBPF / BCC):** Attaches in-kernel tracepoints and kprobes with zero user-to-kernel context-switching penalties:
  - Process lifecycle: `sys_enter_execve`, `sys_enter_clone`, `sched_process_exit`
  - System call auditing: lossless in-kernel counting per (PID, syscall)
  - File I/O: `openat`, `unlinkat`, `renameat`, byte read/write accounting
  - Network sockets: `sys_enter_connect`, `sys_enter_accept4`, TCP/UDP bandwidth
- **Resilient Fallback:** Automatically switches to user-space `psutil` sampling when running in unprivileged containers or non-Linux development environments.
- **Privacy Sanitization:** Salting and SHA-256 hashing of sensitive file paths; redaction of credentials (`token`, `password`, `secret`).
- **Contributors:**
  - prajjwalsingh8705: eBPF C probes and BCC telemetry collector

### 3. Dual-Engine Relational DBMS Storage (`src/chronicle/db/` & `database/`)
- **DBMS Principles Applied:** ACID transactions, relational normalization, B-Tree indexing, surrogate keys (UUIDs immune to Linux PID recycling).
- **Dual-Engine Architecture:**
  - **SQLite (Default):** Zero-configuration embedded database (`data/chronicle.db`) for lightweight single-user desktop monitoring.
  - **PostgreSQL 14+ (Enterprise):** High-throughput concurrent connection pooling via `psycopg` (v3).
- **Automated Versioned Migrations:** Sequential migration runner applying `001_initial_schema.sql`, `002_profiles_and_detections.sql`, and `003_advanced_profiling.sql`.
- **Automated Retention Manager:** Configurable time-based and count-based retention pruning routines to prevent disk exhaustion.
- **Hardened Security:** File permissions automatically enforced to `0600` (owner-only read/write) and storage directories to `0700`.

### 4. Robust Behavioural Baselining (`src/chronicle/db/profiling.py` & `storage.py`)
- **Statistical Baselines:** Program-level profiles computing running mean, variance, and standard deviation via Welford's numerically stable algorithm.
- **Anti-Poisoning Metrics:** Normalized Median Absolute Deviation (NMAD) and Interquartile Range (IQR) preventing gradual baseline corruption by stealthy attackers.
- **Maturity Lifecycle:** Tracks profile progression across `COLD_START` (< 5 executions), `LEARNING` (5–20 executions), and `MATURE` (> 20 executions).

### 5. In-Process Machine Learning & Retraining (`ML/` & `src/chronicle/ml_detector.py`)
- **Supervised Detection (XGBoost):** Evaluated on ADFA-LD (442 features) and PLAID (401 features) benchmarks with **99.60% test accuracy** and **100% attack recall** on PLAID.
- **Unsupervised Detection (Isolation Forest):** Zero-label anomaly scoring baseline evaluating unusual system call distributions.
- **Automated Retraining Pipeline (`retrain_pipeline.py` & `model_registry.py`):**
  - Strict input dataset validation and split leakage checks
  - Candidate model evaluation against approved baseline metrics
  - Configurable acceptance thresholds
  - ModelRegistry candidate staging with schema fingerprinting and SHA-256 artifact hashing
  - Atomic promotion and instant rollback to previous models

### 6. Contextual Risk Scoring & Explainability (`src/chronicle/risk_engine.py`)
- **Multi-Signal Evaluation:** Fuses heuristic attack patterns (e.g., interactive shell spawned from web daemon), statistical deviations (Z-scores), and ML model probabilities into a calibrated 0–100 risk score.
- **Explainability:** Emits natural-language diagnostic reasons backed by numerical evidence.
- **Temporal Deduplication:** Windowed (120s) deduplication preventing duplicate alert fatigue for repeating anomalies.

### 7. Packaging & Distribution (`packaging/`)
- **Debian (`.deb`) Packaging:** Automated build script producing `chronicle_0.2.0-1_amd64.deb` installing into `/opt/chronicle` with launcher in `/usr/local/bin/chronicle`.
- **Desktop Entry:** Registered FreeDesktop launcher (`chronicle.desktop`) with high-resolution application icon (`chronicle.png`).

---

## Machine Learning Benchmark Summary

| Benchmark Dataset | Nature of Data | Feature Count | Primary Model | Attack Recall | Test Accuracy | Status |
| :--- | :--- | :---: | :--- | :---: | :---: | :---: |
| **ADFA-LD** | Linux Syscall Traces | 442 | Supervised XGBoost | 93.29% | 97.65% | Validated |
| **PLAID** | Process-Level Telemetry | 401 | Supervised XGBoost | **100.00%** | **99.60%** | Validated |
| **Unsupervised** | ADFA / PLAID Syscalls | 401 / 442 | Isolation Forest | 88.40% | 91.20% | Complementary |

---

## Complete Git Commit & Development History

| Commit / PR | Type & Scope | Summary of Deliverables |
| :--- | :--- | :--- |
| **Initial Commits** | `feat(init)` | Repository setup, initial UI prototyping, and basic process monitoring. |
| **PR #2** | `feat(ui)` | UI layout refinement, graph illumination in light mode, and dark mode palette. |
| **`f7fa899`** | `feat(ebpf)` | Live kernel probe streaming via BCC, removed mock demo data from live feed. |
| **PR #6 & #7** | `feat(db)` | PostgreSQL + SQLite dual-engine storage, automated migrations, retention, baselining, packaging, and specs. |
| **PR #8** | `feat(ml)` | Automated model retraining pipeline, dataset validation, candidate gates, and evaluation suites. |
| **PR #9** | `feat(risk)` | Contextual risk engine (0–100), explainable diagnostic reasons, and 120s temporal alert deduplication. |
| **Latest** | `refactor(pkg)` | Unified package to `src/chronicle/db/`, created `model_registry.py`, added `pyproject.toml` & `.editorconfig`, purged root junk files, and modernized documentation. |

---

## Test Verification & Quality Status

- **Core Pipeline & Storage Test Suite (`./scripts/run_tests.sh`)**:
  - `tests/test_chronicle_pipeline.py`: Pipeline orchestration, online metrics, and API integration.
  - `tests/test_db_storage.py`: Dual-engine database CRUD, migrations, retention, and 0600 file permissions.
  - `tests/test_risk_scoring_alerts.py`: Contextual risk scoring, deduplication, and explainable alerting.
  - **Result: 90/90 tests passed in 3.08 seconds.**
- **Model Retraining & Validation Suite (`pytest ML/tests/test_retrain_pipeline.py`)**:
  - Validates candidate training, schema preservation, candidate staging, atomic promotion, and rollback.
  - **Result: 20/20 tests passed in 4.31 seconds.**
- **Total Test Suite:** **110/110 tests passing (100% pass rate).**

---

## Academic & Course Alignment

- **Project Title:** Chronicle — An Intelligent Historical Behaviour Analysis System
- **Team ID:** OSDBMS-V-2026-T-005
- **Department:** Computer Science & Engineering
- **Institution:** Graphic Era (Deemed to be University), Dehradun
- **Academic Session:** 2026–27
- **License:** MIT Open Source License