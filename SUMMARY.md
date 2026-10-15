# Chronicle Project Summary

## Overview
Chronicle is an Intelligent Host Behaviour Analysis and Activity Monitoring system that combines local Linux telemetry, historical process baselines, and machine-learning models to identify unusual or potentially malicious behaviour. It records process lifecycle activity, file and network events, resource usage, and syscall patterns, then compares current activity with historical baselines.

## Key Components

### 1. Runtime Dashboard (`app.py` and `ui/`)
- Local web and native-window entry point
- Interactive dashboard with live activity, anomaly scenarios, process inspection, filters, and theme selection
- Built with Python, HTML/CSS/JS, and pywebview for native window mode
- Contributors:
  - the-wilful-youth: UI layout improvements and graph illumination in light mode
  - Anurag: Initial setup and merges

### 2. Linux eBPF Telemetry Collector (`eBPF_collector.py`)
- Captures process execution, file activity, network connections, syscall counts, and I/O statistics
- Uses BCC (BPF Compiler Collection) for eBPF probe attachment
- Features privacy-conscious collection with optional hashed file paths
- Supports various collection scenarios with configurable windows, labels, and tracing options
- Contributors:
  - prajjwalsingh8705: Initial creation of eBPF_collector.py

### 3. Machine Learning Pipeline (`ML/` directory)
#### Data Processing
- Dataset loaders for ADFA-LD and PLAID datasets
- Feature extraction and preprocessing modules
- Contributors:
  - Divyanshi Singh: Major ML pipeline development

#### Model Training
- Supervised detection using XGBoost
- Unsupervised detection using Isolation Forest
- Separate training scripts for each dataset
- Contributors:
  - Divyanshi Singh: XGBoost and Isolation Forest training implementations

#### Evaluation
- Cross-dataset evaluation scripts
- Classification reports, confusion matrices, and feature importance analysis
- Contributors:
  - Divyanshi Singh: ML evaluation metrics and visualizations

### 4. Packaging (`packaging/` directory)
- Debian package build assets
- Standalone binary distribution with desktop integration
- Contributors:
  - Anurag: Packaging setup and maintenance

## Development History

### Recent Activity (October 2026)
- **Oct 9, 2026**: Tanishk Gupta - Refactored documentation (README update for clarity and structure)
- **Oct 8, 2026**: 
  - Divyanshi Singh: Added ML evaluation metrics, result visualizations, and classification reports
  - Divyanshi Singh: Merged ML pipeline fixes (PR #4)
  - Anurag: Merged ML pipeline fixes (PR #3)
- **Oct 8, 2026**: Divyanshi Singh - Added ML pipeline and trained models
- **Oct 5, 2026**: prajjwalsingh8705 - Created eBPF_collector.py
- **Sep 8, 2026**: Anurag - Merged UI improvements (PR #2)
- **Sep 7, 2026**: the-wilful-youth - UI layout de-congestion and graph illumination in light mode

### Core Features Implemented
1. **Linux eBPF telemetry collection** for process execution, file activity, network connections, syscall counts, and I/O statistics
2. **Behaviour-window aggregation** with process, system, and event-level metrics
3. **Privacy-conscious collection** using local processing and optional hashed file paths
4. **Historical baselines** for process families and workload profiles
5. **Interactive dashboard** with live activity, anomaly scenarios, process inspection, filters, and theme selection
6. **Supervised detection** using XGBoost for ADFA-LD and PLAID datasets
7. **Unsupervised detection** using Isolation Forest as a complementary detector
8. **Cross-dataset evaluation** for measuring feature and model transfer limitations
9. **Debian package scaffolding** for distributing the local application

### Current Evaluation Results
| Dataset | Primary Model | Attack Recall | Accuracy | Notes |
|---------|---------------|---------------|----------|-------|
| ADFA-LD | XGBoost | 93.29% | 97.65% | 442 features; supervised detector is primary |
| PLAID | XGBoost | 100.00% | 99.60% | 401 features; 0 false negatives in test set |

## Project Structure
```
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
├── README.md                 # Project documentation
├── PROJECT.md                # Detailed project proposal and documentation
└── SUMMARY.md                # This file
```

## Roadmap Progress

### Completed
- **Runtime Desktop & Native-Window:** `pywebview` lightweight WebKit dashboard with Overview, Process, Baseline, and Alert views (`app.py`, `ui/`).
- **Linux eBPF Telemetry Collection:** Kernel kprobes and tracepoints via BCC C code with zero-crash `psutil` fallback (`eBPF_collector.py`, `src/chronicle/collector.py`).
- **Dual-Engine Relational Storage:** PostgreSQL and SQLite repository with ACID transactions, automated migrations, and schema versioning (`chronicle/db/`).
- **Data Retention & Privacy Layer:** Automatic sensitive credential scrubbing (`password`, `token`, `secret`, `api_key`) and configurable retention pruning (`chronicle/db/privacy.py`, `retention.py`).
- **Robust Historical Behaviour Profiling:** Program-level statistical baselines (Median, NMAD, IQR) separate from individual process instances with maturity handling (`COLD_START`, `LEARNING`, `MATURE`) and anti-poisoning filters (`chronicle/db/profiling.py`).
- **In-Process Machine Learning:** Embedded XGBoost and Isolation Forest inference engines evaluated on ADFA-LD and PLAID benchmarks (`ML/`, `src/chronicle/ml_detector.py`).
- **Risk Scoring & Explainability:** Multi-category 0–100 risk scoring with granular evidence reasons (`src/chronicle/risk_engine.py`).
- **Full Pipeline Integration:** End-to-end integration linking Observer ➔ DBMS ➔ ML ➔ Risk ➔ API ➔ Dashboard (`src/chronicle/pipeline.py`).
- **Comprehensive Testing:** End-to-end integration and database unit test suites passing 17/17 (`tests/`).
- **Debian Distribution Packaging:** Standalone `.deb` package builder with `.desktop` menu launcher (`packaging/build_deb.sh`).
- **Project Structure Alignment:** Phase 1 repository structure fully aligned with `Project.md` (`docs/`, `database/`, `ebpf/`, `research/`, `tests/`, `scripts/`, `LICENSE`).

### Ongoing & Planned
- Long-duration host evaluation benchmarking Model A (current behavior only) vs Model B (current + historical behavior).
- Evaluation of detection overhead and database query latency on high-frequency server workloads.
- Automated baseline re-calibration for legitimate software upgrades.

## Contributing Guidelines
The project follows Conventional Commits format:
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code restructuring
- `perf`: Performance improvement
- `test`: Tests
- `docs`: Documentation
- `build`: Build/dependencies/packaging
- `ci`: CI/CD changes
- `security`: Security-related changes
- `model`: ML model changes
- `research`: Research/experiments
- `chore`: General maintenance

## License
Chronicle is licensed under the MIT License. See [LICENSE](file:///Users/tanishkgupta/Projects/Chronicle/LICENSE) for details.

---
*Summary updated on 2026-10-15*