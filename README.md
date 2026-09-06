# Chronicle

### An Intelligent Historical Behaviour Analysis System

Chronicle is a **Linux-based host behavioural analysis system** designed to improve threat detection by incorporating the historical behaviour of processes into security analysis.

Traditional security monitoring often evaluates individual events or short time windows. Chronicle instead maintains structured behavioural histories for processes and compares their current activity with previously observed patterns to identify significant deviations.

> **Understand behaviour. Learn from history. Detect anomalies.**

---

## Overview

Chronicle collects relevant host-level telemetry and stores it in a structured local database. Historical behavioural information is then used to establish process-specific behavioural profiles and identify unusual activity.

The planned system will include:

* Linux host telemetry collection using **eBPF**
* Structured behavioural data storage using **PostgreSQL**
* Process-specific historical behavioural profiles
* Statistical and machine-learning-based anomaly detection
* Contextual risk scoring and explainable alerts
* A user-facing monitoring dashboard
* Local-first data processing and storage

---

## Project Architecture

The planned high-level pipeline is:

```text
Linux Host
    │
    ▼
eBPF Telemetry
    │
    ▼
Data Collection & Normalization
    │
    ▼
Privacy Filtering
    │
    ▼
PostgreSQL
    │
    ▼
Historical Behaviour Profiles
    │
    ▼
Feature Extraction
    │
    ▼
Anomaly Detection
    │
    ▼
Risk Score & Explanation
    │
    ▼
Chronicle Dashboard
```

---

## Technology Stack

**Linux, eBPF, Python, PostgreSQL/SQLite, SQL, Pandas, NumPy, Scikit-learn, pywebview, JavaScript, HTML5/CSS3, systemd, Debian .deb, Git, GitHub**

---

## Privacy

Chronicle follows a **local-first approach**. Behavioural telemetry is intended to remain on the monitored Linux system and be processed locally wherever possible.

The system is designed to focus on behavioural metadata rather than unnecessarily collecting user-content data.

---

## Development

Clone the repository:

```bash
git clone <repository-url>
cd Chronicle
```

Development instructions will be expanded as implementation begins.

---

## Contributing

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before contributing to the project.

Chronicle follows a Conventional Commits-style convention:

```text
feat(ebpf): add process monitoring
fix(database): prevent duplicate events
docs(readme): update installation guide
```

---

## License

This project is currently under development. Licensing details will be finalized before the public release.

---

## Project Team

**Team ADAPT**

Chronicle is being developed as a Project Based Learning (PBL) project.
