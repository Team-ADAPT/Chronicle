**CHRONICLE**

_An Intelligent Historical Behaviour Analysis System_

**Understand behaviour. Learn from history. Detect anomalies.**

**PBL Project Documentation  
**Team ID: OSDBMS-V-2026-T-005  
Department of Computer Science & Engineering  
Graphic Era (Deemed to be University), Dehradun  
Academic Session 2026–27

# 1\. Project Overview

Chronicle is a Linux-based host behavioural analysis and threat-detection system. The system focuses on historical process behaviour rather than relying only on individual events or short observation windows. Chronicle collects relevant host telemetry, stores it locally, builds process-specific behavioural profiles, and compares current activity with historical patterns. Significant deviations are analyzed using statistical and machine-learning techniques and can result in contextual risk scores and explainable alerts.

# 2\. Problem Statement

Conventional host monitoring can observe system calls, process activity, file access and network events, but individual events do not always provide enough context to determine whether behaviour is unusual. A process may perform a legitimate action that looks suspicious in isolation, while a sequence of individually normal actions may become suspicious when considered against the process's long-term behaviour. Chronicle addresses this limitation by maintaining structured historical behavioural context and using it as part of anomaly analysis.

# 3\. Core Idea

```
Current Process Behaviour
        ↓
Historical Process Profile
        ↓
Behavioural Comparison
        ↓
Significant Deviation
        ↓
Statistical / ML Anomaly Detection
        ↓
Risk Score + Explanation
        ↓
User Alert
```

# 4\. Main Research Question

Does incorporating persistent historical behavioural context improve process-level suspicious behaviour detection compared with using only current behavioural information?

# 5\. Objectives

- Collect relevant Linux host telemetry using eBPF.
- Monitor process, system-call, file and network-related behaviour.
- Normalize and store structured telemetry locally.
- Build historical, process-specific behavioural profiles.
- Extract behavioural features from current and historical activity.
- Detect significant behavioural deviations using statistical and machine-learning methods.
- Generate contextual risk scores and explainable alerts.
- Provide a user-facing dashboard for monitoring and investigation.
- Evaluate detection effectiveness, false positives and system overhead.

# 6\. Scope

Platform: Linux only.

Primary focus: host-based, process-level behavioural anomaly detection.

- Process creation and termination
- System-call activity
- File interactions
- Network-related activity
- Process relationships
- Historical behavioural profiling
- Anomaly detection and contextual alerting
- Local storage and local dashboard

# 7\. High-Level Architecture

```
                    CHRONICLE

                     Linux Host
                         │
                         ▼
                  eBPF / C Telemetry
                         │
                         ▼
              Collection & Normalization
                         │
                         ▼
                  Privacy Filtering
                         │
                         ▼
               PostgreSQL / Local DB
                         │
                         ▼
               Historical Behaviour Profiles
                         │
                         ▼
                  Feature Extraction
                         │
                         ▼
          Embedded Statistical / ML Models
                         │
                         ▼
                Risk Scoring & Explanation
                         │
                         ▼
        Chronicle Desktop App (.deb package)
         (Lightweight WebKit Native Window)
```

# 8\. System Components

| Component                  | Purpose                                                                               |
| -------------------------- | ------------------------------------------------------------------------------------- |
| eBPF Telemetry Layer       | Captures relevant kernel-level process and system activity.                           |
| Collector & Normalizer     | Receives events, converts them into structured records and prepares them for storage. |
| Privacy Layer              | Filters unnecessary sensitive information and supports the local-first design.        |
| Local Repository / DB      | Stores structured historical telemetry and behavioural information locally.           |
| Behaviour Profiling Engine | Builds process-specific baselines from previously observed activity.                  |
| Feature Extraction         | Converts raw events into measurable behavioural features.                             |
| In-Process ML Detection    | Runs embedded Scikit-learn/statistical models directly in Python for anomaly detection.|
| Risk & Alert Engine        | Combines anomaly evidence into contextual risk scores and explainable security alerts.|
| Desktop Application UI     | Embedded lightweight native window (`pywebview` / HTML / CSS / JS) for monitoring.    |
| Debian Packaging (.deb)    | Compiled standalone binary with desktop menu launcher (`.desktop`), protecting internals.|

# 9\. Telemetry to be Monitored

## 9.1 Process Behaviour

- Process creation
- Process termination
- Parent-child relationships
- Process activity

## 9.2 System Calls

Potential examples include open(), read(), write(), execve(), fork(), clone(), and connect(). The exact event set will be finalized during implementation.

## 9.3 File Activity

- File opened
- File read
- File written
- File created
- File deleted

## 9.4 Network Activity

- Network connections
- Connection frequency
- Network-related system calls
- Relevant destination information

# 10\. Historical Behaviour Profiling

Chronicle will gradually learn what normal behaviour looks like for individual processes. Profiles can contain typical system-call distributions, file activity, network activity, process creation patterns and other measurable behavioural features. New observations are compared with these historical patterns to determine whether a deviation is significant.

```
Example profile:
Process: Chrome

Typical:
- Average file accesses/hour
- Average network connections/hour
- Common system calls
- Typical child-process patterns
- Historical activity distribution

New observation:
- File activity significantly above baseline
- Unusual network activity
- New child-process pattern

Result:
- Behavioural deviation → anomaly analysis
```

# 11\. Machine Learning and Statistical Analysis

The project will explore suitable statistical and machine-learning approaches rather than fixing a single algorithm prematurely. Candidate feature families include system-call frequency and sequences, file-access frequency, network-connection frequency, process creation frequency, child-process patterns and deviations from historical distributions.

Primary ML library: Scikit-learn.

# 12\. Risk Scoring and Explainability

Chronicle is intended to provide more than a binary safe/malicious label. Alerts should include a contextual risk score and the evidence responsible for the score.

```
Risk Score: 87/100

Reasons:
• Network activity 4.2× historical average
• Unusual child process created
• New system-call pattern observed
• File access significantly above baseline
```

# 13\. Desktop Application & Monitoring Dashboard

- **Delivery Format**: Self-contained native Linux desktop application packaged as a `.deb` installer.
- **Desktop Integration**: Registers in the Linux system application launcher (`/usr/share/applications/chronicle.desktop`) with application icon for easy one-click access.
- **Internal Protection (Black-box)**: The tracking routines, feature extraction, and ML models are compiled into a standalone binary (ELF binary executable via PyInstaller), ensuring end users cannot view, modify, or tamper with the internal logic, scripts, or model weights.
- **Background Activity Tracking**: Quietly monitors what processes and users are doing on the host in real time, logging process interactions, system calls, resource usage, and network flows.
- **Overview View**: Monitored processes, active anomalies, high-risk processes, and recent alerts.
- **Process View**: Process identity, PID, risk score, status, and behavioural deviation.
- **Historical Baseline View**: System-call, network, file, and process activity compared against historical baselines over time.
- **Alert Investigation**: Anomaly reason, historical comparison, supporting events, and ML-computed risk score.

# 14\. Privacy and Data Handling

Chronicle follows a strict local-first design. All detailed behavioural telemetry is collected, stored, and processed exclusively on the monitored Linux machine. Under no circumstances is raw behavioural data transmitted to external services. The system implements technical controls to ensure data never leaves the user's machine, including:
- Local PostgreSQL database storage on the host machine
- All processing (eBPF collection, feature extraction, anomaly detection) occurs locally
- API endpoints bind only to local interfaces by default
- No external telemetry, analytics, or reporting features are included
- Data retention policies apply only to local storage

# 15\. OS Concepts Applied

- Processes
- Process creation and termination
- Process states
- Linux system calls
- Process scheduling
- Inter-process communication
- File management
- Network operations
- Kernel interaction
- eBPF
- Process monitoring
- System services

Primary project module: Telemetry Collection.

# 16\. DBMS Concepts Applied

- Relational model
- SQL
- Relational tables
- Primary and foreign keys
- Normalization
- Indexing
- Query optimization
- Transactions
- Data aggregation
- Filtering
- Historical data storage
- Database querying and retrieval

Primary project module: Behaviour History.

# 17\. Technology Stack

| Component                  | Technology                                                     |
| -------------------------- | -------------------------------------------------------------- |
| Main host application      | Python                                                         |
| Kernel monitoring          | eBPF / C                                                       |
| eBPF framework             | BCC                                                            |
| Database                   | PostgreSQL / SQLite local storage                              |
| Data processing            | Pandas / NumPy                                                 |
| Machine learning           | Scikit-learn (Embedded in-process models)                      |
| Desktop Window Engine      | `pywebview` (Lightweight native WebKit window, ~25-35MB footprint)|
| Frontend UI                | JavaScript / HTML5 / Modern CSS                                |
| Platform                   | Linux (Debian / Ubuntu / derivates)                            |
| Service management         | systemd                                                        |
| Version control            | Git / GitHub                                                   |
| Packaging & Distribution   | Debian `.deb` package (`dpkg -i`) with compiled binary launcher|

# 18\. Methodology

| Stage    | Activity                                                          |
| -------- | ----------------------------------------------------------------- |
| Collect  | Capture host telemetry using eBPF.                                |
| Store    | Store structured telemetry in PostgreSQL.                         |
| Profile  | Build historical process profiles.                                |
| Analyze  | Extract behavioural features.                                     |
| Detect   | Identify anomalous behaviour using statistical and ML techniques. |
| Alert    | Generate contextual risk scores and explanations.                 |
| Evaluate | Measure detection performance and system overhead.                |

# 19\. State of the Art / Research Background

Chronicle builds on several established research areas: system-call-based host intrusion detection, process behaviour modelling, provenance-based intrusion detection, eBPF-based security monitoring, machine-learning anomaly detection, historical behavioural baselines and explainable security analytics.

- Foundational system-call behaviour modelling, including work associated with Forrest et al.
- STIDE and related sequence-based anomaly detection.
- HMM, LSTM/GRU and system-call argument analysis.
- Provenance-based systems that model causal relationships between processes, files and network entities.
- Systems and research directions including HOLMES, SLEUTH, SAQL, UNICORN, NoDoze, MORSE, ORTHRUS, ProvDetector, RAPID, APTSHIELD, MAGIC and FLASH.
- Graph-based and graph-neural-network approaches to security analytics.

# 20\. Research Gap / Motivation

The project does not claim that historical behaviour or provenance analysis is entirely new. Its research direction is to investigate a practical combination of persistent, process-specific historical behaviour, structured relational storage, efficient historical querying, behavioural feature extraction, anomaly detection, contextual risk scoring and explainable alerts. The central evaluation question is whether persistent historical context improves process-level detection while remaining practical in storage, query and runtime overhead.

# 21\. Evaluation Plan

- Detection accuracy
- Precision
- Recall
- F1-score
- False-positive rate
- CPU overhead
- Memory usage
- eBPF telemetry overhead
- Database query latency
- Detection response latency
- Database scalability with increasing event volume
- Effectiveness of historical context compared with current behaviour alone

A key experimental comparison is:

```
Model A: Current behavioural information only
                    VS
Model B: Current + historical behavioural information
```

# 22\. Assumptions

The proposed Chronicle system assumes that the target environment is a Linux-based operating system with adequate eBPF support and the privileges required for system-level monitoring. It assumes that relevant process-level activities can be collected reliably with acceptable overhead and that sufficient benign historical activity is available to establish behavioural profiles. It assumes that normal process behaviour is sufficiently consistent for historical patterns to provide a useful baseline, while legitimate software updates and behavioural changes may introduce concept drift. It also assumes that telemetry can be processed and stored locally within the DBMS and that PostgreSQL can efficiently index and query the historical information at prototype scale. Chronicle focuses on behavioural anomaly detection and contextual analysis; it does not guarantee detection of every malicious activity or eliminate false positives completely.

# 23\. Project Outcome / Deliverables

- Functional Chronicle Linux prototype.
- eBPF telemetry collection component.
- PostgreSQL historical behavioural repository.
- Process-specific behavioural profiling engine.
- Statistical/ML anomaly detection engine.
- Contextual risk scoring and explainable alerting.
- User-facing monitoring and investigation dashboard.
- Evaluation report covering detection effectiveness, false positives, query performance, resource consumption, telemetry overhead and response latency.
- Research documentation covering literature review, architecture, methodology, experiments, results, limitations and future work.

# 24\. Product Vision

The final product should hide implementation complexity from ordinary users. Users should interact with Chronicle as a normal Linux application while eBPF, PostgreSQL, Python services and background processing operate behind the interface.

```
User
  ↓
Chronicle Application
  ↓
Background Agent / systemd
  ↓
eBPF + Database + Analysis Engine
  ↓
Dashboard + Alerts
```

# 25\. Distribution and Packaging

The distribution model is a self-contained Debian `.deb` package (`chronicle.deb`), enabling simple, standard installation on Linux distributions (Ubuntu, Debian, Linux Mint, etc.):

- **One-Command Installation**: Installed via `sudo dpkg -i chronicle.deb` or `sudo apt install ./chronicle.deb` without requiring manual Python environment setup, virtual environments, or complex dependency chains.
- **Desktop Entry Integration**: Automatically deploys `/usr/share/applications/chronicle.desktop` and icons into `/usr/share/icons/hicolor/` so users can launch Chronicle directly from the OS Applications menu or system tray.
- **Compiled Binary Protection (Black-Box Delivery)**: Application code, tracking pipelines, and proprietary machine learning models are compiled into a standalone native binary (via PyInstaller / ELF binary). Users simply interact with the application window without being able to view, alter, or inspect the underlying source code or data processing scripts.
- **Lightweight Footprint**: Uses the native Linux system WebKit rendering engine (`WebKitGTK` via `pywebview`), avoiding bulky 150MB+ Chromium runtimes while allowing direct in-process Python execution of ML anomaly detection models.
- **Host Process & User Activity Tracking**: Silently monitors background host events, maintaining historical behavioral context to identify anomalies, unauthorized commands, and privilege deviations.

# 26\. Phase 1 Repository Structure

```
Chronicle/
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── .gitignore
│
├── docs/
│   ├── proposal.md
│   └── architecture.md
│
├── src/
│   └── chronicle/
│       ├── __init__.py
│       └── config.py
│
├── ebpf/
│   └── README.md
│
├── database/
│   └── schema.sql
│
├── research/
│   └── README.md
│
├── tests/
│   └── README.md
│
└── scripts/
    └── README.md
```

# 27\. Git and Contribution Convention

Chronicle follows the Conventional Commits format:

```
type(scope): description
```

| Type     | Use                          |
| -------- | ---------------------------- |
| feat     | New feature                  |
| fix      | Bug fix                      |
| refactor | Code restructuring           |
| perf     | Performance improvement      |
| test     | Tests                        |
| docs     | Documentation                |
| build    | Build/dependencies/packaging |
| ci       | CI/CD changes                |
| security | Security-related changes     |
| model    | ML model changes             |
| research | Research/experiments         |
| chore    | General maintenance          |

Examples:

- feat(ebpf): add process monitoring
- fix(database): prevent duplicate events
- refactor(features): simplify feature extraction
- perf(database): optimize history queries
- test(detection): add anomaly detection tests
- docs(readme): update installation guide
- build(packaging): add Debian package
- security(api): restrict privileged endpoints
- model(detection): add historical features
- research: add baseline comparison
- chore: update project configuration

Initial repository commit: chore(repo): initialize Chronicle project structure

# 28\. Recommended Viva Explanation

What is Chronicle?

```
Chronicle is a Linux-based host behavioural analysis system that learns historical process behaviour and uses deviations from those behavioural profiles to detect and explain potentially suspicious activity.
```

What is the key idea?

```
Instead of relying primarily on individual events or short observation windows, Chronicle incorporates persistent, process-specific historical behavioural context into anomaly detection.
```

Where are OS and DBMS used?

```
OS concepts are applied in Linux process and kernel telemetry collection using system calls and eBPF, while DBMS concepts are applied in structured storage, indexing, querying, aggregation and historical analysis of behavioural data using PostgreSQL.
```

# 29\. Important Limitations

- A behavioural change is not automatically malicious.
- False positives and false negatives are possible.
- Historical baselines can be affected by concept drift.
- Legitimate software updates can change process behaviour.
- Previously unseen legitimate behaviour may appear anomalous.
- Attackers may attempt to mimic normal behaviour.
- The prototype will have practical limits on telemetry volume, database size and detection complexity.
- Chronicle is not intended to guarantee detection of every attack.

# 30\. Project Summary

Chronicle combines Operating Systems, DBMS, systems monitoring, data engineering and machine learning into a single Linux-focused security project. Its defining idea is persistent historical context: the system remembers how processes normally behave, stores that history in a structured database, and uses the historical baseline to determine whether current activity is significantly different. The resulting alerts are intended to provide both a risk assessment and an explanation of the behavioural evidence. The project will be validated not only by whether it detects anomalies, but also by whether historical context improves detection quality without creating unacceptable performance, storage or query overhead.