# Chronicle — Project Proposal

**An Intelligent Historical Behaviour Analysis System**  
*Understand behaviour. Learn from history. Detect anomalies.*

---

- **Project Title:** Chronicle  
- **Team ID:** OSDBMS-V-2026-T-005  
- **Department:** Department of Computer Science & Engineering  
- **Institution:** Graphic Era (Deemed to be University), Dehradun  
- **Academic Session:** 2026–27  
- **Target Platform:** Linux (Debian / Ubuntu / derivatives)

---

## 1. Executive Summary

Chronicle is a Linux-based host behavioural analysis and threat-detection system. Instead of relying solely on isolated system events or narrow observation windows, Chronicle maintains persistent, process-specific historical behavioural context. Telemetry is gathered from the Linux kernel using eBPF, filtered for sensitive user data, and persisted into a local relational database (PostgreSQL with zero-dependency SQLite fallback). Using statistical modeling and embedded machine learning (Scikit-learn, Isolation Forest, XGBoost), Chronicle compares current process activity against long-term historical baselines to generate contextual risk scores (0–100) with explainable rationale presented via a native desktop dashboard.

---

## 2. Problem Statement

Conventional host monitoring tools inspect system calls, process activity, file access, and network traffic in isolation. However:
1. **Context Blindness:** A process executing a sensitive system call or opening a socket may look suspicious in isolation, yet be completely normal for that program's historical pattern.
2. **Slow Drift & Camouflage:** Sequences of individually benign actions can constitute malicious operations (e.g. data staging, lateral movement, persistence) when viewed against a process's historical baseline.
3. **Alert Fatigue:** Binary safe/malicious detections lack contextual explainability, leaving system administrators overwhelmed by high false-positive rates.

Chronicle directly addresses these limitations by maintaining structured historical behavioural context and using deviation analysis as the foundation for anomaly detection.

---

## 3. Core Research Question

> **Does incorporating persistent historical behavioural context improve process-level suspicious behaviour detection compared with using only current behavioural information?**

Experimental hypothesis:
- **Model A (Current Behaviour Only):** Analyzes features extracted solely from the active execution window.
- **Model B (Current + Historical Context):** Evaluates live features against historical process profiles (Z-scores, robust median/NMAD deviations, and unprecedented actions).
- **Hypothesis:** Model B will demonstrate superior precision, higher attack recall, and substantially lower false-positive rates on evolving workloads.

---

## 4. Objectives

1. **Kernel Telemetry Collection:** Capture Linux host telemetry using eBPF/BCC with graceful fallback to `psutil`.
2. **Multi-Domain Monitoring:** Track process creation/termination, system calls, file system interactions, network connections, and hardware resources.
3. **Local Relational Storage:** Normalize and store structured telemetry in a local PostgreSQL/SQLite database adhering to strict local-first privacy principles.
4. **Historical Behaviour Profiling:** Construct and maintain robust, process-specific behavioural baselines that resist outlier poisoning and handle cold-starts.
5. **Feature Extraction:** Extract multi-dimensional quantitative and qualitative feature vectors from both live windows and historical profiles.
6. **In-Process ML Anomaly Detection:** Run embedded Scikit-learn/XGBoost models in Python without remote network dependencies.
7. **Contextual Risk Scoring & Explainability:** Provide transparent 0–100 risk assessments with clear diagnostic evidence for security alerts.
8. **Native Desktop Interface:** Deliver an interactive, lightweight desktop application (`pywebview`) displaying real-time processes, baselines, and alerts.
9. **Empirical Evaluation:** Benchmark detection quality, false-positive rates, CPU/memory overhead, and database query latency.

---

## 5. Scope & Assumptions

### 5.1 In-Scope
- Platform: Linux only (Debian/Ubuntu families).
- Scope of monitoring: Process lifecycle, system calls, file activity, network connections, resource utilization.
- Storage: 100% local database storage (PostgreSQL/SQLite) with data retention management.
- User interface: Desktop application with real-time process monitoring, historical baselines, and alert triage.
- Packaging: Self-contained Debian `.deb` distribution package.

### 5.2 Assumptions & Limitations
- The target system runs a Linux kernel with eBPF support and requisite permissions (root/CAP_BPF) for system monitoring.
- Sufficient benign historical activity is recorded to establish stable baseline profiles.
- Legitimate software updates may introduce concept drift, requiring baseline re-computation or incremental learning.
- Chronicle is designed for behavioural anomaly detection; it does not claim to prevent all attacks or eliminate false positives entirely.

---

## 6. Project Deliverables

| Deliverable | Description |
| --- | --- |
| **eBPF Telemetry Layer** | Standalone and pipeline-integrated eBPF collector with BCC C probes. |
| **Relational Database Engine** | PostgreSQL + SQLite repository with schema migrations, indexes, and retention. |
| **Behaviour Profiling Engine** | Robust statistical engine computing program baselines and deviation metrics. |
| **ML Anomaly Detector** | In-process Isolation Forest and XGBoost detection models trained on benchmark datasets. |
| **Explainable Risk Engine** | Risk scoring engine providing 0–100 scores with multi-category evidence. |
| **Desktop Application** | Lightweight WebKit desktop GUI with Overview, Process, Baseline, and Alert views. |
| **Debian Distribution Package** | Debian installer (`.deb`) with system menu launcher (`.desktop`) and desktop icon. |
| **Evaluation Report** | Benchmark analysis assessing Model A vs Model B detection and system overhead. |
