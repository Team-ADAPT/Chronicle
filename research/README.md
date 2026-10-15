# Chronicle — Research & Evaluation Framework

**PBL Project Research Documentation**  
Team ID: OSDBMS-V-2026-T-005 | Graphic Era (Deemed to be University), Dehradun

---

## 1. Central Research Question

> **Does incorporating persistent historical behavioural context improve process-level suspicious behaviour detection compared with using only current behavioural information?**

---

## 2. State of the Art & Research Background

Chronicle builds upon several foundational pillars in host intrusion detection and behavioural analysis:

1. **System-Call Behaviour Modelling:**
   - Foundational work by Forrest et al. on short system-call sequences for intrusion detection.
   - Sequence matching via STIDE (Sequence Time-Delay Embedding) and sliding n-gram windows.
   - Hidden Markov Models (HMM) and Recurrent Neural Networks (LSTM/GRU) for system call sequence prediction.

2. **Provenance-Based Systems:**
   - Graph-based provenance trackers: HOLMES, SLEUTH, SAQL, UNICORN, NoDoze, MORSE, ORTHRUS, ProvDetector, RAPID, APTSHIELD, MAGIC, and FLASH.
   - Causal graph reduction and historical dependency tracking.

3. **eBPF-Based Security Telemetry:**
   - In-kernel programmable event filtering, reducing user-space context-switching overhead compared with ptrace or auditd.

4. **Machine Learning Anomaly Detection:**
   - Unsupervised methods: Isolation Forests, Local Outlier Factor (LOF), One-Class SVM.
   - Supervised classification: Gradient boosted decision trees (XGBoost) on engineered behavioural features.

---

## 3. Research Gap & Chronicle's Contribution

Conventional host monitoring evaluates events or brief observation slices in isolation. However, legitimate software updates, varied workloads, and benign administrative tasks often trigger false positives when evaluated without history. Conversely, stealthy attacks (e.g., slow data exfiltration or credential harvesting) appear normal within single windows.

**Chronicle's contribution** is a practical architecture that unites:
- Persistent, process-specific historical behavioural baselines stored in a relational DBMS.
- Outlier-resistant statistics (Median, NMAD, IQR) resistant to baseline poisoning.
- Multi-metric feature extraction combining historical deviation Z-scores with in-process ML models.
- Contextual, explainable risk scoring (0–100) with supporting diagnostic evidence.

---

## 4. Evaluation Methodology

### 4.1 Comparative Baseline: Model A vs Model B

```text
Model A: Current Behavioural Information Only
                         VS
Model B: Current + Persistent Historical Behavioural Information
```

- **Model A Features:** Syscall counts, current CPU/memory, file operations, socket counts in the active window.
- **Model B Features:** Model A features + Historical Z-scores, median deviations, ratio over historical mean, unprecedented event flags, and baseline maturity calibration.

### 4.2 Benchmark Datasets

| Dataset | Nature | System Calls / Samples | Source |
| --- | --- | --- | --- |
| **ADFA-LD** | Linux Host System Call Traces | 442 unique syscall features, multi-attack scenarios | Australian Defence Force Academy |
| **PLAID** | Process-Level Anomaly Intrusion Dataset | 401 features, 6 attack classes + benign baselines | Linux Host Telemetry Benchmark |

### 4.3 Evaluation Metrics

1. **Detection Performance:**
   - Accuracy
   - Precision
   - Recall (True Positive Rate)
   - F1-Score
   - False-Positive Rate (FPR)

2. **System Overhead & Scalability:**
   - CPU Overhead (% CPU during telemetry capture)
   - Memory Footprint (Resident Set Size MB)
   - Database Query Latency (ms per history comparison)
   - Ingestion Throughput (records/sec)
   - Response Latency (end-to-end time from kernel event to desktop alert)

---

## 5. Summary of Current ML Results

Evaluations conducted on the trained models located in `ML/models/`:

| Dataset | Primary Model | Attack Recall | Accuracy | Notes |
| --- | --- | --- | --- | --- |
| **ADFA-LD** | XGBoost | 93.29% | 97.65% | 442 features; trained on Linux syscall traces |
| **PLAID** | XGBoost | 100.00% | 99.60% | 401 features; 0 false negatives in test set |
| **Unsupervised Baseline** | Isolation Forest | 88.40% | 91.20% | Zero-label anomaly detection baseline |

See `ML/results/` for detailed classification reports, confusion matrices, and feature importance analyses.
