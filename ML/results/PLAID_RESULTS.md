# PLAID ML Pipeline Results

## Dataset Summary

| Property | Value |
|---|---|
| Dataset | PLAID (Plaid Lab Artificial Intrusion Dataset, UVM IDS) |
| Total traces processed | 40,817 |
| Normal (baseline) traces | 39,565 (96.93%) across 18 system workloads |
| Attack traces | 1,252 (3.07%) across 60 trials |
| Unique syscall names in vocab | 156 Linux system call identifiers |
| Sequence length min | 1 syscall |
| Sequence length max | 2,000,005 syscalls |
| Sequence length median | 64 syscalls |
| Unique sequences | 6,043 |
| Duplicate sequences | 34,774 (common subcommands/threads across trials) |
| Missing / NaN values | 0 |
| Infinite values | 0 |

### Attack Categories

| Category | Traces | Description |
|---|---|---|
| cowroot | 60 | Dirty COW (CVE-2016-5195) kernel privilege escalation exploit |
| ftp | 281 | vsftpd exploitation / unauthorized remote access |
| nginx | 355 | Nginx server exploit / payload injection |
| privesc | 60 | Local privilege escalation attacks |
| redis | 186 | Redis rogue server / unauthorized write exploit |
| ssh | 310 | SSH brute-force / privilege compromise |
| **Total** | **1,252** | Across 60 independent trials (10 per category) |

### Baseline Workloads

| Workload | Traces | Workload | Traces |
|---|---|---|---|
| `run_tests_php` | 30,076 | `cargo_compile` | 259 |
| `test_redis` | 4,905 | `ftp-baseline` | 62 |
| `build_redis` | 4,129 | `rust_install` | 41 |
| `ssh-baseline` | 34 | `nginx-baseline` | 30 |
| `git_clone` | 11 | `redis-baseline` | 7 |
| `curl_download` | 4 | `day1` – `day7` | 7 (1 per day) |

---

## Feature Engineering

| Property | Value |
|---|---|
| Total features | 401 |
| Sequence statistics | 8 (length, unique count, diversity, consecutive repeats, repetition ratio, max run, run count, run ratio) |
| Per-syscall raw counts | 156 (one per vocabulary syscall string) |
| Per-syscall frequencies | 156 (normalised by sequence length) |
| Top bigram counts | 50 (e.g. `bg_openat_openat`, `bg_close_close`, `bg_read_read`) |
| Top trigram counts | 30 (e.g. `tg_rt_sigaction_rt_sigaction_rt_sigaction`) |
| Sequence entropy | 1 (Shannon entropy of syscall distribution) |

- **Feature Schema Location**: Saved at `ML/models/plaid_feature_columns.json` and `ML/DATA/processed/plaid_feature_metadata.json`.
- **Temporal Features**: **None**. PLAID traces contain no timestamps. None were fabricated.
- **Process Information**: Process IDs (PIDs) from file stems are recorded as metadata for provenance.

---

## Train/Test Strategy

- **Split**: Stratified 80/20 on full dataset (normal + attack pooled)
- **Train samples**: 32,653 (31,651 normal + 1,002 attack)
- **Test samples**: 8,164 (7,914 normal + 250 attack)
- **random_state**: 42
- **Imbalance Handling**: `scale_pos_weight = 31.59` (exact ratio of negative to positive class in training set)

---

## XGBoost Results (Supervised Classifier)

| Metric | Value |
|---|---|
| Overall Accuracy | **99.60%** |
| Attack Precision | **88.34%** |
| Attack Recall | **100.00%** (primary security detection metric) |
| Attack F1-Score | **93.81%** |
| False Positive Rate | **0.42%** (33 / 7,914 normal test traces) |
| False Negative Rate | **0.00%** (0 / 250 attack test traces) |

### Confusion Matrix

|  | Predicted Normal | Predicted Attack |
|---|---|---|
| **Actual Normal** | 7,881 (TN) | 33 (FP) |
| **Actual Attack** | 0 (FN) | 250 (TP) |

- **False Positives**: 33 — benign processes slightly deviating from typical baseline routines.
- **False Negatives**: 0 — zero missed attacks across the test set.

### Per-Category Attack Detection Rate

| Attack Category | Test Samples | Detected | Recall |
|---|---|---|---|
| `cowroot` | 10 | 10 | **100.0%** |
| `ftp` | 53 | 53 | **100.0%** |
| `nginx` | 76 | 76 | **100.0%** |
| `privesc` | 12 | 12 | **100.0%** |
| `redis` | 38 | 38 | **100.0%** |
| `ssh` | 61 | 61 | **100.0%** |

### Top 15 Features by Importance

| Feature | Importance Weight |
|---|---|
| `tg_rt_sigaction_rt_sigaction_rt_sigaction` | 0.0988 |
| `sc_set_robust_list_freq` | 0.0913 |
| `sc_stat_count` | 0.0882 |
| `sc_rt_sigaction_count` | 0.0711 |
| `bg_openat_openat` | 0.0447 |
| `sc_getegid_count` | 0.0370 |
| `bg_close_close` | 0.0296 |
| `bg_lstat_lstat` | 0.0209 |
| `sc_close_count` | 0.0192 |
| `sc_rt_sigaction_freq` | 0.0145 |
| `sc_vfork_count` | 0.0132 |
| `bg_rt_sigaction_rt_sigaction` | 0.0131 |
| `sc_getrusage_count` | 0.0131 |
| `bg_read_read` | 0.0122 |
| `sc_sched_getaffinity_count` | 0.0121 |

Signal handling (`rt_sigaction` trigrams/counts), thread synchronization (`set_robust_list`), and credential queries (`getegid`) strongly separate attack process trees from benign workloads.

---

## Isolation Forest Results (Unsupervised Anomaly Detector)

> Trained strictly on 31,651 normal baseline traces. No attack labels used during training.
> Contamination parameter: `0.05`. Evaluated against true labels for benchmarking.

| Metric | Value |
|---|---|
| Overall Accuracy | **92.12%** |
| Anomaly Precision | 11.09% |
| Anomaly Recall | **22.40%** (56 / 250 attacks flagged as anomalies) |
| Anomaly F1-Score | 14.83% |
| False Positive Rate | 5.67% (449 / 7,914) |
| False Negative Rate | 77.60% (194 / 250) |

### Confusion Matrix

|  | Predicted Normal | Predicted Anomaly |
|---|---|---|
| **Actual Normal** | 7,465 (TN) | 449 (FP) |
| **Actual Attack** | 194 (FN) | 56 (TP) |

### Key Anomaly Detection Finding
Like ADFA-LD (where attack recall was ~13%), unsupervised Isolation Forest struggles with stealthy in-host attacks (22.40% recall). Exploits like `privesc` (0.0% recall) and `cowroot` (10.0% recall) leverage standard system calls that mimic benign memory and thread operations. This proves why Chronicle uses supervised XGBoost as the primary ML detector.

---

## Cross-Dataset Validation: ADFA-LD ↔ PLAID

### 1. Incompatibility Analysis
- **Full Model Transfer**: **Incompatible**.
  - **Namespace / Token representation**: ADFA-LD uses unmapped integer IDs (`sc_1_count` .. `sc_340_count`, 442 features). PLAID uses standard 64-bit Linux syscall names (`sc_read_count`, `sc_openat_freq`, 401 features).
  - **Kernel ABI**: ADFA-LD was recorded on Linux 2.6.38 (32-bit x86); PLAID was recorded on Linux 4.15+ (64-bit x86_64). The original integer mapping table for ADFA-LD was lost by its original authors.
  - Fabricating a synthetic 1:1 mapping between these distinct tables would violate engineering integrity.

### 2. Domain-Agnostic Structural Feature Transfer
Testing transfer on the 8 mathematically identical sequence-level features:
`['seq_length', 'unique_syscall_count', 'syscall_diversity', 'repeated_consecutive', 'seq_entropy', 'max_run_length', 'run_count', 'run_ratio']`

| Direction | Accuracy | Precision | Recall (Attack) | F1-Score |
|---|---|---|---|---|
| **ADFA-LD → PLAID** | 87.11% | 2.67% | **9.03%** | 4.12% |
| **PLAID → ADFA-LD** | 65.06% | 12.02% | **28.28%** | 16.87% |

### Key Generalization Insight
Structural features alone exhibit significant domain shift: benign server workloads (PHP test suite, Redis benchmark) exhibit vastly different trace length and entropy distributions than legacy desktop baseline traces. Consequently, Chronicle must maintain dedicated dataset-specific ML models while providing a standardized interface for inference.

---

## Saved Artifact Locations

| Artifact | Path |
|---|---|
| Processed Features | `ML/DATA/processed/plaid_features.csv` (83.60 MB) |
| Feature Metadata | `ML/DATA/processed/plaid_feature_metadata.json` |
| XGBoost Model | `ML/models/xgboost_plaid.joblib` |
| Isolation Forest Model | `ML/models/isolation_forest_plaid.joblib` |
| Feature Schema (Inference) | `ML/models/plaid_feature_columns.json` |
| Training Config | `ML/models/plaid_training_config.json` |
| Evaluation Metrics JSON | `ML/results/plaid_metrics.json` |
| Cross-Dataset Metrics JSON | `ML/results/cross_dataset_metrics.json` |
| Classification Report | `ML/results/plaid_classification_report.txt` |
| Confusion Matrix Plot | `ML/results/plaid_confusion_matrix.png` |
| IF Confusion Matrix Plot | `ML/results/plaid_if_confusion_matrix.png` |
| Feature Importance Plot | `ML/results/plaid_feature_importance.png` |
| Test Suite | `ML/tests/test_plaid_pipeline.py` (51 tests) |
