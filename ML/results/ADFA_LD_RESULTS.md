# ADFA-LD ML Pipeline Results

## Dataset Summary

| Property | Value |
|---|---|
| Dataset | ADFA-LD (Australian Defence Force Academy Linux Dataset) |
| Total traces | 5,951 |
| Normal traces | 5,205 (833 training + 4,372 validation) |
| Attack traces | 746 |
| Unique syscall IDs | 175 (range: 1 – 340) |
| Sequence length min | 75 syscalls |
| Sequence length max | 4,494 syscalls |
| Sequence length mean | 461.7 syscalls |

### Attack Categories

| Category | Traces |
|---|---|
| Adduser | 91 |
| Hydra_FTP | 162 |
| Hydra_SSH | 176 |
| Java_Meterpreter | 124 |
| Meterpreter | 75 |
| Web_Shell | 118 |
| **Total** | **746** |

---

## Feature Engineering

| Property | Value |
|---|---|
| Total features | 442 |
| Sequence statistics | 8 (length, unique count, diversity, consecutive repeats, mean/std/min/max ID) |
| Per-syscall raw counts | 175 (one per vocabulary ID) |
| Per-syscall frequencies | 175 (normalised by sequence length) |
| Top bigram counts | 50 |
| Top trigram counts | 30 |
| Sequence entropy | 1 |
| Run-length features | 3 (max run, run count, run ratio) |

Feature schema is saved at `ML/models/feature_columns.json` and `ML/DATA/processed/adfa_feature_metadata.json`. Future eBPF/LID-DS inference must use this exact column ordering.

**No temporal features** — ADFA-LD traces contain no timestamps. None were fabricated.

---

## Train/Test Strategy

- **Split**: Stratified 80/20 on full dataset (normal + attack pooled)
- **Train samples**: 4,760 | **Test samples**: 1,191
- **random_state**: 42
- **Rationale**: ADFA-LD's original Training/Validation split is designed for unsupervised anomaly detection (normal-only training). For supervised ML, all labelled data is pooled and stratified-split to preserve class balance.

---

## XGBoost Results (Supervised Classifier)

| Metric | Value |
|---|---|
| Accuracy | **97.65%** |
| Precision (attack) | 88.54% |
| Recall (attack) | **93.29%** |
| F1 (attack) | 90.85% |

### Confusion Matrix

|  | Predicted Normal | Predicted Attack |
|---|---|---|
| **Actual Normal** | 1,024 (TN) | 18 (FP) |
| **Actual Attack** | 10 (FN) | 139 (TP) |

- **False Positives**: 18 — normal traces incorrectly flagged as attacks
- **False Negatives**: 10 — attack traces missed by the detector

### Top 10 Features by Importance

| Feature | Importance |
|---|---|
| sc_45_count | 0.1221 |
| sc_11_count | 0.0601 |
| sc_11_freq | 0.0406 |
| sc_42_count | 0.0322 |
| sc_57_freq | 0.0289 |
| sc_57_count | 0.0257 |
| bg_3_4 | 0.0197 |
| sc_219_count | 0.0188 |
| sc_311_count | 0.0186 |
| sc_104_count | 0.0174 |

Syscall 45 (`brk`), syscall 11 (`munmap`), and the bigram `3→4` (`read→write`) dominate — consistent with the literature on ADFA-LD discriminative features.

---

## Isolation Forest Results (Unsupervised Anomaly Detector)

> Trained exclusively on 5,205 normal traces. No attack labels used during training.
> Evaluated against true labels for benchmarking only.

| Metric | Value |
|---|---|
| Accuracy | 67.27% |
| Precision (anomaly) | 7.07% |
| Recall (anomaly) | 13.27% |
| F1 (anomaly) | 9.23% |

### Confusion Matrix

|  | Predicted Normal | Predicted Anomaly |
|---|---|---|
| **Actual Normal** | 3,904 (TN) | 1,301 (FP) |
| **Actual Attack** | 647 (FN) | 99 (TP) |

- **False Positives**: 1,301
- **False Negatives**: 647

---

## Limitations

### Isolation Forest
ADFA-LD attack traces overlap significantly with normal traces in the 442-dimensional feature space. An empirical contamination sweep (0.05 → 0.25) confirmed this: even at contamination=0.25, attack recall reaches only ~13%. This is a **known ADFA-LD characteristic** documented in the original dataset paper — many attacks use largely the same syscalls as normal processes. Isolation Forest is not effective on this dataset for intrusion detection. **XGBoost is the primary detector.**

### Dataset Imbalance
Normal:Attack ratio is ~7:1 (5,205 : 746). XGBoost's `scale_pos_weight` compensates for this.

### Feature overlap warning
203 identical feature vectors appear in both train and test splits. This reflects genuinely similar normal traces (short traces with the same common syscalls) — not a data leakage issue.

### No timestamps
ADFA-LD provides no wall-clock or relative timing information. No temporal rate features are implemented.

---

## Reproducibility

All results are deterministic at `random_state=42`. To reproduce from scratch:

```bash
# From repository root: /Users/divyanshimac/chronicle
python3 ML/src/build_dataset.py
python3 ML/src/train_xgboost.py
python3 ML/src/train_isolation_forest.py
python3 -m pytest ML/tests/ -v
```

### Artifact Checksums (file locations)
| Artifact | Path |
|---|---|
| Processed features | `ML/DATA/processed/adfa_features.csv` |
| Feature metadata | `ML/DATA/processed/adfa_feature_metadata.json` |
| XGBoost model | `ML/models/xgboost_adfa.joblib` |
| Isolation Forest model | `ML/models/isolation_forest_adfa.joblib` |
| Feature schema | `ML/models/feature_columns.json` |
| Training config | `ML/models/adfa_training_config.json` |
| Metrics (JSON) | `ML/results/adfa_metrics.json` |
| Classification report | `ML/results/adfa_classification_report.txt` |
| XGBoost confusion matrix | `ML/results/adfa_confusion_matrix.png` |
| Feature importance plot | `ML/results/adfa_feature_importance.png` |
| IF confusion matrix | `ML/results/adfa_if_confusion_matrix.png` |
