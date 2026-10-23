# Chronicle — Automated Model Retraining & Validation Workflow

## 1. Overview & Architecture

Chronicle implements an automated, safe, and verifiable model retraining and evaluation workflow for host intrusion detection. The workflow guarantees that newly labelled training data is thoroughly validated, candidate models are trained reproducibly, and candidates are promoted to production **only** if they satisfy predefined acceptance thresholds and do not regress against the currently approved baseline model.

```
Incoming Labelled Data (CSV)
             │
             ▼
[Stage 1: TrainingDataValidator]
 ├── File & schema completeness
 ├── Binary label check ({0, 1})
 ├── Schema isolation (ADFA vs PLAID)
 ├── Duplicate analysis & leakage checks
 └── Explicit rejection of raw unmapped collector events
             │  (Pass)
             ▼
[Stage 2: Split & Preprocessing]
 ├── Stratified 80/20 train/validation split (fixed seed)
 └── Or optional fixed external validation dataset
             │
             ▼
[Stage 3: Candidate Model Training]
 ├── XGBoost (supervised classifier with class reweighting)
 └── Isolation Forest (unsupervised anomaly detector, normal-only fit)
             │
             ▼
[Stage 4: Validation & Baseline Comparison]
 ├── Candidate evaluated on validation set (Recall, FPR, F1, Accuracy, CM)
 └── Approved baseline model evaluated on identical validation set
             │
             ▼
[Stage 5: Acceptance Gate]
 ├── Check minimum recall, F1, and maximum FPR
 └── Regression check: recall drop and FPR increase vs baseline
             │
             ├── [REJECTED] ──> Staged in registry with audit record; NOT promoted
             └── [ACCEPTED] ──> Staged in registry
                                     │ (if --promote requested)
                                     ▼
                        [Stage 6: Safe Promotion]
                         ├── Archive current approved model to ML/models/archive/
                         ├── Atomically install candidate artifact
                         └── Record active run in ML/models/registry.json
```

---

## 2. Supported Dataset & Model Pipelines

The retraining engine maintains strict schema isolation between dataset domains. Feature schemas must never be mixed.

| Dataset Key | Model Families | Feature Schema | Target Columns | Primary Security Metric |
|---|---|---|---|---|
| `ADFA-LD` (`adfa`) | XGBoost, Isolation Forest | 442 features (numeric syscall IDs, n-grams, sequence stats) | `label` (0=normal, 1=attack) | Attack Recall (minimizing false negatives) |
| `PLAID` (`plaid`) | XGBoost, Isolation Forest | 401 features (named Linux syscalls, n-grams, sequence stats) | `label` (0=normal, 1=attack) | Attack Recall (minimizing false negatives) |

---

## 3. Input Data Format & Validation Rules

### Required Format

Input data must be supplied as a CSV file containing:
- All required feature columns defined in the respective authoritative schema (`ML/models/feature_columns.json` for ADFA-LD or `ML/models/plaid_feature_columns.json` for PLAID).
- A binary target column named `label`:
  - `0`: Normal / benign host behaviour
  - `1`: Attack / malicious activity
- Optional metadata columns (preserved during validation): `category`, `subcategory`, `pid`, `source_split`, `file_name`, `file_path`.

### Validation Rules (`validate_training_data.py`)

1. **Non-empty:** Datasets with 0 rows are rejected immediately.
2. **Schema Conformity:** All feature columns in the authoritative schema must exist. Non-numeric, missing, NaN, or infinite (`Inf`) values cause validation failure.
3. **Label Integrity:** Labels must be binary integers (`0` or `1`). Missing labels, nulls, float representations (e.g. `0.5`), or unrecognized classes cause validation failure.
4. **Class Representation:** For supervised XGBoost retraining, both classes (`0` and `1`) must be present in the training data.
5. **Schema Isolation:** Passing string syscalls to the ADFA pipeline or numeric syscall IDs to the PLAID pipeline triggers an immediate schema cross-contamination error.
6. **Raw Collector Event Rejection:** Unmapped raw telemetry from `eBPF_collector.py` (e.g. files with `event_id`, `instance_id`, `ts_epoch`, `comm`) cannot be fed directly into model retraining without feature extraction. The validator detects this and rejects the file with an actionable diagnostic message.
7. **Leakage & Duplicate Auditing:** Duplicate feature vectors between training and validation splits are detected and reported.

---

## 4. Retraining CLI Commands

The deterministic entry point is `ML/src/retrain_pipeline.py`.

### 4.1 Validate Data Only (No Training)

To verify that a dataset conforms to schema and quality requirements without training:

```bash
# Validate ADFA-LD data
python3 ML/src/retrain_pipeline.py \
  --dataset adfa \
  --model-type xgboost \
  --data ML/DATA/processed/adfa_features.csv \
  --validate-only

# Validate PLAID data
python3 ML/src/retrain_pipeline.py \
  --dataset plaid \
  --model-type xgboost \
  --data ML/DATA/processed/plaid_features.csv \
  --validate-only
```

### 4.2 Retrain and Evaluate Candidate (Without Promotion)

Retrains a candidate model, evaluates performance against a reproducible 80/20 validation split, compares metrics with the currently active baseline model, and stages the candidate in the registry:

```bash
python3 ML/src/retrain_pipeline.py \
  --dataset adfa \
  --model-type xgboost \
  --data ML/DATA/processed/adfa_features.csv
```

### 4.3 Retrain with Explicit Validation Set

```bash
python3 ML/src/retrain_pipeline.py \
  --dataset adfa \
  --model-type xgboost \
  --data /path/to/training_split.csv \
  --val-data /path/to/validation_split.csv
```

### 4.4 Retrain and Promote (Atomic Promotion on Pass)

If acceptance criteria pass, the candidate is automatically promoted to production status:

```bash
python3 ML/src/retrain_pipeline.py \
  --dataset adfa \
  --model-type xgboost \
  --data ML/DATA/processed/adfa_features.csv \
  --promote
```

### 4.5 Rollback to Previous Approved Model

If an issue is discovered after promotion, restore the previous approved model from archive:

```bash
python3 ML/src/retrain_pipeline.py \
  --dataset adfa \
  --model-type xgboost \
  --rollback
```

### 4.6 Custom Acceptance Thresholds

Override default acceptance criteria via JSON string or file:

```bash
python3 ML/src/retrain_pipeline.py \
  --dataset adfa \
  --model-type xgboost \
  --data ML/DATA/processed/adfa_features.csv \
  --thresholds '{"min_recall": 0.90, "max_fpr": 0.03, "max_allowed_recall_drop": 0.01}'
```

---

## 5. Acceptance Thresholds & Gating Logic

| Parameter | XGBoost Default | Isolation Forest Default | Meaning |
|---|---|---|---|
| `min_recall` | 0.85 | 0.10 | Minimum required attack detection rate |
| `min_f1` | 0.80 | 0.05 | Minimum acceptable harmonic mean of precision and recall |
| `max_fpr` | 0.05 | 0.30 | Maximum allowable false positive rate |
| `max_allowed_recall_drop` | 0.02 (2%) | 0.05 (5%) | Maximum allowed drop in attack recall compared to active baseline |
| `max_allowed_fpr_increase` | 0.02 (2%) | 0.05 (5%) | Maximum allowed increase in false positives compared to active baseline |

A candidate is marked `ACCEPTED` only if all threshold conditions hold. If any threshold is violated, the candidate is marked `REJECTED`, the rejection reasons are logged, and promotion is blocked.

---

## 6. Artifact Storage & Model Registry

All model lifecycle records are managed in `ML/models/`:

```
ML/models/
├── registry.json                    # Central registry index with run audit trail
├── xgboost_adfa.joblib              # Active approved production model
├── isolation_forest_adfa.joblib     # Active approved production model
├── feature_columns.json             # Authoritative ADFA feature schema
├── adfa_training_config.json        # Active ADFA training configuration
├── xgboost_plaid.joblib             # Active approved production model
├── isolation_forest_plaid.joblib    # Active approved production model
├── plaid_feature_columns.json       # Authoritative PLAID feature schema
├── plaid_training_config.json       # Active PLAID training configuration
├── candidates/                      # Staged candidate runs (ignored by git)
│   └── <run_id>/
│       ├── model.joblib             # Candidate model binary
│       ├── metadata.json            # Run metadata, provenance, SHA-256 hash
│       ├── metrics.json             # Candidate & comparison metrics
│       └── feature_columns.json     # Feature columns snapshot
└── archive/                         # Rollback archives of superseded models (ignored by git)
    └── <dataset>_<model_type>_<timestamp>/
        ├── <model_name>.joblib
        └── archive_metadata.json
```

---

## 7. CLI Exit Codes

- `0`: Success (validation passed, retraining completed and candidate accepted, or rollback completed).
- `1`: Validation failed (corrupted schema, invalid labels, missing columns, or incompatible format).
- `2`: Retraining completed, but candidate was REJECTED by acceptance criteria.
- `3`: Configuration, system, or runtime error.

---

## 8. Running Retraining Tests

Run focused retraining tests:

```bash
python3 -m pytest ML/tests/test_retrain_pipeline.py -v
```

Run the entire Chronicle ML test suite:

```bash
python3 -m pytest ML/tests/ -v
```

---

## 9. Current Limitations & Future Collector Integration

1. **Controlled Ingestion:** Live retraining on every raw event is deliberately unsupported. Retraining requires explicitly validated, ground-truth-labelled datasets.
2. **Collector Telemetry Bridging:** `eBPF_collector.py` captures raw syscall events (`syscall_trace.csv`) and windowed statistics (`syscall_histogram.csv`). Before collector data can be fed to retraining:
   - Traces must be converted to syscall sequences.
   - Ground-truth labels must be attached via supervised tagging or security incident verification.
   - The sequence must pass through `PLAIDFeatureExtractor` or `FeatureSchema` to generate the exact 401 or 442 feature vector required by the model.
3. **Threshold Calibration:** Production acceptance thresholds should be reviewed and calibrated against institutional threat models before automated promotion in live environments.

---

## 10. Risk Scoring & Explainable Alerts (Task 2)

### Implementation files

| File | Purpose |
|---|---|
| `src/chronicle/risk_engine.py` | Risk scoring, eval-status contract, alert creation, dedup keys |
| `src/chronicle/config.py` | `enable_risk_scoring` feature flag |
| `src/chronicle/pipeline.py` | Wires feature flag and new scoring result into event processing |
| `tests/test_risk_scoring_alerts.py` | 73 unit + integration tests |

### Scoring design

**Config version:** `SCORING_CONFIG_VERSION = "1.1.0"` (bump on any weight/threshold change)

**Risk categories (inclusive lower bound):**

| Category | Score range |
|---|---|
| Low | 0 – 24 |
| Medium | 25 – 49 |
| High | 50 – 74 |
| Critical | 75 – 99 |

**Legacy status (backward compat):** `SAFE` < 40 · `SUSPICIOUS` 40–69 · `ANOMALOUS` ≥ 70

**Component weights (design choices, not empirically validated thresholds):**

```
Statistical baseline:
  cpu_z > 3.0  → min(35, cpu_z × 8)
  cpu_z > 2.0  → +15 (flat)
  mem_z > 3.5  → min(35, mem_z × 6)
  sys_z > 3.0  → min(35, sys_z × 7)

Isolation Forest (ml_available=True, if_pred=-1 or if_score < 0):
  → min(35, |if_score| × 120 + 20)
  Note: anomaly indicator only; NOT a calibrated attack probability.

XGBoost (ml_available=True, xgb_attack=True):
  → min(45, xgb_prob × 45)
  Note: confidence is relative to PLAID training distribution,
        not a real-world base rate.

Heuristic pattern rules (analytic detection):
  interactive_shell_from_daemon → +75
  mass_file_traversal            → +75
  reverse_shell_socket           → +75
  crypto_mining                  → +70
  privilege_escalation           → +70
  Duplicate flags are counted only once.

Score bounds: [0, 99]  (previous floor of 5 removed; 0 is a valid evaluated score)
```

### How thresholds are set

There are two separate threshold concepts in the scoring system.

**1. Risk category boundaries** — map the final score to a label.  
Defined as `RISK_THRESHOLDS` in [`src/chronicle/risk_engine.py`](../src/chronicle/risk_engine.py):

| Category | Minimum score |
|---|---|
| Low | 0 |
| Medium | 25 |
| High | 50 |
| Critical | 75 |

**2. Component trigger levels** — control when each signal fires and how many points it contributes.  
Also defined as constants in `risk_engine.py`:

| Signal | Trigger condition | Points |
|---|---|---|
| CPU Z-score (high) | `cpu_z > 3.0` | `min(35, cpu_z × 8)` |
| CPU Z-score (medium) | `cpu_z > 2.0` | +15 (flat) |
| Memory Z-score | `mem_z > 3.5` | `min(35, mem_z × 6)` |
| Syscall Z-score | `sys_z > 3.0` | `min(35, sys_z × 7)` |
| Isolation Forest | `if_pred == -1` or `if_score < 0` | `min(35, \|if_score\| × 120 + 20)` |
| XGBoost | `xgb_attack == True` | `min(45, xgb_prob × 45)` |
| `interactive_shell_from_daemon` | flag present | +75 |
| `mass_file_traversal` | flag present | +75 |
| `reverse_shell_socket` | flag present | +75 |
| `crypto_mining` | flag present | +70 |
| `privilege_escalation` | flag present | +70 |

The legacy status names (kept for backward compatibility with existing API consumers) apply on top:

| Status | Score range |
|---|---|
| `SAFE` | < 40 |
| `SUSPICIOUS` | 40 – 69 |
| `ANOMALOUS` | ≥ 70 |

**All weights are design choices, not empirically validated thresholds.**  
To change any value, edit the relevant constant in `risk_engine.py` and bump `SCORING_CONFIG_VERSION` so that stored alerts remain traceable to the config version that produced them.

The `config.py` dataclass documents the same thresholds as fields for reference:

```python
z_score_suspicious_threshold: float = 2.0   # cpu_z medium trigger
z_score_anomalous_threshold:  float = 3.5   # mem_z / cpu_z high trigger
ml_anomaly_threshold:         float = -0.05 # if_score boundary reference
xgboost_attack_threshold:     float = 0.50  # xgb_prob reference
```

### Evaluation status contract

Every `ScoringResult` carries one of three `eval_status` values:

| Status | Meaning |
|---|---|
| `evaluated` | Score is meaningful; all required evidence was obtained |
| `insufficient_data` | Key inputs absent, scoring disabled, or ML unavailable without compensating analytic signals |
| `scoring_error` | Technical failure prevented scoring; result is unreliable |

**Missing evidence is never silently treated as low risk.**  
`ml_available=False` with no heuristic flags → `eval_status="insufficient_data"`.

### Alert schema

```json
{
  "id": "ALT-A1B2C3D4",              // random, unique per alert
  "timestamp": "2026-10-16T18:00:00Z", // ingestion time, ISO-8601 UTC
  "timestamp_source": "event",        // "event" or "ingestion"
  "pid": 3812,
  "comm": "nginx",
  "ppid": 1120,                       // optional: present when available
  "user": "www-data",                 // optional: present when available
  "riskScore": 82,
  "riskCategory": "Critical",
  "category": "PRIVILEGE_ESCALATION",
  "description": "High-risk behavioral anomaly detected in 'nginx' (PID 3812). Primary signal: Analytic rule: unauthorized interactive shell...",
  "reasons": ["Analytic rule: unauthorized interactive shell spawned from daemon 'nginx'..."],
  "eval_status": "evaluated",
  "detection_source": "both",         // "analytic", "ml", "both", or "none"
  "contributing_signals": [
    {
      "source": "heuristic",
      "name": "interactive_shell_from_daemon",
      "observed_value": "interactive_shell_from_daemon",
      "score_contribution": 75.0,
      "description": "Analytic rule: unauthorized interactive shell spawned from daemon 'nginx'..."
    }
  ],
  "dedup_key": "DK-A1B2C3D4E5F6",   // deterministic within session
  "dedup_window_seconds": 60,
  "config_version": "1.1.0",
  "source_event_id": "evt-abc123",   // optional: original telemetry event ID
  "status": "ACTIVE"
}
```

> **Note:** This is an illustrative example using synthetic data. It does not represent live eBPF output.

### Deduplication

- **Key inputs:** `comm`, `pid`, `detection_source`, sorted signal names, `floor(event_epoch / 60)`.
- **Algorithm:** SHA-256 truncated to 12 hex characters, prefixed `DK-`.
- **Window:** 60 seconds. Events from the same process + same detection signature within a window share the same dedup key.
- **PID reuse:** Partially mitigated by the time window. Full mitigation requires process start time (not always available from psutil on macOS).
- **Cross-restart persistence:** **NOT guaranteed.** Dedup keys are deterministic within a session. A persistent store lookup would be required to deduplicate across restarts. Documented as a known limitation.

### Feature flag

```python
# Disable risk scoring (alerts suppressed; events still recorded with risk_score=0):
cfg = ChronicleConfig(enable_risk_scoring=False)

# Re-enable (default):
cfg = ChronicleConfig(enable_risk_scoring=True)
```

When disabled, events are still collected and stored. `eval_status` is set to `"insufficient_data"` and `risk_score=0`, preserving backward-compat with existing consumers.

### Timestamps and timezone

- All alert timestamps are UTC, ISO-8601 format: `YYYY-MM-DDTHH:MM:SSZ`.
- Collector events carry `HH:MM:SS` timestamp strings; the pipeline records these as-is in enriched events.
- For dedup window calculation, the pipeline attempts to parse the event's `HH:MM:SS` as UTC today's date. Falls back to ingestion time when parsing fails.
- `timestamp_source` field documents which was used.

### Running the tests

```bash
# Task 2 tests only
python3 -m pytest tests/test_risk_scoring_alerts.py -v

# Full suite (Tasks 1 + 2 + existing pipeline)
python3 -m pytest --tb=short -q
```

### Known limitations and blocked dependencies

| Item | Status | Detail |
|---|---|---|
| Live eBPF runtime | **BLOCKED** | Requires root on Linux; macOS/non-root falls back to psutil |
| Cross-restart dedup | **BLOCKED** | In-memory only; persistent store required for cross-restart guarantee |
| Persistent alert delivery | **BLOCKED** | PostgreSQL integration is pending (per project status) |
| Performance benchmark | **UNVERIFIED** | No meaningful benchmark environment available; per-event scoring is synchronous and computationally light |
| Score calibration | **UNVERIFIED** | Weights are design choices; empirical calibration against a labelled threat dataset has not been performed |

### Components requiring Prajjwal's review

- `src/chronicle/pipeline.py` — modified `process_raw_event` (wrapped in try/except, added feature-flag gating for alert generation). The external API and all existing test assertions are unchanged.
- `src/chronicle/risk_engine.py` — rewritten. The old `evaluate()` return type changed from `dict` to `ScoringResult`; existing callers in `pipeline.py` and `tests/test_chronicle_pipeline.py` have been updated.
