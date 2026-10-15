# Chronicle — Test Suite

This directory contains the unit, integration, and regression test suites for Chronicle.

---

## 1. Test Modules

| Test File | Focus Area | Scope |
| --- | --- | --- |
| `tests/test_db_storage.py` | Storage & History Engine | Tests SQLite and PostgreSQL connectivity, schema migrations, process lifecycle registrations, raw event inserts, behaviour window aggregation, baseline profiling (Z-scores, robust deviations), and privacy credential sanitization. |
| `tests/test_chronicle_pipeline.py` | End-to-End Pipeline & API | Tests the complete Chronicle pipeline: OS Collector (psutil/eBPF fallback) ➔ DBMS storage & online metrics ➔ In-process ML inference (Isolation Forest & XGBoost) ➔ Risk scoring & explainable alert generation ➔ Local HTTP/REST API endpoints. |
| `ML/tests/` | Machine Learning Validation | Tests dataset loaders, feature extractors, model reloadability, and prediction reproducibility across ADFA-LD and PLAID models. |

---

## 2. Running Tests

### 2.1 Complete Test Run via Pytest
```bash
# Run all core tests
pytest tests/ -v
```

### 2.2 Using Python's Built-in Unittest Runner
```bash
python3 -m unittest discover tests -v
```

### 2.3 Individual Test Modules
```bash
# Database & storage layer tests
python3 -m unittest tests/test_db_storage.py -v

# Pipeline, ML inference, and REST API tests
python3 -m unittest tests/test_chronicle_pipeline.py -v
```

---

## 3. Test Coverage Highlights

- **Relational Integrity:** Ensures foreign key constraints, PID reuse handling via `instance_id`, and cascading deletes function correctly.
- **Robust Baselines:** Validates deviation detection when process activity exceeds 3x standard deviations, as well as handling for `COLD_START` programs.
- **Privacy Enforcement:** Confirms that passwords, tokens, API keys, and sensitive paths are redacted before data reaches persistent storage.
- **In-Process ML Verification:** Confirms that trained `.joblib` models load without external server dependencies and output normalized probability scores.
