"""
Unit and integration tests for Chronicle Automated Model Retraining & Validation.

Tests cover all 20 required acceptance areas:
1. Valid training data
2. Empty data
3. Missing required columns
4. Invalid labels
5. NaN and infinite values
6. Feature-schema mismatch
7. Missing class in supervised training
8. Dataset-specific schema isolation (ADFA vs PLAID)
9. Reproducibility
10. Candidate training
11. Metric calculation
12. Acceptance and rejection rules
13. Validation failure handling
14. Candidate artifact serialization and reload
15. Feature-schema preservation
16. Promotion success
17. Rejected candidate does not replace the approved model
18. Rollback or preservation of the previous model
19. Missing or corrupted artifacts
20. CLI exit codes and error reporting
"""
import json
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
import pytest
from xgboost import XGBClassifier

ML_SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(ML_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(ML_SRC_DIR))

from model_registry import ModelRegistry, compute_sha256, compute_schema_fingerprint
from retrain_pipeline import RetrainingPipeline, main as cli_main
from validate_training_data import TrainingDataValidator, check_split_leakage


# ── Helper Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def adfa_feature_names() -> List[str]:
    """Authoritative ADFA feature columns from production schema."""
    schema_path = Path(__file__).resolve().parents[1] / "models" / "feature_columns.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)["feature_columns"]


@pytest.fixture
def plaid_feature_names() -> List[str]:
    """Authoritative PLAID feature columns from production schema."""
    schema_path = Path(__file__).resolve().parents[1] / "models" / "plaid_feature_columns.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)["feature_columns"]


@pytest.fixture
def synthetic_adfa_df(adfa_feature_names) -> pd.DataFrame:
    """Generate a clean synthetic ADFA-LD DataFrame with 50 rows (40 normal, 10 attack)."""
    np.random.seed(42)
    n_samples = 50
    data = {col: np.random.uniform(0, 10, n_samples) for col in adfa_feature_names}
    df = pd.DataFrame(data)
    # Binary labels: 40 normal (0), 10 attack (1)
    labels = np.array([0] * 40 + [1] * 10, dtype=np.int32)
    df["label"] = labels
    df["category"] = ["normal"] * 40 + ["Adduser"] * 10
    return df


@pytest.fixture
def synthetic_plaid_df(plaid_feature_names) -> pd.DataFrame:
    """Generate a clean synthetic PLAID DataFrame with 50 rows (40 normal, 10 attack)."""
    np.random.seed(42)
    n_samples = 50
    data = {col: np.random.uniform(0, 5, n_samples) for col in plaid_feature_names}
    df = pd.DataFrame(data)
    labels = np.array([0] * 40 + [1] * 10, dtype=np.int32)
    df["label"] = labels
    df["category"] = ["normal"] * 40 + ["ssh"] * 10
    return df


@pytest.fixture
def isolated_models_env(tmp_path) -> Path:
    """Create an isolated test models directory with valid production schema copies."""
    repo_models = Path(__file__).resolve().parents[1] / "models"
    test_models = tmp_path / "models"
    test_models.mkdir(parents=True, exist_ok=True)

    # Copy authoritative schemas and configs
    for f in [
        "feature_columns.json",
        "plaid_feature_columns.json",
        "adfa_training_config.json",
        "plaid_training_config.json",
    ]:
        src = repo_models / f
        if src.exists():
            shutil.copy2(src, test_models / f)

    return test_models


# ── Tests 1 to 8: Input Data Validation ──────────────────────────────────────

class TestDataValidation:
    def test_1_valid_training_data(self, synthetic_adfa_df, adfa_feature_names):
        """1. Valid training data passes all checks."""
        validator = TrainingDataValidator("ADFA-LD", expected_features=adfa_feature_names)
        is_valid, report = validator.validate_dataframe(synthetic_adfa_df, is_supervised=True)
        assert is_valid is True
        assert report.accepted_records == 50
        assert report.rejected_records == 0
        assert len(report.errors) == 0

    def test_2_empty_data(self, adfa_feature_names):
        """2. Empty DataFrame is rejected."""
        empty_df = pd.DataFrame(columns=adfa_feature_names + ["label"])
        validator = TrainingDataValidator("ADFA-LD", expected_features=adfa_feature_names)
        is_valid, report = validator.validate_dataframe(empty_df, is_supervised=True)
        assert is_valid is False
        assert any("empty" in e.lower() for e in report.errors)

    def test_3_missing_required_columns(self, synthetic_adfa_df, adfa_feature_names):
        """3. Missing label column is rejected."""
        df_no_label = synthetic_adfa_df.drop(columns=["label"])
        validator = TrainingDataValidator("ADFA-LD", expected_features=adfa_feature_names)
        is_valid, report = validator.validate_dataframe(df_no_label, is_supervised=True)
        assert is_valid is False
        assert any("label" in e.lower() for e in report.errors)

    def test_4_invalid_labels(self, synthetic_adfa_df, adfa_feature_names):
        """4. Invalid (non-binary or float) labels are rejected."""
        # Non-binary labels
        df_invalid = synthetic_adfa_df.copy()
        df_invalid.loc[0, "label"] = 99
        validator = TrainingDataValidator("ADFA-LD", expected_features=adfa_feature_names)
        is_valid, report = validator.validate_dataframe(df_invalid, is_supervised=True)
        assert is_valid is False
        assert any("binary" in e.lower() or "invalid" in e.lower() for e in report.errors)

        # Float labels (e.g. 0.5)
        df_float = synthetic_adfa_df.copy()
        df_float["label"] = df_float["label"].astype(float)
        df_float.loc[0, "label"] = 0.5
        is_valid, report = validator.validate_dataframe(df_float, is_supervised=True)
        assert is_valid is False
        assert any("float" in e.lower() or "integer" in e.lower() for e in report.errors)

    def test_5_nan_and_infinite_values(self, synthetic_adfa_df, adfa_feature_names):
        """5. NaN and infinite values in features are detected and rejected."""
        # NaN in features
        df_nan = synthetic_adfa_df.copy()
        col = adfa_feature_names[0]
        df_nan.loc[0, col] = np.nan
        validator = TrainingDataValidator("ADFA-LD", expected_features=adfa_feature_names)
        is_valid, report = validator.validate_dataframe(df_nan, is_supervised=True)
        assert is_valid is False
        assert any("null/nan" in e.lower() or "nan" in e.lower() for e in report.errors)

        # Infinite value in features
        df_inf = synthetic_adfa_df.copy()
        df_inf.loc[0, col] = np.inf
        is_valid, report = validator.validate_dataframe(df_inf, is_supervised=True)
        assert is_valid is False
        assert any("infinite" in e.lower() for e in report.errors)

    def test_6_feature_schema_mismatch(self, synthetic_adfa_df, adfa_feature_names):
        """6. Missing required features from schema are detected and rejected."""
        # Drop first 5 features
        dropped_cols = adfa_feature_names[:5]
        df_mismatch = synthetic_adfa_df.drop(columns=dropped_cols)
        validator = TrainingDataValidator("ADFA-LD", expected_features=adfa_feature_names)
        is_valid, report = validator.validate_dataframe(df_mismatch, is_supervised=True)
        assert is_valid is False
        assert any("missing 5 required feature columns" in e.lower() for e in report.errors)

    def test_7_missing_class_in_supervised_training(self, synthetic_adfa_df, adfa_feature_names):
        """7. Missing class in supervised training (only normal, no attack) is rejected."""
        df_only_normal = synthetic_adfa_df[synthetic_adfa_df["label"] == 0].copy()
        validator = TrainingDataValidator("ADFA-LD", expected_features=adfa_feature_names, require_both_classes=True)
        is_valid, report = validator.validate_dataframe(df_only_normal, is_supervised=True)
        assert is_valid is False
        assert any("attack class (label 1) is missing" in e.lower() for e in report.errors)

    def test_8_dataset_schema_isolation_and_collector_rejection(self, synthetic_adfa_df, adfa_feature_names):
        """8. Schema cross-contamination and raw collector events are explicitly rejected."""
        # ADFA pipeline rejects PLAID columns
        df_cross = synthetic_adfa_df.copy()
        df_cross["sc_openat_count"] = 1.0  # PLAID string syscall name
        validator_adfa = TrainingDataValidator("ADFA-LD", expected_features=adfa_feature_names)
        is_valid, report = validator_adfa.validate_dataframe(df_cross, is_supervised=True)
        assert is_valid is False
        assert any("plaid" in e.lower() for e in report.errors)

        # Rejection of raw collector data
        df_collector = pd.DataFrame({
            "event_id": [1, 2],
            "instance_id": ["inst1", "inst2"],
            "event_type": ["execve", "openat"],
            "comm": ["bash", "cat"],
            "syscall_category": ["process", "file"],
            "label": [0, 1],
        })
        validator = TrainingDataValidator("ADFA-LD", expected_features=adfa_feature_names)
        is_valid, report = validator.validate_dataframe(df_collector, is_supervised=True)
        assert is_valid is False
        assert any("raw ebpf collector" in e.lower() for e in report.errors)


# ── Tests 9 to 13: Retraining, Metrics & Acceptance ─────────────────────────

class TestRetrainingAndEvaluation:
    def test_9_reproducibility(self, synthetic_adfa_df, isolated_models_env, tmp_path):
        """9. Candidate training produces reproducible predictions with fixed seed."""
        csv_path = tmp_path / "adfa_train.csv"
        synthetic_adfa_df.to_csv(csv_path, index=False)

        pipeline1 = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env, random_state=42)
        _, record1 = pipeline1.run(csv_path, promote=False)

        pipeline2 = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env, random_state=42)
        _, record2 = pipeline2.run(csv_path, promote=False)

        m1 = joblib.load(record1.artifact_path)
        m2 = joblib.load(record2.artifact_path)

        # Test on identical input
        cols = pipeline1.get_feature_columns()
        X_test = synthetic_adfa_df[cols].to_numpy(dtype=np.float32)[:10]
        preds1 = m1.predict(X_test)
        preds2 = m2.predict(X_test)
        assert np.array_equal(preds1, preds2)

    def test_10_candidate_training_xgboost_and_isolation_forest(
        self, synthetic_adfa_df, synthetic_plaid_df, isolated_models_env, tmp_path
    ):
        """10. Candidate training supports both XGBoost and Isolation Forest."""
        adfa_path = tmp_path / "adfa.csv"
        synthetic_adfa_df.to_csv(adfa_path, index=False)

        # XGBoost candidate
        pipe_xgb = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env)
        _, rec_xgb = pipe_xgb.run(adfa_path, promote=False)
        assert Path(rec_xgb.artifact_path).exists()
        assert rec_xgb.train_samples > 0

        # Isolation Forest candidate
        pipe_if = RetrainingPipeline("ADFA-LD", "ISOLATION_FOREST", models_dir=isolated_models_env)
        _, rec_if = pipe_if.run(adfa_path, promote=False)
        assert Path(rec_if.artifact_path).exists()
        assert rec_if.model_type == "ISOLATION_FOREST"

    def test_11_metric_calculation(self, synthetic_adfa_df, isolated_models_env, tmp_path):
        """11. Accuracy, Precision, Recall, F1, and Confusion Matrix are properly computed."""
        csv_path = tmp_path / "adfa.csv"
        synthetic_adfa_df.to_csv(csv_path, index=False)

        pipeline = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env)
        _, record = pipeline.run(csv_path, promote=False)

        cand_metrics = record.metrics["candidate"]
        for key in ["accuracy", "precision", "recall", "f1_score", "confusion_matrix", "false_positive_rate"]:
            assert key in cand_metrics, f"Missing metric {key}"

        cm = cand_metrics["confusion_matrix"]
        assert all(k in cm for k in ["TN", "FP", "FN", "TP"])

    def test_12_acceptance_and_rejection_rules(self, synthetic_adfa_df, isolated_models_env, tmp_path):
        """12. Configurable acceptance thresholds accept good models and reject underperforming ones."""
        csv_path = tmp_path / "adfa.csv"
        synthetic_adfa_df.to_csv(csv_path, index=False)

        # Lenient thresholds -> Should accept
        lenient = {"min_recall": 0.0, "max_fpr": 1.0, "min_f1": 0.0}
        pipe_pass = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env, thresholds=lenient)
        accepted, rec_pass = pipe_pass.run(csv_path, promote=False)
        assert accepted is True
        assert rec_pass.acceptance_decision == "ACCEPTED"
        assert len(rec_pass.rejection_reasons) == 0

        # Impossible threshold (recall > 1.0) -> Must reject
        strict = {"min_recall": 1.01}
        pipe_fail = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env, thresholds=strict)
        accepted, rec_fail = pipe_fail.run(csv_path, promote=False)
        assert accepted is False
        assert rec_fail.acceptance_decision == "REJECTED"
        assert len(rec_fail.rejection_reasons) > 0

    def test_13_validation_failure_handling(self, isolated_models_env, tmp_path):
        """13. Pipeline handles validation errors cleanly and aborts training."""
        bad_csv = tmp_path / "bad.csv"
        # CSV with NaN
        pd.DataFrame({"label": [np.nan, 1]}).to_csv(bad_csv, index=False)

        pipeline = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env)
        with pytest.raises(ValueError, match="failed validation"):
            pipeline.run(bad_csv)


# ── Tests 14 to 19: Registry, Artifacts, Promotion & Rollback ────────────────

class TestRegistryPromotionAndRollback:
    def test_14_candidate_artifact_serialization_and_reload(
        self, synthetic_adfa_df, isolated_models_env, tmp_path
    ):
        """14. Candidate models serialize to disk and reload identically."""
        csv_path = tmp_path / "adfa.csv"
        synthetic_adfa_df.to_csv(csv_path, index=False)

        pipeline = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env)
        _, record = pipeline.run(csv_path, promote=False)

        artifact_file = Path(record.artifact_path)
        assert artifact_file.exists()
        reloaded = joblib.load(artifact_file)
        assert hasattr(reloaded, "predict")

    def test_15_feature_schema_preservation(self, synthetic_adfa_df, isolated_models_env, tmp_path):
        """15. Schema fingerprint is computed and preserved in run metadata."""
        csv_path = tmp_path / "adfa.csv"
        synthetic_adfa_df.to_csv(csv_path, index=False)

        pipeline = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env)
        _, record = pipeline.run(csv_path, promote=False)

        cols = pipeline.get_feature_columns()
        expected_fingerprint = compute_schema_fingerprint(cols)
        assert record.schema_fingerprint == expected_fingerprint
        assert record.feature_count == len(cols)

    def test_16_promotion_success(self, synthetic_adfa_df, isolated_models_env, tmp_path):
        """16. Promotion copies accepted candidate to active production model atomically."""
        csv_path = tmp_path / "adfa.csv"
        synthetic_adfa_df.to_csv(csv_path, index=False)

        lenient = {"min_recall": 0.0, "max_fpr": 1.0, "min_f1": 0.0}
        pipeline = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env, thresholds=lenient)
        accepted, record = pipeline.run(csv_path, promote=True)

        assert accepted is True
        prod_model_path = isolated_models_env / "xgboost_adfa.joblib"
        assert prod_model_path.exists()

        # Check hash of production model matches candidate
        assert compute_sha256(prod_model_path) == record.sha256_hash

        # Registry records active model
        registry = ModelRegistry(isolated_models_env)
        active_info = registry._read_registry_state()["active_models"].get("ADFA-LD_XGBOOST")
        assert active_info is not None
        assert active_info["run_id"] == record.run_id

    def test_17_rejected_candidate_does_not_replace_approved_model(
        self, synthetic_adfa_df, isolated_models_env, tmp_path
    ):
        """17. Underperforming candidate cannot replace the existing approved model."""
        csv_path = tmp_path / "adfa.csv"
        synthetic_adfa_df.to_csv(csv_path, index=False)

        # First, place a mock approved model
        prod_model_path = isolated_models_env / "xgboost_adfa.joblib"
        original_content = b"original approved model content"
        prod_model_path.write_bytes(original_content)

        # Attempt to run with impossible thresholds and promote=True
        strict = {"min_recall": 1.01}
        pipeline = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env, thresholds=strict)
        accepted, record = pipeline.run(csv_path, promote=True)

        assert accepted is False
        assert record.acceptance_decision == "REJECTED"
        assert prod_model_path.read_bytes() == original_content

    def test_18_rollback_and_preservation_of_previous_model(
        self, synthetic_adfa_df, isolated_models_env, tmp_path
    ):
        """18. Safe rollback restores previous approved model from archive."""
        csv_path = tmp_path / "adfa.csv"
        synthetic_adfa_df.to_csv(csv_path, index=False)

        lenient = {"min_recall": 0.0, "max_fpr": 1.0, "min_f1": 0.0}
        pipeline = RetrainingPipeline("ADFA-LD", "XGBOOST", models_dir=isolated_models_env, thresholds=lenient)

        # Initial model promotion (Run 1)
        accepted1, rec1 = pipeline.run(csv_path, promote=True)
        assert accepted1 is True
        hash1 = compute_sha256(isolated_models_env / "xgboost_adfa.joblib")

        # Second model promotion (Run 2)
        accepted2, rec2 = pipeline.run(csv_path, promote=True)
        assert accepted2 is True
        hash2 = compute_sha256(isolated_models_env / "xgboost_adfa.joblib")

        # Verify archive contains previous model
        registry = ModelRegistry(isolated_models_env)
        state = registry._read_registry_state()
        assert len(state["archive"]) >= 1

        # Rollback to Run 1
        success, msg = registry.rollback("ADFA-LD", "XGBOOST")
        assert success is True
        hash_after_rollback = compute_sha256(isolated_models_env / "xgboost_adfa.joblib")
        assert hash_after_rollback == hash1

    def test_19_missing_or_corrupted_artifacts(self, isolated_models_env):
        """19. Corrupted candidate artifact prevents promotion."""
        registry = ModelRegistry(isolated_models_env)
        # Create a mock run record with mismatched hash
        run_id = registry.generate_run_id("ADFA-LD", "XGBOOST")
        run_dir = isolated_models_env / "candidates" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        fake_file = run_dir / "model.joblib"
        fake_file.write_bytes(b"tampered content")

        rec = registry.register_candidate(
            model=XGBClassifier(),
            dataset="ADFA-LD",
            model_type="XGBOOST",
            feature_names=["f1", "f2"],
            train_samples=10,
            val_samples=5,
            training_config={},
            metrics={"recall": 0.9},
            acceptance_decision="ACCEPTED",
        )
        # Corrupt the artifact after registration
        fake_file.write_bytes(b"corrupted bytes after hash calculation")

        success, err = registry.promote_candidate(rec.run_id)
        assert success is False
        assert "hash mismatch" in err.lower()


# ── Test 20: CLI Behavior and Exit Codes ─────────────────────────────────────

class TestCLIExecution:
    def test_20_cli_exit_codes_and_error_reporting(
        self, synthetic_adfa_df, isolated_models_env, tmp_path, monkeypatch
    ):
        """20. CLI exit codes: 0 for success, 1 for validation failure, 2 for rejected candidate."""
        csv_path = tmp_path / "train.csv"
        synthetic_adfa_df.to_csv(csv_path, index=False)

        # 20.1: Validate-only success -> exit code 0
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "retrain_pipeline.py",
                "--dataset", "adfa",
                "--model-type", "xgboost",
                "--data", str(csv_path),
                "--models-dir", str(isolated_models_env),
                "--validate-only",
            ],
        )
        code = cli_main()
        assert code == 0

        # 20.2: Validate-only failure -> exit code 1
        bad_csv = tmp_path / "empty.csv"
        pd.DataFrame().to_csv(bad_csv)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "retrain_pipeline.py",
                "--dataset", "adfa",
                "--model-type", "xgboost",
                "--data", str(bad_csv),
                "--models-dir", str(isolated_models_env),
                "--validate-only",
            ],
        )
        code = cli_main()
        assert code == 1

        # 20.3: Retrain with lenient threshold -> exit code 0
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "retrain_pipeline.py",
                "--dataset", "adfa",
                "--model-type", "xgboost",
                "--data", str(csv_path),
                "--models-dir", str(isolated_models_env),
                "--thresholds", json.dumps({"min_recall": 0.0, "max_fpr": 1.0, "min_f1": 0.0}),
            ],
        )
        code = cli_main()
        assert code == 0

        # 20.4: Retrain rejected by acceptance criteria -> exit code 2
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "retrain_pipeline.py",
                "--dataset", "adfa",
                "--model-type", "xgboost",
                "--data", str(csv_path),
                "--models-dir", str(isolated_models_env),
                "--thresholds", json.dumps({"min_recall": 1.01}),
            ],
        )
        code = cli_main()
        assert code == 2
