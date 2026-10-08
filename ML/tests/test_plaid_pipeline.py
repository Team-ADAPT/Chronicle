"""
PLAID ML pipeline test suite.

Run: python3 -m pytest ML/tests/ -v
"""
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from plaid_loader import load_plaid, ensure_plaid_extracted, ATTACK_CATEGORIES
from plaid_preprocessing import (
    parse_plaid_sequence,
    clean_plaid_sequence,
    validate_plaid_record,
    PreprocessingError,
)
from plaid_feature_extraction import (
    FeatureSchema,
    build_schema,
    extract_features,
    build_feature_matrix,
    _sequence_entropy,
    _run_features,
)

PLAID_DATA_DIR = Path(__file__).resolve().parents[2] / "ML" / "DATA" / "PLAID" / "uvm_ids-master" / "data"
PROCESSED_DIR = Path(__file__).resolve().parents[2] / "ML" / "DATA" / "processed"
MODELS_DIR = Path(__file__).resolve().parents[2] / "ML" / "models"
RESULTS_DIR = Path(__file__).resolve().parents[2] / "ML" / "results"


# ── Phase 1 & 2: Dataset discovery and loading ───────────────────────────────

class TestPlaidDiscovery:
    def test_plaid_data_dir_exists(self):
        assert PLAID_DATA_DIR.exists(), f"PLAID data dir not found: {PLAID_DATA_DIR}"

    def test_archive_or_extracted_dir_exists(self):
        tar_path = PLAID_DATA_DIR / "PLAID.tar.xz"
        extracted_dir = PLAID_DATA_DIR / "PLAID"
        assert tar_path.exists() or extracted_dir.exists()

    def test_required_subdirs_exist(self):
        root = ensure_plaid_extracted()
        assert (root / "attack").is_dir()
        assert (root / "baseline").is_dir()

    def test_attack_subdirs_count(self):
        root = ensure_plaid_extracted()
        attack_dirs = [d for d in (root / "attack").iterdir() if d.is_dir() and not d.name.startswith(".")]
        # 6 categories * 10 trials = 60 directories
        assert len(attack_dirs) == 60

    def test_baseline_subdirs_count(self):
        root = ensure_plaid_extracted()
        baseline_dirs = [d for d in (root / "baseline").iterdir() if d.is_dir() and not d.name.startswith(".")]
        assert len(baseline_dirs) == 18


class TestPlaidLoader:
    @pytest.fixture(scope="module")
    def sample_records(self):
        # Load sample to keep test fast
        return load_plaid(max_baseline_samples=100)

    def test_loads_records(self, sample_records):
        assert len(sample_records) > 0

    def test_expected_attack_count(self, sample_records):
        attacks = [r for r in sample_records if r["label"] == 1]
        assert len(attacks) == 1252

    def test_sample_baseline_count(self, sample_records):
        normals = [r for r in sample_records if r["label"] == 0]
        assert len(normals) == 100

    def test_record_keys(self, sample_records):
        required_keys = {"file_name", "pid", "sequence", "label", "category", "subcategory", "source_split", "file_path"}
        for r in sample_records[:20]:
            assert required_keys.issubset(r.keys())

    def test_label_binary(self, sample_records):
        labels = {r["label"] for r in sample_records}
        assert labels == {0, 1}

    def test_attack_categories_preserved(self, sample_records):
        attacks = [r for r in sample_records if r["label"] == 1]
        found_cats = set(r["category"] for r in attacks)
        assert set(ATTACK_CATEGORIES).issubset(found_cats)

    def test_normal_category_is_normal(self, sample_records):
        normals = [r for r in sample_records if r["label"] == 0]
        assert all(r["category"] == "normal" for r in normals)

    def test_all_sequences_are_strings(self, sample_records):
        for r in sample_records[:30]:
            assert isinstance(r["sequence"], list)
            assert len(r["sequence"]) > 0
            assert all(isinstance(s, str) for s in r["sequence"])

    def test_pid_is_numeric_string(self, sample_records):
        for r in sample_records[:30]:
            assert r["pid"].isdigit()


# ── Phase 3: Preprocessing ───────────────────────────────────────────────────

class TestPlaidPreprocessing:
    def test_valid_sequence(self):
        valid, inv = parse_plaid_sequence("read write openat close")
        assert valid == ["read", "write", "openat", "close"]
        assert inv == []

    def test_normalization_and_whitespace(self):
        valid, inv = parse_plaid_sequence("  READ   \t Write  \n openat ")
        assert valid == ["read", "write", "openat"]

    def test_strace_parens_handled(self):
        valid, inv = parse_plaid_sequence("read(3, 0x123) write(1, 0x456)")
        assert valid == ["read", "write"]

    def test_invalid_tokens_separated(self):
        valid, inv = parse_plaid_sequence("read 1234 +++ write")
        assert valid == ["read", "write"]
        assert inv == ["1234", "+++"]

    def test_empty_string_raises(self):
        with pytest.raises(PreprocessingError):
            parse_plaid_sequence("   ")

    def test_all_invalid_raises(self):
        with pytest.raises(PreprocessingError):
            parse_plaid_sequence("123 456 +++ ---")

    def test_clean_sequence_valid(self):
        seq = ["read", "write"]
        assert clean_plaid_sequence(seq) == seq

    def test_clean_sequence_empty_raises(self):
        with pytest.raises(PreprocessingError):
            clean_plaid_sequence([])

    def test_clean_sequence_non_string_raises(self):
        with pytest.raises(PreprocessingError):
            clean_plaid_sequence(["read", 123])

    def test_validate_plaid_record_valid(self):
        rec = {
            "file_name": "123.txt",
            "pid": "123",
            "sequence": ["read", "write"],
            "label": 1,
            "category": "ssh",
            "subcategory": "ssh_0",
            "source_split": "attack",
            "file_path": "attack/ssh_0/123.txt",
        }
        validated = validate_plaid_record(rec)
        assert validated["label"] == 1
        assert validated["sequence"] == ["read", "write"]

    def test_validate_plaid_record_invalid_label_raises(self):
        rec = {"sequence": ["read"], "label": 99, "category": "ssh"}
        with pytest.raises(PreprocessingError):
            validate_plaid_record(rec)


# ── Phase 4: Feature extraction ──────────────────────────────────────────────

class TestPlaidFeatureExtraction:
    @pytest.fixture
    def mini_schema(self):
        seqs = [
            ["openat", "read", "read", "write", "close"],
            ["read", "write", "openat", "read", "close"],
        ]
        return build_schema(seqs, top_bigrams=3, top_trigrams=2)

    def test_schema_has_vocab(self, mini_schema):
        assert len(mini_schema.vocab) > 0
        assert "read" in mini_schema.vocab

    def test_schema_has_bigrams(self, mini_schema):
        assert len(mini_schema.top_bigrams) > 0

    def test_feature_names_stable(self, mini_schema):
        names1 = mini_schema.feature_names()
        names2 = mini_schema.feature_names()
        assert names1 == names2

    def test_feature_count_matches_names(self, mini_schema):
        seq = ["openat", "read", "write", "close"]
        feat = extract_features(seq, mini_schema)
        assert len(feat) == len(mini_schema.feature_names())

    def test_deterministic(self, mini_schema):
        seq = ["openat", "read", "read", "write", "close"]
        f1 = extract_features(seq, mini_schema)
        f2 = extract_features(seq, mini_schema)
        assert f1 == f2

    def test_no_nan_no_inf(self, mini_schema):
        seq = ["openat", "read", "read", "write", "close"]
        feat = extract_features(seq, mini_schema)
        for k, v in feat.items():
            assert not np.isnan(v), f"NaN in {k}"
            assert not np.isinf(v), f"Inf in {k}"

    def test_seq_length_feature(self, mini_schema):
        seq = ["read", "write", "close"]
        feat = extract_features(seq, mini_schema)
        assert feat["seq_length"] == 3.0

    def test_entropy_calculation(self):
        from collections import Counter
        counts = Counter(["read", "read", "write", "write"])
        ent = _sequence_entropy(counts, 4)
        assert abs(ent - 1.0) < 1e-5

    def test_run_features(self):
        seq = ["read", "read", "read", "write", "close", "close"]
        max_run, count, ratio = _run_features(seq)
        assert max_run == 3
        assert count == 2
        assert abs(ratio - 2 / 6) < 1e-5

    def test_schema_serialization_roundtrip(self, mini_schema):
        d = mini_schema.to_dict()
        reloaded = FeatureSchema.from_dict(d)
        assert reloaded.vocab == mini_schema.vocab
        assert reloaded.top_bigrams == mini_schema.top_bigrams
        assert reloaded.top_trigrams == mini_schema.top_trigrams
        assert reloaded.feature_names() == mini_schema.feature_names()


# ── Phase 5: Processed dataset validation ────────────────────────────────────

class TestProcessedPlaidDataset:
    def test_csv_exists(self):
        assert (PROCESSED_DIR / "plaid_features.csv").exists()

    def test_metadata_exists(self):
        assert (PROCESSED_DIR / "plaid_feature_metadata.json").exists()

    def test_csv_shape(self):
        df = pd.read_csv(PROCESSED_DIR / "plaid_features.csv", nrows=10)
        # 401 features + 7 metadata columns = 408
        assert df.shape[1] == 408

    def test_total_sample_count(self):
        with open(PROCESSED_DIR / "plaid_feature_metadata.json") as f:
            meta = json.load(f)
        assert meta["total_traces"] == 40817
        assert meta["normal_traces"] == 39565
        assert meta["attack_traces"] == 1252

    def test_labels_binary(self):
        df = pd.read_csv(PROCESSED_DIR / "plaid_features.csv", usecols=["label"])
        labels = set(df["label"].unique())
        assert labels == {0, 1}

    def test_all_six_attack_categories_in_metadata(self):
        with open(PROCESSED_DIR / "plaid_feature_metadata.json") as f:
            meta = json.load(f)
        cats = set(meta["attack_categories"].keys())
        assert cats == {"cowroot", "ftp", "nginx", "privesc", "redis", "ssh"}


# ── Phase 7, 8, 10: Models, Serialization, and Artifacts ─────────────────────

class TestPlaidModelArtifacts:
    def test_xgboost_model_exists(self):
        assert (MODELS_DIR / "xgboost_plaid.joblib").exists()

    def test_isolation_forest_model_exists(self):
        assert (MODELS_DIR / "isolation_forest_plaid.joblib").exists()

    def test_plaid_feature_columns_json_exists(self):
        path = MODELS_DIR / "plaid_feature_columns.json"
        assert path.exists()
        with open(path) as f:
            cols = json.load(f)
        assert "feature_columns" in cols
        assert len(cols["feature_columns"]) == 401

    def test_training_config_exists(self):
        path = MODELS_DIR / "plaid_training_config.json"
        assert path.exists()
        with open(path) as f:
            cfg = json.load(f)
        assert cfg["model"] == "XGBoost"
        assert cfg["dataset"] == "PLAID"
        assert cfg["random_state"] == 42

    def test_xgboost_reloads_and_predicts(self):
        model = joblib.load(MODELS_DIR / "xgboost_plaid.joblib")
        with open(MODELS_DIR / "plaid_feature_columns.json") as f:
            cols = json.load(f)["feature_columns"]
        dummy_input = np.zeros((2, len(cols)))
        preds = model.predict(dummy_input)
        assert len(preds) == 2
        assert all(p in (0, 1) for p in preds)

    def test_isolation_forest_reloads_and_predicts(self):
        model = joblib.load(MODELS_DIR / "isolation_forest_plaid.joblib")
        with open(MODELS_DIR / "plaid_feature_columns.json") as f:
            cols = json.load(f)["feature_columns"]
        dummy_input = np.zeros((2, len(cols)))
        raw_preds = model.predict(dummy_input)
        # raw IF outputs are 1 or -1
        assert all(p in (1, -1) for p in raw_preds)
        remapped = np.where(raw_preds == 1, 0, 1)
        assert all(p in (0, 1) for p in remapped)

    def test_metrics_json_valid(self):
        path = RESULTS_DIR / "plaid_metrics.json"
        assert path.exists()
        with open(path) as f:
            metrics = json.load(f)
        assert "xgboost" in metrics
        assert "isolation_forest" in metrics
        xgb = metrics["xgboost"]
        assert xgb["recall_attack"] == 1.0  # 100% recall
        assert xgb["accuracy"] >= 0.99


# ── Phase 9: Cross-Dataset Validation ────────────────────────────────────────

class TestCrossDatasetValidation:
    def test_cross_dataset_metrics_file_exists(self):
        assert (RESULTS_DIR / "cross_dataset_metrics.json").exists()

    def test_cross_dataset_metrics_contents(self):
        with open(RESULTS_DIR / "cross_dataset_metrics.json") as f:
            data = json.load(f)
        assert data["direct_full_model_compatible"] is False
        assert len(data["incompatibility_reasons"]) > 0
        assert "adfa_to_plaid" in data
        assert "plaid_to_adfa" in data

    def test_feature_dimension_difference(self):
        with open(PROCESSED_DIR / "adfa_feature_metadata.json") as f:
            adfa_meta = json.load(f)
        with open(PROCESSED_DIR / "plaid_feature_metadata.json") as f:
            plaid_meta = json.load(f)
        assert adfa_meta["feature_count"] == 442
        assert plaid_meta["feature_count"] == 401
