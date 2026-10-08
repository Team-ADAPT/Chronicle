"""
ADFA-LD ML pipeline test suite.

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
from adfa_loader import load_adfa, _is_trace_file, _read_trace, ATTACK_CATEGORIES
from feature_extraction import (
    FeatureSchema,
    build_schema,
    build_feature_matrix,
    extract_features,
)
from preprocessing import parse_sequence, clean_sequence, PreprocessingError

ADFA_ROOT = Path(__file__).resolve().parents[2] / "ML" / "DATA" / "ADFA-LD"
PROCESSED_DIR = Path(__file__).resolve().parents[2] / "ML" / "DATA" / "processed"
MODELS_DIR = Path(__file__).resolve().parents[2] / "ML" / "models"


# ── Phase 1 & 2: Dataset discovery and loading ───────────────────────────────

class TestDatasetDiscovery:
    def test_adfa_root_exists(self):
        assert ADFA_ROOT.exists(), f"ADFA-LD root not found: {ADFA_ROOT}"

    def test_required_dirs_exist(self):
        for d in ["Training_Data_Master", "Validation_Data_Master", "Attack_Data_Master"]:
            assert (ADFA_ROOT / d).is_dir()

    def test_non_trace_files_excluded(self):
        from adfa_loader import _NON_TRACE_NAMES, _NON_TRACE_SUFFIXES
        ds_store = ADFA_ROOT / ".DS_Store"
        syscall_list = ADFA_ROOT / "ADFA-LD+Syscall+List.txt"
        assert not _is_trace_file(ds_store)
        assert not _is_trace_file(syscall_list)

    def test_png_excluded(self):
        fake_png = Path("Screenshot.png")
        assert not _is_trace_file(fake_png)


class TestTraceLoading:
    def setup_method(self):
        self.records = load_adfa(ADFA_ROOT)

    def test_loads_nonzero_records(self):
        assert len(self.records) > 0

    def test_expected_count(self):
        # 833 training + 1380+ validation + 746 attack
        assert len(self.records) >= 2000

    def test_all_have_sequence(self):
        for r in self.records:
            assert isinstance(r["sequence"], list)
            assert len(r["sequence"]) > 0

    def test_all_sequences_are_integers(self):
        for r in self.records[:200]:
            assert all(isinstance(x, int) for x in r["sequence"])

    def test_label_assignment(self):
        for r in self.records:
            assert r["label"] in (0, 1)

    def test_normal_label_is_zero(self):
        normals = [r for r in self.records if r["source_split"] in ("training", "validation")]
        assert all(r["label"] == 0 for r in normals)

    def test_attack_label_is_one(self):
        attacks = [r for r in self.records if r["source_split"] == "attack"]
        assert all(r["label"] == 1 for r in attacks)

    def test_attack_categories_preserved(self):
        attacks = [r for r in self.records if r["label"] == 1]
        cats = {r["category"] for r in attacks}
        for expected in ATTACK_CATEGORIES:
            assert expected in cats, f"Missing attack category: {expected}"

    def test_normal_category_is_normal(self):
        normals = [r for r in self.records if r["label"] == 0]
        assert all(r["category"] == "normal" for r in normals)

    def test_no_modification_of_raw_dataset(self):
        training_dir = ADFA_ROOT / "Training_Data_Master"
        txt_files = list(training_dir.glob("*.txt"))
        assert len(txt_files) == 833


# ── Phase 3: Preprocessing ───────────────────────────────────────────────────

class TestPreprocessing:
    def test_valid_sequence(self):
        seq, invalid = parse_sequence("6 42 120 195")
        assert seq == [6, 42, 120, 195]
        assert invalid == []

    def test_extra_whitespace(self):
        seq, invalid = parse_sequence("  6   42  120 ")
        assert seq == [6, 42, 120]

    def test_malformed_token_skipped(self):
        seq, invalid = parse_sequence("6 42 abc 120")
        assert seq == [6, 42, 120]
        assert "abc" in invalid

    def test_empty_string_raises(self):
        with pytest.raises(PreprocessingError):
            parse_sequence("   ")

    def test_all_invalid_raises(self):
        with pytest.raises(PreprocessingError):
            parse_sequence("abc xyz")

    def test_repeated_syscall_ids(self):
        seq, _ = parse_sequence("6 6 6 42 42")
        assert seq == [6, 6, 6, 42, 42]

    def test_clean_sequence_empty_raises(self):
        with pytest.raises(PreprocessingError):
            clean_sequence([])

    def test_clean_sequence_valid(self):
        result = clean_sequence([1, 2, 3])
        assert result == [1, 2, 3]

    def test_syscall_ids_not_scaled(self):
        result = clean_sequence([1, 100, 340])
        assert max(result) == 340  # IDs preserved as-is


# ── Phase 4: Feature extraction ───────────────────────────────────────────────

class TestFeatureExtraction:
    def setup_method(self):
        self.seqs = [
            [6, 42, 120, 6, 42, 6],
            [195, 3, 5, 195, 3, 5, 195],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        ]
        self.schema = build_schema(self.seqs)

    def test_schema_has_vocab(self):
        assert len(self.schema.vocab) > 0

    def test_schema_has_bigrams(self):
        assert len(self.schema.top_bigrams) > 0

    def test_feature_names_stable(self):
        names1 = self.schema.feature_names()
        names2 = self.schema.feature_names()
        assert names1 == names2

    def test_feature_count_matches_names(self):
        feat = extract_features(self.seqs[0], self.schema)
        assert len(feat) == len(self.schema.feature_names())

    def test_deterministic(self):
        f1 = extract_features(self.seqs[0], self.schema)
        f2 = extract_features(self.seqs[0], self.schema)
        assert f1 == f2

    def test_no_nan(self):
        for seq in self.seqs:
            feat = extract_features(seq, self.schema)
            assert all(not (v != v) for v in feat.values()), "NaN detected"

    def test_no_inf(self):
        for seq in self.seqs:
            feat = extract_features(seq, self.schema)
            import math
            assert all(not math.isinf(v) for v in feat.values()), "Inf detected"

    def test_seq_length_feature(self):
        feat = extract_features([1, 2, 3, 4, 5], self.schema)
        assert feat["seq_length"] == 5.0

    def test_no_label_in_features(self):
        names = self.schema.feature_names()
        assert "label" not in names
        assert "category" not in names
        assert "source_split" not in names

    def test_schema_roundtrip(self):
        d = self.schema.to_dict()
        schema2 = FeatureSchema.from_dict(d)
        assert schema2.vocab == self.schema.vocab
        assert schema2.top_bigrams == self.schema.top_bigrams

    def test_normal_and_attack_same_schema(self):
        records = load_adfa(ADFA_ROOT)
        seqs = [r["sequence"] for r in records]
        schema = build_schema(seqs)
        normal_rec = next(r for r in records if r["label"] == 0)
        attack_rec = next(r for r in records if r["label"] == 1)
        fn = extract_features(normal_rec["sequence"], schema)
        fa = extract_features(attack_rec["sequence"], schema)
        assert set(fn.keys()) == set(fa.keys())


# ── Phase 5: Processed dataset ───────────────────────────────────────────────

class TestProcessedDataset:
    def test_csv_exists(self):
        assert (PROCESSED_DIR / "adfa_features.csv").exists()

    def test_metadata_exists(self):
        assert (PROCESSED_DIR / "adfa_feature_metadata.json").exists()

    def test_csv_shape(self):
        df = pd.read_csv(PROCESSED_DIR / "adfa_features.csv")
        assert df.shape[0] > 0
        assert df.shape[1] > 10

    def test_no_nan_in_features(self):
        df = pd.read_csv(PROCESSED_DIR / "adfa_features.csv")
        with open(PROCESSED_DIR / "adfa_feature_metadata.json") as f:
            meta = json.load(f)
        feature_cols = meta["feature_names"]
        X = df[feature_cols]
        assert not X.isnull().any().any()

    def test_labels_binary(self):
        df = pd.read_csv(PROCESSED_DIR / "adfa_features.csv")
        assert set(df["label"].unique()).issubset({0, 1})

    def test_both_classes_present(self):
        df = pd.read_csv(PROCESSED_DIR / "adfa_features.csv")
        assert 0 in df["label"].values
        assert 1 in df["label"].values

    def test_feature_columns_reproducible(self):
        with open(PROCESSED_DIR / "adfa_feature_metadata.json") as f:
            meta = json.load(f)
        df = pd.read_csv(PROCESSED_DIR / "adfa_features.csv")
        for col in meta["feature_names"]:
            assert col in df.columns, f"Missing feature column: {col}"


# ── Phase 9: Model artifacts ──────────────────────────────────────────────────

class TestModelArtifacts:
    def test_xgboost_model_exists(self):
        assert (MODELS_DIR / "xgboost_adfa.joblib").exists()

    def test_isolation_forest_model_exists(self):
        assert (MODELS_DIR / "isolation_forest_adfa.joblib").exists()

    def test_feature_columns_json_exists(self):
        assert (MODELS_DIR / "feature_columns.json").exists()

    def test_training_config_exists(self):
        assert (MODELS_DIR / "adfa_training_config.json").exists()

    def test_xgboost_reloads_and_predicts(self):
        model = joblib.load(MODELS_DIR / "xgboost_adfa.joblib")
        df = pd.read_csv(PROCESSED_DIR / "adfa_features.csv")
        with open(PROCESSED_DIR / "adfa_feature_metadata.json") as f:
            meta = json.load(f)
        X = df[meta["feature_names"]].values[:10]
        preds = model.predict(X)
        assert preds.shape == (10,)
        assert set(preds).issubset({0, 1})

    def test_isolation_forest_reloads_and_predicts(self):
        model = joblib.load(MODELS_DIR / "isolation_forest_adfa.joblib")
        df = pd.read_csv(PROCESSED_DIR / "adfa_features.csv")
        with open(PROCESSED_DIR / "adfa_feature_metadata.json") as f:
            meta = json.load(f)
        X = df[meta["feature_names"]].values[:10]
        raw = model.predict(X)
        preds = np.where(raw == 1, 0, 1)
        assert preds.shape == (10,)
        assert set(preds).issubset({0, 1})

    def test_xgboost_predictions_reproducible(self):
        model = joblib.load(MODELS_DIR / "xgboost_adfa.joblib")
        df = pd.read_csv(PROCESSED_DIR / "adfa_features.csv")
        with open(PROCESSED_DIR / "adfa_feature_metadata.json") as f:
            meta = json.load(f)
        X = df[meta["feature_names"]].values[:50]
        p1 = model.predict(X)
        p2 = model.predict(X)
        assert np.array_equal(p1, p2)

    def test_feature_schema_matches_model_input(self):
        with open(MODELS_DIR / "feature_columns.json") as f:
            schema = json.load(f)
        with open(PROCESSED_DIR / "adfa_feature_metadata.json") as f:
            meta = json.load(f)
        assert schema["feature_columns"] == meta["feature_names"]
