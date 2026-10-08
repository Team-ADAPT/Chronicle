"""
Build processed PLAID feature dataset.

Reads raw traces -> extracts features -> saves plaid_features.csv and metadata.
Run from repository root:
    python3 ML/src/build_plaid_dataset.py
"""
import json
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))
from plaid_loader import load_plaid
from plaid_feature_extraction import build_schema, build_feature_matrix_parallel, FeatureSchema

PROCESSED_DIR = Path(__file__).resolve().parents[1] / "DATA" / "processed"
MODELS_DIR = Path(__file__).resolve().parents[1] / "models"
RANDOM_STATE = 42
TEST_SIZE = 0.2
PREPROCESSING_VERSION = "1.0.0"


def main() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("CHRONICLE ML PIPELINE — PLAID DATASET BUILDER")
    print("=" * 60)

    # 1. Load Traces
    print("[build_plaid_dataset] Loading PLAID traces...")
    t0 = time.time()
    records = load_plaid()
    t_load = time.time() - t0
    total_traces = len(records)
    print(f"  Loaded {total_traces} records in {t_load:.2f}s.")

    # 2. Extract Labels & Categories
    labels = np.array([r["label"] for r in records], dtype=np.int32)
    categories = [r["category"] for r in records]
    attack_count = int((labels == 1).sum())
    normal_count = int((labels == 0).sum())
    print(f"  Class distribution: Normal={normal_count} ({normal_count/total_traces*100:.2f}%), "
          f"Attack={attack_count} ({attack_count/total_traces*100:.2f}%)")

    attack_cats = Counter([r["category"] for r in records if r["label"] == 1])
    print(f"  Attack categories: {dict(attack_cats)}")

    # Check duplicates in raw sequences
    seq_hashes = [hash(tuple(r["sequence"])) for r in records]
    unique_seqs = len(set(seq_hashes))
    duplicate_traces = total_traces - unique_seqs
    print(f"  Unique sequences: {unique_seqs}, Duplicate sequences: {duplicate_traces}")

    # 3. Build Schema from all sequences (no labels used — no leakage)
    print("[build_plaid_dataset] Building feature schema...")
    t1 = time.time()
    all_sequences = [r["sequence"] for r in records]
    schema = build_schema(all_sequences)
    t_schema = time.time() - t1
    feature_names = schema.feature_names()
    print(f"  Vocabulary size  : {len(schema.vocab)}")
    print(f"  Top bigrams      : {len(schema.top_bigrams)}")
    print(f"  Top trigrams     : {len(schema.top_trigrams)}")
    print(f"  Total features   : {len(feature_names)} (built in {t_schema:.2f}s)")

    # 4. Extract Features
    print("[build_plaid_dataset] Extracting features in parallel...")
    t2 = time.time()
    X, y = build_feature_matrix_parallel(records, schema, n_workers=8, chunk_size=2500)
    t_extract = time.time() - t2
    print(f"  Extracted feature matrix shape={X.shape} in {t_extract:.2f}s.")

    # 5. Sanity Checks & Dataset Validation
    nan_count = int(X.isnull().sum().sum())
    inf_count = int(np.isinf(X.values).sum())
    print(f"  Missing (NaN) values: {nan_count}")
    print(f"  Infinite values     : {inf_count}")
    assert nan_count == 0, "NaN values detected in extracted features"
    assert inf_count == 0, "Infinite values detected in extracted features"

    # 6. Attach Metadata Columns (preserved for provenance, dropped for model training)
    X["label"] = y
    X["category"] = categories
    X["subcategory"] = [r["subcategory"] for r in records]
    X["pid"] = [r["pid"] for r in records]
    X["source_split"] = [r["source_split"] for r in records]
    X["file_name"] = [r["file_name"] for r in records]
    X["file_path"] = [r["file_path"] for r in records]

    # 7. Save Processed Artifacts
    out_csv = PROCESSED_DIR / "plaid_features.csv"
    print(f"[build_plaid_dataset] Saving {out_csv}...")
    X.to_csv(out_csv, index=False)
    print(f"  Saved {out_csv} (size: {out_csv.stat().st_size / 1024 / 1024:.2f} MB).")

    # Feature metadata JSON
    schema_dict = schema.to_dict()
    metadata = {
        "dataset": "PLAID",
        "preprocessing_version": PREPROCESSING_VERSION,
        "feature_names": feature_names,
        "feature_count": len(feature_names),
        "vocab": schema_dict["vocab"],
        "top_bigrams": schema_dict["top_bigrams"],
        "top_trigrams": schema_dict["top_trigrams"],
        "total_traces": total_traces,
        "normal_traces": normal_count,
        "attack_traces": attack_count,
        "attack_categories": dict(attack_cats),
        "unique_sequences": unique_seqs,
        "duplicate_sequences": duplicate_traces,
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
    }
    meta_path = PROCESSED_DIR / "plaid_feature_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Saved metadata to {meta_path}.")

    # Authoritative feature columns for inference in models/
    cols_path = MODELS_DIR / "plaid_feature_columns.json"
    with open(cols_path, "w") as f:
        json.dump({"feature_columns": feature_names}, f, indent=2)
    print(f"  Saved inference feature columns to {cols_path}.")

    # 8. Verify Reload
    print("[build_plaid_dataset] Verifying reload from disk...")
    df_reloaded = pd.read_csv(out_csv)
    assert df_reloaded.shape == X.shape, f"Reload shape mismatch: {df_reloaded.shape} vs {X.shape}"
    print(f"  Reload verified: {df_reloaded.shape}")

    print("=" * 60)
    print("PLAID DATASET BUILD COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
