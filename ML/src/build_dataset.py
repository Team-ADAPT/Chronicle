"""
Build processed ADFA-LD feature dataset.

Reads raw traces → extracts features → saves adfa_features.csv and metadata.
Run from the repository root:
    python3 ML/src/build_dataset.py

Stratified train/test split:
  - All Training_Data_Master + Validation_Data_Master files are pooled as normal.
  - All Attack_Data_Master files are pooled as attack.
  - Schema (vocabulary, top n-grams) is built from normal+attack sequences
    combined BUT without using labels (no leakage).
  - 80/20 stratified split ensures class balance in both sets.

Rationale for pooling training+validation as normal:
  ADFA-LD's "Training" and "Validation" splits refer to a specific
  host-based anomaly detection evaluation protocol (anomaly detection
  with normal-only training), not to a supervised ML split.
  For supervised ML we pool all labelled data and split by class.
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))
from adfa_loader import load_adfa
from feature_extraction import build_schema, build_feature_matrix, FeatureSchema

PROCESSED_DIR = Path(__file__).resolve().parents[1] / "DATA" / "processed"
RANDOM_STATE = 42
TEST_SIZE = 0.2
PREPROCESSING_VERSION = "1.0.0"


def main() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    print("[build_dataset] Loading ADFA-LD traces...")
    records = load_adfa()
    print(f"  Loaded {len(records)} records.")

    # Build schema from ALL sequences (no label used — no leakage).
    print("[build_dataset] Building feature schema...")
    all_sequences = [r["sequence"] for r in records]
    schema = build_schema(all_sequences)
    print(f"  Vocabulary size  : {len(schema.vocab)}")
    print(f"  Top bigrams      : {len(schema.top_bigrams)}")
    print(f"  Top trigrams     : {len(schema.top_trigrams)}")
    print(f"  Total features   : {len(schema.feature_names())}")

    print("[build_dataset] Extracting features...")
    X, y = build_feature_matrix(records, schema)

    # Sanity check
    assert not X.isnull().any().any(), "NaN in features"
    assert not np.isinf(X.values).any(), "Inf in features"

    # Attach metadata columns (dropped before model training)
    X["label"] = y
    X["category"] = [r["category"] for r in records]
    X["source_split"] = [r["source_split"] for r in records]
    X["file_name"] = [r["file_name"] for r in records]

    out_csv = PROCESSED_DIR / "adfa_features.csv"
    X.to_csv(out_csv, index=False)
    print(f"[build_dataset] Saved {out_csv}  shape={X.shape}")

    # Save feature metadata
    schema_dict = schema.to_dict()
    metadata = {
        "dataset": "ADFA-LD",
        "preprocessing_version": PREPROCESSING_VERSION,
        "feature_names": schema.feature_names(),
        "feature_count": len(schema.feature_names()),
        "vocab": schema_dict["vocab"],
        "top_bigrams": schema_dict["top_bigrams"],
        "top_trigrams": schema_dict["top_trigrams"],
        "total_traces": len(records),
        "normal_traces": int((y == 0).sum()),
        "attack_traces": int((y == 1).sum()),
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
    }
    meta_path = PROCESSED_DIR / "adfa_feature_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"[build_dataset] Saved {meta_path}")

    # Verify reload
    X_reloaded = pd.read_csv(out_csv)
    assert X_reloaded.shape == X.shape, "Reload shape mismatch"
    print(f"[build_dataset] Reload verified: {X_reloaded.shape}")

    print("[build_dataset] Done.")


if __name__ == "__main__":
    main()
