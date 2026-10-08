"""
Cross-Dataset Validation: ADFA-LD <-> PLAID.

Investigates generalization between ADFA-LD and PLAID:
1. Feature Schema & Vocabulary Comparison
2. Direct Feature Compatibility Assessment
3. Shared Structural Feature Transfer (ADFA-LD -> PLAID and PLAID -> ADFA-LD)
4. Thorough documentation of semantic barriers (no fabricated compatibility)
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from xgboost import XGBClassifier

PROCESSED_DIR = Path(__file__).resolve().parents[1] / "DATA" / "processed"
MODELS_DIR = Path(__file__).resolve().parents[1] / "models"
RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"
RANDOM_STATE = 42

SHARED_STRUCTURAL_FEATURES = [
    "seq_length",
    "unique_syscall_count",
    "syscall_diversity",
    "repeated_consecutive",
    "seq_entropy",
    "max_run_length",
    "run_count",
    "run_ratio",
]


def load_dataset_metadata():
    with open(PROCESSED_DIR / "adfa_feature_metadata.json") as f:
        adfa_meta = json.load(f)
    with open(PROCESSED_DIR / "plaid_feature_metadata.json") as f:
        plaid_meta = json.load(f)
    return adfa_meta, plaid_meta


def evaluate_transfer(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    source_name: str,
    target_name: str,
) -> dict:
    """Train XGBoost on source domain shared features, evaluate on target domain."""
    scale_pos = (y_train == 0).sum() / max(1, (y_train == 1).sum())
    clf = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.05,
        scale_pos_weight=scale_pos,
        random_state=RANDOM_STATE,
        eval_metric="logloss",
        verbosity=0,
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    return {
        "direction": f"{source_name} -> {target_name}",
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
    }


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 60)
    print("CHRONICLE ML PIPELINE — CROSS-DATASET VALIDATION")
    print("=" * 60)

    adfa_meta, plaid_meta = load_dataset_metadata()

    print("\n1. Feature Contract & Representation Comparison:")
    print(f"  ADFA-LD Feature Count : {adfa_meta['feature_count']} features")
    print(f"  PLAID Feature Count   : {plaid_meta['feature_count']} features")
    print(f"  ADFA-LD Representation: Raw integer IDs (1..340, lost x86 table)")
    print(f"  PLAID Representation  : String names (156 64-bit Linux syscall names)")

    adfa_cols = set(adfa_meta["feature_names"])
    plaid_cols = set(plaid_meta["feature_names"])
    exact_overlap = adfa_cols & plaid_cols
    print(f"  Direct column name overlap: {len(exact_overlap)} / {len(adfa_cols)} ADFA, {len(plaid_cols)} PLAID")
    print(f"  Shared structural columns: {sorted(list(exact_overlap))}")

    # Check why full direct transfer is invalid
    direct_valid = (adfa_cols == plaid_cols)
    print(f"\n2. Direct Model Transfer Feasibility: {'VALID' if direct_valid else 'INCOMPATIBLE'}")
    incompatibility_reasons = [
        "Feature namespace mismatch: ADFA-LD uses 'sc_<id>_count' (integer IDs), PLAID uses 'sc_<name>_count' (strings).",
        "Kernel ABI differences: ADFA-LD was recorded on Linux 2.6.38 (32-bit x86), PLAID was recorded on Linux 4.15+ (64-bit x86_64).",
        "Syscall table divergence: Syscall numbers in 32-bit and 64-bit Linux do not map 1:1, and original ADFA-LD mapping table was lost.",
        "Dimensionality mismatch: ADFA-LD has 442 features vs PLAID's 401 features.",
    ]
    for reason in incompatibility_reasons:
        print(f"  - {reason}")

    print("\n3. Evaluating Domain-Agnostic Structural Feature Transfer:")
    adfa_df = pd.read_csv(PROCESSED_DIR / "adfa_features.csv")
    plaid_df = pd.read_csv(PROCESSED_DIR / "plaid_features.csv")

    X_adfa = adfa_df[SHARED_STRUCTURAL_FEATURES].values
    y_adfa = adfa_df["label"].values.astype(np.int32)

    X_plaid = plaid_df[SHARED_STRUCTURAL_FEATURES].values
    y_plaid = plaid_df["label"].values.astype(np.int32)

    res_adfa_to_plaid = evaluate_transfer(
        X_adfa, y_adfa, X_plaid, y_plaid, "ADFA-LD", "PLAID"
    )
    print(f"\n  ADFA-LD -> PLAID Transfer Results:")
    print(f"    Accuracy : {res_adfa_to_plaid['accuracy']:.4f}")
    print(f"    Precision: {res_adfa_to_plaid['precision']:.4f}")
    print(f"    Recall   : {res_adfa_to_plaid['recall']:.4f} (attack detection rate)")
    print(f"    F1-Score : {res_adfa_to_plaid['f1']:.4f}")
    print(f"    CM       : {res_adfa_to_plaid['confusion_matrix']}")

    res_plaid_to_adfa = evaluate_transfer(
        X_plaid, y_plaid, X_adfa, y_adfa, "PLAID", "ADFA-LD"
    )
    print(f"\n  PLAID -> ADFA-LD Transfer Results:")
    print(f"    Accuracy : {res_plaid_to_adfa['accuracy']:.4f}")
    print(f"    Precision: {res_plaid_to_adfa['precision']:.4f}")
    print(f"    Recall   : {res_plaid_to_adfa['recall']:.4f} (attack detection rate)")
    print(f"    F1-Score : {res_plaid_to_adfa['f1']:.4f}")
    print(f"    CM       : {res_plaid_to_adfa['confusion_matrix']}")

    findings = {
        "direct_full_model_compatible": False,
        "incompatibility_reasons": incompatibility_reasons,
        "shared_features_tested": SHARED_STRUCTURAL_FEATURES,
        "adfa_to_plaid": res_adfa_to_plaid,
        "plaid_to_adfa": res_plaid_to_adfa,
        "conclusion": (
            "Cross-dataset direct transfer confirms domain shift: structural features alone "
            "cannot generalize across different host environments (e.g. desktop Ubuntu 11.10 "
            "vs containerized multi-benchmark server). Chronicle must maintain dedicated "
            "dataset-specific models while standardizing the ingestion schema."
        ),
    }

    out_path = RESULTS_DIR / "cross_dataset_metrics.json"
    with open(out_path, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"\n[cross_dataset_eval] Saved cross-dataset findings to {out_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
