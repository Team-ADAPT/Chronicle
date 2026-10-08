"""
XGBoost supervised classifier for ADFA-LD.

Usage: python3 ML/src/train_xgboost.py

Split strategy (Phase 6):
  80/20 stratified split on the full dataset.
  Stratification ensures both normal and attack classes are proportionally
  represented in train and test sets.
  Splitting is performed on individual traces (not attack categories),
  which is appropriate here because ADFA-LD traces are independent
  syscall sequences from separate process executions.
  random_state=42 for full reproducibility.

Security metric note:
  For an intrusion detection system, False Negatives (missed attacks)
  are more costly than False Positives. Attack Recall is reported
  explicitly and is the primary detection metric.
"""
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))

PROCESSED_DIR = Path(__file__).resolve().parents[1] / "DATA" / "processed"
MODELS_DIR = Path(__file__).resolve().parents[1] / "models"
RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"
RANDOM_STATE = 42
TEST_SIZE = 0.2

META_COLS = ["label", "category", "source_split", "file_name"]


def load_data():
    df = pd.read_csv(PROCESSED_DIR / "adfa_features.csv")
    with open(PROCESSED_DIR / "adfa_feature_metadata.json") as f:
        meta = json.load(f)
    feature_cols = meta["feature_names"]
    X = df[feature_cols].values
    y = df["label"].values.astype(np.int32)
    return X, y, feature_cols


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("[xgboost] Loading processed features...")
    X, y, feature_cols = load_data()
    print(f"  X shape: {X.shape}, y distribution: normal={int((y==0).sum())}, attack={int((y==1).sum())}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )
    print(f"  Train: {X_train.shape[0]}  Test: {X_test.shape[0]}")

    # Verify no duplicate rows leaked across train/test
    train_hashes = set(map(tuple, X_train.tolist()))
    test_hashes = set(map(tuple, X_test.tolist()))
    overlap = len(train_hashes & test_hashes)
    # Note: some overlap is possible for identical feature vectors (same syscall patterns)
    # but should be minimal; we report it.
    if overlap > 0:
        print(f"  [warn] {overlap} identical feature vectors appear in both splits (may indicate similar normal traces)")

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        scale_pos_weight=int((y_train == 0).sum() / max(1, (y_train == 1).sum())),
        random_state=RANDOM_STATE,
        eval_metric="logloss",
        verbosity=0,
    )

    print("[xgboost] Training...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["normal", "attack"])

    tn, fp, fn, tp = cm.ravel()
    print(f"\n[xgboost] Results:")
    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}  (attack)")
    print(f"  Recall    : {rec:.4f}  (attack — primary security metric)")
    print(f"  F1        : {f1:.4f}")
    print(f"  TN={tn}  FP={fp}  FN={fn}  TP={tp}")
    print(f"\n{report}")

    # Feature importance
    importances = model.feature_importances_
    feat_imp = sorted(zip(feature_cols, importances), key=lambda x: -x[1])
    print("  Top 10 features:")
    for name, score in feat_imp[:10]:
        print(f"    {name:<40} {score:.4f}")

    # Save model
    model_path = MODELS_DIR / "xgboost_adfa.joblib"
    joblib.dump(model, model_path)
    print(f"\n[xgboost] Model saved: {model_path}")

    # Verify reload
    model_reloaded = joblib.load(model_path)
    y_pred_reloaded = model_reloaded.predict(X_test)
    assert np.array_equal(y_pred, y_pred_reloaded), "Reload mismatch"
    print("[xgboost] Model reload verified.")

    # Save feature schema alongside model
    feature_schema_path = MODELS_DIR / "feature_columns.json"
    with open(feature_schema_path, "w") as f:
        json.dump({"feature_columns": feature_cols}, f, indent=2)

    # Save training config
    config = {
        "model": "XGBoost",
        "dataset": "ADFA-LD",
        "n_estimators": 300,
        "max_depth": 6,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 3,
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
        "split_strategy": "stratified_80_20",
        "train_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
    }
    config_path = MODELS_DIR / "adfa_training_config.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

    # Save results
    metrics = {
        "model": "XGBoost",
        "dataset": "ADFA-LD",
        "accuracy": round(acc, 6),
        "precision_attack": round(prec, 6),
        "recall_attack": round(rec, 6),
        "f1_attack": round(f1, 6),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
        "feature_count": len(feature_cols),
        "top_features": [{"name": n, "importance": round(float(s), 6)} for n, s in feat_imp[:20]],
    }
    with open(RESULTS_DIR / "adfa_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    with open(RESULTS_DIR / "adfa_classification_report.txt", "w") as f:
        f.write("XGBoost — ADFA-LD Classification Report\n")
        f.write("=" * 50 + "\n")
        f.write(report)
        f.write(f"\nConfusion Matrix (TN FP / FN TP):\n{cm}\n")
        f.write(f"\nFalse Positives : {fp}\n")
        f.write(f"False Negatives : {fn}\n")

    # Save confusion matrix and feature importance plots
    _save_confusion_matrix_plot(cm, RESULTS_DIR / "adfa_confusion_matrix.png")
    _save_feature_importance_plot(feat_imp[:20], RESULTS_DIR / "adfa_feature_importance.png")

    print("[xgboost] All artifacts saved.")


def _save_confusion_matrix_plot(cm, path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import seaborn as sns

    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Predicted Normal", "Predicted Attack"],
        yticklabels=["Actual Normal", "Actual Attack"],
        ax=ax,
    )
    ax.set_title("XGBoost — ADFA-LD Confusion Matrix")
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[xgboost] Confusion matrix saved: {path}")


def _save_feature_importance_plot(feat_imp: list, path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    names = [f[0] for f in feat_imp]
    scores = [f[1] for f in feat_imp]

    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(names[::-1], scores[::-1], color="steelblue")
    ax.set_xlabel("XGBoost Feature Importance (gain)")
    ax.set_title("ADFA-LD — Top 20 Features")
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[xgboost] Feature importance saved: {path}")


if __name__ == "__main__":
    main()
