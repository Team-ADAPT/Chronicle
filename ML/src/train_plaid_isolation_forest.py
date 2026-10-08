"""
Isolation Forest unsupervised anomaly detector for PLAID.

Usage: python3 ML/src/train_plaid_isolation_forest.py

Design:
  Isolation Forest is trained strictly on NORMAL traces (baseline).
  This reflects its role as an unsupervised anomaly detector:
  it learns the structure of normal process behaviour without access to attack labels.

  Attack traces are held out entirely from training.
  Evaluation uses the unseen test set (7,914 normal test traces + 250 attack test traces).

  Isolation Forest output mapping:
    predict() returns:  1 -> normal (inlier)
                       -1 -> anomaly (outlier)
  Chronicle convention:
    0 = normal
    1 = attack / anomaly

  Contamination parameter:
    Set to 0.05 (reflecting expected low anomaly rate in realistic server environments).
"""
import json
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))

PROCESSED_DIR = Path(__file__).resolve().parents[1] / "DATA" / "processed"
MODELS_DIR = Path(__file__).resolve().parents[1] / "models"
RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"
RANDOM_STATE = 42
TEST_SIZE = 0.2
CONTAMINATION = 0.05


def load_data():
    df = pd.read_csv(PROCESSED_DIR / "plaid_features.csv")
    with open(PROCESSED_DIR / "plaid_feature_metadata.json") as f:
        meta = json.load(f)
    feature_cols = meta["feature_names"]
    X = df[feature_cols].values
    y = df["label"].values.astype(np.int32)
    categories = df["category"].values
    return X, y, categories, feature_cols


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("CHRONICLE ML PIPELINE — PLAID ISOLATION FOREST TRAINING")
    print("=" * 60)

    print("[isolation_forest_plaid] Loading processed features...")
    X, y, categories, feature_cols = load_data()
    total_samples = len(y)

    indices = np.arange(total_samples)
    train_idx, test_idx = train_test_split(
        indices, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    cat_test = categories[test_idx]

    # Train ONLY on normal training traces
    train_normal_mask = (y_train == 0)
    X_train_normal = X_train[train_normal_mask]
    print(f"  Training on {X_train_normal.shape[0]} normal baseline traces only.")
    print(f"  Evaluating on unseen test set: {X_test.shape[0]} samples (Normal={int((y_test==0).sum())}, Attack={int((y_test==1).sum())})")
    print(f"  Contamination parameter assumption: {CONTAMINATION}")

    model = IsolationForest(
        n_estimators=300,
        max_samples="auto",
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    print("[isolation_forest_plaid] Fitting Isolation Forest...")
    model.fit(X_train_normal)
    print("  Model training complete.")

    # Evaluate on test set
    raw_preds = model.predict(X_test)
    # Remap: 1 -> 0 (normal), -1 -> 1 (anomaly)
    y_pred = np.where(raw_preds == 1, 0, 1).astype(np.int32)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    report = classification_report(y_test, y_pred, target_names=["normal", "anomaly"])

    print("\n" + "=" * 50)
    print("ISOLATION FOREST EVALUATION (PLAID TEST SET)")
    print("=" * 50)
    print(f"  Overall Accuracy : {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Anomaly Precision: {prec:.4f}")
    print(f"  Anomaly Recall   : {rec:.4f}  (attack detection rate)")
    print(f"  Anomaly F1-Score : {f1:.4f}")
    print(f"  Confusion Matrix : TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print(f"  False Positive Rate: {fp / max(1, (fp + tn)):.4f}")
    print(f"  False Negative Rate: {fn / max(1, (fn + tp)):.4f}")
    print("\nClassification Report:\n" + report)

    # Per-category attack recall
    print("\nPer-Category Anomaly Detection Breakdown:")
    per_category = {}
    attack_mask = (y_test == 1)
    test_attack_cats = cat_test[attack_mask]
    test_attack_preds = y_pred[attack_mask]
    for cat in sorted(set(test_attack_cats)):
        cat_indices = (test_attack_cats == cat)
        total_cat = int(cat_indices.sum())
        detected = int((test_attack_preds[cat_indices] == 1).sum())
        cat_rec = detected / total_cat if total_cat > 0 else 0.0
        per_category[cat] = {
            "total": total_cat,
            "detected": detected,
            "recall": round(cat_rec, 4),
        }
        print(f"  {cat:<12}: {detected}/{total_cat} flagged as anomaly ({cat_rec*100:.1f}%)")

    # Plot Confusion Matrix
    cm_path = RESULTS_DIR / "plaid_if_confusion_matrix.png"
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Oranges",
        xticklabels=["Normal (0)", "Anomaly (1)"],
        yticklabels=["Normal (0)", "Anomaly (1)"],
    )
    plt.title("PLAID Isolation Forest Confusion Matrix")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.tight_layout()
    plt.savefig(cm_path, dpi=150)
    plt.close()
    print(f"\n[isolation_forest_plaid] Saved confusion matrix plot to {cm_path}")

    # Save Model Artifact
    model_path = MODELS_DIR / "isolation_forest_plaid.joblib"
    joblib.dump(model, model_path)
    print(f"[isolation_forest_plaid] Model saved to {model_path}")

    # Verify Reload
    print("[isolation_forest_plaid] Verifying model reload from disk...")
    reloaded_model = joblib.load(model_path)
    reloaded_preds_raw = reloaded_model.predict(X_test)
    reloaded_preds = np.where(reloaded_preds_raw == 1, 0, 1).astype(np.int32)
    assert np.array_equal(y_pred, reloaded_preds), "Reloaded model predictions mismatch"
    print("  Model reload verified successfully.")

    # Update plaid_metrics.json with IF results
    metrics_path = RESULTS_DIR / "plaid_metrics.json"
    existing_metrics = {}
    if metrics_path.exists():
        with open(metrics_path) as f:
            existing_metrics = json.load(f)

    if_metrics = {
        "model": "IsolationForest",
        "dataset": "PLAID",
        "mode": "unsupervised_anomaly_detection",
        "trained_on": "normal_only",
        "contamination": CONTAMINATION,
        "n_estimators": 300,
        "accuracy": round(acc, 6),
        "precision_anomaly": round(prec, 6),
        "recall_anomaly": round(rec, 6),
        "f1_anomaly": round(f1, 6),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
        "false_positive_rate": round(fp / max(1, (fp + tn)), 6),
        "false_negative_rate": round(fn / max(1, (fn + tp)), 6),
        "per_category_recall": per_category,
    }

    if isinstance(existing_metrics, dict):
        output_metrics = {
            "xgboost": existing_metrics,
            "isolation_forest": if_metrics,
        }
    elif isinstance(existing_metrics, list):
        output_metrics = existing_metrics + [if_metrics]
    else:
        output_metrics = {"isolation_forest": if_metrics}

    with open(metrics_path, "w") as f:
        json.dump(output_metrics, f, indent=2)
    print(f"  Updated metrics in {metrics_path}")

    print("=" * 60)
    print("PLAID ISOLATION FOREST TRAINING & EVALUATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
