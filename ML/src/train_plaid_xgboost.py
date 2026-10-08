"""
XGBoost supervised classifier for PLAID.

Usage: python3 ML/src/train_plaid_xgboost.py

Split strategy:
  80/20 stratified split on the full dataset.
  Stratification ensures both normal and attack classes are proportionally
  represented in train and test sets.
  random_state=42 for full reproducibility.
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

META_COLS = ["label", "category", "subcategory", "pid", "source_split", "file_name", "file_path"]


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
    print("CHRONICLE ML PIPELINE — PLAID XGBOOST TRAINING")
    print("=" * 60)

    print("[xgboost_plaid] Loading processed features...")
    X, y, categories, feature_cols = load_data()
    total_samples = len(y)
    normal_count = int((y == 0).sum())
    attack_count = int((y == 1).sum())
    print(f"  Loaded {total_samples} samples. Normal={normal_count}, Attack={attack_count}")
    print(f"  Feature count: {len(feature_cols)}")

    # Stratified 80/20 train/test split
    indices = np.arange(total_samples)
    train_idx, test_idx = train_test_split(
        indices, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    cat_test = categories[test_idx]

    print(f"  Train samples: {len(y_train)} (Normal={int((y_train==0).sum())}, Attack={int((y_train==1).sum())})")
    print(f"  Test samples : {len(y_test)} (Normal={int((y_test==0).sum())}, Attack={int((y_test==1).sum())})")

    # Handle class imbalance via scale_pos_weight
    scale_pos = (y_train == 0).sum() / max(1, (y_train == 1).sum())
    print(f"  Calculated scale_pos_weight: {scale_pos:.2f}")

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        scale_pos_weight=scale_pos,
        random_state=RANDOM_STATE,
        eval_metric="logloss",
        verbosity=0,
    )

    print("[xgboost_plaid] Training XGBoost classifier...")
    model.fit(X_train, y_train)
    print("  Model training complete.")

    print("[xgboost_plaid] Evaluating on unseen test set...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    report = classification_report(y_test, y_pred, target_names=["normal", "attack"])

    print("\n" + "=" * 50)
    print("XGBOOST EVALUATION METRICS (PLAID TEST SET)")
    print("=" * 50)
    print(f"  Overall Accuracy : {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Attack Precision : {prec:.4f}")
    print(f"  Attack Recall    : {rec:.4f}  (primary security detection metric)")
    print(f"  Attack F1-Score  : {f1:.4f}")
    print(f"  Confusion Matrix : TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print(f"  False Positive Rate: {fp / max(1, (fp + tn)):.4f}")
    print(f"  False Negative Rate: {fn / max(1, (fn + tp)):.4f}")
    print("\nClassification Report:\n" + report)

    # Per-category attack recall
    print("\nPer-Category Attack Breakdown:")
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
        print(f"  {cat:<12}: {detected}/{total_cat} detected ({cat_rec*100:.1f}%)")

    # Feature Importance
    importances = model.feature_importances_
    feat_imp = sorted(zip(feature_cols, importances), key=lambda x: -x[1])
    print("\nTop 15 Most Informative Features:")
    for name, score in feat_imp[:15]:
        print(f"  {name:<35} {score:.4f}")

    # Plot Confusion Matrix
    cm_path = RESULTS_DIR / "plaid_confusion_matrix.png"
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Normal (0)", "Attack (1)"],
        yticklabels=["Normal (0)", "Attack (1)"],
    )
    plt.title("PLAID XGBoost Confusion Matrix")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.tight_layout()
    plt.savefig(cm_path, dpi=150)
    plt.close()
    print(f"\n[xgboost_plaid] Saved confusion matrix plot to {cm_path}")

    # Plot Feature Importance
    imp_path = RESULTS_DIR / "plaid_feature_importance.png"
    top_n = 20
    top_feats = feat_imp[:top_n]
    plt.figure(figsize=(10, 6))
    plt.barh(
        [x[0] for x in reversed(top_feats)],
        [x[1] for x in reversed(top_feats)],
        color="#1f77b4",
    )
    plt.title(f"Top {top_n} Features (PLAID XGBoost)")
    plt.xlabel("Importance Weight")
    plt.tight_layout()
    plt.savefig(imp_path, dpi=150)
    plt.close()
    print(f"[xgboost_plaid] Saved feature importance plot to {imp_path}")

    # Save Model Artifact
    model_path = MODELS_DIR / "xgboost_plaid.joblib"
    joblib.dump(model, model_path)
    print(f"[xgboost_plaid] Model saved to {model_path}")

    # Verify Reload
    print("[xgboost_plaid] Verifying model reload from disk...")
    reloaded_model = joblib.load(model_path)
    reloaded_preds = reloaded_model.predict(X_test)
    assert np.array_equal(y_pred, reloaded_preds), "Reloaded model predictions mismatch"
    print("  Model reload verified successfully.")

    # Save Training Config
    config = {
        "model": "XGBoost",
        "dataset": "PLAID",
        "n_estimators": 300,
        "max_depth": 6,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 3,
        "scale_pos_weight": float(scale_pos),
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
        "split_strategy": "stratified_80_20",
        "train_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
        "feature_count": len(feature_cols),
    }
    config_path = MODELS_DIR / "plaid_training_config.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"  Saved config to {config_path}")

    # Save Metrics JSON
    metrics = {
        "model": "XGBoost",
        "dataset": "PLAID",
        "accuracy": round(acc, 6),
        "precision_attack": round(prec, 6),
        "recall_attack": round(rec, 6),
        "f1_attack": round(f1, 6),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
        "false_positive_rate": round(fp / max(1, (fp + tn)), 6),
        "false_negative_rate": round(fn / max(1, (fn + tp)), 6),
        "per_category_recall": per_category,
        "feature_count": len(feature_cols),
        "top_features": [{"name": n, "importance": round(float(s), 6)} for n, s in feat_imp[:20]],
    }
    metrics_path = RESULTS_DIR / "plaid_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Saved metrics to {metrics_path}")

    # Save Classification Report Text
    report_path = RESULTS_DIR / "plaid_classification_report.txt"
    with open(report_path, "w") as f:
        f.write("XGBoost — PLAID Classification Report\n")
        f.write("=" * 50 + "\n")
        f.write(report)
        f.write(f"\nConfusion Matrix (TN FP / FN TP):\n{cm}\n")
        f.write(f"\nFalse Positives : {fp}\n")
        f.write(f"False Negatives : {fn}\n")
        f.write("\nPer-Category Recall:\n")
        for cat, stats in per_category.items():
            f.write(f"  {cat}: {stats['detected']}/{stats['total']} ({stats['recall']*100:.2f}%)\n")
    print(f"  Saved classification report to {report_path}")

    print("=" * 60)
    print("PLAID XGBOOST TRAINING & EVALUATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
