"""
Automated Model Retraining & Validation Pipeline for Chronicle.

Orchestrates:
1. Input data and schema validation
2. Leakage-safe train/validation splitting
3. Candidate model training (XGBoost supervised or Isolation Forest unsupervised)
4. Comprehensive evaluation against fixed validation data
5. Side-by-side comparison against currently approved production model
6. Configurable acceptance gates and regression prevention
7. Candidate artifact serialization and staging in ModelRegistry
8. Safe atomic promotion with rollback backup
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
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
from xgboost import XGBClassifier

# Path setup
SRC_DIR = Path(__file__).resolve().parent
REPO_ROOT = SRC_DIR.parents[1]
MODELS_DIR = REPO_ROOT / "ML" / "models"
RESULTS_DIR = REPO_ROOT / "ML" / "results"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from model_registry import ModelRegistry, RunRecord
from validate_training_data import TrainingDataValidator, ValidationReport, check_split_leakage

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("chronicle.retrain")

RANDOM_STATE = 42
DEFAULT_TEST_SIZE = 0.2

# Default acceptance thresholds
DEFAULT_THRESHOLDS: Dict[str, Dict[str, float]] = {
    "XGBOOST": {
        "min_recall": 0.85,
        "min_f1": 0.80,
        "max_fpr": 0.05,
        "max_allowed_recall_drop": 0.02,
        "max_allowed_fpr_increase": 0.02,
    },
    "ISOLATION_FOREST": {
        "min_recall": 0.10,
        "min_f1": 0.05,
        "max_fpr": 0.30,
        "max_allowed_recall_drop": 0.05,
        "max_allowed_fpr_increase": 0.05,
    },
}


def load_dataset_features_and_labels(
    data_path: Path,
    feature_cols: List[str],
) -> Tuple[np.ndarray, np.ndarray, pd.DataFrame, Optional[np.ndarray]]:
    """
    Load feature matrix and labels from a validated CSV file.
    """
    df = pd.read_csv(data_path)
    X = df[feature_cols].to_numpy(dtype=np.float32)
    y = df["label"].to_numpy(dtype=np.int32) if "label" in df.columns else np.zeros(len(df), dtype=np.int32)
    categories = df["category"].to_numpy() if "category" in df.columns else None
    return X, y, df, categories


class RetrainingPipeline:
    """
    End-to-end retraining and validation workflow for Chronicle ML pipelines.
    """

    def __init__(
        self,
        dataset: str,
        model_type: str,
        models_dir: Optional[Path] = None,
        thresholds: Optional[Dict[str, float]] = None,
        random_state: int = RANDOM_STATE,
    ):
        self.dataset = dataset.upper()
        self.model_type = model_type.upper()
        self.models_dir = Path(models_dir or MODELS_DIR)
        self.registry = ModelRegistry(self.models_dir)
        self.random_state = random_state

        # Resolve authoritative schema path
        if "PLAID" in self.dataset:
            self.schema_path = self.models_dir / "plaid_feature_columns.json"
            self.default_contamination = 0.05
        else:
            self.schema_path = self.models_dir / "feature_columns.json"
            self.default_contamination = 0.25

        # Configurable thresholds
        base_thresh = DEFAULT_THRESHOLDS.get(self.model_type, DEFAULT_THRESHOLDS["XGBOOST"]).copy()
        if thresholds:
            base_thresh.update(thresholds)
        self.thresholds = base_thresh

    def get_feature_columns(self) -> List[str]:
        if not self.schema_path.exists():
            raise FileNotFoundError(f"Feature schema not found: {self.schema_path}")
        with open(self.schema_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return list(data["feature_columns"])

    def validate_data(self, data_path: Path) -> Tuple[bool, ValidationReport, pd.DataFrame]:
        """Validate candidate dataset before training."""
        logger.info("Validating dataset from %s for %s...", data_path, self.dataset)
        feature_cols = self.get_feature_columns()
        validator = TrainingDataValidator(
            dataset_name=self.dataset,
            expected_features=feature_cols,
            require_both_classes=(self.model_type == "XGBOOST"),
        )
        df = pd.read_csv(data_path)
        is_valid, report = validator.validate_dataframe(
            df,
            is_supervised=(self.model_type == "XGBOOST"),
        )
        return is_valid, report, df

    def train_xgboost(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        n_estimators: int = 300,
        max_depth: int = 6,
        learning_rate: float = 0.05,
    ) -> XGBClassifier:
        """Train XGBoost candidate classifier."""
        normal_count = int((y_train == 0).sum())
        attack_count = int((y_train == 1).sum())
        scale_pos = normal_count / max(1, attack_count)

        logger.info(
            "Training XGBoost (%s): %d train samples (normal=%d, attack=%d), scale_pos_weight=%.2f",
            self.dataset,
            len(y_train),
            normal_count,
            attack_count,
            scale_pos,
        )

        model = XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            scale_pos_weight=scale_pos,
            random_state=self.random_state,
            eval_metric="logloss",
            verbosity=0,
        )
        model.fit(X_train, y_train)
        return model

    def train_isolation_forest(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        contamination: Optional[float] = None,
        n_estimators: int = 300,
    ) -> IsolationForest:
        """
        Train Isolation Forest candidate anomaly detector.
        Trained strictly on normal samples (y == 0).
        """
        contam = contamination if contamination is not None else self.default_contamination
        normal_mask = (y_train == 0)
        X_normal = X_train[normal_mask]

        logger.info(
            "Training Isolation Forest (%s): %d normal samples (out of %d total), contamination=%.3f",
            self.dataset,
            len(X_normal),
            len(y_train),
            contam,
        )

        model = IsolationForest(
            n_estimators=n_estimators,
            max_samples="auto",
            contamination=contam,
            random_state=self.random_state,
            n_jobs=-1,
        )
        model.fit(X_normal)
        return model

    def evaluate_model(
        self,
        model: Any,
        X_val: np.ndarray,
        y_val: np.ndarray,
        categories: Optional[np.ndarray] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate candidate or approved model on validation set.
        """
        if self.model_type == "XGBOOST":
            y_pred = model.predict(X_val)
        else:
            raw_pred = model.predict(X_val)
            # IsolationForest: 1 -> normal (0), -1 -> anomaly (1)
            y_pred = np.where(raw_pred == 1, 0, 1).astype(np.int32)

        acc = float(accuracy_score(y_val, y_pred))
        prec = float(precision_score(y_val, y_pred, zero_division=0))
        rec = float(recall_score(y_val, y_pred, zero_division=0))
        f1 = float(f1_score(y_val, y_pred, zero_division=0))
        cm = confusion_matrix(y_val, y_pred, labels=[0, 1])
        tn, fp, fn, tp = [int(v) for v in cm.ravel()]

        fpr = fp / max(1, (fp + tn))
        fnr = fn / max(1, (fn + tp))

        metrics: Dict[str, Any] = {
            "accuracy": round(acc, 6),
            "precision": round(prec, 6),
            "recall": round(rec, 6),
            "f1_score": round(f1, 6),
            "confusion_matrix": {"TN": tn, "FP": fp, "FN": fn, "TP": tp},
            "false_positive_rate": round(fpr, 6),
            "false_negative_rate": round(fnr, 6),
            "total_val_samples": len(y_val),
            "attack_val_samples": int((y_val == 1).sum()),
            "normal_val_samples": int((y_val == 0).sum()),
        }

        # Per-category recall if available
        if categories is not None and (y_val == 1).any():
            per_cat: Dict[str, Any] = {}
            attack_mask = (y_val == 1)
            test_cats = categories[attack_mask]
            test_preds = y_pred[attack_mask]
            for cat in sorted(set(test_cats)):
                cat_indices = (test_cats == cat)
                tot = int(cat_indices.sum())
                det = int((test_preds[cat_indices] == 1).sum())
                cat_rec = det / tot if tot > 0 else 0.0
                per_cat[str(cat)] = {
                    "total": tot,
                    "detected": det,
                    "recall": round(cat_rec, 4),
                }
            metrics["per_category_recall"] = per_cat

        return metrics

    def check_acceptance(
        self,
        candidate_metrics: Dict[str, Any],
        baseline_metrics: Optional[Dict[str, Any]],
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Evaluate candidate metrics against minimum thresholds and baseline comparison.
        """
        rejection_reasons: List[str] = []
        comparison: Dict[str, Any] = {}

        # 1. Absolute thresholds
        cand_recall = candidate_metrics["recall"]
        cand_fpr = candidate_metrics["false_positive_rate"]
        cand_f1 = candidate_metrics["f1_score"]

        min_rec = self.thresholds["min_recall"]
        max_fpr = self.thresholds["max_fpr"]
        min_f1 = self.thresholds["min_f1"]

        if cand_recall < min_rec:
            rejection_reasons.append(
                f"Candidate recall {cand_recall:.4f} is below minimum requirement {min_rec:.4f}."
            )
        if cand_fpr > max_fpr:
            rejection_reasons.append(
                f"Candidate False Positive Rate {cand_fpr:.4f} exceeds threshold {max_fpr:.4f}."
            )
        if cand_f1 < min_f1:
            rejection_reasons.append(
                f"Candidate F1-score {cand_f1:.4f} is below minimum requirement {min_f1:.4f}."
            )

        # 2. Regression checks against approved baseline model
        if baseline_metrics is not None:
            base_recall = baseline_metrics["recall"]
            base_fpr = baseline_metrics["false_positive_rate"]
            base_f1 = baseline_metrics["f1_score"]

            recall_delta = cand_recall - base_recall
            fpr_delta = cand_fpr - base_fpr
            f1_delta = cand_f1 - base_f1

            comparison = {
                "baseline_recall": base_recall,
                "baseline_fpr": base_fpr,
                "baseline_f1": base_f1,
                "recall_delta": round(recall_delta, 6),
                "fpr_delta": round(fpr_delta, 6),
                "f1_delta": round(f1_delta, 6),
            }

            max_rec_drop = self.thresholds["max_allowed_recall_drop"]
            max_fpr_increase = self.thresholds["max_allowed_fpr_increase"]

            if recall_delta < -max_rec_drop:
                rejection_reasons.append(
                    f"Candidate attack recall regressed by {-recall_delta:.4f} "
                    f"(maximum allowed drop: {max_rec_drop:.4f})."
                )
            if fpr_delta > max_fpr_increase:
                rejection_reasons.append(
                    f"Candidate FPR increased by {fpr_delta:.4f} "
                    f"(maximum allowed increase: {max_fpr_increase:.4f})."
                )

        is_accepted = len(rejection_reasons) == 0
        return is_accepted, rejection_reasons, comparison

    def run(
        self,
        data_path: Path,
        val_data_path: Optional[Path] = None,
        promote: bool = False,
        test_size: float = DEFAULT_TEST_SIZE,
    ) -> Tuple[bool, RunRecord]:
        """
        Execute full retraining workflow.
        """
        logger.info("=" * 60)
        logger.info("STARTING CHRONICLE RETRAINING: %s [%s]", self.dataset, self.model_type)
        logger.info("=" * 60)

        # Step 1: Input Data Validation
        is_valid, val_report, df = self.validate_data(data_path)
        if not is_valid:
            logger.error("Data validation FAILED:\n%s", val_report.summary())
            raise ValueError(f"Input data failed validation: {val_report.errors}")
        logger.info("Input data validation PASSED: %d records.", val_report.accepted_records)

        feature_cols = self.get_feature_columns()

        # Step 2: Prepare Train/Validation Splits
        if val_data_path is not None:
            logger.info("Using provided validation dataset: %s", val_data_path)
            # Validate separate validation set
            val_valid, val_split_report, val_df = self.validate_data(val_data_path)
            if not val_valid:
                raise ValueError(f"Validation dataset failed validation: {val_split_report.errors}")
            train_df = df
        else:
            logger.info("Creating stratified %.0f/%.0f train/validation split...", (1 - test_size) * 100, test_size * 100)
            y_all = df["label"].to_numpy(dtype=np.int32)
            stratify = y_all if (self.model_type == "XGBOOST" and len(set(y_all)) > 1) else None
            train_df, val_df = train_test_split(
                df,
                test_size=test_size,
                stratify=stratify,
                random_state=self.random_state,
            )

        # Leakage check between splits
        leakage_info = check_split_leakage(train_df, val_df, feature_cols)
        if leakage_info["overlapping_vectors"] > 0:
            logger.warning(
                "Split leakage check: %d identical feature vectors appear in both train and val splits.",
                leakage_info["overlapping_vectors"],
            )

        X_train = train_df[feature_cols].to_numpy(dtype=np.float32)
        y_train = train_df["label"].to_numpy(dtype=np.int32) if "label" in train_df.columns else np.zeros(len(train_df), dtype=np.int32)

        X_val = val_df[feature_cols].to_numpy(dtype=np.float32)
        y_val = val_df["label"].to_numpy(dtype=np.int32) if "label" in val_df.columns else np.zeros(len(val_df), dtype=np.int32)
        val_cats = val_df["category"].to_numpy() if "category" in val_df.columns else None

        train_samples = len(X_train)
        val_samples = len(X_val)

        # Step 3: Train Candidate Model
        if self.model_type == "XGBOOST":
            model = self.train_xgboost(X_train, y_train)
            training_config = {
                "model": "XGBoost",
                "dataset": self.dataset,
                "n_estimators": 300,
                "max_depth": 6,
                "learning_rate": 0.05,
                "test_size": test_size,
                "random_state": self.random_state,
                "train_samples": train_samples,
                "val_samples": val_samples,
            }
        else:
            model = self.train_isolation_forest(X_train, y_train)
            training_config = {
                "model": "IsolationForest",
                "dataset": self.dataset,
                "contamination": self.default_contamination,
                "n_estimators": 300,
                "random_state": self.random_state,
                "train_samples": int((y_train == 0).sum()),
                "val_samples": val_samples,
            }

        # Step 4: Evaluate Candidate Model
        logger.info("Evaluating candidate model on validation set (%d samples)...", val_samples)
        cand_metrics = self.evaluate_model(model, X_val, y_val, categories=val_cats)
        logger.info(
            "Candidate metrics: Recall=%.4f, FPR=%.4f, F1=%.4f, Accuracy=%.4f",
            cand_metrics["recall"],
            cand_metrics["false_positive_rate"],
            cand_metrics["f1_score"],
            cand_metrics["accuracy"],
        )

        # Step 5: Compare Against Approved Baseline Model (if present)
        approved_model, _ = self.registry.load_approved_model(self.dataset, self.model_type)
        baseline_metrics = None
        if approved_model is not None:
            logger.info("Evaluating currently approved baseline model on identical validation set...")
            baseline_metrics = self.evaluate_model(approved_model, X_val, y_val, categories=val_cats)
            logger.info(
                "Baseline metrics: Recall=%.4f, FPR=%.4f, F1=%.4f, Accuracy=%.4f",
                baseline_metrics["recall"],
                baseline_metrics["false_positive_rate"],
                baseline_metrics["f1_score"],
                baseline_metrics["accuracy"],
            )

        # Step 6: Acceptance Gate
        is_accepted, rejection_reasons, comparison = self.check_acceptance(cand_metrics, baseline_metrics)
        decision = "ACCEPTED" if is_accepted else "REJECTED"
        logger.info("Acceptance Decision: %s", decision)
        if rejection_reasons:
            for r in rejection_reasons:
                logger.warning("  Rejection reason: %s", r)

        # Compile full metrics dictionary
        full_metrics = {
            "candidate": cand_metrics,
            "baseline": baseline_metrics,
            "comparison": comparison,
            "acceptance_thresholds": self.thresholds,
            "acceptance_decision": decision,
            "rejection_reasons": rejection_reasons,
            "leakage_check": leakage_info,
        }

        # Step 7: Register Candidate in Model Registry
        run_record = self.registry.register_candidate(
            model=model,
            dataset=self.dataset,
            model_type=self.model_type,
            feature_names=feature_cols,
            train_samples=train_samples,
            val_samples=val_samples,
            training_config=training_config,
            metrics=full_metrics,
            acceptance_decision=decision,
            rejection_reasons=rejection_reasons,
        )
        logger.info("Candidate staged in registry: %s", run_record.run_id)

        # Step 8: Safe Promotion if Requested and Accepted
        if promote:
            if is_accepted:
                logger.info("Promoting accepted candidate %s to production...", run_record.run_id)
                success, msg = self.registry.promote_candidate(run_record.run_id)
                if success:
                    run_record.promoted = True
                    logger.info("Promotion SUCCESSFUL: %s", msg)
                else:
                    logger.error("Promotion FAILED: %s", msg)
            else:
                logger.warning(
                    "Promotion requested but candidate was REJECTED. Approved model remains untouched."
                )

        return is_accepted, run_record


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Chronicle Automated Model Retraining and Validation Workflow."
    )
    parser.add_argument(
        "--dataset",
        required=True,
        choices=["adfa", "plaid", "ADFA-LD", "PLAID"],
        help="Target dataset pipeline (adfa or plaid).",
    )
    parser.add_argument(
        "--model-type",
        required=True,
        choices=["xgboost", "isolation_forest"],
        help="Model family to retrain (xgboost or isolation_forest).",
    )
    parser.add_argument(
        "--data",
        type=Path,
        help="Path to training data CSV.",
    )
    parser.add_argument(
        "--val-data",
        type=Path,
        default=None,
        help="Optional path to explicit validation data CSV.",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate input dataset quality and schema without training.",
    )
    parser.add_argument(
        "--promote",
        action="store_true",
        help="Promote candidate model to active production status if accepted.",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Roll back active production model to previous archived version.",
    )
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=MODELS_DIR,
        help="Directory where model artifacts and registry are managed.",
    )
    parser.add_argument(
        "--thresholds",
        type=str,
        default=None,
        help="JSON string or file path overriding acceptance thresholds.",
    )
    return parser


def main() -> int:
    parser = build_cli_parser()
    args = parser.parse_args()

    # Normalize dataset and model type
    ds_name = "ADFA-LD" if args.dataset.lower() == "adfa" else "PLAID"
    model_type = args.model_type.upper()

    # Handle Rollback command
    if args.rollback:
        registry = ModelRegistry(args.models_dir)
        success, msg = registry.rollback(ds_name, model_type)
        if success:
            logger.info("ROLLBACK SUCCESS: %s", msg)
            return 0
        else:
            logger.error("ROLLBACK FAILED: %s", msg)
            return 3

    # Parse custom thresholds if supplied
    custom_thresh: Optional[Dict[str, float]] = None
    if args.thresholds:
        try:
            if Path(args.thresholds).exists():
                with open(args.thresholds, "r", encoding="utf-8") as f:
                    custom_thresh = json.load(f)
            else:
                custom_thresh = json.loads(args.thresholds)
        except Exception as exc:
            logger.error("Failed to parse custom thresholds: %s", exc)
            return 3

    pipeline = RetrainingPipeline(
        dataset=ds_name,
        model_type=model_type,
        models_dir=args.models_dir,
        thresholds=custom_thresh,
    )

    if not args.data:
        logger.error("Missing required --data argument for validation / retraining.")
        return 3

    if not args.data.exists():
        logger.error("Data file does not exist: %s", args.data)
        return 3

    # Validate-only mode
    if args.validate_only:
        is_valid, report, _ = pipeline.validate_data(args.data)
        print("\n" + report.summary() + "\n")
        return 0 if is_valid else 1

    # Full Retraining and Validation run
    try:
        is_accepted, run_record = pipeline.run(
            data_path=args.data,
            val_data_path=args.val_data,
            promote=args.promote,
        )
        print("\n" + "=" * 50)
        print(f"CHRONICLE RETRAINING SUMMARY: {run_record.run_id}")
        print("=" * 50)
        print(f"  Dataset             : {run_record.dataset}")
        print(f"  Model Type          : {run_record.model_type}")
        print(f"  Acceptance Decision : {run_record.acceptance_decision}")
        print(f"  Artifact Path       : {run_record.artifact_path}")
        print(f"  SHA-256             : {run_record.sha256_hash}")
        print(f"  Promoted to Prod    : {run_record.promoted}")

        cand = run_record.metrics.get("candidate", {})
        print(f"  Recall (Attack)     : {cand.get('recall', 0.0):.4f}")
        print(f"  FPR                 : {cand.get('false_positive_rate', 0.0):.4f}")
        print(f"  F1-Score            : {cand.get('f1_score', 0.0):.4f}")
        print(f"  Accuracy            : {cand.get('accuracy', 0.0):.4f}")

        if run_record.rejection_reasons:
            print("  Rejection Reasons:")
            for r in run_record.rejection_reasons:
                print(f"    - {r}")
        print("=" * 50 + "\n")

        return 0 if is_accepted else 2

    except ValueError as val_err:
        logger.error("Validation error: %s", val_err)
        return 1
    except Exception as exc:
        logger.exception("Retraining workflow error: %s", exc)
        return 3


if __name__ == "__main__":
    sys.exit(main())
