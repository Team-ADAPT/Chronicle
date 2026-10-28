"""
Chronicle - In-Process Machine Learning Anomaly Detection Engine
Integrates trained Scikit-learn Isolation Forest and XGBoost models
with real-time syscall trace feature extraction.
"""
from __future__ import annotations

import json
import logging
import math
import warnings
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import joblib
    import numpy as np
    import pandas as pd
    HAS_ML_DEPS = True
except ImportError:
    joblib = None
    np = None
    pd = None
    HAS_ML_DEPS = False

warnings.filterwarnings("ignore")
logger = logging.getLogger("chronicle.ml")


class PLAIDFeatureExtractor:
    """Extracts the exact 401 feature vector required by Chronicle's PLAID ML models."""

    def __init__(self, feature_columns_path: Path):
        with open(feature_columns_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.columns = data.get("feature_columns", [])
        
        # Recover vocabulary from columns
        self.vocab = sorted([c[3:-6] for c in self.columns if c.startswith("sc_") and c.endswith("_count")])
        self.vocab_set = set(self.vocab)

        # Recover bigrams
        self.bigrams: List[Tuple[str, str]] = []
        for c in self.columns:
            if c.startswith("bg_"):
                name = c[3:]
                for v in self.vocab:
                    if name.startswith(v + "_"):
                        second = name[len(v) + 1 :]
                        if second in self.vocab_set:
                            self.bigrams.append((v, second))
                            break
        self.bigram_set = set(self.bigrams)

        # Recover trigrams
        self.trigrams: List[Tuple[str, str, str]] = []
        for c in self.columns:
            if c.startswith("tg_"):
                name = c[3:]
                found = False
                for v1 in self.vocab:
                    if name.startswith(v1 + "_"):
                        rem = name[len(v1) + 1 :]
                        for v2 in self.vocab:
                            if rem.startswith(v2 + "_"):
                                v3 = rem[len(v2) + 1 :]
                                if v3 in self.vocab_set:
                                    self.trigrams.append((v1, v2, v3))
                                    found = True
                                    break
                        if found:
                            break
        self.trigram_set = set(self.trigrams)

    @staticmethod
    def _run_features(seq: List[str]) -> Tuple[int, int, float]:
        if not seq:
            return 0, 0, 0.0
        n = len(seq)
        max_run = 1
        current_run = 1
        run_count = 0
        for i in range(1, n):
            if seq[i] == seq[i - 1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                if current_run > 1:
                    run_count += 1
                current_run = 1
        if current_run > 1:
            run_count += 1
        run_ratio = run_count / n
        return max_run, run_count, run_ratio

    @staticmethod
    def _entropy(counts: Counter, total: int) -> float:
        if total == 0:
            return 0.0
        ent = 0.0
        for c in counts.values():
            if c > 0:
                p = c / total
                ent -= p * math.log2(p)
        return ent

    def extract(self, seq: List[str]) -> pd.DataFrame:
        if not seq:
            seq = ["read", "write"]
        n = len(seq)
        counts = Counter(seq)
        repeated_consecutive = sum(1 for i in range(1, n) if seq[i] == seq[i - 1])
        repetition_ratio = repeated_consecutive / max(1, n - 1)
        max_run, run_count, run_ratio = self._run_features(seq)
        entropy = self._entropy(counts, n)

        # Count targeted bigrams
        bg_counts: Dict[Tuple[str, str], int] = {bg: 0 for bg in self.bigram_set}
        for i in range(n - 1):
            pair = (seq[i], seq[i + 1])
            if pair in self.bigram_set:
                bg_counts[pair] += 1

        # Count targeted trigrams
        tg_counts: Dict[Tuple[str, str, str], int] = {tg: 0 for tg in self.trigram_set}
        for i in range(n - 2):
            triple = (seq[i], seq[i + 1], seq[i + 2])
            if triple in self.trigram_set:
                tg_counts[triple] += 1

        feat: Dict[str, float] = {
            "seq_length": float(n),
            "unique_syscall_count": float(len(counts)),
            "syscall_diversity": len(counts) / n,
            "repeated_consecutive": float(repeated_consecutive),
            "repetition_ratio": float(repetition_ratio),
            "max_run_length": float(max_run),
            "run_count": float(run_count),
            "run_ratio": float(run_ratio),
        }

        for sid in self.vocab:
            c = counts.get(sid, 0)
            feat[f"sc_{sid}_count"] = float(c)
            feat[f"sc_{sid}_freq"] = c / n

        for bg in self.bigrams:
            feat[f"bg_{bg[0]}_{bg[1]}"] = float(bg_counts.get(bg, 0))

        for tg in self.trigrams:
            feat[f"tg_{tg[0]}_{tg[1]}_{tg[2]}"] = float(tg_counts.get(tg, 0))

        feat["seq_entropy"] = float(entropy)

        # Build DataFrame with precise column alignment
        row = [feat.get(col, 0.0) for col in self.columns]
        return pd.DataFrame([row], columns=self.columns)


class MLDetectionEngine:
    """In-process machine learning inference engine for Chronicle host telemetry."""

    def __init__(self, models_dir: Path):
        self.models_dir = models_dir
        self.extractor: Optional[PLAIDFeatureExtractor] = None
        self.isolation_forest: Optional[Any] = None
        self.xgboost_model: Optional[Any] = None
        self.loaded: bool = False
        self._load_models()

    def _load_models(self) -> None:
        if not HAS_ML_DEPS:
            logger.info("Optional ML dependencies (joblib, numpy, pandas) not installed; running in statistical baseline mode.")
            self.loaded = False
            return

        try:
            plaid_cols_path = self.models_dir / "plaid_feature_columns.json"
            if_path = self.models_dir / "isolation_forest_plaid.joblib"
            xgb_path = self.models_dir / "xgboost_plaid.joblib"

            if plaid_cols_path.exists() and if_path.exists() and xgb_path.exists():
                logger.info("Loading Chronicle ML models from %s...", self.models_dir)
                self.extractor = PLAIDFeatureExtractor(plaid_cols_path)
                self.isolation_forest = joblib.load(if_path)
                self.xgboost_model = joblib.load(xgb_path)
                self.loaded = True
                logger.info("Chronicle ML Engine initialized successfully with 401 PLAID features.")
            else:
                logger.warning("ML models not found in %s; running in statistical baseline mode.", self.models_dir)
        except Exception as exc:
            logger.error("Failed to initialize ML models (%s). Falling back to statistical baselines.", exc)
            self.loaded = False

    def predict_sequence(self, syscall_sequence: List[str]) -> Dict[str, Any]:
        """
        Evaluates a sequence of syscalls using both Isolation Forest and XGBoost.
        Returns anomaly decisions, decision scores, and attack probabilities.
        """
        if not self.loaded or not self.extractor or not self.isolation_forest:
            return {
                "ml_available": False,
                "is_anomalous": False,
                "if_score": 0.0,
                "xgb_prob": 0.0,
                "xgb_attack": False,
            }

        try:
            X = self.extractor.extract(syscall_sequence)
            
            # Isolation Forest Unsupervised Anomaly Detection
            # predict returns -1 for anomaly, 1 for inlier
            # decision_function: lower/negative = more anomalous
            if_pred = int(self.isolation_forest.predict(X)[0])
            if_score = float(self.isolation_forest.decision_function(X)[0])
            is_if_anomaly = if_pred == -1 or if_score < 0.0

            # XGBoost Supervised Attack Detection
            # Note: Model was trained with scale_pos_weight=31.58 for high recall
            xgb_prob = 0.0
            if self.xgboost_model:
                probs = self.xgboost_model.predict_proba(X)[0]
                xgb_prob = float(probs[1]) if len(probs) > 1 else 0.0
            
            # An attack is flagged if Isolation Forest detects an inlier violation (score < 0.0)
            # OR XGBoost shows near-certain attack probability (> 0.992)
            xgb_attack = xgb_prob > 0.992 or (xgb_prob > 0.95 and is_if_anomaly)

            return {
                "ml_available": True,
                "is_anomalous": is_if_anomaly or xgb_attack,
                "if_pred": if_pred,
                "if_score": round(if_score, 4),
                "xgb_prob": round(xgb_prob, 4),
                "xgb_attack": xgb_attack,
                "seq_length": len(syscall_sequence),
            }
        except Exception as exc:
            logger.warning("Error during ML sequence prediction: %s", exc)
            return {
                "ml_available": True,
                "is_anomalous": False,
                "if_score": 0.0,
                "xgb_prob": 0.0,
                "xgb_attack": False,
                "error": str(exc),
            }
