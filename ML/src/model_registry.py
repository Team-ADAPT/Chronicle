"""
Model Registry and Artifact Management for Chronicle ML Retraining.

Provides candidate model staging, schema fingerprinting, artifact hashing,
acceptance tracking, and safe atomic promotion and rollback.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib

logger = logging.getLogger("chronicle.ml.registry")


def compute_sha256(filepath: Path | str) -> str:
    """Compute hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def compute_schema_fingerprint(feature_names: List[str]) -> str:
    """Compute reproducible hex SHA-256 fingerprint for a list of feature columns."""
    serialized = json.dumps(list(feature_names), sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass
class RunRecord:
    """Metadata record for a training run and its candidate model artifact."""
    run_id: str
    dataset: str
    model_type: str
    created_at: str
    sha256_hash: str
    schema_fingerprint: str
    train_samples: int
    val_samples: int
    training_config: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    acceptance_decision: str = "PENDING"  # ACCEPTED, REJECTED, PENDING
    rejection_reasons: List[str] = field(default_factory=list)
    model_path: str = ""
    feature_count: int = 0
    promoted: bool = False

    @property
    def artifact_path(self) -> str:
        return self.model_path

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["artifact_path"] = self.artifact_path
        return d


class ModelRegistry:
    """
    Manages model candidate staging, registration, promotion, and rollbacks.
    """

    MODEL_FILENAMES = {
        ("ADFA-LD", "XGBOOST"): "xgboost_adfa.joblib",
        ("ADFA-LD", "ISOLATION_FOREST"): "isolation_forest_adfa.joblib",
        ("PLAID", "XGBOOST"): "xgboost_plaid.joblib",
        ("PLAID", "ISOLATION_FOREST"): "isolation_forest_plaid.joblib",
    }

    CONFIG_FILENAMES = {
        "ADFA-LD": "adfa_training_config.json",
        "PLAID": "plaid_training_config.json",
    }

    def __init__(self, models_dir: Path | str):
        self.models_dir = Path(models_dir)
        self.candidates_dir = self.models_dir / "candidates"
        self.archive_dir = self.models_dir / "archive"
        self.state_file = self.models_dir / "registry_state.json"

        self.candidates_dir.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(parents=True, exist_ok=True)

    def _read_registry_state(self) -> Dict[str, Any]:
        """Read existing registry state or initialize fresh state."""
        if not self.state_file.exists():
            return {
                "active_models": {},
                "candidates": {},
                "archive": [],
            }
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to read registry state file %s: %s", self.state_file, e)
            return {"active_models": {}, "candidates": {}, "archive": []}

    def _write_registry_state(self, state: Dict[str, Any]) -> None:
        """Write registry state atomically."""
        tmp = self.state_file.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        tmp.replace(self.state_file)

    def generate_run_id(self, dataset: str, model_type: str) -> str:
        """Generate a reproducible run ID based on dataset, model, and timestamp."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"{dataset.upper()}_{model_type.upper()}_{ts}"

    def get_model_filename(self, dataset: str, model_type: str) -> str:
        """Resolve production filename for dataset and model type."""
        key = (dataset.upper(), model_type.upper())
        if key in self.MODEL_FILENAMES:
            return self.MODEL_FILENAMES[key]
        return f"{model_type.lower()}_{dataset.lower()}.joblib"

    def load_approved_model(
        self, dataset: str, model_type: str
    ) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
        """Load currently active/production approved model artifact."""
        filename = self.get_model_filename(dataset, model_type)
        prod_path = self.models_dir / filename
        if not prod_path.exists():
            return None, None

        try:
            model = joblib.load(prod_path)
        except Exception as e:
            logger.warning("Failed to load approved model from %s: %s", prod_path, e)
            return None, None

        cfg_name = self.CONFIG_FILENAMES.get(dataset.upper())
        cfg = None
        if cfg_name and (self.models_dir / cfg_name).exists():
            try:
                with open(self.models_dir / cfg_name, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            except Exception:
                pass

        return model, cfg

    def register_candidate(
        self,
        model: Any,
        dataset: str,
        model_type: str,
        feature_names: List[str],
        train_samples: int,
        val_samples: int,
        training_config: Dict[str, Any],
        metrics: Dict[str, Any],
        acceptance_decision: str = "PENDING",
        rejection_reasons: Optional[List[str]] = None,
        run_id: Optional[str] = None,
    ) -> RunRecord:
        """Serialize candidate model artifact and record run metadata."""
        if not run_id:
            run_id = self.generate_run_id(dataset, model_type)
        run_dir = self.candidates_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        model_path = run_dir / "model.joblib"
        joblib.dump(model, model_path)

        sha = compute_sha256(model_path)
        schema_fingerprint = compute_schema_fingerprint(feature_names)
        now_iso = datetime.now(timezone.utc).isoformat()

        record = RunRecord(
            run_id=run_id,
            dataset=dataset.upper(),
            model_type=model_type.upper(),
            created_at=now_iso,
            sha256_hash=sha,
            schema_fingerprint=schema_fingerprint,
            train_samples=train_samples,
            val_samples=val_samples,
            training_config=training_config,
            metrics=metrics,
            acceptance_decision=acceptance_decision,
            rejection_reasons=rejection_reasons or [],
            model_path=str(model_path),
            feature_count=len(feature_names),
        )

        # Write run record JSON
        with open(run_dir / "run_record.json", "w", encoding="utf-8") as f:
            json.dump(record.to_dict(), f, indent=2)

        # Update registry state
        state = self._read_registry_state()
        state["candidates"][run_id] = record.to_dict()
        self._write_registry_state(state)

        return record

    def promote_candidate(self, run_id: str) -> Tuple[bool, str]:
        """
        Safely promote staged candidate to production model filename.
        Archives existing model to enable instant rollback.
        """
        state = self._read_registry_state()
        cand_info = state["candidates"].get(run_id)
        if not cand_info:
            return False, f"Run ID {run_id} not found in registered candidates."

        candidate_model_path = Path(cand_info["model_path"])
        if not candidate_model_path.exists():
            return False, f"Candidate artifact file missing: {candidate_model_path}"

        current_hash = compute_sha256(candidate_model_path)
        if current_hash != cand_info["sha256_hash"]:
            return False, f"Candidate artifact hash mismatch for {run_id}."

        dataset = cand_info["dataset"]
        model_type = cand_info["model_type"]
        target_filename = self.get_model_filename(dataset, model_type)
        prod_path = self.models_dir / target_filename

        # Archive existing model if it exists
        key = f"{dataset}_{model_type}"
        if prod_path.exists():
            archive_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            prev_run_id = state["active_models"].get(key, {}).get("run_id", "pre_registry")
            archive_filename = f"{target_filename}.{archive_ts}_{prev_run_id}"
            archive_path = self.archive_dir / archive_filename
            shutil.copy2(prod_path, archive_path)
            state["archive"].append({
                "key": key,
                "dataset": dataset,
                "model_type": model_type,
                "run_id": prev_run_id,
                "archived_at": datetime.now(timezone.utc).isoformat(),
                "archive_path": str(archive_path),
                "sha256_hash": compute_sha256(archive_path),
            })

        # Atomically copy candidate to production
        tmp_prod = prod_path.with_suffix(".tmp")
        shutil.copy2(candidate_model_path, tmp_prod)
        tmp_prod.replace(prod_path)

        # Update active model in registry
        state["active_models"][key] = {
            "run_id": run_id,
            "promoted_at": datetime.now(timezone.utc).isoformat(),
            "sha256_hash": current_hash,
            "model_path": str(prod_path),
        }
        cand_info["promoted"] = True
        self._write_registry_state(state)

        return True, f"Candidate {run_id} promoted to {target_filename} successfully."

    def rollback(self, dataset: str, model_type: str) -> Tuple[bool, str]:
        """Roll back active model to the most recent archived version."""
        state = self._read_registry_state()
        key = f"{dataset.upper()}_{model_type.upper()}"
        matching_archives = [a for a in state.get("archive", []) if a.get("key") == key]
        if not matching_archives:
            return False, f"No previous archive found for {key}."

        latest_archive = matching_archives[-1]
        archive_path = Path(latest_archive["archive_path"])
        if not archive_path.exists():
            return False, f"Archive file {archive_path} does not exist."

        target_filename = self.get_model_filename(dataset, model_type)
        prod_path = self.models_dir / target_filename
        tmp_prod = prod_path.with_suffix(".tmp")
        shutil.copy2(archive_path, tmp_prod)
        tmp_prod.replace(prod_path)

        state["active_models"][key] = {
            "run_id": latest_archive.get("run_id", "rolled_back"),
            "promoted_at": datetime.now(timezone.utc).isoformat(),
            "sha256_hash": compute_sha256(prod_path),
            "model_path": str(prod_path),
        }
        self._write_registry_state(state)

        return True, f"Successfully rolled back {key} from {archive_path.name}."
