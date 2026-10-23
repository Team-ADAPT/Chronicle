"""
Local filesystem model registry for Chronicle ML models.

Manages candidate staging, SHA-256 integrity verification, schema fingerprints,
audit trails, atomic model promotion, and instant rollback preservation.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib

logger = logging.getLogger("chronicle.ml.registry")

# Standard model filename mappings
MODEL_FILENAMES: Dict[Tuple[str, str], str] = {
    ("ADFA-LD", "XGBOOST"): "xgboost_adfa.joblib",
    ("ADFA-LD", "ISOLATION_FOREST"): "isolation_forest_adfa.joblib",
    ("PLAID", "XGBOOST"): "xgboost_plaid.joblib",
    ("PLAID", "ISOLATION_FOREST"): "isolation_forest_plaid.joblib",
}

SCHEMA_FILENAMES: Dict[str, str] = {
    "ADFA-LD": "feature_columns.json",
    "PLAID": "plaid_feature_columns.json",
}

CONFIG_FILENAMES: Dict[str, str] = {
    "ADFA-LD": "adfa_training_config.json",
    "PLAID": "plaid_training_config.json",
}


def compute_sha256(filepath: Union[Path, str]) -> str:
    """Compute hex SHA-256 digest of a file for integrity verification."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_schema_fingerprint(feature_names: List[str]) -> str:
    """Compute deterministic hex SHA-256 fingerprint for a sequence of feature names."""
    canonical = json.dumps(list(feature_names), sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass
class RunRecord:
    """Metadata record for a retraining candidate run and its artifact."""

    run_id: str
    dataset: str
    model_type: str
    created_at: str
    sha256_hash: str
    schema_fingerprint: str
    train_samples: int
    val_samples: int
    artifact_path: str = ""
    model_path: str = ""
    feature_count: int = 0
    training_config: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    acceptance_decision: str = "PENDING"  # ACCEPTED, REJECTED, PENDING
    rejection_reasons: List[str] = field(default_factory=list)
    promoted: bool = False
    promoted_at: Optional[str] = None
    baseline_run_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.model_path and self.artifact_path:
            self.model_path = self.artifact_path
        elif not self.artifact_path and self.model_path:
            self.artifact_path = self.model_path

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["artifact_path"] = self.artifact_path or self.model_path
        d["model_path"] = self.model_path or self.artifact_path
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RunRecord":
        data = dict(d)
        if "artifact_path" in data and not data.get("model_path"):
            data["model_path"] = data["artifact_path"]
        elif "model_path" in data and not data.get("artifact_path"):
            data["artifact_path"] = data["model_path"]
        valid_keys = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


class ModelRegistry:
    """
    Filesystem-backed model registry ensuring safe model lifecycle management.
    """

    MODEL_FILENAMES = MODEL_FILENAMES
    SCHEMA_FILENAMES = SCHEMA_FILENAMES
    CONFIG_FILENAMES = CONFIG_FILENAMES

    def __init__(self, models_dir: Union[Path, str]):
        self.models_dir = Path(models_dir)
        self.candidates_dir = self.models_dir / "candidates"
        self.archive_dir = self.models_dir / "archive"
        self.registry_file = self.models_dir / "registry.json"
        self.state_file = self.models_dir / "registry_state.json"

        self.candidates_dir.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        self._init_registry()

    def _init_registry(self) -> None:
        """Initialize or load the central registry index."""
        if not self.registry_file.exists() and not self.state_file.exists():
            default_state: Dict[str, Any] = {
                "active_models": {},
                "runs": {},
                "candidates": {},
                "archive": [],
            }
            self._write_registry_state(default_state)

    def _read_registry_state(self) -> Dict[str, Any]:
        """Read and reconcile registry state across registry.json and registry_state.json."""
        state: Dict[str, Any] = {
            "active_models": {},
            "runs": {},
            "candidates": {},
            "archive": [],
        }

        # Load registry.json if present
        if self.registry_file.exists():
            try:
                with open(self.registry_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        state["active_models"].update(data.get("active_models", {}))
                        state["runs"].update(data.get("runs", {}))
                        state["candidates"].update(data.get("candidates", {}))
                        state["archive"].extend(data.get("archive", []))
            except Exception as e:
                logger.warning("Failed to read registry file %s: %s", self.registry_file, e)

        # Load registry_state.json if present (reconciling legacy or parallel writes)
        if self.state_file.exists() and self.state_file.resolve() != self.registry_file.resolve():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    legacy_data = json.load(f)
                    if isinstance(legacy_data, dict):
                        for k, v in legacy_data.get("active_models", {}).items():
                            state["active_models"].setdefault(k, v)
                        for k, v in legacy_data.get("runs", {}).items():
                            state["runs"].setdefault(k, v)
                        for k, v in legacy_data.get("candidates", {}).items():
                            state["candidates"].setdefault(k, v)
                        for entry in legacy_data.get("archive", []):
                            if entry not in state["archive"]:
                                state["archive"].append(entry)
            except Exception as e:
                logger.warning("Failed to read legacy registry state %s: %s", self.state_file, e)

        # Ensure runs and candidates are unified
        for k, v in list(state["runs"].items()):
            state["candidates"].setdefault(k, v)
        for k, v in list(state["candidates"].items()):
            state["runs"].setdefault(k, v)

        return state

    def _write_registry_state(self, state: Dict[str, Any]) -> None:
        """Write registry state atomically to both registry.json and registry_state.json."""
        runs = state.setdefault("runs", {})
        candidates = state.setdefault("candidates", {})
        for k, v in list(runs.items()):
            candidates.setdefault(k, v)
        for k, v in list(candidates.items()):
            runs.setdefault(k, v)

        # Atomic write to registry.json
        tmp_registry = self.registry_file.with_suffix(".tmp")
        with open(tmp_registry, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        tmp_registry.replace(self.registry_file)

        # Atomic write to registry_state.json
        tmp_state = self.state_file.with_suffix(".tmp")
        with open(tmp_state, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        tmp_state.replace(self.state_file)

    def generate_run_id(self, dataset: str, model_type: str) -> str:
        """Generate a deterministic and timestamped unique run ID."""
        ts = time.strftime("%Y%m%d_%H%M%S")
        ds_slug = dataset.lower().replace("-", "_")
        model_slug = model_type.lower()
        return f"run_{ds_slug}_{model_slug}_{ts}"

    def get_model_filename(self, dataset: str, model_type: str) -> str:
        """Resolve production filename for dataset and model type."""
        key = (dataset.upper(), model_type.upper())
        if key in self.MODEL_FILENAMES:
            return self.MODEL_FILENAMES[key]
        return f"{model_type.lower()}_{dataset.lower()}.joblib"

    def get_approved_artifact_path(self, dataset: str, model_type: str) -> Optional[Path]:
        """Return the path to the currently approved model file in models_dir."""
        filename = self.get_model_filename(dataset, model_type)
        path = self.models_dir / filename
        return path if path.exists() else None

    def load_approved_model(
        self, dataset: str, model_type: str
    ) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
        """
        Load the approved model and its associated schema or training config from models_dir.
        """
        model_path = self.get_approved_artifact_path(dataset, model_type)
        if not model_path or not model_path.exists():
            return None, None

        metadata: Optional[Dict[str, Any]] = None
        schema_name = self.SCHEMA_FILENAMES.get(dataset.upper(), "feature_columns.json")
        schema_path = self.models_dir / schema_name
        if schema_path.exists():
            try:
                with open(schema_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
            except Exception:
                pass

        if metadata is None:
            cfg_name = self.CONFIG_FILENAMES.get(dataset.upper())
            if cfg_name and (self.models_dir / cfg_name).exists():
                try:
                    with open(self.models_dir / cfg_name, "r", encoding="utf-8") as f:
                        metadata = json.load(f)
                except Exception:
                    pass

        try:
            model = joblib.load(model_path)
            return model, metadata
        except Exception as exc:
            logger.warning("Failed to load approved model from %s: %s", model_path, exc)
            return None, metadata

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
        baseline_run_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> RunRecord:
        """
        Stage candidate model artifacts into candidate directory with full provenance.
        """
        dataset_key = dataset.upper()
        model_key = model_type.upper()
        if not run_id:
            run_id = self.generate_run_id(dataset_key, model_key)
        run_dir = self.candidates_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        # 1. Save candidate model artifact
        artifact_path = run_dir / "model.joblib"
        joblib.dump(model, artifact_path)

        # 2. Compute checksums
        sha256 = compute_sha256(artifact_path)
        schema_hash = compute_schema_fingerprint(feature_names)

        # 3. Save feature schema alongside candidate
        with open(run_dir / "feature_columns.json", "w", encoding="utf-8") as f:
            json.dump({"feature_columns": feature_names}, f, indent=2)

        # 4. Save candidate metrics
        with open(run_dir / "metrics.json", "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        # 5. Save candidate training config if provided
        if training_config:
            with open(run_dir / "training_config.json", "w", encoding="utf-8") as f:
                json.dump(training_config, f, indent=2)

        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # 6. Build record
        record = RunRecord(
            run_id=run_id,
            dataset=dataset_key,
            model_type=model_key,
            created_at=now_iso,
            artifact_path=str(artifact_path.resolve()),
            model_path=str(artifact_path.resolve()),
            sha256_hash=sha256,
            schema_fingerprint=schema_hash,
            feature_count=len(feature_names),
            train_samples=train_samples,
            val_samples=val_samples,
            training_config=training_config,
            metrics=metrics,
            acceptance_decision=acceptance_decision,
            rejection_reasons=rejection_reasons or [],
            promoted=False,
            baseline_run_id=baseline_run_id,
        )

        record_dict = record.to_dict()

        # 7. Save metadata and run_record JSONs in run directory
        with open(run_dir / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(record_dict, f, indent=2)
        with open(run_dir / "run_record.json", "w", encoding="utf-8") as f:
            json.dump(record_dict, f, indent=2)

        # 8. Update central registry index
        state = self._read_registry_state()
        state["runs"][run_id] = record_dict
        state["candidates"][run_id] = record_dict
        self._write_registry_state(state)

        return record

    def get_run(self, run_id: str) -> Optional[RunRecord]:
        """Fetch a specific run record by ID."""
        state = self._read_registry_state()
        data = state.get("runs", {}).get(run_id) or state.get("candidates", {}).get(run_id)
        if data:
            return RunRecord.from_dict(data)

        meta_file = self.candidates_dir / run_id / "metadata.json"
        if meta_file.exists():
            with open(meta_file, "r", encoding="utf-8") as f:
                return RunRecord.from_dict(json.load(f))

        rr_file = self.candidates_dir / run_id / "run_record.json"
        if rr_file.exists():
            with open(rr_file, "r", encoding="utf-8") as f:
                return RunRecord.from_dict(json.load(f))

        return None

    def promote_candidate(self, run_id: str) -> Tuple[bool, str]:
        """
        Promote an accepted candidate model to production.
        Preserves the previous approved model in archive for rollback.
        Restricted to ACCEPTED models with verified SHA-256 integrity.
        """
        record = self.get_run(run_id)
        if not record:
            return False, f"Run ID '{run_id}' not found in registry."

        if record.acceptance_decision != "ACCEPTED":
            return False, f"Cannot promote candidate '{run_id}': status is '{record.acceptance_decision}'."

        candidate_artifact = Path(record.artifact_path or record.model_path)
        if not candidate_artifact.exists():
            return False, f"Candidate artifact file missing: {candidate_artifact}"

        # Verify candidate integrity
        current_hash = compute_sha256(candidate_artifact)
        if current_hash != record.sha256_hash:
            return False, f"Candidate artifact hash mismatch ({current_hash} != {record.sha256_hash})."

        dataset_key = record.dataset
        model_key = record.model_type
        target_filename = self.get_model_filename(dataset_key, model_key)
        prod_model_path = self.models_dir / target_filename
        state = self._read_registry_state()
        active_key = f"{dataset_key}_{model_key}"
        previous_active = state.get("active_models", {}).get(active_key)

        # 1. Archive current production model if it exists
        if prod_model_path.exists():
            archive_ts = time.strftime("%Y%m%d_%H%M%S")
            archive_entry_dir = self.archive_dir / f"{active_key}_{archive_ts}"
            archive_entry_dir.mkdir(parents=True, exist_ok=True)
            archived_model_path = archive_entry_dir / target_filename
            shutil.copy2(prod_model_path, archived_model_path)

            prev_run_id = (
                previous_active.get("run_id", "pre_registry")
                if isinstance(previous_active, dict)
                else "pre_registry"
            )
            # Also preserve flat archive copy for legacy path lookups
            flat_archive_filename = f"{target_filename}.{archive_ts}_{prev_run_id}"
            shutil.copy2(prod_model_path, self.archive_dir / flat_archive_filename)

            archive_meta = {
                "key": active_key,
                "active_key": active_key,
                "dataset": dataset_key,
                "model_type": model_key,
                "run_id": prev_run_id,
                "archived_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "archived_artifact_path": str(archived_model_path.resolve()),
                "archive_path": str(archived_model_path.resolve()),
                "sha256_hash": compute_sha256(archived_model_path),
                "superseded_by_run_id": run_id,
                "previous_run_info": previous_active,
            }
            with open(archive_entry_dir / "archive_metadata.json", "w", encoding="utf-8") as f:
                json.dump(archive_meta, f, indent=2)

            state["archive"].append(archive_meta)

        # 2. Atomically copy candidate artifact to production location
        temp_prod = prod_model_path.with_suffix(".tmp")
        shutil.copy2(candidate_artifact, temp_prod)
        temp_prod.replace(prod_model_path)

        # 3. Update production feature schema and training config
        schema_file = self.SCHEMA_FILENAMES.get(dataset_key)
        if schema_file:
            cand_schema = candidate_artifact.parent / "feature_columns.json"
            if cand_schema.exists():
                shutil.copy2(cand_schema, self.models_dir / schema_file)

        config_file = self.CONFIG_FILENAMES.get(dataset_key)
        if config_file and record.training_config:
            with open(self.models_dir / config_file, "w", encoding="utf-8") as f:
                json.dump(record.training_config, f, indent=2)

        # 4. Update registry metadata
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        record.promoted = True
        record.promoted_at = now_iso
        rec_dict = record.to_dict()
        state["runs"][run_id] = rec_dict
        state["candidates"][run_id] = rec_dict
        state["active_models"][active_key] = {
            "run_id": run_id,
            "promoted_at": now_iso,
            "model_path": str(prod_model_path.resolve()),
            "sha256_hash": current_hash,
            "metrics": record.metrics,
        }
        self._write_registry_state(state)

        # Also update candidate metadata files
        with open(candidate_artifact.parent / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(rec_dict, f, indent=2)
        with open(candidate_artifact.parent / "run_record.json", "w", encoding="utf-8") as f:
            json.dump(rec_dict, f, indent=2)

        return True, f"Successfully promoted candidate '{run_id}' to active model {target_filename}."

    def rollback(self, dataset: str, model_type: str) -> Tuple[bool, str]:
        """
        Roll back to the previous approved model from the archive.
        Restores previous artifact and updates registry metadata consistently.
        """
        dataset_key = dataset.upper()
        model_key = model_type.upper()
        active_key = f"{dataset_key}_{model_key}"
        target_filename = self.get_model_filename(dataset_key, model_key)

        state = self._read_registry_state()
        archives = [
            a for a in state.get("archive", [])
            if a.get("active_key") == active_key or a.get("key") == active_key
        ]
        if not archives:
            return False, f"No previous archive found for {active_key}."

        # Pick the most recently archived model
        latest_archive = archives[-1]
        archived_path_str = latest_archive.get("archived_artifact_path") or latest_archive.get("archive_path")
        if not archived_path_str:
            return False, f"Invalid archive entry: missing artifact path for {active_key}."

        archived_artifact = Path(archived_path_str)
        if not archived_artifact.exists():
            return False, f"Archived artifact file missing at: {archived_artifact}"

        # Verify hash of archived model
        archived_hash = compute_sha256(archived_artifact)
        expected_hash = latest_archive.get("sha256_hash")
        if expected_hash and archived_hash != expected_hash:
            return False, "Archived artifact integrity check failed."

        # Atomically restore
        prod_model_path = self.models_dir / target_filename
        temp_prod = prod_model_path.with_suffix(".tmp")
        shutil.copy2(archived_artifact, temp_prod)
        temp_prod.replace(prod_model_path)

        # Update registry state
        restored_run = latest_archive.get("previous_run_info") or {}
        prev_run_id = (
            restored_run.get("run_id")
            if isinstance(restored_run, dict)
            else latest_archive.get("run_id", "restored_from_archive")
        ) or latest_archive.get("run_id", "restored_from_archive")

        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        state["active_models"][active_key] = {
            "run_id": prev_run_id,
            "promoted_at": now_iso,
            "rolled_back_at": now_iso,
            "model_path": str(prod_model_path.resolve()),
            "sha256_hash": archived_hash,
            "source_archive": str(archived_artifact.resolve()),
        }

        # Pop used archive
        state["archive"] = [a for a in state["archive"] if a != latest_archive]
        self._write_registry_state(state)

        return True, f"Successfully rolled back {active_key} from archive: {archived_artifact.name}"
