"""
Training data validation module for Chronicle ML retraining.

Validates incoming data quality, schema conformity, label integrity,
duplicate distribution, and leakage boundaries before model training.
Supports ADFA-LD and PLAID feature schemas as separate pipelines, and
explicitly rejects incompatible or unmapped collector event schemas.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import numpy as np
import pandas as pd


@dataclass
class ValidationReport:
    """Summary of data validation checks and statistics."""

    is_valid: bool
    dataset_name: str
    total_records: int
    accepted_records: int
    rejected_records: int
    label_distribution: Dict[int, int] = field(default_factory=dict)
    feature_count: int = 0
    duplicate_records: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "dataset_name": self.dataset_name,
            "total_records": self.total_records,
            "accepted_records": self.accepted_records,
            "rejected_records": self.rejected_records,
            "label_distribution": self.label_distribution,
            "feature_count": self.feature_count,
            "duplicate_records": self.duplicate_records,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }

    def summary(self) -> str:
        status = "PASSED" if self.is_valid else "FAILED"
        lines = [
            f"Validation Report [{self.dataset_name}]: {status}",
            f"  Total records: {self.total_records}",
            f"  Accepted: {self.accepted_records}, Rejected: {self.rejected_records}",
            f"  Labels: {self.label_distribution}",
            f"  Features: {self.feature_count}",
            f"  Duplicates: {self.duplicate_records}",
        ]
        if self.errors:
            lines.append("  Errors:")
            for err in self.errors:
                lines.append(f"    - {err}")
        if self.warnings:
            lines.append("  Warnings:")
            for warn in self.warnings:
                lines.append(f"    - {warn}")
        return "\n".join(lines)


# Known metadata columns that may accompany feature matrices
KNOWN_METADATA_COLS: Set[str] = {
    "label",
    "category",
    "subcategory",
    "source_split",
    "file_name",
    "file_path",
    "pid",
}

# Signatures of raw collector events that cannot be used directly without feature extraction
RAW_COLLECTOR_SIGNATURE_COLS: Set[str] = {
    "event_id",
    "instance_id",
    "event_type",
    "syscall_category",
    "comm",
    "ts_epoch",
    "tid",
}


def load_authoritative_features(schema_path: Path) -> List[str]:
    """Load authoritative feature column names from schema JSON."""
    if not schema_path.exists():
        raise FileNotFoundError(f"Authoritative schema file not found: {schema_path}")
    with open(schema_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "feature_columns" in data:
        return list(data["feature_columns"])
    elif isinstance(data, dict) and "feature_names" in data:
        return list(data["feature_names"])
    elif isinstance(data, list):
        return list(data)
    else:
        raise ValueError(f"Unable to parse feature list from {schema_path}")


class TrainingDataValidator:
    """
    Validates training datasets against strict data quality and schema requirements.
    """

    def __init__(
        self,
        dataset_name: str,
        expected_features: Optional[Sequence[str]] = None,
        schema_file: Optional[Path] = None,
        require_both_classes: bool = True,
        allow_duplicates: bool = True,
    ):
        """
        Args:
            dataset_name: 'ADFA-LD' or 'PLAID' (case-insensitive) or custom name.
            expected_features: List of expected feature column names in exact order.
            schema_file: Path to feature_columns.json if expected_features not provided.
            require_both_classes: Whether both normal (0) and attack (1) labels must exist.
            allow_duplicates: If False, duplicate records cause validation failure.
        """
        self.dataset_name = dataset_name.upper()
        if expected_features is not None:
            self.expected_features = list(expected_features)
        elif schema_file is not None:
            self.expected_features = load_authoritative_features(schema_file)
        else:
            self.expected_features = []
        self.require_both_classes = require_both_classes
        self.allow_duplicates = allow_duplicates

    def validate_dataframe(
        self,
        df: pd.DataFrame,
        is_supervised: bool = True,
    ) -> Tuple[bool, ValidationReport]:
        """
        Validate a pandas DataFrame containing features and labels.

        Args:
            df: DataFrame containing candidate training data.
            is_supervised: True if validating for supervised models (requires labels),
                           False if unsupervised (labels optional, used only for eval).

        Returns:
            (is_valid, report)
        """
        errors: List[str] = []
        warnings: List[str] = []
        total_records = len(df)
        label_dist: Dict[int, int] = {}
        duplicate_count = 0

        # Check 1: Non-empty dataset
        if total_records == 0:
            errors.append("Dataset is completely empty (0 rows).")
            return False, ValidationReport(
                is_valid=False,
                dataset_name=self.dataset_name,
                total_records=0,
                accepted_records=0,
                rejected_records=0,
                errors=errors,
            )

        cols_set = set(df.columns)

        # Check 2: Raw collector data detection (incompatible schema)
        collector_matches = cols_set & RAW_COLLECTOR_SIGNATURE_COLS
        if len(collector_matches) >= 2:
            errors.append(
                f"Input data contains raw eBPF collector columns ({sorted(collector_matches)}). "
                "Raw collector events cannot be trained directly without feature extraction into "
                f"the {self.dataset_name} feature schema."
            )
            return False, ValidationReport(
                is_valid=False,
                dataset_name=self.dataset_name,
                total_records=total_records,
                accepted_records=0,
                rejected_records=total_records,
                errors=errors,
            )

        # Check 3: Schema isolation check (ADFA vs PLAID cross-contamination)
        if "PLAID" in self.dataset_name:
            adfa_indicators = [c for c in df.columns if c.startswith("sc_") and c[3:].split("_")[0].isdigit()]
            if adfa_indicators:
                errors.append(
                    f"Dataset is marked as PLAID but contains numeric ADFA-LD syscall columns "
                    f"(e.g., {adfa_indicators[:3]}). Feature schemas cannot be mixed."
                )
        elif "ADFA" in self.dataset_name:
            plaid_indicators = [c for c in df.columns if c.startswith("sc_") and not c[3:].split("_")[0].isdigit()]
            if plaid_indicators:
                errors.append(
                    f"Dataset is marked as ADFA-LD but contains string PLAID syscall columns "
                    f"(e.g., {plaid_indicators[:3]}). Feature schemas cannot be mixed."
                )

        # Check 4: Labels (for supervised training or evaluation)
        if "label" not in df.columns:
            if is_supervised:
                errors.append("Missing required 'label' column for supervised training.")
            else:
                warnings.append("No 'label' column found; unsupervised model will train without ground-truth labels.")
        else:
            # Check for NaN in labels
            nan_labels = df["label"].isna().sum()
            if nan_labels > 0:
                errors.append(f"Found {nan_labels} records with null/NaN labels.")

            # Validate label values
            valid_labels = df["label"].dropna()
            try:
                int_labels = valid_labels.astype(int)
                # Verify that casting didn't change values (e.g. 0.5 -> 0)
                if not (valid_labels == int_labels).all():
                    errors.append("Label values contain non-integer float values.")
                
                unique_labels = set(int_labels.unique())
                if not unique_labels.issubset({0, 1}):
                    invalid = unique_labels - {0, 1}
                    errors.append(f"Invalid label values detected: {invalid}. Labels must be strictly binary: 0 (normal) or 1 (attack).")
                
                for lbl in (0, 1):
                    count = int((int_labels == lbl).sum())
                    label_dist[lbl] = count

                if is_supervised and self.require_both_classes:
                    if 0 not in unique_labels:
                        errors.append("Normal class (label 0) is missing in training data.")
                    if 1 not in unique_labels:
                        errors.append("Attack class (label 1) is missing in training data.")
            except (ValueError, TypeError) as exc:
                errors.append(f"Unable to parse labels as binary integers: {exc}")

        # Check 5: Expected feature schema presence and ordering
        if self.expected_features:
            missing_features = [f for f in self.expected_features if f not in df.columns]
            if missing_features:
                sample_missing = missing_features[:5]
                errors.append(
                    f"Missing {len(missing_features)} required feature columns from schema "
                    f"(sample: {sample_missing})."
                )

            # Feature columns present
            present_features = [f for f in self.expected_features if f in df.columns]
            feature_count = len(present_features)
        else:
            # Fallback to numeric columns excluding metadata
            feature_cols = [c for c in df.columns if c not in KNOWN_METADATA_COLS]
            present_features = feature_cols
            feature_count = len(feature_cols)
            if feature_count == 0:
                errors.append("No feature columns identified in dataset.")

        # Check 6: Feature data types, NaN, Infinity
        if present_features:
            feature_df = df[present_features]

            # Check for non-numeric types
            non_numeric = feature_df.select_dtypes(exclude=[np.number]).columns.tolist()
            if non_numeric:
                errors.append(f"Non-numeric values found in feature columns: {non_numeric[:5]}")

            # Check for NaN / nulls
            null_counts = feature_df.isnull().sum()
            total_nulls = int(null_counts.sum())
            if total_nulls > 0:
                cols_with_null = null_counts[null_counts > 0].index.tolist()
                errors.append(
                    f"Found {total_nulls} null/NaN values across {len(cols_with_null)} feature columns "
                    f"(sample columns: {cols_with_null[:5]})."
                )

            # Check for Infinite values
            if not non_numeric:
                numeric_vals = feature_df.to_numpy()
                inf_count = int(np.isinf(numeric_vals).sum())
                if inf_count > 0:
                    errors.append(f"Found {inf_count} infinite values in feature data.")

            # Check 7: Duplicates
            duplicates = feature_df.duplicated()
            duplicate_count = int(duplicates.sum())
            if duplicate_count > 0:
                dup_pct = (duplicate_count / total_records) * 100
                msg = f"Found {duplicate_count} duplicate feature rows ({dup_pct:.1f}% of dataset)."
                if not self.allow_duplicates:
                    errors.append(f"{msg} Duplicate records are disallowed.")
                else:
                    warnings.append(f"{msg} Repeated process executions or common syscall patterns detected.")

        is_valid = len(errors) == 0
        accepted_records = total_records if is_valid else 0
        rejected_records = 0 if is_valid else total_records

        report = ValidationReport(
            is_valid=is_valid,
            dataset_name=self.dataset_name,
            total_records=total_records,
            accepted_records=accepted_records,
            rejected_records=rejected_records,
            label_distribution=label_dist,
            feature_count=feature_count,
            duplicate_records=duplicate_count,
            errors=errors,
            warnings=warnings,
            metadata={
                "has_category": "category" in df.columns,
                "has_pid": "pid" in df.columns,
            },
        )
        return is_valid, report


def check_split_leakage(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    feature_cols: Sequence[str],
) -> Dict[str, Any]:
    """
    Check for feature vector collisions between train and validation splits.
    Returns collision counts and overlap metrics.
    """
    train_feats = train_df[list(feature_cols)]
    val_feats = val_df[list(feature_cols)]

    train_tuples = set(map(tuple, train_feats.to_numpy().tolist()))
    val_tuples = set(map(tuple, val_feats.to_numpy().tolist()))

    overlap = train_tuples & val_tuples
    overlap_count = len(overlap)

    return {
        "train_unique_vectors": len(train_tuples),
        "val_unique_vectors": len(val_tuples),
        "overlapping_vectors": overlap_count,
        "leakage_ratio": overlap_count / max(1, len(val_tuples)),
        "has_overlap": overlap_count > 0,
    }
