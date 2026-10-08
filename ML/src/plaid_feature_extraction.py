"""
Feature extraction for PLAID syscall traces.

Features are derived purely from the string syscall sequence.
No timestamps exist in PLAID — no temporal features are fabricated.

Feature groups:
  Group 1: Sequence-level behavioural statistics (8 features)
  Group 2: Per-syscall raw frequency counts (N_VOCAB features)
  Group 3: Per-syscall normalised frequencies (N_VOCAB features)
  Group 4: Top-K bigram counts (K features)
  Group 5: Top-K trigram counts (K features)
  Group 6: Sequence Shannon entropy (1 feature)

Deterministic and serialisable via FeatureSchema.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List, Sequence, Tuple, Any

import numpy as np
import pandas as pd

TOP_BIGRAMS_K = 50
TOP_TRIGRAMS_K = 30


class FeatureSchema:
    """Holds vocabulary and top n-grams for consistent, deterministic feature extraction."""

    def __init__(
        self,
        vocab: List[str],
        top_bigrams: List[Tuple[str, str]],
        top_trigrams: List[Tuple[str, str, str]],
    ):
        self.vocab = sorted(vocab)
        self.top_bigrams = [tuple(bg) for bg in top_bigrams]
        self.top_trigrams = [tuple(tg) for tg in top_trigrams]
        self._vocab_set = set(self.vocab)
        self._bigram_set = set(self.top_bigrams)
        self._trigram_set = set(self.top_trigrams)

    def feature_names(self) -> List[str]:
        names: List[str] = [
            # Group 1: Sequence statistics
            "seq_length",
            "unique_syscall_count",
            "syscall_diversity",
            "repeated_consecutive",
            "repetition_ratio",
            "max_run_length",
            "run_count",
            "run_ratio",
        ]

        # Group 2: Raw counts
        names += [f"sc_{sid}_count" for sid in self.vocab]

        # Group 3: Normalised frequencies
        names += [f"sc_{sid}_freq" for sid in self.vocab]

        # Group 4: Bigram counts
        names += [f"bg_{bg[0]}_{bg[1]}" for bg in self.top_bigrams]

        # Group 5: Trigram counts
        names += [f"tg_{tg[0]}_{tg[1]}_{tg[2]}" for tg in self.top_trigrams]

        # Group 6: Entropy
        names.append("seq_entropy")

        return names

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vocab": self.vocab,
            "top_bigrams": [list(bg) for bg in self.top_bigrams],
            "top_trigrams": [list(tg) for tg in self.top_trigrams],
            "feature_count": len(self.feature_names()),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FeatureSchema":
        return cls(
            vocab=d["vocab"],
            top_bigrams=[tuple(bg) for bg in d["top_bigrams"]],
            top_trigrams=[tuple(tg) for tg in d["top_trigrams"]],
        )


def build_schema(
    sequences: List[List[str]],
    top_bigrams: int = TOP_BIGRAMS_K,
    top_trigrams: int = TOP_TRIGRAMS_K,
) -> FeatureSchema:
    """
    Build a FeatureSchema from sequences (typically training set only).
    Does NOT use labels (prevents leakage).
    """
    all_vocab: set = set()
    bigram_counter: Counter = Counter()
    trigram_counter: Counter = Counter()

    for seq in sequences:
        all_vocab.update(seq)
        n = len(seq)
        for i in range(n - 1):
            bigram_counter[(seq[i], seq[i + 1])] += 1
        for i in range(n - 2):
            trigram_counter[(seq[i], seq[i + 1], seq[i + 2])] += 1

    selected_bigrams = [bg for bg, _ in bigram_counter.most_common(top_bigrams)]
    selected_trigrams = [tg for tg, _ in trigram_counter.most_common(top_trigrams)]

    return FeatureSchema(
        vocab=sorted(all_vocab),
        top_bigrams=selected_bigrams,
        top_trigrams=selected_trigrams,
    )


def _sequence_entropy(counts: Counter, total: int) -> float:
    if total <= 0:
        return 0.0
    entropy = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _run_features(seq: List[str]) -> Tuple[int, int, float]:
    """Calculate (max_run_length, run_count, run_ratio)."""
    n = len(seq)
    if n == 0:
        return 0, 0, 0.0
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


def extract_features(seq: List[str], schema: FeatureSchema) -> Dict[str, float]:
    """
    Extract a deterministic feature dictionary for a single sequence using schema.
    """
    n = len(seq)
    if n == 0:
        raise ValueError("Cannot extract features from empty sequence.")

    counts: Counter = Counter(seq)
    repeated_consecutive = sum(1 for i in range(1, n) if seq[i] == seq[i - 1])
    repetition_ratio = repeated_consecutive / max(1, n - 1)
    max_run, run_count, run_ratio = _run_features(seq)
    entropy = _sequence_entropy(counts, n)

    # Fast targeted n-gram counting
    bg_counts: Dict[Tuple[str, str], int] = {bg: 0 for bg in schema._bigram_set}
    for i in range(n - 1):
        pair = (seq[i], seq[i + 1])
        if pair in schema._bigram_set:
            bg_counts[pair] += 1

    tg_counts: Dict[Tuple[str, str, str], int] = {tg: 0 for tg in schema._trigram_set}
    for i in range(n - 2):
        triple = (seq[i], seq[i + 1], seq[i + 2])
        if triple in schema._trigram_set:
            tg_counts[triple] += 1

    feat: Dict[str, float] = {}

    # Group 1: Sequence stats
    feat["seq_length"] = float(n)
    feat["unique_syscall_count"] = float(len(counts))
    feat["syscall_diversity"] = len(counts) / n
    feat["repeated_consecutive"] = float(repeated_consecutive)
    feat["repetition_ratio"] = float(repetition_ratio)
    feat["max_run_length"] = float(max_run)
    feat["run_count"] = float(run_count)
    feat["run_ratio"] = float(run_ratio)

    # Group 2 & 3: Counts and Frequencies
    for sid in schema.vocab:
        c = counts.get(sid, 0)
        feat[f"sc_{sid}_count"] = float(c)
        feat[f"sc_{sid}_freq"] = c / n

    # Group 4: Bigrams
    for bg in schema.top_bigrams:
        feat[f"bg_{bg[0]}_{bg[1]}"] = float(bg_counts.get(bg, 0))

    # Group 5: Trigrams
    for tg in schema.top_trigrams:
        feat[f"tg_{tg[0]}_{tg[1]}_{tg[2]}"] = float(tg_counts.get(tg, 0))

    # Group 6: Entropy
    feat["seq_entropy"] = float(entropy)

    return feat


def build_feature_matrix(
    records: List[Dict[str, Any]],
    schema: FeatureSchema,
) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Build (X, y) from records using schema sequentially.
    records must have 'sequence' and 'label' keys.
    """
    feature_names = schema.feature_names()
    rows = [extract_features(r["sequence"], schema) for r in records]
    X = pd.DataFrame(rows, columns=feature_names)
    y = np.array([r["label"] for r in records], dtype=np.int32)
    return X, y


def _extract_chunk(args: Tuple[List[Dict[str, Any]], Dict[str, Any]]) -> List[Dict[str, float]]:
    """Worker function for parallel feature extraction across processes."""
    chunk_records, schema_dict = args
    schema = FeatureSchema.from_dict(schema_dict)
    return [extract_features(r["sequence"], schema) for r in chunk_records]


def build_feature_matrix_parallel(
    records: List[Dict[str, Any]],
    schema: FeatureSchema,
    n_workers: int = 4,
    chunk_size: int = 2000,
) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Build (X, y) from records using multiprocessing for fast execution.
    """
    if n_workers <= 1 or len(records) < 1000:
        return build_feature_matrix(records, schema)

    from concurrent.futures import ProcessPoolExecutor

    feature_names = schema.feature_names()
    schema_dict = schema.to_dict()
    chunks = [
        (records[i : i + chunk_size], schema_dict)
        for i in range(0, len(records), chunk_size)
    ]

    rows: List[Dict[str, float]] = []
    with ProcessPoolExecutor(max_workers=n_workers) as executor:
        for chunk_rows in executor.map(_extract_chunk, chunks):
            rows.extend(chunk_rows)

    X = pd.DataFrame(rows, columns=feature_names)
    y = np.array([r["label"] for r in records], dtype=np.int32)
    return X, y

