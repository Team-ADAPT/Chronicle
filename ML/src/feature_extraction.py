"""
Feature extraction for ADFA-LD syscall traces.

Features are derived purely from the raw integer syscall sequence.
No timestamps exist in ADFA-LD — no temporal features are fabricated.

Feature schema (stable ordering — required by Chronicle inference):
  Group 1: Sequence-level statistics (8 features)
  Group 2: Per-syscall frequency counts, one per vocabulary ID (N_VOCAB features)
  Group 3: Normalised frequencies (N_VOCAB features)
  Group 4: Bigram (2-gram) top-K counts (K features)
  Group 5: Trigram (3-gram) top-K counts (K features)
  Group 6: Sequence entropy (1 feature)
  Group 7: Run-length / repetition features (3 features)

The vocabulary and top-K n-gram keys are determined from training data only
and stored in a schema object that must be reused at inference time.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List, Sequence, Tuple

import numpy as np
import pandas as pd


# How many top bigrams/trigrams to track as explicit features.
TOP_BIGRAMS = 50
TOP_TRIGRAMS = 30


class FeatureSchema:
    """Holds the vocabulary and n-gram keys required for stable feature vectors."""

    def __init__(self, vocab: List[int], top_bigrams: List[Tuple], top_trigrams: List[Tuple]):
        self.vocab = sorted(vocab)
        self.top_bigrams = top_bigrams
        self.top_trigrams = top_trigrams
        self._vocab_set = set(self.vocab)

    def feature_names(self) -> List[str]:
        names: List[str] = []

        # Group 1: sequence stats
        names += [
            "seq_length",
            "unique_syscall_count",
            "syscall_diversity",
            "repeated_consecutive",
            "mean_syscall_id",
            "std_syscall_id",
            "min_syscall_id",
            "max_syscall_id",
        ]

        # Group 2: raw counts per vocab syscall
        names += [f"sc_{sid}_count" for sid in self.vocab]

        # Group 3: normalised freq per vocab syscall
        names += [f"sc_{sid}_freq" for sid in self.vocab]

        # Group 4: bigram counts
        names += [f"bg_{a}_{b}" for (a, b) in self.top_bigrams]

        # Group 5: trigram counts
        names += [f"tg_{a}_{b}_{c}" for (a, b, c) in self.top_trigrams]

        # Group 6: entropy
        names += ["seq_entropy"]

        # Group 7: run features
        names += [
            "max_run_length",
            "run_count",
            "run_ratio",
        ]

        return names

    def to_dict(self) -> dict:
        return {
            "vocab": self.vocab,
            "top_bigrams": [list(bg) for bg in self.top_bigrams],
            "top_trigrams": [list(tg) for tg in self.top_trigrams],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FeatureSchema":
        return cls(
            vocab=d["vocab"],
            top_bigrams=[tuple(bg) for bg in d["top_bigrams"]],
            top_trigrams=[tuple(tg) for tg in d["top_trigrams"]],
        )


def build_schema(sequences: List[List[int]]) -> FeatureSchema:
    """
    Build a FeatureSchema from training sequences only.
    Must NOT use labels — no leakage.
    """
    all_vocab: set = set()
    bigram_counter: Counter = Counter()
    trigram_counter: Counter = Counter()

    for seq in sequences:
        all_vocab.update(seq)
        for i in range(len(seq) - 1):
            bigram_counter[(seq[i], seq[i + 1])] += 1
        for i in range(len(seq) - 2):
            trigram_counter[(seq[i], seq[i + 1], seq[i + 2])] += 1

    top_bigrams = [bg for bg, _ in bigram_counter.most_common(TOP_BIGRAMS)]
    top_trigrams = [tg for tg, _ in trigram_counter.most_common(TOP_TRIGRAMS)]

    return FeatureSchema(
        vocab=sorted(all_vocab),
        top_bigrams=top_bigrams,
        top_trigrams=top_trigrams,
    )


def _sequence_entropy(counts: Counter, total: int) -> float:
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _run_features(seq: List[int]) -> Tuple[int, int, float]:
    """Returns (max_run_length, run_count, run_ratio)."""
    if not seq:
        return 0, 0, 0.0
    max_run = 1
    current_run = 1
    run_count = 0
    for i in range(1, len(seq)):
        if seq[i] == seq[i - 1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            if current_run > 1:
                run_count += 1
            current_run = 1
    if current_run > 1:
        run_count += 1
    run_ratio = run_count / len(seq)
    return max_run, run_count, run_ratio


def extract_features(seq: List[int], schema: FeatureSchema) -> Dict[str, float]:
    n = len(seq)
    counts: Counter = Counter(seq)
    arr = np.array(seq, dtype=np.float64)

    repeated_consecutive = sum(1 for i in range(1, n) if seq[i] == seq[i - 1])

    bigram_counts: Counter = Counter()
    for i in range(n - 1):
        bigram_counts[(seq[i], seq[i + 1])] += 1

    trigram_counts: Counter = Counter()
    for i in range(n - 2):
        trigram_counts[(seq[i], seq[i + 1], seq[i + 2])] += 1

    entropy = _sequence_entropy(counts, n)
    max_run, run_count, run_ratio = _run_features(seq)

    feat: Dict[str, float] = {}

    # Group 1
    feat["seq_length"] = float(n)
    feat["unique_syscall_count"] = float(len(counts))
    feat["syscall_diversity"] = len(counts) / n
    feat["repeated_consecutive"] = float(repeated_consecutive)
    feat["mean_syscall_id"] = float(arr.mean())
    feat["std_syscall_id"] = float(arr.std())
    feat["min_syscall_id"] = float(arr.min())
    feat["max_syscall_id"] = float(arr.max())

    # Group 2 & 3
    for sid in schema.vocab:
        c = counts.get(sid, 0)
        feat[f"sc_{sid}_count"] = float(c)
        feat[f"sc_{sid}_freq"] = c / n

    # Group 4
    for bg in schema.top_bigrams:
        feat[f"bg_{bg[0]}_{bg[1]}"] = float(bigram_counts.get(bg, 0))

    # Group 5
    for tg in schema.top_trigrams:
        feat[f"tg_{tg[0]}_{tg[1]}_{tg[2]}"] = float(trigram_counts.get(tg, 0))

    # Group 6
    feat["seq_entropy"] = entropy

    # Group 7
    feat["max_run_length"] = float(max_run)
    feat["run_count"] = float(run_count)
    feat["run_ratio"] = run_ratio

    return feat


def build_feature_matrix(
    records: List[dict],
    schema: FeatureSchema,
) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Build (X, y) from loaded records using the given schema.
    records must already have 'sequence' and 'label' keys.
    Schema must be built from training data only before calling this.
    """
    rows = [extract_features(r["sequence"], schema) for r in records]
    X = pd.DataFrame(rows, columns=schema.feature_names())
    y = np.array([r["label"] for r in records], dtype=np.int32)
    return X, y
