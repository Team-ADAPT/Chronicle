"""
Raw syscall trace preprocessing.

Converts raw space-separated integer strings into validated integer sequences.
Syscall IDs are categorical identifiers — they are NOT scaled.
"""
from typing import List, Tuple


class PreprocessingError(Exception):
    pass


def parse_sequence(raw: str) -> Tuple[List[int], List[str]]:
    """
    Parse a raw syscall trace string.

    Returns (valid_tokens, invalid_tokens).
    Strips whitespace, skips non-integer tokens (recorded in invalid_tokens).
    Raises PreprocessingError if no valid tokens remain.
    """
    tokens = raw.strip().split()
    valid: List[int] = []
    invalid: List[str] = []
    for t in tokens:
        try:
            valid.append(int(t))
        except ValueError:
            invalid.append(t)
    if not valid:
        raise PreprocessingError(f"No valid syscall tokens in sequence: {raw!r:.80}")
    return valid, invalid


def clean_sequence(seq: List[int]) -> List[int]:
    """
    Validate an already-parsed integer sequence.
    Raises PreprocessingError if the sequence is empty.
    Syscall IDs are returned as-is (categorical, not scaled).
    """
    if not seq:
        raise PreprocessingError("Empty syscall sequence.")
    return seq
