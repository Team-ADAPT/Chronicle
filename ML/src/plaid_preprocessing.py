"""
Preprocessing for PLAID syscall traces.

Normalizes and validates system call traces composed of string names.
Syscall names are categorical identifiers.
"""
import re
from typing import List, Tuple, Dict, Any


class PreprocessingError(Exception):
    """Raised when a trace fails preprocessing validation."""
    pass


# Valid Linux system call names are lowercase alphanumeric plus underscores
_VALID_SYSCALL_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


def parse_plaid_sequence(raw: str) -> Tuple[List[str], List[str]]:
    """
    Parse a raw PLAID trace string of space-separated syscall names.

    Returns:
        (valid_tokens, invalid_tokens)

    Strips whitespace, converts to lowercase, skips non-conforming tokens.
    Raises PreprocessingError if no valid tokens remain.
    """
    tokens = raw.strip().split()
    valid: List[str] = []
    invalid: List[str] = []

    for t in tokens:
        clean_t = t.strip().lower()
        # Clean any trailing or leading punctuation if strace remnants exist
        clean_t = clean_t.split("(")[0].strip()
        if clean_t and _VALID_SYSCALL_PATTERN.match(clean_t):
            valid.append(clean_t)
        else:
            invalid.append(t)

    if not valid:
        raise PreprocessingError(f"No valid syscall tokens in sequence: {raw!r:.80}")

    return valid, invalid


def clean_plaid_sequence(seq: List[str]) -> List[str]:
    """
    Validate an already-parsed sequence of syscall names.
    Raises PreprocessingError if sequence is empty or contains non-string elements.
    """
    if not seq:
        raise PreprocessingError("Empty syscall sequence.")
    for s in seq:
        if not isinstance(s, str) or not s:
            raise PreprocessingError(f"Invalid syscall token in sequence: {s!r}")
    return seq


def validate_plaid_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and clean a complete PLAID record dictionary.
    Ensures all metadata and sequence integrity are preserved.
    """
    if "sequence" not in record or not record["sequence"]:
        raise PreprocessingError("Record missing valid sequence.")
    if "label" not in record or record["label"] not in (0, 1):
        raise PreprocessingError(f"Invalid or missing label: {record.get('label')}")
    if "category" not in record or not record["category"]:
        raise PreprocessingError("Record missing category metadata.")

    clean_seq = clean_plaid_sequence(record["sequence"])
    return {
        **record,
        "sequence": clean_seq,
    }
