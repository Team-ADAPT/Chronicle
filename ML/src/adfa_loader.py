"""
ADFA-LD dataset loader.

Label convention: 0 = normal, 1 = attack
"""
from pathlib import Path
from typing import List, Dict, Any

_ADFA_ROOT = Path(__file__).resolve().parents[1] / "DATA" / "ADFA-LD"

_NON_TRACE_NAMES = {".DS_Store", "ADFA-LD+Syscall+List.txt"}
_NON_TRACE_SUFFIXES = {".png", ".jpg", ".jpeg", ".pdf"}

ATTACK_CATEGORIES = [
    "Adduser",
    "Hydra_FTP",
    "Hydra_SSH",
    "Java_Meterpreter",
    "Meterpreter",
    "Web_Shell",
]


def _is_trace_file(path: Path) -> bool:
    return path.suffix == ".txt" and path.name not in _NON_TRACE_NAMES


def _read_trace(path: Path) -> List[int] | None:
    """Return integer syscall list or None on parse failure."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return None
        tokens = text.split()
        return [int(t) for t in tokens]
    except (ValueError, OSError):
        return None


def _category_from_dir(directory: Path) -> str:
    """Extract base attack category name from attack subdirectory (e.g. Adduser_1 → Adduser)."""
    name = directory.name
    for cat in ATTACK_CATEGORIES:
        if name.startswith(cat):
            return cat
    return name


def load_adfa(adfa_root: Path = _ADFA_ROOT) -> List[Dict[str, Any]]:
    """
    Load all ADFA-LD traces.

    Returns list of dicts with keys:
        file_name     – stem of source file
        sequence      – list[int] of syscall IDs
        label         – 0 (normal) or 1 (attack)
        category      – "normal" or attack category name
        source_split  – "training" | "validation" | "attack"

    Files that fail to parse are skipped; failures logged to stderr.
    """
    records: List[Dict[str, Any]] = []
    rejected: List[str] = []

    # Normal training traces
    training_dir = adfa_root / "Training_Data_Master"
    for p in sorted(training_dir.iterdir()):
        if not _is_trace_file(p):
            continue
        seq = _read_trace(p)
        if seq is None or len(seq) == 0:
            rejected.append(str(p))
            continue
        records.append({
            "file_name": p.stem,
            "sequence": seq,
            "label": 0,
            "category": "normal",
            "source_split": "training",
        })

    # Normal validation traces
    validation_dir = adfa_root / "Validation_Data_Master"
    for p in sorted(validation_dir.iterdir()):
        if not _is_trace_file(p):
            continue
        seq = _read_trace(p)
        if seq is None or len(seq) == 0:
            rejected.append(str(p))
            continue
        records.append({
            "file_name": p.stem,
            "sequence": seq,
            "label": 0,
            "category": "normal",
            "source_split": "validation",
        })

    # Attack traces
    attack_master = adfa_root / "Attack_Data_Master"
    for attack_subdir in sorted(attack_master.iterdir()):
        if not attack_subdir.is_dir():
            continue
        if attack_subdir.name.startswith("."):
            continue
        category = _category_from_dir(attack_subdir)
        for p in sorted(attack_subdir.iterdir()):
            if not _is_trace_file(p):
                continue
            seq = _read_trace(p)
            if seq is None or len(seq) == 0:
                rejected.append(str(p))
                continue
            records.append({
                "file_name": p.stem,
                "sequence": seq,
                "label": 1,
                "category": category,
                "source_split": "attack",
            })

    if rejected:
        import sys
        print(f"[adfa_loader] Rejected {len(rejected)} files (empty/malformed):", file=sys.stderr)
        for r in rejected:
            print(f"  {r}", file=sys.stderr)

    return records
