"""
PLAID (Plaid Lab Artificial Intrusion Dataset) loader for Chronicle.

Extracts/reads traces from ML/DATA/PLAID/uvm_ids-master/data/PLAID.
Label convention: 0 = normal (baseline), 1 = attack
"""
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional

_DATA_DIR = Path(__file__).resolve().parents[1] / "DATA" / "PLAID" / "uvm_ids-master" / "data"
_PLAID_ROOT = _DATA_DIR / "PLAID"
_TAR_PATH = _DATA_DIR / "PLAID.tar.xz"

ATTACK_CATEGORIES = [
    "cowroot",
    "ftp",
    "nginx",
    "privesc",
    "redis",
    "ssh",
]


def ensure_plaid_extracted(plaid_root: Path = _PLAID_ROOT, tar_path: Path = _TAR_PATH) -> Path:
    """Ensure the PLAID dataset directory exists, extracting PLAID.tar.xz if necessary."""
    if not plaid_root.exists() or not (plaid_root / "attack").exists():
        if not tar_path.exists():
            raise FileNotFoundError(f"PLAID archive not found at {tar_path}")
        print(f"[plaid_loader] Extracting {tar_path}...")
        with tarfile.open(tar_path, "r:xz") as tar:
            tar.extractall(path=plaid_root.parent)
        print(f"[plaid_loader] Extraction complete at {plaid_root}")
    return plaid_root


def _read_trace_file(path: Path) -> Optional[List[str]]:
    """Read a space-separated syscall trace file, returning list of syscall name strings."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return None
        tokens = text.split()
        return tokens if len(tokens) > 0 else None
    except (OSError, UnicodeDecodeError):
        return None


def load_plaid(
    plaid_root: Optional[Path] = None,
    max_baseline_samples: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Load PLAID traces recursively.

    Parameters:
    -----------
    plaid_root: Path
        Root path to PLAID directory containing 'attack' and 'baseline' subdirs.
    max_baseline_samples: Optional[int]
        If set, limits baseline samples (useful for quick testing/balanced subsets).
        Defaults to None (loads all baseline traces).

    Returns:
    --------
    List of dicts with keys:
        file_name     - filename (e.g. '10008.txt')
        pid           - process ID extracted from filename stem
        sequence      - list of syscall name strings
        label         - 0 (normal) or 1 (attack)
        category      - attack category name ('cowroot', 'ftp', etc.) or baseline activity name
        subcategory   - detailed subdirectory (e.g. 'ssh_1', 'run_tests_php')
        source_split  - 'attack' | 'baseline'
        file_path     - relative path string for provenance
    """
    if plaid_root is None:
        plaid_root = ensure_plaid_extracted()
    else:
        plaid_root = Path(plaid_root)

    attack_dir = plaid_root / "attack"
    baseline_dir = plaid_root / "baseline"

    if not attack_dir.exists():
        raise FileNotFoundError(f"Attack directory not found at {attack_dir}")
    if not baseline_dir.exists():
        raise FileNotFoundError(f"Baseline directory not found at {baseline_dir}")

    records: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []

    # 1. Load Attack Traces
    for trial_dir in sorted(attack_dir.iterdir()):
        if not trial_dir.is_dir() or trial_dir.name.startswith("."):
            continue
        # Subdirectory name format: <category>_<trial_id>, e.g. ssh_1, cowroot_0
        parts = trial_dir.name.split("_")
        category = parts[0]
        if category not in ATTACK_CATEGORIES:
            # Fallback if naming differs
            category = trial_dir.name

        for f in sorted(trial_dir.iterdir()):
            if not f.is_file() or not f.name.endswith(".txt") or f.name.startswith("."):
                continue
            seq = _read_trace_file(f)
            if seq is None or len(seq) == 0:
                skipped.append({"file": str(f), "reason": "empty_or_unreadable"})
                continue

            pid = f.stem
            records.append({
                "file_name": f.name,
                "pid": pid,
                "sequence": seq,
                "label": 1,
                "category": category,
                "subcategory": trial_dir.name,
                "source_split": "attack",
                "file_path": str(f.relative_to(plaid_root)),
            })

    # 2. Load Baseline Traces
    baseline_files: List[Path] = []
    for act_dir in sorted(baseline_dir.iterdir()):
        if not act_dir.is_dir() or act_dir.name.startswith("."):
            continue
        for f in sorted(act_dir.iterdir()):
            if f.is_file() and f.name.endswith(".txt") and not f.name.startswith("."):
                baseline_files.append(f)

    if max_baseline_samples is not None and len(baseline_files) > max_baseline_samples:
        import numpy as np
        rng = np.random.default_rng(42)
        indices = rng.choice(len(baseline_files), size=max_baseline_samples, replace=False)
        baseline_files = [baseline_files[i] for i in sorted(indices)]

    for f in baseline_files:
        seq = _read_trace_file(f)
        if seq is None or len(seq) == 0:
            skipped.append({"file": str(f), "reason": "empty_or_unreadable"})
            continue

        act_name = f.parent.name
        pid = f.stem
        records.append({
            "file_name": f.name,
            "pid": pid,
            "sequence": seq,
            "label": 0,
            "category": "normal",
            "subcategory": act_name,
            "source_split": "baseline",
            "file_path": str(f.relative_to(plaid_root)),
        })

    if skipped:
        import sys
        print(f"[plaid_loader] Skipped {len(skipped)} invalid files.", file=sys.stderr)

    return records
