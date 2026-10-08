"""
ADFA-LD dataset inspection. Outputs statistics without modifying any files.

Usage: python ML/src/inspect_adfa.py
"""
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))
from adfa_loader import load_adfa


def main() -> None:
    records = load_adfa()

    lengths = [len(r["sequence"]) for r in records]
    all_syscalls: Counter = Counter()
    for r in records:
        all_syscalls.update(r["sequence"])

    normal = [r for r in records if r["label"] == 0]
    attack = [r for r in records if r["label"] == 1]

    cat_counts: Counter = Counter(r["category"] for r in records)
    split_counts: Counter = Counter(r["source_split"] for r in records)

    print("=" * 60)
    print("ADFA-LD Dataset Inspection")
    print("=" * 60)
    print(f"Total traces        : {len(records)}")
    print(f"  Normal            : {len(normal)}")
    print(f"  Attack            : {len(attack)}")
    print()
    print("Source split counts:")
    for split, cnt in sorted(split_counts.items()):
        print(f"  {split:<15}: {cnt}")
    print()
    print("Attack category counts:")
    for cat, cnt in sorted(cat_counts.items()):
        if cat != "normal":
            print(f"  {cat:<25}: {cnt}")
    print()
    print(f"Sequence length stats:")
    print(f"  min               : {min(lengths)}")
    print(f"  max               : {max(lengths)}")
    print(f"  mean              : {sum(lengths)/len(lengths):.1f}")
    print(f"  median            : {sorted(lengths)[len(lengths)//2]}")
    print()
    print(f"Unique syscall IDs  : {len(all_syscalls)}")
    print(f"Syscall ID range    : {min(all_syscalls)} – {max(all_syscalls)}")
    print(f"Top 10 syscalls     : {all_syscalls.most_common(10)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
