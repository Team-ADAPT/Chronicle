#!/usr/bin/env python3
"""
Chronicle - eBPF Telemetry Collector (Root Launcher)

Canonical implementation is located in `ebpf/collector.py`.
"""
import runpy
from pathlib import Path

_TARGET = Path(__file__).resolve().parent / "ebpf" / "collector.py"

if __name__ == "__main__":
    runpy.run_path(str(_TARGET), run_name="__main__")
