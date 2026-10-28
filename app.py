#!/usr/bin/env python3
"""
Chronicle — Intelligent Host Behaviour Analysis & Activity Monitor
Executable entry point linking eBPF/psutil telemetry, historical baselines (DBMS),
in-process Scikit-learn/XGBoost ML anomaly detection, and the UI dashboard.
Runs as a menu bar / system tray application that continuously collects and stores
host telemetry in the local database until quit.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socketserver
import sys
import threading
import time
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# Add src to Python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "src"))

from chronicle.api import ChronicleAPIHandler
from chronicle.config import ChronicleConfig
from chronicle.pipeline import ChroniclePipeline
from chronicle.tray import ChronicleTrayApp, is_gui_available

VERSION = "1.0.0"
UI_DIR = str(BASE_DIR / "ui")

# Global instances
_pipeline: ChroniclePipeline | None = None
_api_handler: ChronicleAPIHandler | None = None
_shutdown_event = threading.Event()
_tray_app: ChronicleTrayApp | None = None


class ChronicleHTTPHandler(SimpleHTTPRequestHandler):
    """Unified HTTP handler serving both the REST API and the static UI assets."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=UI_DIR, **kwargs)

    def do_GET(self):
        if self.path.startswith("/api/"):
            self._handle_api("GET")
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self._handle_api("POST")
        else:
            self.send_error(404, "Not Found")

    def _handle_api(self, method: str):
        try:
            content_length = max(0, int(self.headers.get("Content-Length", 0)))
        except (ValueError, TypeError):
            content_length = 0
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b""

        if _api_handler:
            status, ctype, resp = _api_handler.handle_request(method, self.path, body_bytes)
        else:
            status, ctype, resp = 503, "application/json", b'{"error": "Pipeline not initialized"}'

        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(resp)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(resp)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def log_message(self, format, *args):
        if os.getenv("CHRONICLE_VERBOSE"):
            super().log_message(format, *args)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


def print_banner(mode: str, url: str, pipeline: ChroniclePipeline, tray_status: str):
    ebpf_str = "ACTIVE (Kernel eBPF/BCC)" if pipeline.collector.ebpf_enabled else "ACTIVE (psutil Host Telemetry)"
    ml_str = "ACTIVE (Isolation Forest + XGBoost)" if pipeline.ml_engine.loaded else "STANDBY (Statistical Baselines)"

    print("=" * 72)
    print(f"  🛡️  CHRONICLE — Host Behaviour Analysis & Activity Monitor [{VERSION}]")
    print("=" * 72)
    print(f"  • Dashboard URL:     {url}")
    print(f"  • Execution Mode:    {mode}")
    print(f"  • Menu Bar / Tray:   {tray_status}")
    print(f"  • Local Database:    {pipeline.config.db_path} (WAL enabled)")
    print(f"  • Telemetry Engine:  {ebpf_str}")
    print(f"  • Anomaly Detector:  {ml_str}")
    print(f"  • Privacy Invariant: 0 Bytes transmitted externally (Air-Gapped)")
    print("=" * 72)
    print("  Application running in background. Telemetry is saved to local DB.")
    print("  To quit: use 'Quit Chronicle' in the menu bar tray, or press Ctrl+C.")
    print("=" * 72)


def open_dashboard_window(url: str):
    """Opens the dashboard in a native webview window if available, or system browser."""
    try:
        import webview
        window = webview.create_window(
            title="Chronicle — Host Behaviour Analysis System",
            url=url,
            width=1320,
            height=880,
            min_size=(1024, 700),
            background_color="#080c14",
        )
        webview.start(debug=False)
    except Exception:
        webbrowser.open(url)


def request_shutdown(signum=None, frame=None):
    """Signals all threads to terminate cleanly."""
    global _shutdown_event
    _shutdown_event.set()


def enforce_linux_debian_environment():
    """Ensures Chronicle runs strictly on Linux as designed."""
    if not sys.platform.startswith("linux") and not os.getenv("CHRONICLE_ALLOW_NON_LINUX"):
        print("=" * 72, file=sys.stderr)
        print("  ❌ PLATFORM ERROR: Linux Environment Required", file=sys.stderr)
        print("=" * 72, file=sys.stderr)
        print("  Chronicle is an enterprise Linux-only host threat detection system.", file=sys.stderr)
        print("  It requires the Linux kernel eBPF/BCC subsystems, /proc telemetry,", file=sys.stderr)
        print("  and must be deployed via the Debian (.deb) desktop application.", file=sys.stderr)
        print("", file=sys.stderr)
        print("  Supported Distributions: Debian 11/12, Ubuntu 20.04/22.04/24.04, Linux Mint.", file=sys.stderr)
        print("  Install the Debian package on Linux:", file=sys.stderr)
        print("    sudo dpkg -i chronicle_1.0.0-1_all.deb", file=sys.stderr)
        print("    chronicle", file=sys.stderr)
        print("=" * 72, file=sys.stderr)
        sys.exit(1)


def main():
    global _pipeline, _api_handler, _tray_app

    enforce_linux_debian_environment()

    parser = argparse.ArgumentParser(description="Chronicle Host Behaviour Analysis System")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind server (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open default web browser")
    parser.add_argument("--no-gui", action="store_true", help="Run in headless daemon mode (no GUI window or tray)")
    parser.add_argument("--no-tray", action="store_true", help="Disable menu bar tray icon")
    parser.add_argument("--window", action="store_true", help="Open native desktop window on startup")
    parser.add_argument("--no-ebpf", action="store_true", help="Disable eBPF even if available on Linux")

    args = parser.parse_args()

    # Intercept termination signals for clean shutdown and DB commit
    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)

    # 1. Configure and start background telemetry pipeline
    cfg = ChronicleConfig()
    if args.no_ebpf:
        cfg.enable_ebpf = False

    _pipeline = ChroniclePipeline(cfg)
    _pipeline.start()
    _api_handler = ChronicleAPIHandler(_pipeline)

    # 2. Start HTTP server
    actual_port = args.port
    server = None
    for attempt in range(10):
        try:
            server = ThreadedHTTPServer(("127.0.0.1", actual_port), ChronicleHTTPHandler)
            break
        except OSError:
            actual_port += 1

    if not server:
        print(f"Error: Could not bind to port {args.port} or next 10 ports.", file=sys.stderr)
        _pipeline.stop()
        sys.exit(1)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True, name="ChronicleHTTPServer")
    server_thread.start()

    url = f"http://127.0.0.1:{actual_port}"

    # 3. Setup Menu Bar / System Tray Application
    enable_tray = not (args.no_tray or args.no_gui) and is_gui_available()
    tray_status = "Disabled (Headless/CLI)"

    if enable_tray:
        _tray_app = ChronicleTrayApp(
            pipeline=_pipeline,
            dashboard_url=url,
            on_open_dashboard=lambda: open_dashboard_window(url),
            on_quit=request_shutdown,
        )
        if _tray_app.is_supported():
            tray_status = "ACTIVE (Running in Top Menu Bar / Tray)"
        else:
            tray_status = "Unavailable (Missing pystray or Pillow; running background daemon)"

    mode_label = "Headless Daemon" if args.no_gui else ("Native Window" if args.window else "Menu Bar Application")
    print_banner(mode_label, url, _pipeline, tray_status)

    # 4. Open UI window if requested
    if args.window and not args.no_gui:
        # Run in separate thread so closing window doesn't terminate background data collection
        threading.Thread(target=open_dashboard_window, args=(url,), daemon=True).start()
    elif not args.no_browser and not args.no_gui and not (enable_tray and _tray_app and _tray_app.is_supported()):
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    # 5. Run Tray event loop or wait for shutdown signal
    try:
        if enable_tray and _tray_app and _tray_app.is_supported():
            # Run tray loop on main thread (required by macOS NSStatusBar and Linux X11/GTK)
            _tray_app.run()
        else:
            while not _shutdown_event.is_set():
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nStopping Chronicle background services...")
        if _pipeline:
            _pipeline.stop()
        server.shutdown()
        server.server_close()
        print("Chronicle shut down cleanly. Local telemetry database saved.")


if __name__ == "__main__":
    main()
