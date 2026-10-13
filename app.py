#!/usr/bin/env python3
"""
Chronicle — Intelligent Host Behaviour Analysis & Activity Monitor
Executable entry point linking eBPF/psutil telemetry, historical baselines (DBMS),
in-process Scikit-learn/XGBoost ML anomaly detection, and the UI dashboard.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import socketserver
import sys
import threading
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# Add src to Python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "src"))

from chronicle.api import ChronicleAPIHandler
from chronicle.config import ChronicleConfig
from chronicle.pipeline import ChroniclePipeline

VERSION = "0.2.0-deb"
UI_DIR = str(BASE_DIR / "ui")

# Global pipeline instance
_pipeline: ChroniclePipeline | None = None
_api_handler: ChronicleAPIHandler | None = None


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
        content_length = int(self.headers.get("Content-Length", 0))
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
        # Disable browser caching for real-time responsiveness
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def log_message(self, format, *args):
        if os.getenv("CHRONICLE_VERBOSE"):
            super().log_message(format, *args)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


def print_banner(mode: str, url: str, pipeline: ChroniclePipeline):
    ebpf_str = "ACTIVE (Kernel eBPF/BCC)" if pipeline.collector.ebpf_enabled else "ACTIVE (psutil Host Telemetry)"
    ml_str = "ACTIVE (Isolation Forest + XGBoost)" if pipeline.ml_engine.loaded else "STANDBY"

    print("=" * 68)
    print(f"  🐧 CHRONICLE — Host Behaviour Analysis System [{VERSION}]")
    print("=" * 68)
    print(f"  • Interface:         {url}")
    print(f"  • Window Mode:       {mode}")
    print(f"  • Local Privacy:     ENFORCED (0 B external telemetry / Air-Gapped)")
    print(f"  • Telemetry Engine:  {ebpf_str}")
    print(f"  • ML Anomaly Engine: {ml_str}")
    print(f"  • Historical DBMS:   SQLite ({pipeline.config.db_path.name})")
    print("=" * 68)
    print("  Press Ctrl+C to terminate application.")
    print("=" * 68)


def run_web_server(port: int = 8000, open_browser: bool = True):
    actual_port = port
    server = None
    for attempt in range(10):
        try:
            server = ThreadedHTTPServer(("127.0.0.1", actual_port), ChronicleHTTPHandler)
            break
        except OSError:
            actual_port += 1

    if not server:
        print(f"Error: Could not bind to port {port} or next 10 ports.", file=sys.stderr)
        sys.exit(1)

    url = f"http://127.0.0.1:{actual_port}"
    print_banner("Desktop Web Application", url, _pipeline)

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Chronicle services...")
        if _pipeline:
            _pipeline.stop()
        server.shutdown()
        server.server_close()
        print("Chronicle stopped cleanly.")


def run_native_window(port: int = 8000):
    """Launch native desktop window using pywebview if available."""
    try:
        import webview
    except ImportError:
        return False

    actual_port = port
    server = None
    for attempt in range(10):
        try:
            server = ThreadedHTTPServer(("127.0.0.1", actual_port), ChronicleHTTPHandler)
            break
        except OSError:
            actual_port += 1

    if not server:
        return False

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    url = f"http://127.0.0.1:{actual_port}"
    print_banner("Native Linux Desktop Window (WebKit)", url, _pipeline)

    try:
        window = webview.create_window(
            title="Chronicle — Host Behaviour Analysis System",
            url=url,
            width=1320,
            height=880,
            min_size=(1024, 700),
            background_color="#080c14",
        )
        webview.start(debug=False)
    finally:
        if _pipeline:
            _pipeline.stop()
        server.shutdown()
        server.server_close()

    return True


def main():
    global _pipeline, _api_handler

    parser = argparse.ArgumentParser(description="Chronicle Host Behaviour Analysis System")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind server (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open default web browser")
    parser.add_argument("--window", action="store_true", help="Force native window mode using pywebview")
    parser.add_argument("--no-ebpf", action="store_true", help="Disable eBPF even if available on Linux")

    args = parser.parse_args()

    # Configure and start Chronicle pipeline
    cfg = ChronicleConfig()
    if args.no_ebpf:
        cfg.enable_ebpf = False

    _pipeline = ChroniclePipeline(cfg)
    _pipeline.start()
    _api_handler = ChronicleAPIHandler(_pipeline)

    if args.window:
        if not run_native_window(port=args.port):
            print("Notice: 'pywebview' is not available. Falling back to local browser mode.")
            run_web_server(port=args.port, open_browser=not args.no_browser)
    else:
        run_web_server(port=args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
