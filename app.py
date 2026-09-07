#!/usr/bin/env python3
"""
Chronicle — Intelligent Host Behaviour Analysis & Activity Monitor
Executable entry point for desktop and development modes.
"""

import sys
import os
import argparse
import webbrowser
import threading
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socketserver

VERSION = "0.2.0-deb"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UI_DIR = os.path.join(BASE_DIR, "ui")

class CustomUIHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler serving the UI directory with no caching for development."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=UI_DIR, **kwargs)

    def end_headers(self):
        # Disable browser caching for real-time development
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def log_message(self, format, *args):
        # Keep terminal output clean
        if os.getenv("CHRONICLE_VERBOSE"):
            super().log_message(format, *args)

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

def print_banner(mode: str, url: str):
    print("=" * 60)
    print(f"  🐧 CHRONICLE — Host Behaviour Analysis System [{VERSION}]")
    print("=" * 60)
    print("  • Mode:             " + mode)
    print("  • Interface:        " + url)
    print("  • Local Privacy:    ENFORCED (0 B external telemetry)")
    print("  • Telemetry Engine: Active (Simulated Kernel Mode)")
    print("=" * 60)
    print("  Press Ctrl+C to terminate application.")
    print("=" * 60)

def run_web_server(port: int = 8000, open_browser: bool = True):
    """Run local zero-dependency HTTP server."""
    # Find available port if 8000 is occupied
    actual_port = port
    server = None
    for attempt in range(10):
        try:
            server = ThreadedHTTPServer(("127.0.0.1", actual_port), CustomUIHandler)
            break
        except OSError:
            actual_port += 1

    if not server:
        print(f"Error: Could not bind to port {port} or next 10 ports.", file=sys.stderr)
        sys.exit(1)

    url = f"http://127.0.0.1:{actual_port}"
    print_banner("Desktop Web Application", url)

    if open_browser:
        # Open in default browser after server initializes
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Chronicle service...")
        server.shutdown()
        server.server_close()
        print("Chronicle stopped cleanly.")

def run_native_window():
    """Launch native desktop window using pywebview if available."""
    try:
        import webview
    except ImportError:
        return False

    index_path = os.path.join(UI_DIR, "index.html")
    if not os.path.exists(index_path):
        print(f"Error: UI files not found at {index_path}", file=sys.stderr)
        sys.exit(1)

    print_banner("Native Linux Desktop Window (WebKit)", "Native Window")

    window = webview.create_window(
        title="Chronicle — Host Behaviour Analysis System",
        url=f"file://{index_path}",
        width=1320,
        height=880,
        min_size=(1024, 700),
        background_color="#080c14"
    )
    webview.start(debug=False)
    return True

def main():
    parser = argparse.ArgumentParser(description="Chronicle Host Behaviour Analysis System")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind development server (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open default web browser")
    parser.add_argument("--window", action="store_true", help="Force native window mode using pywebview")

    args = parser.parse_args()

    # Check if pywebview should be used
    if args.window:
        if not run_native_window():
            print("Notice: 'pywebview' is not installed. Falling back to local web server mode.")
            run_web_server(port=args.port, open_browser=not args.no_browser)
    else:
        # Default mode: run web server (works anywhere out of the box)
        run_web_server(port=args.port, open_browser=not args.no_browser)

if __name__ == "__main__":
    main()
