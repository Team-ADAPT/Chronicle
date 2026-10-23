#!/usr/bin/env python3
"""
Chronicle — Security Tool Service Launcher
==========================================
Starts the read-only HTTP service interface for external security tools.

Configuration (environment variables)
--------------------------------------
CHRONICLE_SERVICE_HOST   Bind address. Default: 127.0.0.1
                         To bind to 0.0.0.0, CHRONICLE_API_KEY must be set.
CHRONICLE_SERVICE_PORT   Port number. Default: 8765
CHRONICLE_API_KEY        Optional shared API key (read once at startup, never logged).
                         Required when binding to a non-loopback address.
CHRONICLE_VERBOSE        Set to any non-empty value to enable per-request logs.

Start command
-------------
    python serve_api.py

Stop: Ctrl-C
"""
from __future__ import annotations

import logging
import os
import socketserver
import sys
from http.server import HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronicle.config import ChronicleConfig
from chronicle.pipeline import ChroniclePipeline
from chronicle.service_api import SecurityServiceHandler, _PipelineAccessor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("chronicle.serve_api")

# ── Defaults ──────────────────────────────────────────────────────────────────
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8765
_LOOPBACK_PREFIXES = ("127.", "::1", "localhost")


def _is_loopback(host: str) -> bool:
    return any(host.startswith(p) for p in _LOOPBACK_PREFIXES)


class _ThreadedServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main() -> None:
    host = os.environ.get("CHRONICLE_SERVICE_HOST", _DEFAULT_HOST).strip()
    try:
        port = int(os.environ.get("CHRONICLE_SERVICE_PORT", _DEFAULT_PORT))
    except ValueError:
        logger.error("CHRONICLE_SERVICE_PORT must be an integer.")
        sys.exit(1)

    api_key: str | None = os.environ.get("CHRONICLE_API_KEY") or None

    # Security gate: refuse non-loopback bind without a key
    if not _is_loopback(host) and api_key is None:
        logger.error(
            "SECURITY: Binding to %s requires CHRONICLE_API_KEY to be set. "
            "Refusing to start without authentication on a non-local address.",
            host,
        )
        sys.exit(1)

    # Initialize pipeline (psutil fallback; eBPF requires Linux + BCC)
    try:
        config = ChronicleConfig()
        pipeline = ChroniclePipeline(config)
    except Exception as exc:
        logger.error("Failed to initialize pipeline: %s", exc)
        sys.exit(1)

    # Inject pipeline and key into handler class
    SecurityServiceHandler.accessor = _PipelineAccessor(pipeline)
    SecurityServiceHandler._api_key = api_key  # type: ignore[assignment]

    try:
        server = _ThreadedServer((host, port), SecurityServiceHandler)
    except OSError as exc:
        logger.error("Could not bind to %s:%s — %s", host, port, exc)
        sys.exit(1)

    auth_note = "API key authentication ENABLED." if api_key else "No authentication (localhost only)."
    logger.info("Chronicle security tool service starting on http://%s:%s", host, port)
    logger.info("Base path: /api/v1/   |  %s", auth_note)
    if not _is_loopback(host):
        logger.warning("Bound to non-loopback address %s — ensure network controls are in place.", host)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
