"""
Chronicle — System Tray & Menu Bar Indicator Module
Enables Chronicle to run quietly in the background as a menu bar / system tray app,
continuously collecting telemetry and persisting to the local DBMS without occupying dock space.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("chronicle.tray")

# Check optional tray dependencies
try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except ImportError:
    pystray = None
    Image = None
    ImageDraw = None
    HAS_TRAY = False


def is_gui_available() -> bool:
    """Checks whether a graphical desktop display server is present."""
    if sys.platform == "darwin":
        return True
    if sys.platform.startswith("linux"):
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return True


def create_default_icon_image() -> Any:
    """Generates an embedded fallback shield icon in-memory if PNG is missing."""
    if not Image or not ImageDraw:
        return None
    img = Image.new("RGBA", (64, 64), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Draw emerald shield shape
    draw.polygon([(32, 4), (58, 14), (50, 48), (32, 60), (14, 48), (6, 14)], fill="#00c288", outline="#ffffff")
    draw.line([(32, 14), (32, 50)], fill="#ffffff", width=3)
    return img


def load_tray_icon() -> Any:
    """Loads the Chronicle app icon for the system tray / menu bar."""
    if not Image:
        return None

    # Search candidates
    icon_candidates = [
        Path(__file__).resolve().parents[2] / "packaging" / "chronicle.png",
        Path(__file__).resolve().parents[2] / "ui" / "assets" / "icon.png",
        Path("/usr/share/icons/hicolor/256x256/apps/chronicle.png"),
        Path("/opt/chronicle/ui/assets/icon.png"),
    ]

    for cand in icon_candidates:
        if cand.exists():
            try:
                img = Image.open(str(cand))
                img = img.resize((64, 64), Image.Resampling.LANCZOS)
                return img
            except Exception as exc:
                logger.debug("Failed reading icon from %s: %s", cand, exc)

    return create_default_icon_image()


class ChronicleTrayApp:
    """
    Manages the Chronicle menu bar / system tray life-cycle.
    Runs quietly in the menu bar and allows toggling the UI dashboard,
    while background telemetry collection continues uninterrupted.
    """

    def __init__(
        self,
        pipeline: Any,
        dashboard_url: str,
        on_open_dashboard: Optional[Callable[[], None]] = None,
        on_quit: Optional[Callable[[], None]] = None,
    ):
        self.pipeline = pipeline
        self.dashboard_url = dashboard_url
        self.on_open_dashboard = on_open_dashboard
        self.on_quit = on_quit
        self.icon: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self.is_running = False

    def is_supported(self) -> bool:
        """Returns True if tray dependencies and display environment are available."""
        return HAS_TRAY and is_gui_available()

    def _open_dashboard(self, icon: Any = None, item: Any = None):
        """Opens or brings the dashboard window to focus."""
        if self.on_open_dashboard:
            try:
                self.on_open_dashboard()
                return
            except Exception as exc:
                logger.warning("Error invoking on_open_dashboard: %s", exc)
        webbrowser.open(self.dashboard_url)

    def _open_db_folder(self, icon: Any = None, item: Any = None):
        """Reveals the folder where chronicle.db is stored."""
        try:
            db_dir = str(self.pipeline.config.db_path.parent.resolve())
            if sys.platform == "darwin":
                subprocess.Popen(["open", db_dir])
            elif sys.platform.startswith("linux"):
                subprocess.Popen(["xdg-open", db_dir])
        except Exception as exc:
            logger.warning("Could not open DB directory: %s", exc)

    def _simulate_attack(self, icon: Any = None, item: Any = None):
        """Triggers an in-process attack simulation to verify anomaly detection."""
        try:
            self.pipeline.inject_simulation("interactive_shell_from_daemon")
            logger.info("Injected test simulation from menu bar.")
        except Exception as exc:
            logger.warning("Simulation error: %s", exc)

    def _quit_app(self, icon: Any = None, item: Any = None):
        """Cleanly terminates Chronicle from the menu bar."""
        logger.info("Quit requested via menu bar tray.")
        self.is_running = False
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass
        if self.on_quit:
            try:
                self.on_quit()
            except Exception as exc:
                logger.warning("Error in on_quit: %s", exc)

    def _get_status_label(self, item: Any = None) -> str:
        """Returns dynamic monitoring state for menu display."""
        events = getattr(self.pipeline, "total_events_processed", 0)
        anomalies = getattr(self.pipeline, "total_anomalies_detected", 0)
        engine = "eBPF" if getattr(self.pipeline.collector, "ebpf_enabled", False) else "psutil"
        return f"● Active ({engine}) | Events: {events} | Alerts: {anomalies}"

    def run(self):
        """Runs the menu bar tray icon."""
        if not self.is_supported():
            logger.warning("System tray is not supported in this environment.")
            return

        icon_image = load_tray_icon()
        if not icon_image:
            logger.warning("Could not create tray icon image.")
            return

        menu = pystray.Menu(
            pystray.MenuItem("Chronicle — Host Monitor", None, enabled=False),
            pystray.MenuItem(self._get_status_label, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Dashboard", self._open_dashboard, default=True),
            pystray.MenuItem("Simulate Attack Test", self._simulate_attack),
            pystray.MenuItem("Open Local Database Folder", self._open_db_folder),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit Chronicle", self._quit_app),
        )

        self.icon = pystray.Icon("Chronicle", icon_image, "Chronicle Host Monitor", menu)
        self.is_running = True
        logger.info("Chronicle running in menu bar / system tray.")
        self.icon.run()

    def run_detached(self):
        """Runs the tray icon in a dedicated background thread."""
        if not self.is_supported():
            return
        self._thread = threading.Thread(target=self.run, daemon=True, name="ChronicleTrayThread")
        self._thread.start()

