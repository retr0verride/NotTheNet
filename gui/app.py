"""Application class and CLI/GUI entry point for NotTheNet."""

from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import tkinter as tk

from config import Config
from gui.logic import ServiceControlMixin
from gui.views import DashboardMixin, _print_logo
from gui.widgets import (
    _APP_ICON_B64,
    _BASE_H,
    _BASE_MIN_H,
    _BASE_MIN_W,
    _BASE_W,
    APP_TITLE,
    C_BG,
    _QueueHandler,
)
from service_manager import ServiceManager
from utils.logging_utils import setup_logging

logger = logging.getLogger(__name__)


class NotTheNetApp(DashboardMixin, ServiceControlMixin, tk.Tk):
    """Main application window combining layout (DashboardMixin) and
    runtime logic (ServiceControlMixin)."""

    def __init__(self, config_path: str | None = None):
        super().__init__()
        self.title(APP_TITLE)
        self.configure(bg=C_BG)
        self.resizable(True, True)

        # Window / taskbar icon
        try:
            _icon = tk.PhotoImage(data=_APP_ICON_B64)
            self.iconphoto(True, _icon)
            self._icon = _icon  # prevent GC
        except Exception:
            logger.debug("App icon load failed (cosmetic)", exc_info=True)

        self._cfg = Config(config_path or "config.json")
        self._log_queue: queue.Queue = queue.Queue(maxsize=2000)
        self._log_line_count: int = 0
        self._manager: ServiceManager | None = None
        self._svc_vars: dict = {}
        self._pages: dict = {}
        self._start_time = None
        self._timer_job = None

        self._zoom_factor: float = float(self._cfg.get("ui", "zoom") or 1.0)
        self._init_fonts()

        z = self._zoom_factor
        self.geometry(f"{round(_BASE_W * z)}x{round(_BASE_H * z)}")
        self.minsize(round(_BASE_MIN_W * z), round(_BASE_MIN_H * z))

        root_logger = logging.getLogger()
        qh = _QueueHandler(self._log_queue)
        qh.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        root_logger.addHandler(qh)

        self._log_level_filter: set[str] = set()
        self._build_ui()
        self._poll_log_queue()
        self.protocol("WM_DELETE_WINDOW", self._on_close)


def main():
    """Parse CLI args and launch either headless or GUI mode."""
    import argparse
    import traceback

    _project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(_project_root)

    _default_config = os.path.join(_project_root, "config.json")

    parser = argparse.ArgumentParser(description="NotTheNet \u2014 Fake Internet Simulator")
    parser.add_argument("--config", default=_default_config, help="Path to config JSON")
    parser.add_argument("--nogui", action="store_true",
                        help="Run headless (CLI mode, no GUI)")
    parser.add_argument("--loglevel", default=None,
                        help="Override log level (DEBUG/INFO/WARNING/ERROR)")
    args = parser.parse_args()

    _crash_log = os.path.join(_project_root, "logs", "notthenet-crash.log")
    try:
        os.makedirs(os.path.join(_project_root, "logs"), exist_ok=True)
    except OSError:
        pass

    try:
        cfg = Config(args.config)
        log_level = args.loglevel or cfg.get("general", "log_level") or "INFO"
        setup_logging(
            log_dir=cfg.get("general", "log_dir") or os.path.join(_project_root, "logs"),
            log_level=log_level,
            log_to_file=bool(cfg.get("general", "log_to_file")),
        )

        if args.nogui:
            import signal
            _print_logo()
            manager = ServiceManager(cfg)
            if not manager.start():
                sys.exit(1)
            _logger = logging.getLogger("notthenet")
            _logger.info("Running in headless mode. Press Ctrl+C to stop.")

            stop_event = threading.Event()

            def _sig_handler(sig, _frame):
                _logger.info("Signal %s received; shutting down\u2026", sig)
                stop_event.set()

            signal.signal(signal.SIGINT, _sig_handler)
            signal.signal(signal.SIGTERM, _sig_handler)

            stop_event.wait()
            manager.stop()
            sys.exit(0)
        else:
            app = NotTheNetApp(config_path=args.config)
            app.mainloop()

    except Exception:
        import datetime
        try:
            with open(_crash_log, "a", encoding="utf-8") as _cf:
                _cf.write(f"\n--- CRASH {datetime.datetime.now().isoformat()} ---\n")
                traceback.print_exc(file=_cf)
        except OSError:
            pass
        raise


if __name__ == "__main__":
    main()
