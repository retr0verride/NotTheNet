"""Main dashboard window. Launched by ``notthenet.py`` in GUI mode."""

from __future__ import annotations

import logging
import queue
import tkinter as tk

from config import Config
from gui.logic import ServiceControlMixin
from gui.views import DashboardMixin
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
        except tk.TclError:
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


def run_gui(config_path: str) -> None:
    """Open the dashboard and block until the window closes."""
    NotTheNetApp(config_path=config_path).mainloop()
