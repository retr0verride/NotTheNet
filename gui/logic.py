"""Service control, log polling, and runtime logic for the main window."""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
import webbrowser
from tkinter import filedialog, messagebox
from typing import TYPE_CHECKING

from gui.widgets import (
    C_DIM,
    C_GREEN,
    C_ORANGE,
    C_RED,
    LOG_MAX_LINES,
    _open_path_external,
)
from service_manager import ServiceManager
from utils.logging_utils import setup_logging

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from tkinter import scrolledtext

    from config import Config

    class _ControlHost(tk.Tk):
        """Type stub describing attributes the ServiceControlMixin expects."""

        _log_level_filter: set[str]
        _log_filter_btns: dict[str, tk.Button]
        _log_widget: scrolledtext.ScrolledText
        _btn_start: tk.Button
        _btn_stop: tk.Button
        _btn_check_updates: tk.Button
        _status_label: tk.Label
        _cfg: Config
        _pages: dict
        _manager: ServiceManager | None
        _start_time: float | None
        _timer_job: str | None
        _svc_vars: dict
        _log_queue: queue.Queue
        _log_line_count: int
else:
    _ControlHost = object


class ServiceControlMixin(_ControlHost):
    """Mixin providing service lifecycle, log management, and filter logic.

    Expects the consuming class to be a ``tk.Tk`` subclass that also mixes in
    ``DashboardMixin`` and initialises the following attributes in ``__init__``:

    * ``_cfg``, ``_log_queue``, ``_log_line_count``
    * ``_manager``, ``_svc_vars``, ``_pages``
    * ``_start_time``, ``_timer_job``
    * ``_log_level_filter``, ``_log_filter_btns``
    * ``_log_widget``, ``_btn_start``, ``_btn_stop``, ``_status_label``
    """

    # ── Log filter ────────────────────────────────────────────────────────

    def _toggle_log_filter(self, level: str):
        """Toggle visibility of a single log level in the live panel.

        Any combination of levels can be active simultaneously.
        When no levels are active the view shows all messages.
        """
        if level in self._log_level_filter:
            self._log_level_filter.discard(level)
        else:
            self._log_level_filter.add(level)
        for lvl, b in self._log_filter_btns.items():
            active = lvl in self._log_level_filter
            b.configure(relief="sunken" if active else "flat",
                        bd=1 if active else 0)
        self._reapply_log_filter()

    def _reapply_log_filter(self):
        """Re-apply the active filter set to all existing lines in the log widget.

        Uses ``tag_ranges()`` to fetch all ranges for each hidden level in
        O(1) calls, then adds HIDDEN to those ranges — far faster than
        iterating every line with ``tag_names()``.
        """
        w = self._log_widget
        w.configure(state="normal")
        w.tag_remove("HIDDEN", "1.0", "end")
        if self._log_level_filter:
            for level in ("INFO", "WARNING", "ERROR", "DEBUG"):
                if level not in self._log_level_filter:
                    ranges = w.tag_ranges(level)
                    for i in range(0, len(ranges), 2):
                        w.tag_add("HIDDEN", ranges[i], ranges[i + 1])
        w.configure(state="disabled")

    # ── Log polling ───────────────────────────────────────────────────────

    def _poll_log_queue(self):
        """Drain up to 200 queued log messages per poll cycle.

        Uses adaptive timing: 250 ms when messages are flowing, 500 ms
        when idle.
        """
        msgs: list[str] = []
        try:
            for _ in range(200):
                msgs.append(self._log_queue.get_nowait())
        except queue.Empty:
            pass
        if msgs:
            self._append_logs(msgs)
            self.after(250, self._poll_log_queue)
        else:
            self.after(500, self._poll_log_queue)

    def _open_log_folder(self):
        """Open the configured log directory in the system file manager."""
        log_dir = os.path.abspath(
            self._cfg.get("general", "log_dir") or "logs"
        )
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError:
            pass
        try:
            _open_path_external(log_dir)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open log folder:\n{e}")

    def _clear_log_widget(self):
        """Clear the live log panel and reset the line counter atomically."""
        self._log_widget.configure(state="normal")
        self._log_widget.delete("1.0", "end")
        self._log_line_count = 0
        self._log_widget.configure(state="disabled")

    def _append_logs(self, msgs: list[str]):
        """Insert a batch of log messages in a single widget open/close cycle."""
        widget = self._log_widget
        widget.configure(state="normal")

        for msg in msgs:
            tag = "INFO"
            upper = msg.upper()
            if "[ERROR]" in upper:
                tag = "ERROR"
            elif "[WARNING]" in upper:
                tag = "WARNING"
            elif "[DEBUG]" in upper:
                tag = "DEBUG"

            tags: tuple[str, ...] = (tag,)
            if self._log_level_filter and tag not in self._log_level_filter:
                tags = (tag, "HIDDEN")

            widget.insert("end", msg + "\n", tags)
            self._log_line_count += 1

        if self._log_line_count > LOG_MAX_LINES:
            excess = self._log_line_count - LOG_MAX_LINES
            widget.delete("1.0", f"{excess + 1}.0")
            self._log_line_count = LOG_MAX_LINES

        if widget.yview()[1] >= 0.99:
            widget.see("end")
        widget.configure(state="disabled")

    def _append_log(self, msg: str):
        """Single-message convenience wrapper."""
        self._append_logs([msg])

    # ── Service control ───────────────────────────────────────────────────

    def _apply_all_pages_to_config(self):
        for page in self._pages.values():
            if hasattr(page, "apply_to_config"):
                page.apply_to_config()

    def _on_start(self):
        self._apply_all_pages_to_config()
        self._clear_log_widget()
        setup_logging(
            log_dir=self._cfg.get("general", "log_dir") or "logs",
            log_level=self._cfg.get("general", "log_level") or "INFO",
            log_to_file=bool(self._cfg.get("general", "log_to_file")),
        )
        self._manager = ServiceManager(self._cfg)

        def _start_thread():
            ok = self._manager.start()
            self.after(0, self._update_ui_after_start, ok)

        threading.Thread(target=_start_thread, daemon=True).start()
        self._status_label.configure(text="\u25cf  Starting\u2026", fg=C_ORANGE)

    def _update_ui_after_start(self, ok: bool):
        if ok:
            self._btn_start.configure(state="disabled")
            self._btn_stop.configure(state="normal")
            self._start_time = time.monotonic()
            self._tick_timer()
            running = set(self._manager.status().keys()) if self._manager else set()
            if "catch_tcp" in running or "catch_udp" in running:
                running.add("catch_all")
            for key, dot in self._svc_vars.items():
                dot.configure(fg=C_GREEN if key in running else C_DIM)
        else:
            self._status_label.configure(text="\u25cf  Failed \u2014 check log", fg=C_RED)

    def _tick_timer(self):
        """Update the status label with elapsed running time, once per second."""
        if self._start_time is None:
            return
        elapsed = int(time.monotonic() - self._start_time)
        h, remainder = divmod(elapsed, 3600)
        m, s = divmod(remainder, 60)
        if h:
            clock = f"{h}h {m:02d}m {s:02d}s"
        elif m:
            clock = f"{m}m {s:02d}s"
        else:
            clock = f"{s}s"
        self._status_label.configure(text=f"\u25cf  Running  {clock}", fg=C_GREEN)
        self._timer_job = self.after(1000, self._tick_timer)

    def _stop_timer(self):
        """Cancel the elapsed timer and clear state."""
        if self._timer_job is not None:
            self.after_cancel(self._timer_job)
            self._timer_job = None
        self._start_time = None

    def _on_stop(self):
        if not self._manager:
            return
        self._btn_start.configure(state="disabled")
        self._btn_stop.configure(state="disabled")
        self._status_label.configure(text="\u25cf  Stopping...", fg=C_ORANGE)

        def _stop_thread():
            self._manager.stop()
            self.after(0, self._update_ui_after_stop)

        threading.Thread(target=_stop_thread, daemon=True).start()

    def _update_ui_after_stop(self):
        self._stop_timer()
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled")
        self._status_label.configure(text="\u25cf  Stopped", fg=C_DIM)
        for dot in self._svc_vars.values():
            dot.configure(fg=C_DIM)

    def _on_save(self):
        self._apply_all_pages_to_config()
        if self._cfg.save():
            messagebox.showinfo("Saved", f"Config saved to:\n{self._cfg.config_path}")
        else:
            messagebox.showerror("Error", "Failed to save config \u2014 check log.")

    def _on_load(self):
        initial = os.path.dirname(os.path.abspath(self._cfg.config_path)) or os.getcwd()
        path = filedialog.askopenfilename(
            title="Load Config",
            initialdir=initial,
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if path:
            if self._cfg.load(path):
                messagebox.showinfo("Loaded", f"Config loaded from:\n{path}")
                for page in self._pages.values():
                    page.destroy()
                self._pages.clear()
                self._build_pages()
                self._show_page("general")
            else:
                messagebox.showerror("Error", f"Failed to load config from:\n{path}")

    # ── Update check ──────────────────────────────────────────────────────

    _RELEASES_URL = (
        "https://api.github.com/repos/retr0verride/NotTheNet/releases/latest"
    )

    def _on_check_updates(self) -> None:
        """Check GitHub for a newer release (non-blocking)."""
        self._btn_check_updates.configure(state="disabled")
        self._status_label.configure(text="\u25cb  Checking for updates\u2026", fg=C_DIM)
        threading.Thread(target=self._fetch_latest_release, daemon=True).start()

    def _fetch_latest_release(self) -> None:
        """Network call — runs on worker thread, schedules GUI update via after()."""
        from gui.widgets import APP_VERSION  # noqa: PLC0415

        try:
            req = urllib.request.Request(  # noqa: S310
                self._RELEASES_URL,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": f"NotTheNet/{APP_VERSION}",
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                data = json.loads(resp.read())
            tag = data.get("tag_name", "").lstrip("v")
            url = data.get(
                "html_url",
                "https://github.com/retr0verride/NotTheNet/releases",
            )
            self.after(0, self._show_update_result, tag, url, None)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Update check failed", exc_info=True)
            self.after(0, self._show_update_result, None, None, str(exc))

    def _show_update_result(
        self,
        tag: str | None,
        url: str | None,
        error: str | None,
    ) -> None:
        """Main-thread callback: show result dialog and restore UI state."""
        from gui.widgets import APP_VERSION  # noqa: PLC0415

        self._btn_check_updates.configure(state="normal")
        if self._start_time is None:
            self._status_label.configure(text="\u25cf  Stopped", fg=C_DIM)

        if error:
            messagebox.showerror(
                "Update Check Failed",
                f"Could not reach GitHub:\n{error}",
            )
            return

        if not tag:
            messagebox.showinfo("Update Check", "No release information available.")
            return

        if tag == APP_VERSION:
            messagebox.showinfo(
                "Up to date",
                f"You are running the latest release: v{APP_VERSION}",
            )
        else:
            if messagebox.askyesno(
                "Update Available",
                f"A newer version is available: v{tag}\n"
                f"You are running: v{APP_VERSION}\n\n"
                f"Open the releases page?",
            ):
                webbrowser.open(url)

    def _on_close(self):
        if self._manager and self._manager.running:
            if messagebox.askyesno(
                "Confirm Exit",
                "NotTheNet is still running.\nStop all services and exit?",
            ):
                def _stop_and_destroy():
                    self._manager.stop()
                    self.after(0, self.destroy)
                threading.Thread(target=_stop_and_destroy, daemon=True).start()
        else:
            self.destroy()
