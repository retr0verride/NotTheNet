"""Shared constants, styling helpers, and reusable widget factories."""

from __future__ import annotations

import logging
import os
import queue
import subprocess
import sys
import tkinter as tk
from tkinter import ttk

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def _open_path_external(path: str) -> None:
    """Open a file or directory in the platform's default handler."""
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


# ---------------------------------------------------------------------------
# Application constants
# ---------------------------------------------------------------------------

APP_TITLE = "NotTheNet \u2014 Fake Internet Simulator"
APP_VERSION = "2026.04.08-2"
PAD = 8
FIELD_WIDTH = 22
LOG_MAX_LINES = 2000

# ---------------------------------------------------------------------------
# Colour scheme
# ---------------------------------------------------------------------------

C_BG       = "#13131f"
C_PANEL    = "#1a1a2c"
C_SURFACE  = "#222235"
C_BORDER   = "#2d2d48"
C_ACCENT   = "#00d4aa"
C_ACCENT2  = "#00aaff"
C_GREEN    = "#4ade80"
C_RED      = "#e53e3e"
C_ORANGE   = "#fb923c"
C_TEXT     = "#e2e8f0"
C_DIM      = "#4a5568"
C_SUBTLE   = "#94a3b8"
C_ENTRY_BG = "#111122"
C_ENTRY_FG = "#e2e8f0"
C_HOVER    = "#262640"
C_SELECTED = "#1a3a4f"
C_LOG_BG   = "#0c0c18"

# ---------------------------------------------------------------------------
# Zoom / font / event / style constants
# ---------------------------------------------------------------------------

_ZOOM_STEP = 0.15
_ZOOM_MIN  = 0.70
_ZOOM_MAX  = 2.00

_EVT_CONFIGURE  = "<Configure>"
_EVT_BUTTON1    = "<Button-1>"
_EVT_BUTTON4    = "<Button-4>"
_EVT_BUTTON5    = "<Button-5>"
_EVT_MOUSEWHEEL = "<MouseWheel>"

_STY_DARK_COMBO = "Dark.TCombobox"
_STY_JSONLOG_TV = "JsonLog.Treeview"

_JSON_LOG_PATH  = "logs/events.jsonl"
_MAIL_HOST_DEFAULT = "mail.example.com"

# Base window / pane dimensions (at zoom 1.0)
_BASE_W,    _BASE_H    = 1000, 720
_BASE_MIN_W, _BASE_MIN_H = 800, 600
_PANE_BODY_MIN   = 340
_PANE_LOG_MIN    = 120
_PANE_SIDE_MIN   = 148
_PANE_CONFIG_MIN = 500

# NotTheNet globe+prohibition window icon (64x64 RGBA PNG, base64-encoded)
_APP_ICON_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAC/0lEQVR4nO1bvXEsIQwGzabbgF/q"
    "4FIX4UZeES9wAS9wEW7ERTjdwKkrcAH2EOwMwyD0g8Qyw33Z3YHQ96EVOmDjvj/8hIUBYXFAWBwQ"
    "FgeExbGNHOx4emS3vX18hhGI3quAhPQVYkQPASxIjxIjWgrAIc4hYGVnqAAH4rSFo562Y68Ans6N"
    "GCv2CFBzaET2thw3agUonRi1bLV80PgRNQL0kP9+/0+22Z9f1L5I/YlSATTkOaR7xOgRIUoEkJLH"
    "iOekUpvyM9Wn5RPXN/F/gaODfHL+JEDNaN6OEqZVL3CLsS0o0CJfEs+/5z7bqd3Z/uyTPp+2v/69"
    "oX5Jq1DgNMqNepPP+9fstciX/nHEAKoBV1GMvCVq5BPh1qRQ/oPEAWygFnnN7Oe2Tts1In9e/4r8"
    "FAtwCJ8nr5mXkOf2F0fAjZj90WGfJ8chy6CGfE/4cwocSoQuAQ5m5p+5zuesCBCU8Ax9CfneKIAw"
    "ERLx3oRnIsAhzP419aXPf6umL4ui1rjSMYDqVAs96/DHQp77zLceA8oGhIuBLXOjABZGsBD1zPS9"
    "S6x5BOxCEWYgj26IUDVAT+GBhb1Vpq8J0+KzWQ9GJUls5qkZ5VSdGkBwAJaVtWu8Z9G1BUfkeUGS"
    "7UvhtEl2iuPxL2QHJ5/5GuFRAKpBLWzLEMdmh6ruyg3QciOUQjk+N+eQAtwMChHN9pX3slcbG4ID"
    "rjoz1AC0HfPHgNq78yBfjquNEMB+kG4vJwdGk6fA2dSBHkfyKMDI9y5ftaOzMgn35AfgNsSiIA0+"
    "6h+dhLzJ0diNcdTkNfM5SrJS263J2CSGEtnTGCZMKnCwMz1uuLYKI44tyY5W5ByPl8mkRR5zWjJ7"
    "5QqT26nZp/w1uR9wNFTNB5EekHK/9yBv8l+gHKQW+ucjwV2+sIih+mouaMaeCJjhhgjm35ArMrPe"
    "ERp6SWq2W2JDrsnNek9Q40O83xTd73eFfzzCcZnb4jmWfl8gx7JvjNSw5DtDGJZ8a2x2QFgcEBYH"
    "XO3A1fgF9DBZrZ2pzfAAAAAASUVORK5CYII="
)

# Populated by NotTheNetApp._init_fonts(); keyed by (base_size, bold: bool)
_F: dict = {}


def _f(size: int, bold: bool = False):
    """Return the named Font for *size* / *bold*, or a fallback tuple."""
    key = (size, bold)
    if key in _F:
        return _F[key]
    return ("monospace", size, "bold") if bold else ("monospace", size)


# ---------------------------------------------------------------------------
# Hover helper
# ---------------------------------------------------------------------------

def _hover_bind(widget, normal_bg: str, hover_bg: str):
    """Simulate button hover by swapping background colour on Enter/Leave."""
    widget.bind("<Enter>", lambda _e: widget.configure(bg=hover_bg))
    widget.bind("<Leave>", lambda _e: widget.configure(bg=normal_bg))


# ---------------------------------------------------------------------------
# Tooltip
# ---------------------------------------------------------------------------

class _Tooltip:
    """Dark-themed tooltip that appears after a short hover delay."""

    _DELAY_MS = 500
    _WRAP = 280

    def __init__(self, widget: tk.Widget, text: str):
        self._widget = widget
        self._text = text
        self._tw: tk.Toplevel | None = None
        self._job: str | None = None
        widget.bind("<Enter>",    self._on_enter, add="+")
        widget.bind("<Leave>",    self._on_leave, add="+")
        widget.bind("<Button>",   self._on_leave, add="+")
        widget.bind("<Destroy>",  self._on_leave, add="+")

    def _on_enter(self, _event=None):
        self._cancel()
        self._job = self._widget.after(self._DELAY_MS, self._show)

    def _on_leave(self, _event=None):
        self._cancel()
        self._hide()

    def _cancel(self):
        if self._job:
            self._widget.after_cancel(self._job)
            self._job = None

    def _show(self):
        if self._tw:
            return
        x = self._widget.winfo_rootx() + 16
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4

        font = _f(8)
        zoom = 1.0
        if (8, False) in _F:
            try:
                zoom = _F[(8, False)].cget("size") / 8
            except Exception:
                logger.debug("Tooltip font zoom query failed", exc_info=True)
        wrap = round(self._WRAP * zoom)

        self._tw = tk.Toplevel(self._widget)
        self._tw.wm_overrideredirect(True)
        self._tw.wm_geometry(f"+{x}+{y}")
        self._tw.configure(bg=C_BORDER)

        outer = tk.Frame(self._tw, bg=C_BORDER, padx=1, pady=1)
        outer.pack()
        inner = tk.Frame(outer, bg="#1e1e32", padx=7, pady=5)
        inner.pack()
        tk.Label(
            inner,
            text=self._text,
            bg="#1e1e32",
            fg=C_TEXT,
            font=font,
            wraplength=wrap,
            justify="left",
        ).pack()

    def _hide(self):
        if self._tw:
            self._tw.destroy()
            self._tw = None


def tooltip(widget: tk.Widget, text: str) -> None:
    """Attach a tooltip to *widget* showing *text* after a short hover."""
    if text:
        _Tooltip(widget, text)


# ---------------------------------------------------------------------------
# Info panel (field-level help box)
# ---------------------------------------------------------------------------

class _InfoPanel(tk.Frame):
    """Persistent help box pinned at the bottom of each config page."""

    _IDLE = "Click inside a field to see help."

    def __init__(self, parent):
        super().__init__(
            parent,
            bg="#0d0d1c",
            highlightbackground=C_ACCENT,
            highlightthickness=1,
            padx=10, pady=8,
        )
        self._title = tk.Label(
            self, bg="#0d0d1c", fg=C_ACCENT,
            font=_f(9, True), anchor="w", text="",
        )
        self._title.pack(fill="x")
        self._desc = tk.Label(
            self, bg="#0d0d1c", fg=C_TEXT,
            font=_f(8), anchor="w", justify="left",
            wraplength=480, text=self._IDLE,
        )
        self._desc.pack(fill="x", pady=(2, 0))
        self._default_lbl = tk.Label(
            self, bg="#0d0d1c", fg=C_ACCENT2,
            font=_f(8, True), anchor="w", text="",
        )
        self._default_lbl.pack(fill="x", pady=(2, 0))
        self._restore_fn = None
        self._restore_btn = tk.Button(
            self, text="\u21ba",
            bg=C_HOVER, fg=C_TEXT,
            relief="flat", bd=0, padx=8, pady=3,
            font=_f(10), cursor="hand2",
            state="disabled",
            command=self._do_restore,
        )
        self._restore_btn.pack(side="bottom", anchor="e", pady=(4, 0))
        tooltip(self._restore_btn, "Restore suggested default")
        self.bind(_EVT_CONFIGURE, self._on_resize)

    def _on_resize(self, event):
        self._desc.configure(wraplength=max(100, event.width - 24))

    def _do_restore(self):
        if self._restore_fn:
            self._restore_fn()

    def show(self, title: str, tip: str, default: str = "", restore_fn=None):
        """Display field help in the panel."""
        self._title.configure(text=title)
        self._desc.configure(text=tip or "")
        self._default_lbl.configure(
            text=f"Suggested default:  {default}" if default else ""
        )
        self._restore_fn = restore_fn
        self._restore_btn.configure(
            state="normal" if restore_fn else "disabled"
        )

    def clear(self):
        """Reset the panel to its idle state."""
        self._title.configure(text="")
        self._desc.configure(text=self._IDLE)
        self._default_lbl.configure(text="")
        self._restore_fn = None
        self._restore_btn.configure(state="disabled")


# ---------------------------------------------------------------------------
# Logging bridge: route Python log records -> GUI queue
# ---------------------------------------------------------------------------

class _QueueHandler(logging.Handler):
    """Non-blocking log handler that feeds formatted records into a queue."""

    def __init__(self, log_queue: queue.Queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord):
        try:
            try:
                self.log_queue.put_nowait(self.format(record))
            except queue.Full:
                try:
                    self.log_queue.get_nowait()
                except queue.Empty:
                    pass
                self.log_queue.put_nowait(self.format(record))
        except Exception:
            logger.debug("Log record enqueue failed", exc_info=True)


# ---------------------------------------------------------------------------
# Widget factory helpers
# ---------------------------------------------------------------------------

def _label(parent, text, **kw):
    bg = kw.pop("bg", C_SURFACE)
    return tk.Label(parent, text=text, bg=bg, fg=C_TEXT, font=_f(9), **kw)


def _entry(parent, textvariable, width=FIELD_WIDTH):
    return tk.Entry(
        parent,
        textvariable=textvariable,
        width=width,
        bg=C_ENTRY_BG,
        fg=C_ENTRY_FG,
        insertbackground=C_ACCENT,
        relief="flat",
        bd=6,
        font=_f(9),
        highlightthickness=1,
        highlightbackground=C_BORDER,
        highlightcolor=C_ACCENT,
    )


def _combo(parent, textvariable, choices: list, width=FIELD_WIDTH):
    """Dark-styled read-only Combobox for fixed-choice fields."""
    return ttk.Combobox(
        parent,
        textvariable=textvariable,
        values=choices,
        state="readonly",
        width=width - 2,
        font=_f(9),
        style=_STY_DARK_COMBO,
    )


def _check(parent, text, variable):
    return tk.Checkbutton(
        parent,
        text=text,
        variable=variable,
        bg=C_SURFACE,
        fg=C_SUBTLE,
        selectcolor=C_ENTRY_BG,
        activebackground=C_SURFACE,
        activeforeground=C_TEXT,
        font=_f(9),
    )


def _section_frame(parent, title: str):
    """Labelled frame for a config group."""
    return tk.LabelFrame(
        parent,
        text=f"  {title}  ",
        bg=C_SURFACE,
        fg=C_ACCENT,
        font=_f(9, True),
        relief="flat",
        bd=0,
        highlightbackground=C_BORDER,
        highlightthickness=1,
        padx=PAD + 2,
        pady=PAD,
    )


def _row(parent, label: str, widget_factory, row: int,
         col_offset: int = 0, tip: str = "", info_panel=None, default: str = "",
         var=None):
    """Lay out a label + widget pair; update info_panel on click/focus."""
    lbl = tk.Label(parent, text=label, bg=C_SURFACE, fg=C_SUBTLE,
                   font=_f(9), anchor="e")
    lbl.grid(row=row, column=col_offset, sticky="e", padx=(0, 6), pady=4)
    w = widget_factory()
    w.grid(row=row, column=col_offset + 1, sticky="w", pady=4)
    if info_panel and tip:
        def _show(_e=None, _t=label, _d=tip, _def=default, _v=var):
            restore_fn = (lambda: _v.set(_def)) if _v is not None and _def != "" else None
            info_panel.show(_t, _d, str(_def), restore_fn=restore_fn)
        w.bind("<FocusIn>", _show)
        w.bind(_EVT_BUTTON1, _show)
    else:
        if tip:
            tooltip(lbl, tip)
            tooltip(w, tip)
    return w
