"""
NotTheNet - Main GUI Application
Tkinter-based configuration and control panel.

Layout:
  ┌─────────────────────────────────────────────────────┐
  │  NotTheNet  [Start] [Stop] [●/○ status]            │
  ├───────────────┬─────────────────────────────────────┤
  │  Services     │  Config Panel (tabbed per service)  │
  │  ○ DNS        │                                     │
  │  ○ HTTP       │                                     │
  │  ○ HTTPS      │                                     │
  │  ...          │                                     │
  ├───────────────┴─────────────────────────────────────┤
  │  Live Log                                           │
  └─────────────────────────────────────────────────────┘
"""

import json
import logging
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from tkinter import font as _tkfont
from typing import Optional

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config
from service_manager import ServiceManager
from utils.logging_utils import setup_logging

# ─── Constants ────────────────────────────────────────────────────────────────

APP_TITLE = "NotTheNet — Fake Internet Simulator"
APP_VERSION = "2026.03.06-13"
PAD = 8
FIELD_WIDTH = 22
LOG_MAX_LINES = 2000  # Cap displayed log lines to avoid memory creep
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Project root

# ─── Colour scheme ──────────────────────────────────────────────────────────
C_BG       = "#13131f"   # Window background
C_PANEL    = "#1a1a2c"   # Sidebar / panel background
C_SURFACE  = "#222235"   # Config page surface
C_BORDER   = "#2d2d48"   # Subtle dividers
C_ACCENT   = "#00d4aa"   # Primary teal
C_ACCENT2  = "#00aaff"   # Secondary blue
C_GREEN    = "#4ade80"   # Running / OK
C_RED      = "#e53e3e"   # Error / stop
C_ORANGE   = "#fb923c"   # Warning
C_TEXT     = "#e2e8f0"   # Primary text
C_DIM      = "#4a5568"   # Muted / secondary
C_SUBTLE   = "#94a3b8"   # Sub-labels
C_ENTRY_BG = "#111122"   # Input background
C_ENTRY_FG = "#e2e8f0"   # Input foreground
C_HOVER    = "#262640"   # Sidebar hover
C_SELECTED = "#1a3a4f"   # Sidebar selected
C_LOG_BG   = "#0c0c18"   # Log panel background


# ─── Zoom / font scale ───────────────────────────────────────────────────────

_ZOOM_STEP = 0.15
_ZOOM_MIN  = 0.70
_ZOOM_MAX  = 2.00

# Base window / pane dimensions (at zoom 1.0)
_BASE_W,    _BASE_H    = 1000, 720
_BASE_MIN_W, _BASE_MIN_H = 800, 600
_PANE_BODY_MIN   = 340   # main pane: body frame
_PANE_LOG_MIN    = 120   # main pane: log panel
_PANE_SIDE_MIN   = 148   # body pane: sidebar
_PANE_CONFIG_MIN = 500   # body pane: config area

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


# ─── Hover helper ────────────────────────────────────────────────────────────

def _hover_bind(widget, normal_bg: str, hover_bg: str):
    """Simulate button hover by swapping background colour on Enter/Leave."""
    widget.bind("<Enter>", lambda _e: widget.configure(bg=hover_bg))
    widget.bind("<Leave>", lambda _e: widget.configure(bg=normal_bg))


# ─── Tooltip ─────────────────────────────────────────────────────────────────

class _Tooltip:
    """Dark-themed tooltip that appears after a short hover delay."""

    _DELAY_MS = 500
    _WRAP = 280

    def __init__(self, widget: tk.Widget, text: str):
        self._widget = widget
        self._text = text
        self._tw: Optional[tk.Toplevel] = None
        self._job: Optional[str] = None
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

        # Scale wraplength with current zoom if fonts are initialised
        font = _f(8)
        zoom = 1.0
        if (8, False) in _F:
            try:
                zoom = _F[(8, False)].cget("size") / 8
            except Exception:
                pass
        wrap = round(self._WRAP * zoom)

        self._tw = tk.Toplevel(self._widget)
        self._tw.wm_overrideredirect(True)
        self._tw.wm_geometry(f"+{x}+{y}")
        self._tw.configure(bg=C_BORDER)

        # 1 px border via outer frame
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


# ─── Field info panel ───────────────────────────────────────────────────────

class _InfoPanel(tk.Frame):
    """Persistent help box pinned at the bottom of each config page.
    Updates when the user focuses or hovers a field."""

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
        self.bind("<Configure>", self._on_resize)

    def _on_resize(self, event):
        self._desc.configure(wraplength=max(100, event.width - 24))

    def _do_restore(self):
        if self._restore_fn:
            self._restore_fn()

    def show(self, title: str, tip: str, default: str = "", restore_fn=None):
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
        self._title.configure(text="")
        self._desc.configure(text=self._IDLE)
        self._default_lbl.configure(text="")
        self._restore_fn = None
        self._restore_btn.configure(state="disabled")


# ─── Logging bridge: route Python log records → GUI queue ────────────────────

class _QueueHandler(logging.Handler):
    def __init__(self, log_queue: queue.Queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord):
        try:
            self.log_queue.put_nowait(self.format(record))
        except Exception:
            pass


# ─── Helper widgets ──────────────────────────────────────────────────────────

def _label(parent, text, **kw):
    bg = kw.pop("bg", C_SURFACE)
    return tk.Label(parent, text=text, bg=bg, fg=C_TEXT, font=_f(9), **kw)


def _entry(parent, textvariable, width=FIELD_WIDTH):
    e = tk.Entry(
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
    return e


def _combo(parent, textvariable, choices: list, width=FIELD_WIDTH):
    """Dark-styled read-only Combobox for fixed-choice fields."""
    cb = ttk.Combobox(
        parent,
        textvariable=textvariable,
        values=choices,
        state="readonly",
        width=width - 2,
        font=_f(9),
        style="Dark.TCombobox",
    )
    return cb


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
    frame = tk.LabelFrame(
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
    return frame


def _row(parent, label: str, widget_factory, row: int,
         col_offset: int = 0, tip: str = "", info_panel=None, default: str = "",
         var=None):
    """Lay out a label + widget pair; update info_panel on click/focus when provided."""
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
        w.bind("<Button-1>", _show)
    else:
        if tip:
            tooltip(lbl, tip)
            tooltip(w, tip)
    return w


# ─── Per-service configuration pages ─────────────────────────────────────────

# ─── Tiny canvas globe icon ─────────────────────────────────────────────────

class _GlobeCanvas(tk.Canvas):
    """~46×46 px canvas that draws the NotTheNet globe+prohibition logo."""

    SIZE = 46

    def __init__(self, parent):
        super().__init__(
            parent,
            width=self.SIZE, height=self.SIZE,
            bg=C_BG, bd=0, highlightthickness=0,
        )
        self._draw()

    def _draw(self):
        cx, cy, r = 23, 23, 17   # globe circle centre + radius
        pr = 21                  # prohibition circle radius
        teal = "#00c8a0"
        red  = "#ff3b3b"

        # Latitude lines (horizontal)
        self.create_line(cx - r, cy, cx + r, cy, fill=teal, width=1)
        for dy, rw in ((6, r - 2), (12, r - 7)):
            for sign in (-1, 1):
                y = cy + sign * dy
                self.create_arc(cx - rw, y - 4, cx + rw, y + 4,
                                start=0, extent=180, style="arc",
                                outline=teal, width=1)

        # Longitude lines (vertical)
        self.create_line(cx, cy - r, cx, cy + r, fill=teal, width=1)
        self.create_oval(cx - 9, cy - r, cx + 9, cy + r,
                         outline=teal, width=1)

        # Globe outer circle
        self.create_oval(cx - r, cy - r, cx + r, cy + r,
                         outline=teal, width=2)

        # Prohibition red circle
        self.create_oval(cx - pr, cy - pr, cx + pr, cy + pr,
                         outline=red, width=3)

        # Prohibition slash (top-right → bottom-left, 45°)
        import math
        angle = math.radians(45)
        x1 = cx + pr * math.cos(angle)
        y1 = cy - pr * math.sin(angle)
        x2 = cx - pr * math.cos(angle)
        y2 = cy + pr * math.sin(angle)
        self.create_line(x1, y1, x2, y2, fill=red, width=3,
                         capstyle="round")


# ─── Per-service configuration pages ─────────────────────────────────────────

class _GeneralPage(tk.Frame):
    def __init__(self, parent, cfg: Config):
        super().__init__(parent, bg=C_SURFACE)
        self.cfg = cfg
        self.vars: dict = {}
        self._build()

    def _build(self):
        # Horizontal split: form on left, info panel on right
        outer = tk.Frame(self, bg=C_SURFACE)
        outer.pack(fill="both", expand=True)

        self._left_frame = tk.Frame(outer, bg=C_SURFACE)
        self._left_frame.pack(side="left", fill="both", expand=True)

        right = tk.Frame(outer, bg=C_SURFACE, width=240)
        right.pack(side="right", fill="y", padx=(0, PAD + 4), pady=PAD + 4)
        right.pack_propagate(False)
        self._info_panel = _InfoPanel(right)
        self._info_panel.pack(fill="both", expand=True)

        f = _section_frame(self._left_frame, "General Settings")
        f.pack(fill="x", padx=PAD + 4, pady=PAD + 4)

        fields = [
            ("Bind IP",       "bind_ip",      "0.0.0.0",
             "IP address that all services bind to.\n"
             "Use 0.0.0.0 to listen on every interface,\n"
             "or a specific IP to restrict to one interface."),
            ("Redirect IP",   "redirect_ip",  "10.10.10.1",
             "IP returned for all DNS A/AAAA queries.\n"
             "Usually 127.0.0.1 to route malware traffic back to this machine."),
            ("Interface",     "interface",    "eth0",
             "Network interface for iptables REDIRECT rules (e.g. eth0, ens33).\n"
             "Run 'ip link' to list available interfaces."),
            ("iptables Mode", "iptables_mode", "gateway",
             "How iptables REDIRECT rules are applied.\n"
             "loopback \u2014 OUTPUT chain, intercepts traffic from this machine only (default).\n"
             "gateway  \u2014 PREROUTING chain, intercepts traffic from other hosts on the network.\n"
             "Use gateway when NotTheNet is acting as a network gateway for a malware VM.",
             ["loopback", "gateway"]),
            ("Log Directory", "log_dir",      "logs",
             "Directory where rotating log files are written.\n"
             "Created automatically if it does not exist."),
            ("Log Level",     "log_level",    "INFO",
             "Log verbosity: DEBUG (most output) > INFO > WARNING > ERROR (least).\n"
             "DEBUG shows every packet; ERROR shows only failures.",
             ["DEBUG", "INFO", "WARNING", "ERROR"]),
            ("Spoof Public IP", "spoof_public_ip", "93.184.216.34",
             "When set, HTTP/HTTPS responses to well-known IP-check services\n"
             "(api.ipify.org, icanhazip.com, checkip.amazonaws.com, etc.)\n"
             "will return this IP instead of the normal page body.\n"
             "Defeats malware that checks 'am I on the real internet?' via HTTP.\n"
             "Example: 93.184.216.34   Leave blank to disable."),
        ]
        for row, item in enumerate(fields):
            label, key, default, tip = item[0], item[1], item[2], item[3]
            choices = item[4] if len(item) > 4 else None
            val = self.cfg.get("general", key) or default
            v = tk.StringVar(value=str(val))
            self.vars[key] = v
            if choices:
                _row(f, label, lambda v=v, c=choices: _combo(f, v, c), row,
                     tip=tip, info_panel=self._info_panel, default=default, var=v)
            else:
                _row(f, label, lambda v=v: _entry(f, v), row,
                     tip=tip, info_panel=self._info_panel, default=default, var=v)

        check_fields = [
            ("Enable auto-iptables rules", "auto_iptables", True,
             "Add NAT REDIRECT rules via iptables when services start,\n"
             "and remove them cleanly on stop. Requires root."),
            ("Log to file",               "log_to_file",   True,
             "Write log output to a rotating file in the log directory\n"
             "in addition to the GUI log panel."),
            ("JSON structured logging",    "json_logging",  True,
             "Write every intercepted request as a JSON Lines (.jsonl) file\n"
             "for automated pipeline ingestion (CAPEv2, Splunk, ELK).\n"
             "Output: logs/events.jsonl  \u2014  one JSON object per line."),
            ("TCP/IP fingerprint spoofing", "tcp_fingerprint", True,
             "Modify TCP/IP stack parameters (TTL, window size, DF bit)\n"
             "on all listening sockets so responses appear to come from\n"
             "the selected OS. Defeats malware that fingerprints the\n"
             "network stack (e.g. checking TTL=128 for Windows).\n"
             "Select the target OS below."),
        ]
        for i, (label, key, default, tip) in enumerate(check_fields):
            val = self.cfg.get("general", key)
            if val is None:
                val = default
            v = tk.BooleanVar(value=bool(val))
            self.vars[key] = v
            cb = _check(f, label, v)
            cb.grid(row=len(fields) + i, column=0, columnspan=2, sticky="w", pady=4)
            if tip:
                tooltip(cb, tip)

        # TCP fingerprint OS dropdown (shown after the checkboxes)
        fp_row = len(fields) + len(check_fields)
        fp_os_val = self.cfg.get("general", "tcp_fingerprint_os") or "windows"
        v_fp = tk.StringVar(value=str(fp_os_val))
        self.vars["tcp_fingerprint_os"] = v_fp
        _row(f, "Fingerprint OS",
             lambda v=v_fp: _combo(f, v, ["windows", "linux", "macos", "solaris"]),
             fp_row,
             tip="OS profile for TCP/IP fingerprint spoofing.\n"
                 "windows \u2014 TTL=128, Window=65535 (Windows Server 2019+)\n"
                 "linux   \u2014 TTL=64,  Window=29200 (Linux 5.x)\n"
                 "macos   \u2014 TTL=64,  Window=65535 (macOS/BSD)\n"
                 "solaris \u2014 TTL=255, Window=49640",
             info_panel=self._info_panel, default="windows", var=v_fp)

        # JSON log file path
        json_path_val = self.cfg.get("general", "json_log_file") or "logs/events.jsonl"
        v_jp = tk.StringVar(value=str(json_path_val))
        self.vars["json_log_file"] = v_jp
        _row(f, "JSON Log File",
             lambda v=v_jp: _entry(f, v),
             fp_row + 1,
             tip="Path to the JSON Lines event log file.\n"
                 "Each intercepted request is written as one JSON object per line.\n"
                 "Relative to the NotTheNet project root.",
             info_panel=self._info_panel, default="logs/events.jsonl", var=v_jp)

    def apply_to_config(self):
        for key, var in self.vars.items():
            self.cfg.set("general", key, var.get())


class _JsonEventsPage(tk.Frame):
    """Live-updating JSON event log viewer with search and event-type filtering."""

    _POLL_MS = 1000          # file-poll interval
    _MAX_DISPLAY_ROWS = 5000 # cap rows to keep the Treeview responsive
    _COLUMNS = ("timestamp", "event", "src_ip", "detail")

    def __init__(self, parent, cfg: "Config"):
        super().__init__(parent, bg=C_SURFACE)
        self.cfg = cfg
        self._file_pos = 0        # byte offset — resume reading from here
        self._all_rows: list = [] # every parsed row (for re-filtering)
        self._poll_job = None
        self._search_var = tk.StringVar()
        self._filter_var = tk.StringVar(value="ALL")
        self._event_types: set = set()
        self._build()

    # ── UI construction ───────────────────────────────────────────────────

    def _build(self):
        # ── Toolbar row: search + filter + buttons ──
        bar = tk.Frame(self, bg=C_SURFACE)
        bar.pack(fill="x", padx=PAD, pady=(PAD, 4))

        tk.Label(bar, text="Search:", bg=C_SURFACE, fg=C_SUBTLE,
                 font=_f(9)).pack(side="left")
        search_entry = _entry(bar, self._search_var, width=28)
        search_entry.pack(side="left", padx=(4, 10))
        self._search_var.trace_add("write", lambda *_: self._apply_filter())

        tk.Label(bar, text="Event:", bg=C_SURFACE, fg=C_SUBTLE,
                 font=_f(9)).pack(side="left")
        self._filter_combo = _combo(bar, self._filter_var, ["ALL"], width=18)
        self._filter_combo.pack(side="left", padx=(4, 10))
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())

        btn_style = dict(relief="flat", bd=0, padx=10, pady=3,
                         font=_f(8), cursor="hand2")
        refresh_btn = tk.Button(
            bar, text="⟳ Refresh", bg=C_HOVER, fg=C_TEXT,
            command=self._full_reload, **btn_style,
        )
        refresh_btn.pack(side="left", padx=2)
        _hover_bind(refresh_btn, C_HOVER, C_SELECTED)
        tooltip(refresh_btn, "Re-read the entire JSON log file from disk.")

        clear_btn = tk.Button(
            bar, text="✕ Clear View", bg=C_HOVER, fg=C_TEXT,
            command=self._clear_view, **btn_style,
        )
        clear_btn.pack(side="left", padx=2)
        _hover_bind(clear_btn, C_HOVER, C_SELECTED)
        tooltip(clear_btn,
                "Clear the table (does NOT delete the file on disk).")

        open_btn = tk.Button(
            bar, text="📂 Open File", bg=C_HOVER, fg=C_TEXT,
            command=self._open_file_external, **btn_style,
        )
        open_btn.pack(side="left", padx=2)
        _hover_bind(open_btn, C_HOVER, C_SELECTED)
        tooltip(open_btn,
                "Open the raw .jsonl file in the system default editor.")

        # Row count label (right side)
        self._count_label = tk.Label(
            bar, text="0 events", bg=C_SURFACE, fg=C_DIM, font=_f(8),
        )
        self._count_label.pack(side="right")

        # ── Treeview ──
        tree_frame = tk.Frame(self, bg=C_SURFACE)
        tree_frame.pack(fill="both", expand=True, padx=PAD, pady=(0, PAD))

        style = ttk.Style(self)
        style.configure(
            "JsonLog.Treeview",
            background=C_ENTRY_BG,
            foreground=C_ENTRY_FG,
            fieldbackground=C_ENTRY_BG,
            rowheight=22,
            font=_f(8),
        )
        style.configure(
            "JsonLog.Treeview.Heading",
            background=C_PANEL,
            foreground=C_ACCENT,
            font=_f(8, True),
        )
        style.map("JsonLog.Treeview",
                  background=[("selected", C_SELECTED)],
                  foreground=[("selected", C_TEXT)])

        self._tree = ttk.Treeview(
            tree_frame,
            columns=self._COLUMNS,
            show="headings",
            selectmode="extended",
            style="JsonLog.Treeview",
        )
        self._tree.heading("timestamp", text="Timestamp", anchor="w")
        self._tree.heading("event",     text="Event",     anchor="w")
        self._tree.heading("src_ip",    text="Source IP", anchor="w")
        self._tree.heading("detail",    text="Detail",    anchor="w")

        self._tree.column("timestamp", width=180, minwidth=140, stretch=False)
        self._tree.column("event",     width=150, minwidth=100, stretch=False)
        self._tree.column("src_ip",    width=120, minwidth=80,  stretch=False)
        self._tree.column("detail",    width=500, minwidth=200, stretch=True)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal",
                            command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set,
                             xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        # ── Detail panel at bottom ──
        detail_frame = _section_frame(self, "Selected Event (raw JSON)")
        detail_frame.pack(fill="x", padx=PAD, pady=(0, PAD))
        self._detail_text = scrolledtext.ScrolledText(
            detail_frame, height=4, bg=C_ENTRY_BG, fg=C_ENTRY_FG,
            insertbackground=C_ACCENT, relief="flat", font=_f(8),
            highlightthickness=1, highlightbackground=C_BORDER,
            highlightcolor=C_ACCENT, state="disabled", wrap="word",
        )
        self._detail_text.pack(fill="x")
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Kick off file polling
        self._poll_job = self.after(500, self._poll_file)

    # ── Data loading ──────────────────────────────────────────────────────

    def _get_log_path(self) -> str:
        return str(self.cfg.get("general", "json_log_file") or "logs/events.jsonl")

    def _poll_file(self):
        """Incrementally read new lines appended since last poll."""
        path = self._get_log_path()
        try:
            with open(path, encoding="utf-8") as fh:
                fh.seek(self._file_pos)
                new_lines = fh.readlines()
                self._file_pos = fh.tell()
        except OSError:
            new_lines = []

        if new_lines:
            added = 0
            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                row = self._obj_to_row(obj)
                self._all_rows.append((row, obj))
                added += 1

                # Track event types for filter dropdown
                evt = obj.get("event", "")
                if evt and evt not in self._event_types:
                    self._event_types.add(evt)
                    choices = ["ALL"] + sorted(self._event_types)
                    self._filter_combo.configure(values=choices)

            if added:
                self._apply_filter()

        self._poll_job = self.after(self._POLL_MS, self._poll_file)

    def _full_reload(self):
        """Re-read the entire file from offset 0."""
        self._file_pos = 0
        self._all_rows.clear()
        self._event_types.clear()
        self._filter_combo.configure(values=["ALL"])
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._poll_file()

    def _clear_view(self):
        """Clear the table without deleting the file."""
        self._all_rows.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._count_label.configure(text="0 events")

    @staticmethod
    def _obj_to_row(obj: dict) -> tuple:
        """Extract display columns from a JSON event dict."""
        ts = obj.get("timestamp", "")
        evt = obj.get("event", "")
        src = obj.get("src_ip", "")
        # Build a compact detail string from remaining keys
        skip = {"timestamp", "epoch", "event", "src_ip"}
        parts = [f"{k}={v}" for k, v in obj.items() if k not in skip]
        detail = "  ".join(parts)
        return (ts, evt, src, detail)

    # ── Filtering ─────────────────────────────────────────────────────────

    def _apply_filter(self, *_args):
        """Rebuild the Treeview to show only matching rows."""
        search = self._search_var.get().strip().lower()
        evt_filter = self._filter_var.get()

        for iid in self._tree.get_children():
            self._tree.delete(iid)

        count = 0
        start = max(0, len(self._all_rows) - self._MAX_DISPLAY_ROWS)
        for row, obj in self._all_rows[start:]:
            # Event type filter
            if evt_filter != "ALL" and obj.get("event", "") != evt_filter:
                continue
            # Text search (across all values)
            if search:
                haystack = " ".join(str(v) for v in obj.values()).lower()
                if search not in haystack:
                    continue
            self._tree.insert("", "end", values=row)
            count += 1

        self._count_label.configure(
            text=f"{count} event{'s' if count != 1 else ''}"
                 f" (of {len(self._all_rows)} total)"
        )
        # Auto-scroll to bottom
        children = self._tree.get_children()
        if children:
            self._tree.see(children[-1])

    # ── Selection detail ──────────────────────────────────────────────────

    def _on_select(self, _event=None):
        sel = self._tree.selection()
        if not sel:
            return
        item = self._tree.item(sel[0])
        values = item.get("values", ())
        # Find the matching raw JSON object
        ts = values[0] if values else ""
        matched = None
        for row, obj in reversed(self._all_rows):
            if row[0] == ts:
                matched = obj
                break
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        if matched:
            self._detail_text.insert(
                "1.0", json.dumps(matched, indent=2, default=str)
            )
        else:
            self._detail_text.insert("1.0", str(values))
        self._detail_text.configure(state="disabled")

    # ── External open ─────────────────────────────────────────────────────

    def _open_file_external(self):
        """Open the .jsonl file in the OS default application."""
        import subprocess
        path = os.path.abspath(self._get_log_path())
        if not os.path.exists(path):
            messagebox.showinfo("Not Found",
                                f"JSON log file does not exist yet:\n{path}")
            return
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa: S606 — intentional; opens user's own log file
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file:\n{e}")

    def destroy(self):
        if self._poll_job:
            self.after_cancel(self._poll_job)
            self._poll_job = None
        super().destroy()

    def apply_to_config(self):
        pass  # read-only page — nothing to save


class _ServicePage(tk.Frame):
    """Generic service config page (HTTP, HTTPS, SMTP, FTP, etc.)."""

    def __init__(self, parent, cfg: Config, section: str, fields: list, checks: list):
        super().__init__(parent, bg=C_SURFACE)
        self.cfg = cfg
        self.section = section
        self.fields = fields
        self.checks = checks
        self.vars: dict = {}
        self._build()

    def _build(self):
        # Horizontal split: form on left, info panel on right
        outer = tk.Frame(self, bg=C_SURFACE)
        outer.pack(fill="both", expand=True)

        self._left_frame = tk.Frame(outer, bg=C_SURFACE)
        self._left_frame.pack(side="left", fill="both", expand=True)

        right = tk.Frame(outer, bg=C_SURFACE, width=240)
        right.pack(side="right", fill="y", padx=(0, PAD + 4), pady=PAD + 4)
        right.pack_propagate(False)
        self._info_panel = _InfoPanel(right)
        self._info_panel.pack(fill="both", expand=True)

        f = _section_frame(self._left_frame, self.section.upper() + " Service")
        f.pack(fill="x", padx=PAD + 4, pady=PAD + 4)
        self._form_frame = f

        for i, item in enumerate(self.fields):
            label, key, default = item[0], item[1], item[2]
            tip = item[3] if len(item) > 3 else ""
            choices = item[4] if len(item) > 4 else None
            val = self.cfg.get(self.section, key) or default
            v = tk.StringVar(value=str(val))
            self.vars[key] = v
            if choices:
                _row(f, label, lambda v=v, c=choices: _combo(f, v, c), i,
                     tip=tip, info_panel=self._info_panel, default=default, var=v)
            else:
                _row(f, label, lambda v=v: _entry(f, v), i,
                     tip=tip, info_panel=self._info_panel, default=default, var=v)

        for j, item in enumerate(self.checks):
            label, key, default = item[0], item[1], item[2]
            tip = item[3] if len(item) > 3 else ""
            val = self.cfg.get(self.section, key)
            if val is None:
                val = default
            v = tk.BooleanVar(value=bool(val))
            self.vars[key] = v
            cb = _check(f, label, v)
            cb.grid(row=len(self.fields) + j, column=0, columnspan=2, sticky="w", pady=4)
            if tip:
                tooltip(cb, tip)

    def apply_to_config(self):
        for key, var in self.vars.items():
            self.cfg.set(self.section, key, var.get())


class _DNSPage(_ServicePage):
    def __init__(self, parent, cfg: Config):
        super().__init__(
            parent, cfg, "dns",
            fields=[
                ("Port",        "port",       "53",
                 "UDP/TCP port for the fake DNS server. Default: 53.\n"
                 "iptables will redirect all DNS traffic here. Requires root."),
                ("Resolve To",  "resolve_to", "10.10.10.1",
                 "IP address returned for all A/AAAA queries unless\n"
                 "overridden by a custom record in the section below."),
                ("TTL (s)",     "ttl",        "300",
                 "DNS record TTL in seconds. Lower values cause malware to\n"
                 "re-resolve hostnames more frequently (min re-query interval)."),
            ],
            checks=[
                ("Enabled",          "enabled",    True,
                 "Enable or disable the fake DNS service."),
                ("Handle PTR/rDNS",  "handle_ptr", True,
                 "Respond to reverse DNS (PTR) lookups with a synthesized hostname.\n"
                 "Prevents connection timeouts in malware that queries its own IP."),
            ],
        )
        # Custom records editor (popup button)
        self._custom_records_str: str = ""
        self._build_custom_records()

    def _build_custom_records(self):
        # Load initial records from config into a plain string
        records = self.cfg.get("dns", "custom_records") or {}
        self._custom_records_str = "\n".join(f"{k} = {v}" for k, v in records.items())

        # Button sits at the bottom of the form section
        btn_row = len(self.fields) + len(self.checks)
        _btn_style = dict(relief="flat", bd=0, padx=10, pady=4,
                          font=_f(9), cursor="hand2")
        btn = tk.Button(
            self._form_frame,
            text="⊞  Custom DNS Records…",
            bg=C_HOVER, fg=C_TEXT,
            command=self._open_records_popup,
            **_btn_style,
        )
        btn.grid(row=btn_row, column=0, columnspan=2, sticky="w", pady=(10, 4))
        _hover_bind(btn, C_HOVER, C_SELECTED)
        tooltip(btn, "Edit per-hostname DNS overrides.\nFormat: hostname = IP  (one per line)")

    def _open_records_popup(self):
        dlg = tk.Toplevel()
        dlg.title("Custom DNS Records")
        dlg.configure(bg=C_SURFACE)
        dlg.geometry("460x340")
        dlg.resizable(True, True)
        dlg.grab_set()

        tk.Label(dlg, text="One entry per line:  example.com = 192.168.1.1",
                 bg=C_SURFACE, fg=C_DIM, font=_f(8)).pack(anchor="w", padx=12, pady=(10, 2))

        txt = scrolledtext.ScrolledText(
            dlg, bg=C_ENTRY_BG, fg=C_ENTRY_FG,
            insertbackground=C_ACCENT, relief="flat",
            font=_f(9),
            highlightthickness=1, highlightbackground=C_BORDER,
            highlightcolor=C_ACCENT,
        )
        txt.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        if self._custom_records_str:
            txt.insert("end", self._custom_records_str)

        bar = tk.Frame(dlg, bg=C_SURFACE)
        bar.pack(fill="x", padx=12, pady=(0, 12))

        def _save():
            self._custom_records_str = txt.get("1.0", "end").strip()
            dlg.destroy()

        tk.Button(bar, text="Cancel", bg=C_HOVER, fg=C_TEXT,
                  relief="flat", bd=0, padx=12, pady=4, font=_f(9),
                  cursor="hand2", command=dlg.destroy).pack(side="right", padx=(4, 0))
        tk.Button(bar, text="Save", bg=C_ACCENT, fg="#0c0c18",
                  relief="flat", bd=0, padx=12, pady=4, font=_f(9, True),
                  cursor="hand2", command=_save).pack(side="right")

    def apply_to_config(self):
        super().apply_to_config()
        # Parse custom records from the stored string
        records = {}
        for line in self._custom_records_str.splitlines():
            line = line.strip()
            if "=" in line:
                parts = line.split("=", 1)
                name = parts[0].strip().lower()
                ip = parts[1].strip()
                if name and ip:
                    records[name] = ip
        self.cfg.set("dns", "custom_records", records)


# ─── Main Application Window ─────────────────────────────────────────────────

class NotTheNetApp(tk.Tk):
    def __init__(self, config_path: Optional[str] = None):
        super().__init__()
        self.title(APP_TITLE)
        self.configure(bg=C_BG)
        self.resizable(True, True)

        # Window / taskbar icon
        try:
            _icon = tk.PhotoImage(data=_APP_ICON_B64)
            self.iconphoto(True, _icon)
            self._icon = _icon  # keep reference so GC does not drop it
        except Exception:
            pass  # non-fatal -- icon is cosmetic only

        self._cfg = Config(config_path or "config.json")
        self._log_queue: queue.Queue = queue.Queue()
        self._manager: Optional[ServiceManager] = None
        self._svc_vars: dict = {}  # service name → BooleanVar (status indicator)
        self._pages: dict = {}     # section name → page frame

        # Initialise zoom-aware fonts before any widget is built
        self._zoom_factor: float = float(self._cfg.get("ui", "zoom") or 1.0)
        self._init_fonts()

        # Apply initial geometry scaled to saved zoom
        z = self._zoom_factor
        self.geometry(f"{round(_BASE_W * z)}x{round(_BASE_H * z)}")
        self.minsize(round(_BASE_MIN_W * z), round(_BASE_MIN_H * z))

        # Set up logging → queue bridge
        # Attach to root logger so messages from all modules (services.*, etc.) appear.
        root_logger = logging.getLogger()
        qh = _QueueHandler(self._log_queue)
        qh.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                              datefmt="%H:%M:%S")
        )
        root_logger.addHandler(qh)

        self._log_level_filter: str = ""   # empty = show all
        self._build_ui()
        self._poll_log_queue()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI construction ───────────────────────────────────────────────────────

    def _init_fonts(self):
        """Create (or reconfigure) all named Font objects for the current zoom."""
        scale = self._zoom_factor
        for sz in (7, 8, 9, 10, 17):
            for bold in (False, True):
                key = (sz, bold)
                pt = max(6, round(sz * scale))
                if key in _F:
                    _F[key].configure(size=pt)
                else:
                    _F[key] = _tkfont.Font(
                        family="monospace",
                        size=pt,
                        weight="bold" if bold else "normal",
                    )

    def _set_zoom(self, delta: float):
        """Step the UI font scale by *delta*, resize the window, and persist."""
        new = max(_ZOOM_MIN, min(_ZOOM_MAX, self._zoom_factor + delta))
        if new == self._zoom_factor:
            return
        old = self._zoom_factor
        self._zoom_factor = new
        self._init_fonts()
        # Update zoom label in toolbar if it exists
        if hasattr(self, "_zoom_label"):
            pct = round(new * 100)
            self._zoom_label.configure(text=f"{pct}%")
        # Resize window proportionally
        ratio = new / old
        cw = self.winfo_width()  or _BASE_W
        ch = self.winfo_height() or _BASE_H
        nw = max(round(_BASE_MIN_W * new), round(cw * ratio))
        nh = max(round(_BASE_MIN_H * new), round(ch * ratio))
        self.geometry(f"{nw}x{nh}")
        self.minsize(round(_BASE_MIN_W * new), round(_BASE_MIN_H * new))
        # Update paned-window minsizes so sashes stay sensible
        if hasattr(self, "_main_pane"):
            panes = self._main_pane.panes()
            if len(panes) >= 2:
                self._main_pane.paneconfig(panes[0], minsize=round(_PANE_BODY_MIN * new))
                self._main_pane.paneconfig(panes[1], minsize=round(_PANE_LOG_MIN  * new))
        if hasattr(self, "_body_pane"):
            panes = self._body_pane.panes()
            if len(panes) >= 2:
                self._body_pane.paneconfig(panes[0], minsize=round(_PANE_SIDE_MIN   * new))
                self._body_pane.paneconfig(panes[1], minsize=round(_PANE_CONFIG_MIN * new))
        self._cfg.set("ui", "zoom", round(new, 2))
        self._cfg.save()

    def _build_ui(self):
        self._apply_ttk_styles()
        self._build_toolbar()
        self._build_main_pane()
        self._build_statusbar()
        # Keyboard zoom shortcuts
        self.bind_all("<Control-equal>",  lambda _e: self._set_zoom(+_ZOOM_STEP))
        self.bind_all("<Control-minus>",  lambda _e: self._set_zoom(-_ZOOM_STEP))
        self.bind_all("<Control-0>",      lambda _e: self._set_zoom(1.0 - self._zoom_factor))

    def _apply_ttk_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Sash",  sashthickness=5, background=C_BORDER)
        style.configure("VSash", sashthickness=5, background=C_BORDER)
        style.configure("HSash", sashthickness=5, background=C_BORDER)
        # Dark combobox style
        style.configure("Dark.TCombobox",
            fieldbackground=C_ENTRY_BG,
            background=C_ENTRY_BG,
            foreground=C_ENTRY_FG,
            selectbackground=C_SELECTED,
            selectforeground=C_TEXT,
            arrowcolor=C_ACCENT,
            bordercolor=C_BORDER,
            lightcolor=C_BORDER,
            darkcolor=C_BORDER,
            insertcolor=C_ACCENT,
        )
        style.map("Dark.TCombobox",
            fieldbackground=[("readonly", C_ENTRY_BG), ("disabled", C_BG)],
            foreground=[("readonly", C_ENTRY_FG), ("disabled", C_DIM)],
            background=[("active", C_HOVER), ("pressed", C_SELECTED)],
            arrowcolor=[("active", C_ACCENT), ("pressed", C_ACCENT2)],
        )

    def _build_toolbar(self):
        # Outer toolbar container
        bar = tk.Frame(self, bg=C_BG)
        bar.pack(fill="x")

        # Thin accent line at very top
        tk.Frame(bar, bg=C_ACCENT, height=2).pack(fill="x")

        inner = tk.Frame(bar, bg=C_BG, pady=8)
        inner.pack(fill="x")

        # Globe canvas icon
        globe = _GlobeCanvas(inner)
        globe.pack(side="left", padx=(PAD + 2, 6))

        # Wordmark + version
        name_frame = tk.Frame(inner, bg=C_BG)
        name_frame.pack(side="left", padx=(0, 14))
        tk.Label(
            name_frame, text="NotTheNet",
            font=_f(17, True),
            bg=C_BG, fg=C_ACCENT,
        ).pack(anchor="sw")
        tk.Label(
            name_frame, text=f"v{APP_VERSION}  ·  Fake Internet Simulator",
            font=_f(8),
            bg=C_BG, fg=C_DIM,
        ).pack(anchor="nw")

        # Vertical divider
        tk.Frame(inner, bg=C_BORDER, width=1).pack(side="left", fill="y", padx=8)

        # Buttons
        btn_style = dict(relief="flat", bd=0, padx=14, pady=5,
                         font=_f(9, True), cursor="hand2")

        self._btn_start = tk.Button(
            inner, text="▶  Start", bg=C_GREEN, fg="#0c0c18",
            command=self._on_start, **btn_style
        )
        self._btn_start.pack(side="left", padx=(0, 4))
        _hover_bind(self._btn_start, C_GREEN, "#6ee89a")
        tooltip(self._btn_start,
                "Apply all config values and start every enabled service.\n"
                "Also installs iptables REDIRECT rules if auto-iptables is on.\n"
                "Requires root (or sudo).")

        self._btn_stop = tk.Button(
            inner, text="■  Stop", bg=C_RED, fg="#0c0c18",
            command=self._on_stop, state="disabled", **btn_style
        )
        self._btn_stop.pack(side="left", padx=(0, 10))
        _hover_bind(self._btn_stop, C_RED, "#fc5c5c")
        tooltip(self._btn_stop,
                "Gracefully stop all running services and remove\n"
                "any iptables REDIRECT rules that were added on start.")

        # Vertical divider
        tk.Frame(inner, bg=C_BORDER, width=1).pack(side="left", fill="y", padx=6)

        sec_btn = dict(relief="flat", bd=0, padx=10, pady=5,
                       font=_f(9), cursor="hand2")
        self._btn_save = tk.Button(
            inner, text="💾  Save", bg=C_HOVER, fg=C_TEXT,
            command=self._on_save, **sec_btn
        )
        self._btn_save.pack(side="left", padx=2)
        _hover_bind(self._btn_save, C_HOVER, C_SELECTED)
        tooltip(self._btn_save, "Save current GUI settings to config.json.")

        self._btn_load = tk.Button(
            inner, text="📂  Load…", bg=C_HOVER, fg=C_TEXT,
            command=self._on_load, **sec_btn
        )
        self._btn_load.pack(side="left", padx=2)
        _hover_bind(self._btn_load, C_HOVER, C_SELECTED)
        tooltip(self._btn_load,
                "Load settings from a different JSON config file.\n"
                "All panels will be rebuilt with the new values.")

        # ── Zoom controls ──
        tk.Frame(inner, bg=C_BORDER, width=1).pack(side="left", fill="y", padx=6)

        zoom_frame = tk.Frame(inner, bg=C_BG)
        zoom_frame.pack(side="left")

        btn_zoom_out = tk.Button(
            zoom_frame, text="A−",
            bg=C_HOVER, fg=C_SUBTLE, relief="flat",
            padx=6, pady=3, font=_f(8), cursor="hand2",
            command=lambda: self._set_zoom(-_ZOOM_STEP),
        )
        btn_zoom_out.pack(side="left")
        _hover_bind(btn_zoom_out, C_HOVER, C_SELECTED)
        tooltip(btn_zoom_out, "Zoom out  (Ctrl+−)")

        self._zoom_label = tk.Label(
            zoom_frame,
            text=f"{round(self._zoom_factor * 100)}%",
            bg=C_BG, fg=C_DIM,
            font=_f(8), width=4,
        )
        self._zoom_label.pack(side="left")
        tooltip(self._zoom_label,
                "Current zoom level.\n"
                "Ctrl+= zoom in · Ctrl+− zoom out · Ctrl+0 reset")

        btn_zoom_in = tk.Button(
            zoom_frame, text="A+",
            bg=C_HOVER, fg=C_SUBTLE, relief="flat",
            padx=6, pady=3, font=_f(8), cursor="hand2",
            command=lambda: self._set_zoom(+_ZOOM_STEP),
        )
        btn_zoom_in.pack(side="left")
        _hover_bind(btn_zoom_in, C_HOVER, C_SELECTED)
        tooltip(btn_zoom_in, "Zoom in  (Ctrl+=)")

        # Root warning (right side)
        if os.name != "nt" and os.geteuid() != 0:  # type: ignore[attr-defined]
            warn = tk.Label(
                inner,
                text="⚠  Not root — ports <1024 may fail",
                bg=C_BG, fg=C_ORANGE,
                font=_f(8),
            )
            warn.pack(side="right", padx=PAD)

        # Bottom border
        tk.Frame(bar, bg=C_BORDER, height=1).pack(fill="x")

    def _build_main_pane(self):
        """Vertical split: top = body (sidebar + config), bottom = log panel."""
        self._main_pane = tk.PanedWindow(
            self, orient="vertical", bg=C_BG,
            sashwidth=5, sashpad=0, sashrelief="flat",
        )
        self._main_pane.pack(fill="both", expand=True)

        body_frame = tk.Frame(self._main_pane, bg=C_BG)
        self._main_pane.add(body_frame, minsize=340)

        log_frame_outer = tk.Frame(self._main_pane, bg=C_BG)
        self._main_pane.add(log_frame_outer, minsize=120)

        self._build_body(body_frame)
        self._build_log_panel(log_frame_outer)

    def _build_body(self, parent):
        self._body_pane = tk.PanedWindow(parent, orient="horizontal", bg=C_BG,
                              sashwidth=5, sashpad=0, sashrelief="flat")
        self._body_pane.pack(fill="both", expand=True)
        body = self._body_pane

        # ── Left: service list ──
        left = tk.Frame(body, bg=C_PANEL)
        body.add(left, minsize=148)

        # Sidebar header (pinned, not scrollable)
        hdr = tk.Frame(left, bg=C_PANEL, pady=8)
        hdr.pack(fill="x")
        tk.Label(
            hdr, text="  SERVICES",
            bg=C_PANEL, fg=C_DIM,
            font=_f(8, True),
        ).pack(anchor="w")
        tk.Frame(left, bg=C_BORDER, height=1).pack(fill="x")

        # Scrollable canvas for sidebar items
        self._sb_canvas = tk.Canvas(left, bg=C_PANEL, highlightthickness=0, bd=0)
        self._sb_canvas.pack(fill="both", expand=True)
        sb_inner = tk.Frame(self._sb_canvas, bg=C_PANEL)
        _sb_win = self._sb_canvas.create_window((0, 0), window=sb_inner, anchor="nw")
        sb_inner.bind(
            "<Configure>",
            lambda e: self._sb_canvas.configure(
                scrollregion=self._sb_canvas.bbox("all")
            ),
        )
        self._sb_canvas.bind(
            "<Configure>",
            lambda e: self._sb_canvas.itemconfig(_sb_win, width=e.width),
        )

        def _sb_scroll(event):
            if event.num == 4 or getattr(event, "delta", 0) > 0:
                self._sb_canvas.yview_scroll(-1, "units")
            elif event.num == 5 or getattr(event, "delta", 0) < 0:
                self._sb_canvas.yview_scroll(1, "units")

        self._sb_scroll = _sb_scroll
        for _w in (self._sb_canvas, sb_inner):
            _w.bind("<MouseWheel>", _sb_scroll)
            _w.bind("<Button-4>",   _sb_scroll)
            _w.bind("<Button-5>",   _sb_scroll)

        self._service_btns: dict = {}

        # Group: General
        self._add_sidebar_section(sb_inner, "CONFIG")
        self._add_sidebar_btn(sb_inner, "general", "⚙  General",
                              "Global settings: bind IP, redirect IP,\n"
                              "network interface, log directory, and verbosity.",
                              show_dot=False)

        # Group: Network services
        self._add_sidebar_section(sb_inner, "NETWORK")
        for key, label, tip in [
            ("dns",   "◈  DNS",
             "Fake DNS server — resolves all hostnames to redirect_ip.\n"
             "Supports custom per-hostname overrides and PTR responses."),
            ("http",  "◈  HTTP",
             "Fake HTTP server — responds to all plaintext web requests\n"
             "with a configurable status code and body."),
            ("https", "◈  HTTPS",
             "Fake HTTPS server — TLS-encrypted HTTP with a self-signed cert.\n"
             "Malware rarely validates the certificate."),
            ("ftp",   "◈  FTP",
             "Fake FTP server — accepts logins and optionally saves uploads\n"
             "to disk with UUID filenames."),
            ("ntp",   "◈  NTP",
             "Fake NTP server — returns current system time on UDP/123.\n"
             "Defeats clock-skew sandbox detection used by evasive malware."),
            ("irc",   "◈  IRC",
             "Fake IRC server — accepts botnet C2 connections on TCP/6667.\n"
             "Provides realistic welcome sequence and channel join so bots\n"
             "proceed to sit awaiting commands."),
            ("tftp",    "◈  TFTP",
             "Fake TFTP server — handles RRQ (serves stub file) and WRQ\n"
             "(saves uploads) on UDP/69. Used for payload staging and\n"
             "lateral movement exfiltration."),
            ("telnet",  "◈  Telnet",
             "Fake Telnet server (TCP/23) — Mirai and virtually all IoT botnets\n"
             "authenticate through Telnet. Logs credentials and simulates a\n"
             "BusyBox shell to keep bots alive and issuing commands."),
            ("socks5",  "◈  SOCKS5",
             "Fake SOCKS5 proxy (TCP/1080) — SystemBC, QakBot, Cobalt Strike\n"
             "and many RATs tunnel C2 through SOCKS5.\n"
             "The CONNECT request reveals the real C2 host and port even when\n"
             "DNS is fake."),
            ("ircs",    "◈  IRC/TLS",
             "TLS-wrapped fake IRC server (TCP/6697) — modern botnets use SSL\n"
             "IRC to avoid plaintext interception. Same full sinkhole logic as\n"
             "the plain IRC service, with TLS handshake on top."),
            ("icmp",    "◈  ICMP",
             "ICMP echo responder — answers all pings so malware connectivity\n"
             "checks succeed. iptables DNAT redirects forwarded pings here;\n"
             "the kernel issues genuine echo-replies automatically."),
            ("smb",     "◈  SMB",
             "Fake SMB server (TCP/445) — captures SMBv1/v2 negotiate requests.\n"
             "Flags EternalBlue (MS17-010) probes. Used by WannaCry, NotPetya,\n"
             "Emotet, ransomware lateral movement."),
            ("rdp",     "◈  RDP",
             "Fake RDP server (TCP/3389) — extracts Windows username from the\n"
             "TPKT mstshash cookie before any encryption. Used by NLBrute,\n"
             "ransomware operators, RATs."),
            ("vnc",     "◈  VNC",
             "Fake VNC server (TCP/5900) — RFB 3.8 handshake + VNC Auth\n"
             "challenge. Captures DES response for offline cracking. Used by\n"
             "hVNC RATs and brute-force scanners."),
            ("mysql",   "◈  MySQL",
             "Fake MySQL server (TCP/3306) — Handshake V10 greeting; captures\n"
             "plaintext username and logs COM_QUERY commands. Used by stealers\n"
             "(RedLine, Raccoon) and web shells."),
            ("mssql",   "◈  MSSQL",
             "Fake MSSQL server (TCP/1433) — TDS pre-login with ENCRYPT_NOT_SUP\n"
             "causes Login7 to arrive unencrypted; the password is only XOR-\n"
             "obfuscated and is fully recovered. Used by QakBot, Emotet."),
            ("redis",   "◈  Redis",
             "Fake Redis server (TCP/6379) — RESP protocol; responds to PING,\n"
             "INFO, CONFIG, SLAVEOF, SAVE. Flags write-webshell and SLAVEOF\n"
             "exfil attempts. Used by cryptominers and persistence implants."),
            ("ldap",    "◈  LDAP",
             "Fake LDAP server (TCP/389) — parses BER BindRequest; captures\n"
             "plaintext SimpleBind DN and password. Used by BloodHound,\n"
             "Cobalt Strike LDAP query BOF, AD-targeting stealers."),
        ]:
            self._add_sidebar_btn(sb_inner, key, label, tip)

        # Group: Mail services
        self._add_sidebar_section(sb_inner, "MAIL")
        for key, label, tip in [
            ("smtp",  "◈  SMTP",
             "Fake SMTP server — accepts email submissions and optionally\n"
             "saves them as .eml files for analysis."),
            ("smtps", "◈  SMTPS",
             "Fake SMTPS server (implicit TLS port 465) — used by stealers\n"
             "such as RedLine, AgentTesla, and FormBook to exfiltrate credentials."),
            ("pop3",  "◈  POP3",
             "Fake POP3 server — announces an empty mailbox to connecting clients."),
            ("pop3s", "◈  POP3S",
             "Fake POP3S server (implicit TLS port 995)."),
            ("imap",  "◈  IMAP",
             "Fake IMAP server — announces an empty INBOX to connecting clients."),
            ("imaps", "◈  IMAPS",
             "Fake IMAPS server (implicit TLS port 993)."),
        ]:
            self._add_sidebar_btn(sb_inner, key, label, tip)

        # Group: Catch-all
        self._add_sidebar_section(sb_inner, "FALLBACK")
        self._add_sidebar_btn(sb_inner, "catch_all", "◈  Catch-All",
                              "TCP/UDP catch-all — iptables redirects all traffic\n"
                              "not handled by specific services to these ports.")

        # Group: Logging / analysis
        self._add_sidebar_section(sb_inner, "ANALYSIS")
        self._add_sidebar_btn(sb_inner, "json_events", "◈  JSON Events",
                              "Live view of structured JSON event log.\n"
                              "Shows every intercepted request with search\n"
                              "and event-type filtering.",
                              show_dot=False)

        # ── Right: config pages ──
        right = tk.Frame(body, bg=C_SURFACE)
        body.add(right, minsize=500)

        self._page_container = tk.Frame(right, bg=C_SURFACE)
        self._page_container.pack(fill="both", expand=True)

        self._build_pages()
        self._show_page("general")

    def _add_sidebar_section(self, parent, title: str):
        """Small muted category header in the sidebar."""
        f = tk.Frame(parent, bg=C_PANEL, pady=0)
        f.pack(fill="x", pady=(6, 0))
        lbl = tk.Label(
            f, text=f"  {title}",
            bg=C_PANEL, fg=C_DIM,
            font=_f(7, True),
        )
        lbl.pack(anchor="w", padx=4)
        if hasattr(self, "_sb_scroll"):
            for _w in (f, lbl):
                _w.bind("<MouseWheel>", self._sb_scroll)
                _w.bind("<Button-4>",   self._sb_scroll)
                _w.bind("<Button-5>",   self._sb_scroll)

    def _add_sidebar_btn(self, parent, key: str, label: str, tip: str = "", show_dot: bool = True):
        """Add one sidebar service button with an optional status dot on the right."""
        row = tk.Frame(parent, bg=C_PANEL, cursor="hand2")
        row.pack(fill="x", pady=1)

        btn = tk.Label(
            row, text=f"  {label}",
            bg=C_PANEL, fg=C_SUBTLE,
            font=_f(9), anchor="w",
        )
        btn.pack(side="left", fill="x", expand=True, ipady=5)

        # Store row + btn so _show_page can highlight the active item
        self._service_btns[key] = (row, btn)

        # Click anywhere on the row navigates to the page
        row.bind("<Button-1>", lambda _e=None: self._show_page(key))  # type: ignore[misc]
        btn.bind("<Button-1>", lambda _e=None: self._show_page(key))  # type: ignore[misc]
        _hover_bind(row, C_PANEL, C_HOVER)
        _hover_bind(btn, C_PANEL, C_HOVER)

        if tip:
            tooltip(row, tip)
            tooltip(btn, tip)

        dot = None
        if show_dot:
            dot = tk.Label(
                row, text="●",
                bg=C_PANEL, fg=C_DIM,
                font=_f(8), padx=6,
            )
            dot.pack(side="right")
            dot.bind("<Button-1>", lambda _e=None: self._show_page(key))  # type: ignore[misc]
            self._svc_vars[key] = dot

        if hasattr(self, "_sb_scroll"):
            for _w in ([row, btn] + ([dot] if dot else [])):
                _w.bind("<MouseWheel>", self._sb_scroll)
                _w.bind("<Button-4>",   self._sb_scroll)
                _w.bind("<Button-5>",   self._sb_scroll)

    def _build_pages(self):
        """Create one config page per service."""
        self._pages["general"] = _GeneralPage(self._page_container, self._cfg)

        self._pages["dns"] = _DNSPage(self._page_container, self._cfg)

        _PORT_ROOT = "Requires root (or iptables redirect from standard port)."
        _ENABLED   = "Enable or disable this service entirely."
        _LOG_REQ   = "Log every incoming request (method, path, headers) to the log panel."

        http_fields = [
            ("Port",            "port",           "80",
             f"TCP port for the HTTP server. Default: 80. {_PORT_ROOT}"),
            ("Response Code",   "response_code",  "200",
             "HTTP status code returned for every request.",
             ["200", "301", "302", "400", "403", "404", "500", "503"]),
            ("Response Body",   "response_body",  "<html><body>OK</body></html>",
             "HTML/text body returned in every HTTP response.\n"
             "Malware may check this content for specific strings."),
            ("Response Body File", "response_body_file", "",
             "Path to an HTML file to serve instead of the Response Body field above.\n"
             "Relative to the NotTheNet project root (e.g. assets/notthenet-page.html).\n"
             "Leave blank to use the Response Body string."),
            ("Server Header",   "server_header",  "Apache/2.4.51",
             "Value of the 'Server:' response header.\n"
             "Spoofing a real server (Apache, nginx) may satisfy malware fingerprinting checks."),
            ("Response Delay (ms)", "response_delay_ms", "50",
             "Artificial delay in milliseconds added before each HTTP response.\n"
             "Realistic latency (50-200 ms) defeats timing-based sandbox detection\n"
             "that flags environments with suspiciously instant responses.\n"
             "Set to 0 to disable."),
        ]
        self._pages["http"] = _ServicePage(
            self._page_container, self._cfg, "http", http_fields,
            [("Enabled", "enabled", True, _ENABLED),
             ("Log Requests", "log_requests", True, _LOG_REQ),
             ("Dynamic Responses", "dynamic_responses", True,
              "Serve context-aware responses based on requested file extension.\n"
              "If malware requests /payload.dll, it gets a valid PE stub.\n"
              "If it requests an image, it gets a valid PNG/JPEG header.\n"
              "Defeats sandbox detection that checks Content-Type vs extension."),
             ("DoH Sinkhole", "doh_sinkhole", True,
              "Intercept DNS-over-HTTPS (DoH) queries embedded in HTTPS traffic.\n"
              "Resolves DoH requests to the configured redirect_ip,\n"
              "preventing malware from bypassing the fake DNS server."),
             ("WebSocket Sinkhole", "websocket_sinkhole", True,
              "Accept WebSocket upgrade requests, complete the handshake,\n"
              "and then send a close frame. Satisfies malware that uses\n"
              "WebSocket-based C2 channels.")],
        )

        https_fields = [
            ("Port",            "port",           "443",
             f"TCP port for the HTTPS server. Default: 443. {_PORT_ROOT}"),
            ("Cert File",       "cert_file",      "certs/server.crt",
             "Path to the TLS certificate. Generated automatically by notthenet-install.sh\n"
             "(RSA-4096, self-signed). Malware rarely validates the cert."),
            ("Key File",        "key_file",       "certs/server.key",
             "Path to the TLS private key. Should be readable only by root (mode 0600)."),
            ("Response Code",   "response_code",  "200",
             "HTTP status code returned inside the TLS tunnel.",
             ["200", "301", "302", "400", "403", "404", "500", "503"]),
            ("Response Body",   "response_body",  "<html><body>OK</body></html>",
             "HTML/text body returned inside every HTTPS response."),
            ("Response Body File", "response_body_file", "",
             "Path to an HTML file to serve instead of the Response Body field above.\n"
             "Relative to the NotTheNet project root (e.g. assets/notthenet-page.html).\n"
             "Leave blank to use the Response Body string."),
            ("Server Header",   "server_header",  "Apache/2.4.51",
             "Value of the 'Server:' response header inside the TLS tunnel."),
            ("Response Delay (ms)", "response_delay_ms", "50",
             "Artificial delay in milliseconds added before each HTTPS response.\n"
             "Realistic latency (50-200 ms) defeats timing-based sandbox detection.\n"
             "Set to 0 to disable."),
        ]
        self._pages["https"] = _ServicePage(
            self._page_container, self._cfg, "https", https_fields,
            [("Enabled", "enabled", True, _ENABLED),
             ("Log Requests", "log_requests", True, _LOG_REQ),
             ("Dynamic Responses", "dynamic_responses", True,
              "Serve context-aware responses based on requested file extension.\n"
              "Same as the HTTP option — applied inside the TLS tunnel."),
             ("Dynamic Certificates", "dynamic_certs", True,
              "Forge a unique TLS certificate for each domain on-the-fly.\n"
              "When malware connects to https://evil-c2.com, a cert with\n"
              "CN=evil-c2.com and matching SANs is generated instantly,\n"
              "signed by NotTheNet\u2019s Root CA. Install the CA cert in the\n"
              "analysis VM\u2019s trust store for seamless interception."),
             ("DoH Sinkhole", "doh_sinkhole", True,
              "Intercept DNS-over-HTTPS queries inside the TLS tunnel.\n"
              "Responds with the configured redirect_ip."),
             ("WebSocket Sinkhole", "websocket_sinkhole", True,
              "Accept and sinkhole WebSocket upgrade requests\n"
              "inside the TLS tunnel.")],
        )

        for section, fields, checks in [
            ("smtp", [
                ("Port",     "port",     "25",
                 f"TCP port for the SMTP server. Default: 25. {_PORT_ROOT}"),
                ("Hostname", "hostname", "mail.example.com",
                 "SMTP server hostname announced in the 220 banner and EHLO response."),
                ("Banner",   "banner",   "220 mail.example.com ESMTP",
                 "Full 220 greeting sent on connection.\n"
                 "Malware may parse this to fingerprint the mail server."),
            ], [
                ("Enabled",     "enabled",     True,  _ENABLED),
                ("Save Emails", "save_emails", True,
                 "Save each received email as a .eml file in logs/emails/\n"
                 "with a UUID filename for later analysis."),
            ]),
            ("smtps", [
                ("Port",     "port",     "465",
                 f"TCP port for SMTPS (implicit TLS). Default: 465. {_PORT_ROOT}"),
                ("Hostname", "hostname", "mail.example.com",
                 "Hostname announced in the SMTPS banner and EHLO response."),
                ("Banner",   "banner",   "220 mail.example.com ESMTP",
                 "220 greeting sent after TLS handshake completes."),
            ], [
                ("Enabled",     "enabled",     True,  _ENABLED),
                ("Save Emails", "save_emails", True,
                 "Save received emails to logs/emails/ (same directory as SMTP)."),
            ]),
            ("pop3", [
                ("Port",     "port",     "110",
                 f"TCP port for the POP3 server. Default: 110. {_PORT_ROOT}"),
                ("Hostname", "hostname", "mail.example.com",
                 "Hostname announced in the POP3 +OK greeting banner."),
            ], [
                ("Enabled", "enabled", True, _ENABLED),
            ]),
            ("pop3s", [
                ("Port",     "port",     "995",
                 f"TCP port for POP3S (implicit TLS). Default: 995. {_PORT_ROOT}"),
                ("Hostname", "hostname", "mail.example.com",
                 "Hostname announced in the POP3S +OK greeting banner."),
            ], [
                ("Enabled", "enabled", True, _ENABLED),
            ]),
            ("imap", [
                ("Port",     "port",     "143",
                 f"TCP port for the IMAP server. Default: 143. {_PORT_ROOT}"),
                ("Hostname", "hostname", "mail.example.com",
                 "Hostname used in the IMAP greeting and capability responses."),
            ], [
                ("Enabled", "enabled", True, _ENABLED),
            ]),
            ("imaps", [
                ("Port",     "port",     "993",
                 f"TCP port for IMAPS (implicit TLS). Default: 993. {_PORT_ROOT}"),
                ("Hostname", "hostname", "mail.example.com",
                 "Hostname used in the IMAPS greeting and capability responses."),
            ], [
                ("Enabled", "enabled", True, _ENABLED),
            ]),
            ("ftp", [
                ("Port",       "port",       "21",
                 f"TCP port for the FTP server. Default: 21. {_PORT_ROOT}"),
                ("Banner",     "banner",     "220 Microsoft FTP Service",
                 "220 greeting sent on connection.\n"
                 "Malware may check this to confirm an FTP server is listening."),
                ("Upload Dir", "upload_dir", "logs/ftp_uploads",
                 "Directory where uploaded files are saved.\n"
                 "Each file is renamed to a UUID to prevent collisions."),
            ], [
                ("Enabled",       "enabled",       True,
                 _ENABLED),
                ("Allow Uploads", "allow_uploads", True,
                 "Accept STOR commands (file uploads).\n"
                 "Disable to silently reject all upload attempts."),
            ]),
        ]:
            self._pages[section] = _ServicePage(
                self._page_container, self._cfg, section, fields, checks
            )

        # JSON events viewer page
        self._pages["json_events"] = _JsonEventsPage(
            self._page_container, self._cfg
        )

        # NTP page
        self._pages["ntp"] = _ServicePage(
            self._page_container, self._cfg, "ntp",
            [
                ("Port", "port", "123",
                 f"UDP port for the NTP server. Default: 123. {_PORT_ROOT}"),
            ],
            [
                ("Enabled", "enabled", True, _ENABLED),
            ],
        )

        # IRC page
        self._pages["irc"] = _ServicePage(
            self._page_container, self._cfg, "irc",
            [
                ("Port",     "port",     "6667",
                 f"TCP port for the fake IRC server. Default: 6667. {_PORT_ROOT}"),
                ("Hostname", "hostname", "irc.example.com",
                 "IRC server hostname advertised in the 001–004 welcome burst.\n"
                 "Malware often uses this to verify it connected to the right server."),
                ("Network",  "network",  "IRCnet",
                 "IRC network name sent in RPL_ISUPPORT (005).\n"
                 "Some bots check this to confirm the correct network."),
                ("Channel",  "channel",  "botnet",
                 "Default channel name returned in /LIST. Bots typically JOIN\n"
                 "a hard-coded channel name rather than relying on /LIST."),
                ("MOTD",     "motd",     "Welcome to IRC.",
                 "Message of the Day text sent after successful registration."),
            ],
            [
                ("Enabled", "enabled", True, _ENABLED),
            ],
        )

        # TFTP page
        self._pages["tftp"] = _ServicePage(
            self._page_container, self._cfg, "tftp",
            [
                ("Port",       "port",       "69",
                 f"UDP port for the TFTP server. Default: 69. {_PORT_ROOT}"),
                ("Upload Dir", "upload_dir", "logs/tftp_uploads",
                 "Directory where WRQ (write) uploads are saved.\n"
                 "Created automatically. Each file is prefixed with a UUID\n"
                 "to prevent collisions."),
            ],
            [
                ("Enabled",       "enabled",       True, _ENABLED),
                ("Allow Uploads", "allow_uploads", True,
                 "Accept WRQ (write) transfers from clients.\n"
                 "Disable to silently reject all upload attempts with\n"
                 "TFTP error code 2 (Access violation)."),
            ],
        )

        # Telnet page
        self._pages["telnet"] = _ServicePage(
            self._page_container, self._cfg, "telnet",
            [
                ("Port",   "port",   "23",
                 f"TCP port for the Telnet server. Default: 23. {_PORT_ROOT}"),
                ("Banner", "banner", "router login",
                 "Text displayed before the login prompt.\n"
                 "Common Mirai targets: 'router login', 'BusyBox on OpenWrt',\n"
                 "'(none)' — match whatever the target bot expects."),
                ("Prompt", "prompt", "# ",
                 "Shell prompt shown to the bot after login.\n"
                 "'# ' implies a root shell; '$ ' implies a normal user.\n"
                 "Mirai simply issues commands without checking the prompt."),
            ],
            [("Enabled", "enabled", True, _ENABLED)],
        )

        # SOCKS5 page
        self._pages["socks5"] = _ServicePage(
            self._page_container, self._cfg, "socks5",
            [
                ("Port", "port", "1080",
                 f"TCP port for the SOCKS5 proxy. Default: 1080. {_PORT_ROOT}\n"
                 "Every CONNECT request logs the real destination host and port\n"
                 "the malware was trying to reach — the highest-value intel\n"
                 "this service captures."),
            ],
            [("Enabled", "enabled", True, _ENABLED)],
        )

        # IRC/TLS page
        self._pages["ircs"] = _ServicePage(
            self._page_container, self._cfg, "ircs",
            [
                ("Port",     "port",     "6697",
                 f"TCP port for the TLS-wrapped IRC server. Default: 6697. {_PORT_ROOT}"),
                ("Hostname", "hostname", "irc.example.com",
                 "IRC server hostname in the 001–004 welcome burst."),
                ("Network",  "network",  "IRCnet",
                 "IRC network name sent in RPL_ISUPPORT (005)."),
                ("Channel",  "channel",  "botnet",
                 "Default channel name. Bots typically JOIN a hard-coded name."),
                ("MOTD",     "motd",     "Welcome to IRC.",
                 "Message of the Day text sent after successful registration."),
            ],
            [("Enabled", "enabled", True, _ENABLED)],
        )

        # Catch-all page
        catch_fields = [
            ("TCP Catch-All Port", "tcp_port", "9999",
             "Fallback TCP port. iptables redirects all unmatched TCP traffic here\n"
             "when 'Redirect TCP' is enabled."),
            ("UDP Catch-All Port", "udp_port", "9998",
             "Fallback UDP port. iptables redirects all unmatched UDP traffic here\n"
             "when 'Redirect UDP' is enabled."),
        ]
        catch_checks = [
            ("Redirect TCP (catch-all)", "redirect_tcp", True,
             "Add an iptables REDIRECT rule to send all unmatched TCP traffic\n"
             "to the TCP catch-all port above."),
            ("Redirect UDP (catch-all)", "redirect_udp", False,
             "Add an iptables REDIRECT rule to send all unmatched UDP traffic\n"
             "to the UDP catch-all port. Use with caution — may disrupt UDP services."),
        ]
        self._pages["catch_all"] = _ServicePage(
            self._page_container, self._cfg, "catch_all", catch_fields, catch_checks
        )

        # SMB page
        self._pages["smb"] = _ServicePage(
            self._page_container, self._cfg, "smb",
            [("Port", "port", "445",
              f"TCP port for the fake SMB server. Default: 445. {_PORT_ROOT}")],
            [("Enabled", "enabled", True, _ENABLED)],
        )

        # RDP page
        self._pages["rdp"] = _ServicePage(
            self._page_container, self._cfg, "rdp",
            [("Port", "port", "3389",
              f"TCP port for the fake RDP server. Default: 3389. {_PORT_ROOT}")],
            [("Enabled", "enabled", True, _ENABLED)],
        )

        # VNC page
        self._pages["vnc"] = _ServicePage(
            self._page_container, self._cfg, "vnc",
            [("Port", "port", "5900",
              f"TCP port for the fake VNC server. Default: 5900. {_PORT_ROOT}")],
            [("Enabled", "enabled", True, _ENABLED)],
        )

        # MySQL page
        self._pages["mysql"] = _ServicePage(
            self._page_container, self._cfg, "mysql",
            [("Port", "port", "3306",
              f"TCP port for the fake MySQL server. Default: 3306. {_PORT_ROOT}")],
            [("Enabled", "enabled", True, _ENABLED)],
        )

        # MSSQL page
        self._pages["mssql"] = _ServicePage(
            self._page_container, self._cfg, "mssql",
            [("Port", "port", "1433",
              f"TCP port for the fake MSSQL server. Default: 1433. {_PORT_ROOT}")],
            [("Enabled", "enabled", True, _ENABLED)],
        )

        # Redis page
        self._pages["redis"] = _ServicePage(
            self._page_container, self._cfg, "redis",
            [("Port", "port", "6379",
              f"TCP port for the fake Redis server. Default: 6379. {_PORT_ROOT}")],
            [("Enabled", "enabled", True, _ENABLED)],
        )

        # LDAP page
        self._pages["ldap"] = _ServicePage(
            self._page_container, self._cfg, "ldap",
            [("Port", "port", "389",
              f"TCP port for the fake LDAP server. Default: 389. {_PORT_ROOT}")],
            [("Enabled", "enabled", True, _ENABLED)],
        )

        # ICMP page
        self._pages["icmp"] = _ServicePage(
            self._page_container, self._cfg, "icmp",
            [],
            [
                ("Enabled", "enabled", True,
                 "Enable the ICMP echo responder.\n"
                 "When active, an iptables DNAT rule redirects all forwarded\n"
                 "ICMP echo-requests (pings) to this host. The kernel then\n"
                 "replies automatically, so malware connectivity checks succeed.\n"
                 "Requires root / CAP_NET_RAW."),
            ],
        )

    def _show_page(self, key: str):
        """Display a config page and highlight the active sidebar button."""
        for page in self._pages.values():
            page.pack_forget()
        if key in self._pages:
            self._pages[key].pack(fill="both", expand=True)

        for k, widgets in self._service_btns.items():
            row, btn = widgets
            dot = self._svc_vars.get(k)
            if k == key:
                row.configure(bg=C_SELECTED)
                btn.configure(bg=C_SELECTED, fg=C_TEXT, font=_f(9, True))
                if dot:
                    dot.configure(bg=C_SELECTED)
            else:
                row.configure(bg=C_PANEL)
                btn.configure(bg=C_PANEL, fg=C_SUBTLE, font=_f(9))
                if dot:
                    dot.configure(bg=C_PANEL)

    def _build_log_panel(self, parent):
        # Header bar
        hdr = tk.Frame(parent, bg=C_BG, pady=4)
        hdr.pack(fill="x")
        tk.Frame(parent, bg=C_BORDER, height=1).pack(fill="x")

        tk.Label(
            hdr, text="  LIVE LOG",
            bg=C_BG, fg=C_DIM,
            font=_f(8, True),
        ).pack(side="left")

        # Level filter pills
        filter_frame = tk.Frame(hdr, bg=C_BG)
        filter_frame.pack(side="left", padx=12)
        self._log_filter_btns: dict = {}
        _pill_tips = {
            "DEBUG":   "Show only DEBUG messages (verbose trace output).\nClick again to show all levels.",
            "INFO":    "Show only INFO messages (normal operational events).\nClick again to show all levels.",
            "WARNING": "Show only WARNING messages (non-fatal issues).\nClick again to show all levels.",
            "ERROR":   "Show only ERROR messages (failures and exceptions).\nClick again to show all levels.",
        }
        for lvl, colour in [("DEBUG", C_DIM), ("INFO", C_SUBTLE),
                            ("WARNING", C_ORANGE), ("ERROR", C_RED)]:
            b = tk.Button(
                filter_frame, text=lvl,
                bg=C_HOVER, fg=colour,
                relief="flat", bd=0, padx=6, pady=2,
                font=_f(7, True), cursor="hand2",
                command=lambda lvl_=lvl: self._toggle_log_filter(lvl_),
            )
            b.pack(side="left", padx=2)
            _hover_bind(b, C_HOVER, C_SELECTED)
            tooltip(b, _pill_tips[lvl])
            self._log_filter_btns[lvl] = b

        clear_btn = tk.Button(
            hdr, text="✕ Clear",
            bg=C_BG, fg=C_DIM, relief="flat",
            font=_f(8), cursor="hand2",
            command=lambda: self._log_widget.configure(state="normal") or
                            self._log_widget.delete("1.0", "end") or
                            self._log_widget.configure(state="disabled"),
        )
        clear_btn.pack(side="right", padx=PAD)
        tooltip(clear_btn, "Clear all messages from the log panel.\n(Log files on disk are not affected.)")

        self._log_widget = scrolledtext.ScrolledText(
            parent,
            bg=C_LOG_BG,
            fg=C_TEXT,
            font=_f(9),
            relief="flat",
            state="disabled",
            wrap="none",
            highlightthickness=0,
        )
        self._log_widget.pack(fill="both", expand=True)
        self._log_widget.tag_config("ERROR",   foreground=C_RED)
        self._log_widget.tag_config("WARNING", foreground=C_ORANGE)
        self._log_widget.tag_config("INFO",    foreground=C_TEXT)
        self._log_widget.tag_config("DEBUG",   foreground=C_DIM)
        self._log_widget.tag_config("HIDDEN",  elide=True)

    def _toggle_log_filter(self, level: str):
        """Toggle showing only one log level. Click again to clear filter."""
        if self._log_level_filter == level:
            self._log_level_filter = ""
            for b in self._log_filter_btns.values():
                b.configure(relief="flat", bd=0)
        else:
            self._log_level_filter = level
            for lvl, b in self._log_filter_btns.items():
                b.configure(relief=("sunken" if lvl == level else "flat"),
                            bd=(1 if lvl == level else 0))
        self._reapply_log_filter()

    def _reapply_log_filter(self):
        """Re-apply the active level filter to all existing lines in the log widget."""
        w = self._log_widget
        w.configure(state="normal")
        w.tag_remove("HIDDEN", "1.0", "end")
        if self._log_level_filter:
            end_line = int(w.index("end-1c").split(".")[0])
            for i in range(1, end_line + 1):
                if self._log_level_filter not in w.tag_names(f"{i}.0"):
                    w.tag_add("HIDDEN", f"{i}.0", f"{i + 1}.0")
        w.configure(state="disabled")

    def _build_statusbar(self):
        tk.Frame(self, bg=C_BORDER, height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(self, bg=C_BG, height=24)
        bar.pack(fill="x", side="bottom")
        self._status_label = tk.Label(
            bar, text="●  Stopped", bg=C_BG, fg=C_DIM,
            font=_f(8), anchor="w"
        )
        self._status_label.pack(side="left", padx=(PAD + 2, 0))
        tk.Label(
            bar, text="github.com/retr0verride/NotTheNet",
            bg=C_BG, fg=C_DIM, font=_f(8),
        ).pack(side="right", padx=PAD)

    # ── Log polling ───────────────────────────────────────────────────────────

    def _poll_log_queue(self):
        """Drain the log queue into the GUI log widget every 100 ms."""
        try:
            while True:
                msg = self._log_queue.get_nowait()
                self._append_log(msg)
        except queue.Empty:
            pass
        self.after(100, self._poll_log_queue)

    def _append_log(self, msg: str):
        self._log_widget.configure(state="normal")

        # Trim to cap
        line_count = int(self._log_widget.index("end-1c").split(".")[0])
        if line_count > LOG_MAX_LINES:
            self._log_widget.delete("1.0", f"{line_count - LOG_MAX_LINES}.0")

        # Pick colour tag
        tag = "INFO"
        upper = msg.upper()
        if "[ERROR]" in upper:
            tag = "ERROR"
        elif "[WARNING]" in upper:
            tag = "WARNING"
        elif "[DEBUG]" in upper:
            tag = "DEBUG"

        # Apply active level filter (hide non-matching lines)
        tags: tuple[str, ...] = (tag,)
        if self._log_level_filter and tag != self._log_level_filter:
            tags = (tag, "HIDDEN")

        self._log_widget.insert("end", msg + "\n", tags)
        self._log_widget.see("end")
        self._log_widget.configure(state="disabled")

    # ── Service control ───────────────────────────────────────────────────────

    def _apply_all_pages_to_config(self):
        for page in self._pages.values():
            if hasattr(page, "apply_to_config"):
                page.apply_to_config()

    def _on_start(self):
        self._apply_all_pages_to_config()
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
        self._status_label.configure(text="●  Starting…", fg=C_ORANGE)

    def _update_ui_after_start(self, ok: bool):
        if ok:
            self._btn_start.configure(state="disabled")
            self._btn_stop.configure(state="normal")
            self._status_label.configure(text="●  Running", fg=C_GREEN)
            running = set(self._manager.status().keys()) if self._manager else set()
            # catch_all sidebar key maps to catch_tcp / catch_udp in _services
            if "catch_tcp" in running or "catch_udp" in running:
                running.add("catch_all")
            for key, dot in self._svc_vars.items():
                dot.configure(fg=C_GREEN if key in running else C_DIM)
        else:
            self._status_label.configure(text="●  Failed — check log", fg=C_RED)

    def _on_stop(self):
        if not self._manager:
            return
        # Keep both buttons disabled until the background stop thread finishes
        # so a rapid Stop->Start cannot attempt to rebind ports still in use.
        self._btn_start.configure(state="disabled")
        self._btn_stop.configure(state="disabled")
        self._status_label.configure(text="●  Stopping...", fg=C_ORANGE)

        def _stop_thread():
            self._manager.stop()
            self.after(0, self._update_ui_after_stop)

        threading.Thread(target=_stop_thread, daemon=True).start()

    def _update_ui_after_stop(self):
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled")
        self._status_label.configure(text="●  Stopped", fg=C_DIM)
        for dot in self._svc_vars.values():
            dot.configure(fg=C_DIM)

    def _on_save(self):
        self._apply_all_pages_to_config()
        if self._cfg.save():
            messagebox.showinfo("Saved", f"Config saved to:\n{self._cfg.config_path}")
        else:
            messagebox.showerror("Error", "Failed to save config — check log.")

    def _on_load(self):
        path = filedialog.askopenfilename(
            title="Load Config",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if path:
            if self._cfg.load(path):
                messagebox.showinfo("Loaded", f"Config loaded from:\n{path}")
                # Rebuild pages to reflect new values
                for page in self._pages.values():
                    page.destroy()
                self._pages.clear()
                self._build_pages()
                self._show_page("general")
            else:
                messagebox.showerror("Error", f"Failed to load config from:\n{path}")

    def _on_close(self):
        if self._manager and self._manager.running:
            if messagebox.askyesno(
                "Confirm Exit",
                "NotTheNet is still running.\nStop all services and exit?",
            ):
                self._manager.stop()
                self.destroy()
        else:
            self.destroy()


def _print_logo() -> None:
    """Print the NotTheNet ASCII banner to stdout (CLI mode only)."""
    CYAN = "\033[36m"
    RESET = "\033[0m"
    banner = (
        f"{CYAN}"
        "\n"
        "  ███╗   ██╗ ██████╗ ████████╗    ████████╗██╗  ██╗███████╗    ███╗   ██╗███████╗████████╗\n"
        "  ████╗  ██║██╔═══██╗╚══██╔══╝       ██║   ██║  ██║██╔════╝    ████╗  ██║██╔════╝╚══██╔══╝\n"
        "  ██╔██╗ ██║██║   ██║   ██║          ██║   ███████║█████╗      ██╔██╗ ██║█████╗     ██║   \n"
        "  ██║╚██╗██║██║   ██║   ██║          ██║   ██╔══██║██╔══╝      ██║╚██╗██║██╔══╝     ██║   \n"
        "  ██║ ╚████║╚██████╔╝   ██║          ██║   ██║  ██║███████╗    ██║ ╚████║███████╗   ██║   \n"
        "  ╚═╝  ╚═══╝ ╚═════╝    ╚═╝          ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═══╝╚══════╝   ╚═╝  \n"
        "                          Fake Internet Simulator  ·  Malware Analysis\n"
        f"{RESET}"
    )
    print(banner)


def main():
    import argparse
    import traceback

    # Resolve the project root from this file's location so that all relative
    # paths (config, logs, certs) work correctly when the process is launched
    # via pkexec / a .desktop icon, which may start with a different CWD.
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(_script_dir)

    _default_config = os.path.join(_script_dir, "config.json")

    parser = argparse.ArgumentParser(description="NotTheNet — Fake Internet Simulator")
    parser.add_argument("--config", default=_default_config, help="Path to config JSON")
    parser.add_argument("--nogui", action="store_true",
                        help="Run headless (CLI mode, no GUI)")
    parser.add_argument("--loglevel", default=None,
                        help="Override log level (DEBUG/INFO/WARNING/ERROR)")
    args = parser.parse_args()

    # When launched without a terminal (e.g. via desktop icon + pkexec),
    # any unhandled exception is completely invisible.  Catch everything and
    # append a crash report to a known log file so the user has something to
    # inspect when the program appears to "do nothing".
    _crash_log = os.path.join(_script_dir, "logs", "notthenet-crash.log")
    try:
        os.makedirs(os.path.join(_script_dir, "logs"), exist_ok=True)
    except OSError:
        pass

    try:
        cfg = Config(args.config)
        log_level = args.loglevel or cfg.get("general", "log_level") or "INFO"
        setup_logging(
            log_dir=cfg.get("general", "log_dir") or os.path.join(_script_dir, "logs"),
            log_level=log_level,
            log_to_file=bool(cfg.get("general", "log_to_file")),
        )

        if args.nogui:
            import signal
            _print_logo()
            manager = ServiceManager(cfg)
            if not manager.start():
                sys.exit(1)
            logger = logging.getLogger("notthenet")
            logger.info("Running in headless mode. Press Ctrl+C to stop.")

            stop_event = threading.Event()

            def _sig_handler(sig, _frame):
                logger.info("Signal %s received; shutting down…", sig)
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
