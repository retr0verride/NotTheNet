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

import logging
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tkinter import font as _tkfont
from typing import Optional

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config
from service_manager import ServiceManager
from utils.logging_utils import setup_logging

# ─── Constants ────────────────────────────────────────────────────────────────

APP_TITLE = "NotTheNet — Fake Internet Simulator"
APP_VERSION = "1.0.0"
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
            font=_f(8),
            wraplength=self._WRAP,
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


def _info_icon(parent, tip: str) -> tk.Label:
    """Small ⓘ label that carries a tooltip. Returns the widget."""
    lbl = tk.Label(
        parent, text=" ⓘ",
        bg=C_SURFACE, fg=C_DIM,
        font=_f(9), cursor="question_arrow",
    )
    tooltip(lbl, tip)
    lbl.bind("<Enter>", lambda _e: lbl.configure(fg=C_ACCENT))
    lbl.bind("<Leave>", lambda _e: lbl.configure(fg=C_DIM))
    return lbl


def _row(parent, label: str, widget_factory, row: int,
         col_offset: int = 0, tip: str = ""):
    """Lay out a label + widget pair in a grid, with an optional ⓘ info icon."""
    lbl = tk.Label(parent, text=label, bg=C_SURFACE, fg=C_SUBTLE,
                   font=_f(9), anchor="e")
    lbl.grid(row=row, column=col_offset, sticky="e", padx=(0, 6), pady=4)
    w = widget_factory()
    w.grid(row=row, column=col_offset + 1, sticky="w", pady=4)
    if tip:
        icon = _info_icon(parent, tip)
        icon.grid(row=row, column=col_offset + 2, sticky="w", padx=(2, 0))
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
        f = _section_frame(self, "General Settings")
        f.pack(fill="x", padx=PAD + 4, pady=PAD + 4)

        fields = [
            ("Bind IP",       "bind_ip",      "0.0.0.0",
             "IP address that all services bind to.\n"
             "Use 0.0.0.0 to listen on every interface,\n"
             "or a specific IP to restrict to one interface."),
            ("Redirect IP",   "redirect_ip",  "127.0.0.1",
             "IP returned for all DNS A/AAAA queries.\n"
             "Usually 127.0.0.1 to route malware traffic back to this machine."),
            ("Interface",     "interface",    "eth0",
             "Network interface for iptables REDIRECT rules (e.g. eth0, ens33).\n"
             "Run 'ip link' to list available interfaces."),
            ("Log Directory", "log_dir",      "logs",
             "Directory where rotating log files are written.\n"
             "Created automatically if it does not exist."),
            ("Log Level",     "log_level",    "INFO",
             "Log verbosity: DEBUG (most output) > INFO > WARNING > ERROR (least).\n"
             "DEBUG shows every packet; ERROR shows only failures."),
        ]
        for row, (label, key, default, tip) in enumerate(fields):
            val = self.cfg.get("general", key) or default
            v = tk.StringVar(value=str(val))
            self.vars[key] = v
            _row(f, label, lambda v=v: _entry(f, v), row, tip=tip)

        check_fields = [
            ("Enable auto-iptables rules", "auto_iptables", True,
             "Add NAT REDIRECT rules via iptables when services start,\n"
             "and remove them cleanly on stop. Requires root."),
            ("Log to file",               "log_to_file",   True,
             "Write log output to a rotating file in the log directory\n"
             "in addition to the GUI log panel."),
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
                _info_icon(f, tip).grid(
                    row=len(fields) + i, column=2, sticky="w", padx=(2, 0)
                )

    def apply_to_config(self):
        for key, var in self.vars.items():
            self.cfg.set("general", key, var.get())


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
        f = _section_frame(self, self.section.upper() + " Service")
        f.pack(fill="x", padx=PAD + 4, pady=PAD + 4)

        for i, item in enumerate(self.fields):
            label, key, default = item[0], item[1], item[2]
            tip = item[3] if len(item) > 3 else ""
            val = self.cfg.get(self.section, key) or default
            v = tk.StringVar(value=str(val))
            self.vars[key] = v
            _row(f, label, lambda v=v: _entry(f, v), i, tip=tip)

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
                _info_icon(f, tip).grid(
                    row=len(self.fields) + j, column=2, sticky="w", padx=(2, 0)
                )

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
                ("Resolve To",  "resolve_to", "127.0.0.1",
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
                 "Respond to reverse DNS (PTR) lookups with 'notthenet.local'.\n"
                 "Prevents connection timeouts in malware that queries its own IP."),
            ],
        )
        # Custom records editor
        self._build_custom_records()

    def _build_custom_records(self):
        f2 = _section_frame(self, "Custom DNS Records  (name = IP)")
        f2.pack(fill="both", expand=True, padx=PAD + 4, pady=(0, PAD + 4))
        hint = tk.Label(f2, text="One entry per line:  example.com = 192.168.1.1",
                        bg=C_SURFACE, fg=C_DIM, font=_f(8))
        hint.pack(anchor="w", pady=(0, 4))
        self._records_text = scrolledtext.ScrolledText(
            f2, height=6, bg=C_ENTRY_BG, fg=C_ENTRY_FG,
            insertbackground=C_ACCENT, relief="flat",
            font=_f(9),
            highlightthickness=1, highlightbackground=C_BORDER,
            highlightcolor=C_ACCENT,
        )
        self._records_text.pack(fill="both", expand=True)
        # Populate from config
        records = self.cfg.get("dns", "custom_records") or {}
        for name, ip in records.items():
            self._records_text.insert("end", f"{name} = {ip}\n")

    def apply_to_config(self):
        super().apply_to_config()
        # Parse custom records
        records = {}
        for line in self._records_text.get("1.0", "end").splitlines():
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
        self.geometry("1000x720")
        self.minsize(800, 600)
        self.configure(bg=C_BG)
        self.resizable(True, True)

        self._cfg = Config(config_path or "config.json")
        self._log_queue: queue.Queue = queue.Queue()
        self._manager: Optional[ServiceManager] = None
        self._svc_vars: dict = {}  # service name → BooleanVar (status indicator)
        self._pages: dict = {}     # section name → page frame

        # Initialise zoom-aware fonts before any widget is built
        self._zoom_factor: float = float(self._cfg.get("ui", "zoom") or 1.0)
        self._init_fonts()

        # Set up logging → queue bridge
        root_logger = logging.getLogger("notthenet")
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
        """Step the UI font scale by *delta* and persist it."""
        new = max(_ZOOM_MIN, min(_ZOOM_MAX, self._zoom_factor + delta))
        if new == self._zoom_factor:
            return
        self._zoom_factor = new
        self._init_fonts()
        # Update zoom label in toolbar if it exists
        if hasattr(self, "_zoom_label"):
            pct = round(new * 100)
            self._zoom_label.configure(text=f"{pct}%")
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
        style.configure("Sash", sashthickness=5, background=C_BORDER)
        style.configure("VSash", sashthickness=5, background=C_BORDER)
        style.configure("HSash", sashthickness=5, background=C_BORDER)

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

        # Vertical divider
        tk.Frame(inner, bg=C_BORDER, width=1).pack(side="left", fill="y", padx=6)

        self._btn_update = tk.Button(
            inner, text="↑  Update", bg=C_HOVER, fg=C_ACCENT2,
            command=self._on_update, **sec_btn
        )
        self._btn_update.pack(side="left", padx=2)
        _hover_bind(self._btn_update, C_HOVER, C_SELECTED)
        tooltip(self._btn_update,
                "Pull the latest code from GitHub (git pull) and\n"
                "reinstall Python dependencies (pip install -e .).\n"
                "A restart prompt is shown if any files changed.")

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
        import os as _os
        if _os.name != "nt" and _os.geteuid() != 0:
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
        body = tk.PanedWindow(parent, orient="horizontal", bg=C_BG,
                              sashwidth=5, sashpad=0, sashrelief="flat")
        body.pack(fill="both", expand=True)

        # ── Left: service list ──
        left = tk.Frame(body, bg=C_PANEL)
        body.add(left, minsize=148)

        # Sidebar header
        hdr = tk.Frame(left, bg=C_PANEL, pady=8)
        hdr.pack(fill="x")
        tk.Label(
            hdr, text="  SERVICES",
            bg=C_PANEL, fg=C_DIM,
            font=_f(8, True),
        ).pack(anchor="w")
        tk.Frame(left, bg=C_BORDER, height=1).pack(fill="x")

        self._service_btns: dict = {}

        # Group: General
        self._add_sidebar_section(left, "CONFIG")
        self._add_sidebar_btn(left, "general", "⚙  General",
                              "Global settings: bind IP, redirect IP,\n"
                              "network interface, log directory, and verbosity.")

        # Group: Network services
        self._add_sidebar_section(left, "NETWORK")
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
        ]:
            self._add_sidebar_btn(left, key, label, tip)

        # Group: Mail services
        self._add_sidebar_section(left, "MAIL")
        for key, label, tip in [
            ("smtp", "◈  SMTP",
             "Fake SMTP server — accepts email submissions and optionally\n"
             "saves them as .eml files for analysis."),
            ("pop3", "◈  POP3",
             "Fake POP3 server — announces an empty mailbox to connecting clients."),
            ("imap", "◈  IMAP",
             "Fake IMAP server — announces an empty INBOX to connecting clients."),
        ]:
            self._add_sidebar_btn(left, key, label, tip)

        # Group: Catch-all
        self._add_sidebar_section(left, "FALLBACK")
        self._add_sidebar_btn(left, "catch_all", "◈  Catch-All",
                              "TCP/UDP catch-all — iptables redirects all traffic\n"
                              "not handled by specific services to these ports.")

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
        tk.Label(
            f, text=f"  {title}",
            bg=C_PANEL, fg=C_DIM,
            font=_f(7, True),
        ).pack(anchor="w", padx=4)

    def _add_sidebar_btn(self, parent, key: str, label: str, tip: str = ""):
        """Add one sidebar service button with a status dot on the right."""
        row = tk.Frame(parent, bg=C_PANEL, cursor="hand2")
        row.pack(fill="x", pady=1)

        dot = tk.Label(row, text="●", bg=C_PANEL, fg=C_DIM,
                       font=_f(7))
        dot.pack(side="right", padx=(0, 8))

        btn = tk.Label(
            row, text=f"  {label}",
            bg=C_PANEL, fg=C_SUBTLE,
            font=_f(9), anchor="w",
        )
        btn.pack(side="left", fill="x", expand=True, ipady=5)

        def _click(_e=None):
            self._show_page(key)

        row.bind("<Button-1>", _click)
        btn.bind("<Button-1>", _click)
        dot.bind("<Button-1>", _click)
        _hover_bind(row, C_PANEL, C_HOVER)
        _hover_bind(btn, C_PANEL, C_HOVER)
        _hover_bind(dot, C_PANEL, C_HOVER)

        if tip:
            tooltip(row, tip)
            tooltip(btn, tip)
            tooltip(dot, tip)

        self._service_btns[key] = (row, btn, dot)

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
             "HTTP status code returned for every request (e.g. 200, 301, 404)."),
            ("Response Body",   "response_body",  "<html><body>OK</body></html>",
             "HTML/text body returned in every HTTP response.\n"
             "Malware may check this content for specific strings."),
            ("Server Header",   "server_header",  "Apache/2.4.51",
             "Value of the 'Server:' response header.\n"
             "Spoofing a real server (Apache, nginx) may satisfy malware fingerprinting checks."),
        ]
        self._pages["http"] = _ServicePage(
            self._page_container, self._cfg, "http", http_fields,
            [("Enabled", "enabled", True, _ENABLED),
             ("Log Requests", "log_requests", True, _LOG_REQ)],
        )

        https_fields = [
            ("Port",            "port",           "443",
             f"TCP port for the HTTPS server. Default: 443. {_PORT_ROOT}"),
            ("Cert File",       "cert_file",      "certs/server.crt",
             "Path to the TLS certificate. Generated automatically by install.sh\n"
             "(RSA-4096, self-signed). Malware rarely validates the cert."),
            ("Key File",        "key_file",       "certs/server.key",
             "Path to the TLS private key. Should be readable only by root (mode 0600)."),
            ("Response Code",   "response_code",  "200",
             "HTTP status code returned inside the TLS tunnel."),
            ("Response Body",   "response_body",  "<html><body>OK</body></html>",
             "HTML/text body returned inside every HTTPS response."),
            ("Server Header",   "server_header",  "Apache/2.4.51",
             "Value of the 'Server:' response header inside the TLS tunnel."),
        ]
        self._pages["https"] = _ServicePage(
            self._page_container, self._cfg, "https", https_fields,
            [("Enabled", "enabled", True, _ENABLED),
             ("Log Requests", "log_requests", True, _LOG_REQ)],
        )

        for section, fields, checks in [
            ("smtp", [
                ("Port",     "port",     "25",
                 f"TCP port for the SMTP server. Default: 25. {_PORT_ROOT}"),
                ("Hostname", "hostname", "mail.notthenet.local",
                 "SMTP server hostname announced in the 220 banner and EHLO response."),
                ("Banner",   "banner",   "220 mail.notthenet.local ESMTP",
                 "Full 220 greeting sent on connection.\n"
                 "Malware may parse this to fingerprint the mail server."),
            ], [
                ("Enabled",     "enabled",     True,  _ENABLED),
                ("Save Emails", "save_emails", True,
                 "Save each received email as a .eml file in logs/emails/\n"
                 "with a UUID filename for later analysis."),
            ]),
            ("pop3", [
                ("Port",     "port",     "110",
                 f"TCP port for the POP3 server. Default: 110. {_PORT_ROOT}"),
                ("Hostname", "hostname", "mail.notthenet.local",
                 "Hostname announced in the POP3 +OK greeting banner."),
            ], [
                ("Enabled", "enabled", True, _ENABLED),
            ]),
            ("imap", [
                ("Port",     "port",     "143",
                 f"TCP port for the IMAP server. Default: 143. {_PORT_ROOT}"),
                ("Hostname", "hostname", "mail.notthenet.local",
                 "Hostname used in the IMAP greeting and capability responses."),
            ], [
                ("Enabled", "enabled", True, _ENABLED),
            ]),
            ("ftp", [
                ("Port",       "port",       "21",
                 f"TCP port for the FTP server. Default: 21. {_PORT_ROOT}"),
                ("Banner",     "banner",     "220 FTP Server Ready",
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

    def _show_page(self, key: str):
        """Display a config page and highlight the active sidebar button."""
        for page in self._pages.values():
            page.pack_forget()
        if key in self._pages:
            self._pages[key].pack(fill="both", expand=True)

        for k, widgets in self._service_btns.items():
            row, btn, dot = widgets
            if k == key:
                row.configure(bg=C_SELECTED)
                btn.configure(bg=C_SELECTED, fg=C_TEXT,
                              font=_f(9, True))
                dot.configure(bg=C_SELECTED)
            else:
                row.configure(bg=C_PANEL)
                btn.configure(bg=C_PANEL, fg=C_SUBTLE,
                              font=_f(9))
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
                command=lambda l=lvl: self._toggle_log_filter(l),
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
        tags = (tag,)
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
        from utils.logging_utils import setup_logging
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
            self._update_service_indicators()
        else:
            self._status_label.configure(text="●  Failed — check log", fg=C_RED)

    def _on_stop(self):
        if self._manager:
            threading.Thread(target=self._manager.stop, daemon=True).start()
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled")
        self._status_label.configure(text="●  Stopped", fg=C_DIM)
        for key, (row, btn, dot) in self._service_btns.items():
            dot.configure(fg=C_DIM)

    def _update_service_indicators(self):
        """Refresh sidebar status dots based on actual service status."""
        if not self._manager:
            return
        status = self._manager.status()
        mapping = {
            "dns": "dns", "http": "http", "https": "https",
            "smtp": "smtp", "pop3": "pop3", "imap": "imap",
            "ftp": "ftp", "catch_tcp": "catch_all",
        }
        for svc_key, page_key in mapping.items():
            colour = C_GREEN if status.get(svc_key) else C_RED
            widgets = self._service_btns.get(page_key)
            if widgets:
                _row, _btn, dot = widgets
                dot.configure(fg=colour)

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

    def _on_update(self):
        """Pull latest code from GitHub and reinstall dependencies."""
        # Confirm first
        if not messagebox.askyesno(
            "Check for Updates",
            "This will run:\n"
            "  git pull origin master\n"
            "  pip install -r requirements.txt\n\n"
            "Any running services will NOT be interrupted.\n"
            "Continue?",
        ):
            return

        self._btn_update.configure(state="disabled", text="↑  Updating…")
        self._status_label.configure(text="↑  Checking for updates…", fg=C_ACCENT2)

        def _run():
            import subprocess
            import sys as _sys
            results = []
            changed = False

            # ── Step 1: git pull ──────────────────────────────────────────
            try:
                proc = subprocess.run(
                    ["git", "pull", "origin", "master"],
                    capture_output=True, text=True, cwd=_BASE_DIR,
                )
                output = (proc.stdout + proc.stderr).strip()
                results.append(("git pull", proc.returncode, output))
                changed = proc.returncode == 0 and "Already up to date." not in output
            except FileNotFoundError:
                results.append(("git pull", -1,
                                 "git not found — is git installed?"))

            # ── Step 2: pip install ───────────────────────────────────────
            try:
                proc = subprocess.run(
                    [_sys.executable, "-m", "pip", "install",
                     "-r", os.path.join(_BASE_DIR, "requirements.txt"),
                     "--quiet"],
                    capture_output=True, text=True,
                )
                output = (proc.stdout + proc.stderr).strip() or "Dependencies up to date."
                results.append(("pip install", proc.returncode, output))
            except Exception as exc:
                results.append(("pip install", -1, str(exc)))

            self.after(0, self._show_update_result, results, changed)

        threading.Thread(target=_run, daemon=True).start()

    def _show_update_result(self, results: list, changed: bool):
        """Display update output in a scrollable dialog."""
        self._btn_update.configure(state="normal", text="↑  Update")
        all_ok = all(rc == 0 for _, rc, _ in results)
        self._status_label.configure(
            text="● Running" if (self._manager and self._manager.running) else "●  Stopped",
            fg=C_GREEN if (self._manager and self._manager.running) else C_DIM,
        )

        # Build dialog
        dlg = tk.Toplevel(self)
        dlg.title("Update Result")
        dlg.configure(bg=C_BG)
        dlg.geometry("620x380")
        dlg.resizable(True, True)
        dlg.transient(self)
        dlg.grab_set()

        # Accent strip
        tk.Frame(dlg, bg=C_ACCENT if all_ok else C_ORANGE, height=2).pack(fill="x")

        # Header
        header_color = C_GREEN if (all_ok and changed) else (C_ACCENT if all_ok else C_RED)
        header_text = (
            "✔  Updated successfully — restart to apply changes."
            if (all_ok and changed) else
            "✔  Already up to date." if all_ok else
            "✘  Update encountered errors."
        )
        tk.Label(
            dlg, text=header_text,
            bg=C_BG, fg=header_color,
            font=_f(10, True),
            anchor="w",
        ).pack(fill="x", padx=PAD + 4, pady=(PAD, 4))

        tk.Frame(dlg, bg=C_BORDER, height=1).pack(fill="x", padx=PAD)

        # Scrollable output
        txt = scrolledtext.ScrolledText(
            dlg, bg=C_LOG_BG, fg=C_TEXT,
            font=_f(9), relief="flat",
            highlightthickness=0, state="normal",
        )
        txt.pack(fill="both", expand=True, padx=PAD, pady=PAD)

        txt.tag_config("header",  foreground=C_ACCENT2,  font=_f(9, True))
        txt.tag_config("ok",      foreground=C_GREEN)
        txt.tag_config("err",     foreground=C_RED)
        txt.tag_config("body",    foreground=C_SUBTLE)

        for step, returncode, output in results:
            txt.insert("end", f"── {step} ", "header")
            status = "(OK)" if returncode == 0 else f"(exit {returncode})"
            txt.insert("end", status + "\n", "ok" if returncode == 0 else "err")
            if output:
                for line in output.splitlines():
                    txt.insert("end", f"   {line}\n", "body")
            txt.insert("end", "\n")

        txt.configure(state="disabled")

        # Footer buttons
        btn_frame = tk.Frame(dlg, bg=C_BG)
        btn_frame.pack(fill="x", padx=PAD, pady=(0, PAD))

        if all_ok and changed:
            def _restart():
                dlg.destroy()
                import subprocess as _sp
                import sys as _sys
                # Stop services cleanly before restart
                if self._manager and self._manager.running:
                    self._manager.stop()
                _sp.Popen([_sys.executable] + _sys.argv)
                self.destroy()

            tk.Button(
                btn_frame, text="↺  Restart Now",
                bg=C_GREEN, fg="#0c0c18",
                relief="flat", padx=12, pady=4,
                font=_f(9, True), cursor="hand2",
                command=_restart,
            ).pack(side="left", padx=(0, 6))

        tk.Button(
            btn_frame, text="Close",
            bg=C_HOVER, fg=C_TEXT,
            relief="flat", padx=12, pady=4,
            font=_f(9), cursor="hand2",
            command=dlg.destroy,
        ).pack(side="left")

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
    parser = argparse.ArgumentParser(description="NotTheNet — Fake Internet Simulator")
    parser.add_argument("--config", default="config.json", help="Path to config JSON")
    parser.add_argument("--nogui", action="store_true",
                        help="Run headless (CLI mode, no GUI)")
    parser.add_argument("--loglevel", default=None,
                        help="Override log level (DEBUG/INFO/WARNING/ERROR)")
    args = parser.parse_args()

    cfg = Config(args.config)
    log_level = args.loglevel or cfg.get("general", "log_level") or "INFO"
    setup_logging(
        log_dir=cfg.get("general", "log_dir") or "logs",
        log_level=log_level,
        log_to_file=bool(cfg.get("general", "log_to_file")),
        name="notthenet",
    )

    if args.nogui:
        import signal
        import time
        _print_logo()
        manager = ServiceManager(cfg)
        if not manager.start():
            sys.exit(1)
        logger = logging.getLogger("notthenet")
        logger.info("Running in headless mode. Press Ctrl+C to stop.")

        stop_event = threading.Event()

        def _sig_handler(sig, frame):
            logger.info(f"Signal {sig} received; shutting down…")
            stop_event.set()

        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)

        stop_event.wait()
        manager.stop()
        sys.exit(0)
    else:
        app = NotTheNetApp(config_path=args.config)
        app.mainloop()


if __name__ == "__main__":
    main()
