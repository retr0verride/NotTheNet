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


# ─── Hover helper ────────────────────────────────────────────────────────────

def _hover_bind(widget, normal_bg: str, hover_bg: str):
    """Simulate button hover by swapping background colour on Enter/Leave."""
    widget.bind("<Enter>", lambda _e: widget.configure(bg=hover_bg))
    widget.bind("<Leave>", lambda _e: widget.configure(bg=normal_bg))


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
    return tk.Label(parent, text=text, bg=bg, fg=C_TEXT, **kw)


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
        font=("monospace", 9),
    )


def _section_frame(parent, title: str):
    """Labelled frame for a config group."""
    frame = tk.LabelFrame(
        parent,
        text=f"  {title}  ",
        bg=C_SURFACE,
        fg=C_ACCENT,
        font=("monospace", 9, "bold"),
        relief="flat",
        bd=0,
        highlightbackground=C_BORDER,
        highlightthickness=1,
        padx=PAD + 2,
        pady=PAD,
    )
    return frame


def _row(parent, label: str, widget_factory, row: int, col_offset: int = 0):
    """Lay out a label + widget pair in a grid."""
    lbl = tk.Label(parent, text=label, bg=C_SURFACE, fg=C_SUBTLE,
                   font=("monospace", 9), anchor="e")
    lbl.grid(row=row, column=col_offset, sticky="e", padx=(0, 6), pady=4)
    w = widget_factory()
    w.grid(row=row, column=col_offset + 1, sticky="w", pady=4)
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
            ("Bind IP",       "bind_ip",      "0.0.0.0"),
            ("Redirect IP",   "redirect_ip",  "127.0.0.1"),
            ("Interface",     "interface",    "eth0"),
            ("Log Directory", "log_dir",      "logs"),
            ("Log Level",     "log_level",    "INFO"),
        ]
        for row, (label, key, default) in enumerate(fields):
            val = self.cfg.get("general", key) or default
            v = tk.StringVar(value=str(val))
            self.vars[key] = v
            _row(f, label, lambda v=v: _entry(f, v), row)

        check_fields = [
            ("Enable auto-iptables rules", "auto_iptables", True),
            ("Log to file",               "log_to_file",   True),
        ]
        for i, (label, key, default) in enumerate(check_fields):
            val = self.cfg.get("general", key)
            if val is None:
                val = default
            v = tk.BooleanVar(value=bool(val))
            self.vars[key] = v
            _check(f, label, v).grid(
                row=len(fields) + i, column=0, columnspan=2, sticky="w", pady=4
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

        for i, (label, key, default) in enumerate(self.fields):
            val = self.cfg.get(self.section, key) or default
            v = tk.StringVar(value=str(val))
            self.vars[key] = v
            _row(f, label, lambda v=v: _entry(f, v), i)

        for j, (label, key, default) in enumerate(self.checks):
            val = self.cfg.get(self.section, key)
            if val is None:
                val = default
            v = tk.BooleanVar(value=bool(val))
            self.vars[key] = v
            _check(f, label, v).grid(
                row=len(self.fields) + j, column=0, columnspan=2, sticky="w", pady=4
            )

    def apply_to_config(self):
        for key, var in self.vars.items():
            self.cfg.set(self.section, key, var.get())


class _DNSPage(_ServicePage):
    def __init__(self, parent, cfg: Config):
        super().__init__(
            parent, cfg, "dns",
            fields=[
                ("Port",        "port",       "53"),
                ("Resolve To",  "resolve_to", "127.0.0.1"),
                ("TTL (s)",     "ttl",        "300"),
            ],
            checks=[
                ("Enabled",          "enabled",    True),
                ("Handle PTR/rDNS",  "handle_ptr", True),
            ],
        )
        # Custom records editor
        self._build_custom_records()

    def _build_custom_records(self):
        f2 = _section_frame(self, "Custom DNS Records  (name = IP)")
        f2.pack(fill="both", expand=True, padx=PAD + 4, pady=(0, PAD + 4))
        hint = tk.Label(f2, text="One entry per line:  example.com = 192.168.1.1",
                        bg=C_SURFACE, fg=C_DIM, font=("monospace", 8))
        hint.pack(anchor="w", pady=(0, 4))
        self._records_text = scrolledtext.ScrolledText(
            f2, height=6, bg=C_ENTRY_BG, fg=C_ENTRY_FG,
            insertbackground=C_ACCENT, relief="flat",
            font=("monospace", 9),
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

    def _build_ui(self):
        self._apply_ttk_styles()
        self._build_toolbar()
        self._build_main_pane()
        self._build_statusbar()

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
            font=("monospace", 17, "bold"),
            bg=C_BG, fg=C_ACCENT,
        ).pack(anchor="sw")
        tk.Label(
            name_frame, text=f"v{APP_VERSION}  ·  Fake Internet Simulator",
            font=("monospace", 8),
            bg=C_BG, fg=C_DIM,
        ).pack(anchor="nw")

        # Vertical divider
        tk.Frame(inner, bg=C_BORDER, width=1).pack(side="left", fill="y", padx=8)

        # Buttons
        btn_style = dict(relief="flat", bd=0, padx=14, pady=5,
                         font=("monospace", 9, "bold"), cursor="hand2")

        self._btn_start = tk.Button(
            inner, text="▶  Start", bg=C_GREEN, fg="#0c0c18",
            command=self._on_start, **btn_style
        )
        self._btn_start.pack(side="left", padx=(0, 4))
        _hover_bind(self._btn_start, C_GREEN, "#6ee89a")

        self._btn_stop = tk.Button(
            inner, text="■  Stop", bg=C_RED, fg="#0c0c18",
            command=self._on_stop, state="disabled", **btn_style
        )
        self._btn_stop.pack(side="left", padx=(0, 10))
        _hover_bind(self._btn_stop, C_RED, "#fc5c5c")

        # Vertical divider
        tk.Frame(inner, bg=C_BORDER, width=1).pack(side="left", fill="y", padx=6)

        sec_btn = dict(relief="flat", bd=0, padx=10, pady=5,
                       font=("monospace", 9), cursor="hand2")
        self._btn_save = tk.Button(
            inner, text="💾  Save", bg=C_HOVER, fg=C_TEXT,
            command=self._on_save, **sec_btn
        )
        self._btn_save.pack(side="left", padx=2)
        _hover_bind(self._btn_save, C_HOVER, C_SELECTED)

        self._btn_load = tk.Button(
            inner, text="📂  Load…", bg=C_HOVER, fg=C_TEXT,
            command=self._on_load, **sec_btn
        )
        self._btn_load.pack(side="left", padx=2)
        _hover_bind(self._btn_load, C_HOVER, C_SELECTED)

        # Vertical divider
        tk.Frame(inner, bg=C_BORDER, width=1).pack(side="left", fill="y", padx=6)

        self._btn_update = tk.Button(
            inner, text="↑  Update", bg=C_HOVER, fg=C_ACCENT2,
            command=self._on_update, **sec_btn
        )
        self._btn_update.pack(side="left", padx=2)
        _hover_bind(self._btn_update, C_HOVER, C_SELECTED)

        # Root warning (right side)
        import os as _os
        if _os.name != "nt" and _os.geteuid() != 0:
            warn = tk.Label(
                inner,
                text="⚠  Not root — ports <1024 may fail",
                bg=C_BG, fg=C_ORANGE,
                font=("monospace", 8),
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
            font=("monospace", 8, "bold"),
        ).pack(anchor="w")
        tk.Frame(left, bg=C_BORDER, height=1).pack(fill="x")

        self._service_btns: dict = {}

        # Group: General
        self._add_sidebar_section(left, "CONFIG")
        self._add_sidebar_btn(left, "general", "⚙  General")

        # Group: Network services
        self._add_sidebar_section(left, "NETWORK")
        for key, label in [
            ("dns",   "◈  DNS"),
            ("http",  "◈  HTTP"),
            ("https", "◈  HTTPS"),
            ("ftp",   "◈  FTP"),
        ]:
            self._add_sidebar_btn(left, key, label)

        # Group: Mail services
        self._add_sidebar_section(left, "MAIL")
        for key, label in [
            ("smtp", "◈  SMTP"),
            ("pop3", "◈  POP3"),
            ("imap", "◈  IMAP"),
        ]:
            self._add_sidebar_btn(left, key, label)

        # Group: Catch-all
        self._add_sidebar_section(left, "FALLBACK")
        self._add_sidebar_btn(left, "catch_all", "◈  Catch-All")

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
            font=("monospace", 7, "bold"),
        ).pack(anchor="w", padx=4)

    def _add_sidebar_btn(self, parent, key: str, label: str):
        """Add one sidebar service button with a status dot on the right."""
        row = tk.Frame(parent, bg=C_PANEL, cursor="hand2")
        row.pack(fill="x", pady=1)

        dot = tk.Label(row, text="●", bg=C_PANEL, fg=C_DIM,
                       font=("monospace", 7))
        dot.pack(side="right", padx=(0, 8))

        btn = tk.Label(
            row, text=f"  {label}",
            bg=C_PANEL, fg=C_SUBTLE,
            font=("monospace", 9), anchor="w",
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

        self._service_btns[key] = (row, btn, dot)

    def _build_pages(self):
        """Create one config page per service."""
        self._pages["general"] = _GeneralPage(self._page_container, self._cfg)

        self._pages["dns"] = _DNSPage(self._page_container, self._cfg)

        http_fields = [
            ("Port",            "port",           "80"),
            ("Response Code",   "response_code",  "200"),
            ("Response Body",   "response_body",  "<html><body>OK</body></html>"),
            ("Server Header",   "server_header",  "Apache/2.4.51"),
        ]
        self._pages["http"] = _ServicePage(
            self._page_container, self._cfg, "http", http_fields,
            [("Enabled", "enabled", True), ("Log Requests", "log_requests", True)],
        )

        https_fields = [
            ("Port",            "port",           "443"),
            ("Cert File",       "cert_file",      "certs/server.crt"),
            ("Key File",        "key_file",       "certs/server.key"),
            ("Response Code",   "response_code",  "200"),
            ("Response Body",   "response_body",  "<html><body>OK</body></html>"),
            ("Server Header",   "server_header",  "Apache/2.4.51"),
        ]
        self._pages["https"] = _ServicePage(
            self._page_container, self._cfg, "https", https_fields,
            [("Enabled", "enabled", True), ("Log Requests", "log_requests", True)],
        )

        for section, fields, checks in [
            ("smtp", [
                ("Port",     "port",     "25"),
                ("Hostname", "hostname", "mail.notthenet.local"),
                ("Banner",   "banner",   "220 mail.notthenet.local ESMTP"),
            ], [("Enabled", "enabled", True), ("Save Emails", "save_emails", True)]),
            ("pop3", [("Port", "port", "110"), ("Hostname", "hostname", "mail.notthenet.local")],
             [("Enabled", "enabled", True)]),
            ("imap", [("Port", "port", "143"), ("Hostname", "hostname", "mail.notthenet.local")],
             [("Enabled", "enabled", True)]),
            ("ftp", [
                ("Port",       "port",       "21"),
                ("Banner",     "banner",     "220 FTP Server Ready"),
                ("Upload Dir", "upload_dir", "logs/ftp_uploads"),
            ], [("Enabled", "enabled", True), ("Allow Uploads", "allow_uploads", True)]),
        ]:
            self._pages[section] = _ServicePage(
                self._page_container, self._cfg, section, fields, checks
            )

        # Catch-all page
        catch_fields = [
            ("TCP Catch-All Port", "tcp_port", "9999"),
            ("UDP Catch-All Port", "udp_port", "9998"),
        ]
        catch_checks = [
            ("Redirect TCP (catch-all)", "redirect_tcp", True),
            ("Redirect UDP (catch-all)", "redirect_udp", False),
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
                              font=("monospace", 9, "bold"))
                dot.configure(bg=C_SELECTED)
            else:
                row.configure(bg=C_PANEL)
                btn.configure(bg=C_PANEL, fg=C_SUBTLE,
                              font=("monospace", 9))
                dot.configure(bg=C_PANEL)

    def _build_log_panel(self, parent):
        # Header bar
        hdr = tk.Frame(parent, bg=C_BG, pady=4)
        hdr.pack(fill="x")
        tk.Frame(parent, bg=C_BORDER, height=1).pack(fill="x")

        tk.Label(
            hdr, text="  LIVE LOG",
            bg=C_BG, fg=C_DIM,
            font=("monospace", 8, "bold"),
        ).pack(side="left")

        # Level filter pills
        filter_frame = tk.Frame(hdr, bg=C_BG)
        filter_frame.pack(side="left", padx=12)
        self._log_filter_btns: dict = {}
        for lvl, colour in [("DEBUG", C_DIM), ("INFO", C_SUBTLE),
                            ("WARNING", C_ORANGE), ("ERROR", C_RED)]:
            b = tk.Button(
                filter_frame, text=lvl,
                bg=C_HOVER, fg=colour,
                relief="flat", bd=0, padx=6, pady=2,
                font=("monospace", 7, "bold"), cursor="hand2",
                command=lambda l=lvl: self._toggle_log_filter(l),
            )
            b.pack(side="left", padx=2)
            _hover_bind(b, C_HOVER, C_SELECTED)
            self._log_filter_btns[lvl] = b

        tk.Button(
            hdr, text="✕ Clear",
            bg=C_BG, fg=C_DIM, relief="flat",
            font=("monospace", 8), cursor="hand2",
            command=lambda: self._log_widget.configure(state="normal") or
                            self._log_widget.delete("1.0", "end") or
                            self._log_widget.configure(state="disabled"),
        ).pack(side="right", padx=PAD)

        self._log_widget = scrolledtext.ScrolledText(
            parent,
            bg=C_LOG_BG,
            fg=C_TEXT,
            font=("monospace", 9),
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
            font=("monospace", 8), anchor="w"
        )
        self._status_label.pack(side="left", padx=(PAD + 2, 0))
        tk.Label(
            bar, text="github.com/retr0verride/NotTheNet",
            bg=C_BG, fg=C_DIM, font=("monospace", 8),
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
            font=("monospace", 10, "bold"),
            anchor="w",
        ).pack(fill="x", padx=PAD + 4, pady=(PAD, 4))

        tk.Frame(dlg, bg=C_BORDER, height=1).pack(fill="x", padx=PAD)

        # Scrollable output
        txt = scrolledtext.ScrolledText(
            dlg, bg=C_LOG_BG, fg=C_TEXT,
            font=("monospace", 9), relief="flat",
            highlightthickness=0, state="normal",
        )
        txt.pack(fill="both", expand=True, padx=PAD, pady=PAD)

        txt.tag_config("header",  foreground=C_ACCENT2,  font=("monospace", 9, "bold"))
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
                font=("monospace", 9, "bold"), cursor="hand2",
                command=_restart,
            ).pack(side="left", padx=(0, 6))

        tk.Button(
            btn_frame, text="Close",
            bg=C_HOVER, fg=C_TEXT,
            relief="flat", padx=12, pady=4,
            font=("monospace", 9), cursor="hand2",
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
