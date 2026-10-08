"""Dashboard layout: globe canvas, toolbar, sidebar, panes, log panel."""

from __future__ import annotations

import functools
import math
import os
import tkinter as tk
from tkinter import font as _tkfont
from tkinter import scrolledtext, ttk
from typing import TYPE_CHECKING, Any

from gui.dialogs import _DNSPage, _GeneralPage, _JsonEventsPage, _ServicePage
from gui.preflight import _PreflightPage
from gui.service_pages import SERVICE_PAGES
from gui.widgets import (
    _BASE_H,
    _BASE_MIN_H,
    _BASE_MIN_W,
    _BASE_W,
    _EVT_BUTTON1,
    _EVT_BUTTON4,
    _EVT_BUTTON5,
    _EVT_CONFIGURE,
    _EVT_MOUSEWHEEL,
    _F,
    _PANE_BODY_MIN,
    _PANE_CONFIG_MIN,
    _PANE_LOG_MIN,
    _PANE_SIDE_MIN,
    _STY_DARK_COMBO,
    _ZOOM_MAX,
    _ZOOM_MIN,
    _ZOOM_STEP,
    C_ACCENT,
    C_ACCENT2,
    C_BG,
    C_BORDER,
    C_DIM,
    C_ENTRY_BG,
    C_ENTRY_FG,
    C_GREEN,
    C_HOVER,
    C_LOG_BG,
    C_ORANGE,
    C_PANEL,
    C_RED,
    C_SELECTED,
    C_SUBTLE,
    C_SURFACE,
    C_TEXT,
    PAD,
    _f,
    _hover_bind,
    tooltip,
)
from version import APP_VERSION

# ---------------------------------------------------------------------------
# Globe canvas icon
# ---------------------------------------------------------------------------

class _GlobeCanvas(tk.Canvas):
    """~46x46 px canvas that draws the NotTheNet globe+prohibition logo."""

    SIZE = 46

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(
            parent,
            width=self.SIZE, height=self.SIZE,
            bg=C_BG, bd=0, highlightthickness=0,
        )
        self._draw()

    def _draw(self) -> None:
        cx, cy, r = 23, 23, 17
        pr = 21
        teal = "#00c8a0"
        red  = "#ff3b3b"

        self.create_line(cx - r, cy, cx + r, cy, fill=teal, width=1)
        for dy, rw in ((6, r - 2), (12, r - 7)):
            for sign in (-1, 1):
                y = cy + sign * dy
                self.create_arc(cx - rw, y - 4, cx + rw, y + 4,
                                start=0, extent=180, style="arc",
                                outline=teal, width=1)

        self.create_line(cx, cy - r, cx, cy + r, fill=teal, width=1)
        self.create_oval(cx - 9, cy - r, cx + 9, cy + r,
                         outline=teal, width=1)
        self.create_oval(cx - r, cy - r, cx + r, cy + r,
                         outline=teal, width=2)
        self.create_oval(cx - pr, cy - pr, cx + pr, cy + pr,
                         outline=red, width=3)

        angle = math.radians(45)
        x1 = cx + pr * math.cos(angle)
        y1 = cy - pr * math.sin(angle)
        x2 = cx - pr * math.cos(angle)
        y2 = cy + pr * math.sin(angle)
        self.create_line(x1, y1, x2, y2, fill=red, width=3,
                         capstyle="round")


# ---------------------------------------------------------------------------
# Dashboard mixin (all _build_* methods for the main window)
# ---------------------------------------------------------------------------

if TYPE_CHECKING:
    import queue

    from config import Config
    from service_manager import ServiceManager

    class _DashboardHost(tk.Tk):
        """Type stub describing attributes the DashboardMixin expects."""

        _zoom_factor: float
        _cfg: Config
        _svc_vars: dict[str, tk.Label]
        _pages: dict[str, tk.Frame]
        _log_queue: queue.Queue[str]
        _log_line_count: int
        _manager: ServiceManager | None
        _start_time: float | None
        _timer_job: str | None
        _log_level_filter: set[str]
        _log_filter_btns: dict[str, tk.Button]
        _log_widget: scrolledtext.ScrolledText
        _btn_start: tk.Button
        _btn_stop: tk.Button
        _btn_check_updates: tk.Button
        _status_label: tk.Label

        # Provided by ServiceControlMixin (gui/logic.py).
        def _on_start(self) -> None: ...
        def _on_stop(self) -> None: ...
        def _on_save(self) -> None: ...
        def _on_load(self) -> None: ...
        def _on_check_updates(self) -> None: ...
        def _toggle_log_filter(self, level: str) -> None: ...
        def _open_log_folder(self) -> None: ...
        def _clear_log_widget(self) -> None: ...
else:
    _DashboardHost = object


class DashboardMixin(_DashboardHost):
    """Mixin providing layout-building methods for the main application window.

    Expects the consuming class to be a ``tk.Tk`` subclass that also mixes in
    ``ServiceControlMixin`` and initialises the following attributes in
    ``__init__``:

    * ``_cfg``, ``_log_queue``, ``_log_line_count``
    * ``_manager``, ``_svc_vars``, ``_pages``, ``_start_time``, ``_timer_job``
    * ``_zoom_factor``, ``_log_level_filter``
    """

    # -- Fonts / zoom -------------------------------------------------------

    def _init_fonts(self) -> None:
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

    def _set_zoom(self, delta: float) -> None:
        """Step the UI font scale by *delta*, resize the window, and persist."""
        new = max(_ZOOM_MIN, min(_ZOOM_MAX, self._zoom_factor + delta))
        if new == self._zoom_factor:
            return
        old = self._zoom_factor
        self._zoom_factor = new
        self._init_fonts()
        if hasattr(self, "_zoom_label"):
            pct = round(new * 100)
            self._zoom_label.configure(text=f"{pct}%")
        ratio = new / old
        cw = self.winfo_width()  or _BASE_W
        ch = self.winfo_height() or _BASE_H
        nw = max(round(_BASE_MIN_W * new), round(cw * ratio))
        nh = max(round(_BASE_MIN_H * new), round(ch * ratio))
        self.geometry(f"{nw}x{nh}")
        self.minsize(round(_BASE_MIN_W * new), round(_BASE_MIN_H * new))
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

    # -- Top-level build ----------------------------------------------------

    def _build_ui(self) -> None:
        """Construct the full window layout (toolbar, body, log, statusbar)."""
        self._apply_ttk_styles()
        self._build_toolbar()
        self._build_main_pane()
        self._build_statusbar()
        self.bind_all("<Control-equal>",  lambda _e: self._set_zoom(+_ZOOM_STEP))
        self.bind_all("<Control-minus>",  lambda _e: self._set_zoom(-_ZOOM_STEP))
        self.bind_all("<Control-0>",      lambda _e: self._set_zoom(1.0 - self._zoom_factor))

    def _apply_ttk_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Sash",  sashthickness=5, background=C_BORDER)
        style.configure("VSash", sashthickness=5, background=C_BORDER)
        style.configure("HSash", sashthickness=5, background=C_BORDER)
        style.configure(_STY_DARK_COMBO,
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
        style.map(_STY_DARK_COMBO,
            fieldbackground=[("readonly", C_ENTRY_BG), ("disabled", C_BG)],
            foreground=[("readonly", C_ENTRY_FG), ("disabled", C_DIM)],
            background=[("active", C_HOVER), ("pressed", C_SELECTED)],
            arrowcolor=[("active", C_ACCENT), ("pressed", C_ACCENT2)],
        )

    # -- Toolbar ------------------------------------------------------------

    def _build_toolbar(self) -> None:
        bar = tk.Frame(self, bg=C_BG)
        bar.pack(fill="x")

        tk.Frame(bar, bg=C_ACCENT, height=2).pack(fill="x")

        inner = tk.Frame(bar, bg=C_BG, pady=8)
        inner.pack(fill="x")

        globe = _GlobeCanvas(inner)
        globe.pack(side="left", padx=(PAD + 2, 6))

        name_frame = tk.Frame(inner, bg=C_BG)
        name_frame.pack(side="left", padx=(0, 14))
        tk.Label(
            name_frame, text="NotTheNet",
            font=_f(17, True), bg=C_BG, fg=C_ACCENT,
        ).pack(anchor="sw")
        tk.Label(
            name_frame, text=f"v{APP_VERSION}  \u00b7  Fake Internet Simulator",
            font=_f(8), bg=C_BG, fg=C_DIM,
        ).pack(anchor="nw")

        tk.Frame(inner, bg=C_BORDER, width=1).pack(side="left", fill="y", padx=8)

        btn_style: dict[str, Any] = {"relief": "flat", "bd": 0, "padx": 14, "pady": 5,
                     "font": _f(9, True), "cursor": "hand2"}

        self._btn_start = tk.Button(
            inner, text="\u25b6  Start", bg=C_GREEN, fg="#0c0c18",
            command=self._on_start, **btn_style
        )
        self._btn_start.pack(side="left", padx=(0, 4))
        _hover_bind(self._btn_start, C_GREEN, "#6ee89a")
        tooltip(self._btn_start,
                "Apply all config values and start every enabled service.\n"
                "Also installs iptables REDIRECT rules if auto-iptables is on.\n"
                "Requires root (or sudo).")

        self._btn_stop = tk.Button(
            inner, text="\u25a0  Stop", bg=C_RED, fg="#0c0c18",
            command=self._on_stop, state="disabled", **btn_style
        )
        self._btn_stop.pack(side="left", padx=(0, 10))
        _hover_bind(self._btn_stop, C_RED, "#fc5c5c")
        tooltip(self._btn_stop,
                "Gracefully stop all running services and remove\n"
                "any iptables REDIRECT rules that were added on start.")

        tk.Frame(inner, bg=C_BORDER, width=1).pack(side="left", fill="y", padx=6)

        sec_btn: dict[str, Any] = {"relief": "flat", "bd": 0, "padx": 10, "pady": 5,
                   "font": _f(9), "cursor": "hand2"}
        self._btn_save = tk.Button(
            inner, text="\U0001f4be  Save", bg=C_HOVER, fg=C_TEXT,
            command=self._on_save, **sec_btn
        )
        self._btn_save.pack(side="left", padx=2)
        _hover_bind(self._btn_save, C_HOVER, C_SELECTED)
        tooltip(self._btn_save, "Save current GUI settings to config.json.")

        self._btn_load = tk.Button(
            inner, text="\U0001f4c2  Load\u2026", bg=C_HOVER, fg=C_TEXT,
            command=self._on_load, **sec_btn
        )
        self._btn_load.pack(side="left", padx=2)
        _hover_bind(self._btn_load, C_HOVER, C_SELECTED)
        tooltip(self._btn_load,
                "Load settings from a different JSON config file.\n"
                "All panels will be rebuilt with the new values.")

        # Zoom controls
        tk.Frame(inner, bg=C_BORDER, width=1).pack(side="left", fill="y", padx=6)

        zoom_frame = tk.Frame(inner, bg=C_BG)
        zoom_frame.pack(side="left")

        btn_zoom_out = tk.Button(
            zoom_frame, text="A\u2212",
            bg=C_HOVER, fg=C_SUBTLE, relief="flat",
            padx=6, pady=3, font=_f(8), cursor="hand2",
            command=lambda: self._set_zoom(-_ZOOM_STEP),
        )
        btn_zoom_out.pack(side="left")
        _hover_bind(btn_zoom_out, C_HOVER, C_SELECTED)
        tooltip(btn_zoom_out, "Zoom out  (Ctrl+-)")

        self._zoom_label = tk.Label(
            zoom_frame,
            text=f"{round(self._zoom_factor * 100)}%",
            bg=C_BG, fg=C_DIM, font=_f(8), width=4,
        )
        self._zoom_label.pack(side="left")
        tooltip(self._zoom_label,
                "Current zoom level.\n"
                "Ctrl+= zoom in \u00b7 Ctrl+- zoom out \u00b7 Ctrl+0 reset")

        btn_zoom_in = tk.Button(
            zoom_frame, text="A+",
            bg=C_HOVER, fg=C_SUBTLE, relief="flat",
            padx=6, pady=3, font=_f(8), cursor="hand2",
            command=lambda: self._set_zoom(+_ZOOM_STEP),
        )
        btn_zoom_in.pack(side="left")
        _hover_bind(btn_zoom_in, C_HOVER, C_SELECTED)
        tooltip(btn_zoom_in, "Zoom in  (Ctrl+=)")

        # Check for Updates button (right-aligned)
        self._btn_check_updates = tk.Button(
            inner, text="\u27f3  Updates",
            bg=C_HOVER, fg=C_SUBTLE, relief="flat",
            padx=8, pady=3, font=_f(8), cursor="hand2",
            command=self._on_check_updates,
        )
        self._btn_check_updates.pack(side="right", padx=(0, PAD))
        _hover_bind(self._btn_check_updates, C_HOVER, C_SELECTED)
        tooltip(self._btn_check_updates,
                "Check GitHub for a newer release.\n"
                "Opens the releases page if an update is available.")

        # Root warning (POSIX only)
        if os.name != "nt" and os.geteuid() != 0:
            warn = tk.Label(
                inner,
                text="\u26a0  Not root \u2014 ports <1024 may fail",
                bg=C_BG, fg=C_ORANGE, font=_f(8),
            )
            warn.pack(side="right", padx=PAD)

        tk.Frame(bar, bg=C_BORDER, height=1).pack(fill="x")

    # -- Main pane (vertical split: body | log) -----------------------------

    def _build_main_pane(self) -> None:
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

    # -- Body (horizontal split: sidebar | config pages) --------------------

    def _build_body(self, parent: tk.Misc) -> None:
        self._body_pane = tk.PanedWindow(parent, orient="horizontal", bg=C_BG,
                              sashwidth=5, sashpad=0, sashrelief="flat")
        self._body_pane.pack(fill="both", expand=True)
        body = self._body_pane

        # Left sidebar
        left = tk.Frame(body, bg=C_PANEL)
        body.add(left, minsize=148)

        hdr = tk.Frame(left, bg=C_PANEL, pady=8)
        hdr.pack(fill="x")
        tk.Label(hdr, text="  SERVICES", bg=C_PANEL, fg=C_DIM,
                 font=_f(8, True)).pack(anchor="w")
        tk.Frame(left, bg=C_BORDER, height=1).pack(fill="x")

        self._sb_canvas = tk.Canvas(left, bg=C_PANEL, highlightthickness=0, bd=0)
        self._sb_canvas.pack(fill="both", expand=True)
        sb_inner = tk.Frame(self._sb_canvas, bg=C_PANEL)
        _sb_win = self._sb_canvas.create_window((0, 0), window=sb_inner, anchor="nw")
        sb_inner.bind(
            _EVT_CONFIGURE,
            lambda e: self._sb_canvas.configure(
                scrollregion=self._sb_canvas.bbox("all")
            ),
        )
        self._sb_canvas.bind(
            _EVT_CONFIGURE,
            lambda e: self._sb_canvas.itemconfig(_sb_win, width=e.width),
        )

        def _sb_scroll(event: tk.Event[tk.Misc]) -> None:
            if event.num == 4 or getattr(event, "delta", 0) > 0:
                self._sb_canvas.yview_scroll(-1, "units")
            elif event.num == 5 or getattr(event, "delta", 0) < 0:
                self._sb_canvas.yview_scroll(1, "units")

        self._sb_scroll = _sb_scroll
        for _w in (self._sb_canvas, sb_inner):
            _w.bind(_EVT_MOUSEWHEEL, _sb_scroll)
            _w.bind(_EVT_BUTTON4,   _sb_scroll)
            _w.bind(_EVT_BUTTON5,   _sb_scroll)

        self._service_btns: dict[str, tuple[tk.Frame, tk.Label]] = {}

        # Sidebar sections and items
        self._add_sidebar_section(sb_inner, "CONFIG")
        self._add_sidebar_btn(sb_inner, "general", "\u2699  General",
                              "Global settings: bind IP, redirect IP,\n"
                              "network interface, log directory, and verbosity.",
                              show_dot=False)
        self._add_sidebar_btn(sb_inner, "preflight", "\u2708  Preflight",
                              "Pre-detonation readiness check.\n"
                              "Verifies stealth config, certs, network,\n"
                              "ports, and optionally checks/fixes the\n"
                              "victim VM via SSH.",
                              show_dot=False)

        self._add_sidebar_section(sb_inner, "NETWORK")
        _net_items = [
            ("dns",   "\u25c8  DNS",
             "Fake DNS server \u2014 resolves all hostnames to redirect_ip.\n"
             "Supports custom per-hostname overrides and PTR responses."),
            ("http",  "\u25c8  HTTP",
             "Fake HTTP server \u2014 responds to all plaintext web requests\n"
             "with a configurable status code and body."),
            ("https", "\u25c8  HTTPS",
             "Fake HTTPS server \u2014 TLS-encrypted HTTP with a self-signed cert.\n"
             "Malware rarely validates the certificate."),
            ("ftp",   "\u25c8  FTP",
             "Fake FTP server \u2014 accepts logins and optionally saves uploads\n"
             "to disk with UUID filenames."),
            ("ntp",   "\u25c8  NTP",
             "Fake NTP server \u2014 returns current system time on UDP/123.\n"
             "Defeats clock-skew sandbox detection used by evasive malware."),
            ("irc",   "\u25c8  IRC",
             "Fake IRC server \u2014 accepts botnet C2 connections on TCP/6667.\n"
             "Provides realistic welcome sequence and channel join so bots\n"
             "proceed to sit awaiting commands."),
            ("tftp",    "\u25c8  TFTP",
             "Fake TFTP server \u2014 handles RRQ (serves stub file) and WRQ\n"
             "(saves uploads) on UDP/69. Used for payload staging and\n"
             "lateral movement exfiltration."),
            ("telnet",  "\u25c8  Telnet",
             "Fake Telnet server (TCP/23) \u2014 Mirai and virtually all IoT botnets\n"
             "authenticate through Telnet. Logs credentials and simulates a\n"
             "BusyBox shell to keep bots alive and issuing commands."),
            ("socks5",  "\u25c8  SOCKS5",
             "Fake SOCKS5 proxy (TCP/1080) \u2014 SystemBC, QakBot, Cobalt Strike\n"
             "and many RATs tunnel C2 through SOCKS5.\n"
             "The CONNECT request reveals the real C2 host and port even when\n"
             "DNS is fake."),
            ("ircs",    "\u25c8  IRC/TLS",
             "TLS-wrapped fake IRC server (TCP/6697) \u2014 modern botnets use SSL\n"
             "IRC to avoid plaintext interception. Same full intercept logic as\n"
             "the plain IRC service, with TLS handshake on top."),
            ("icmp",    "\u25c8  ICMP",
             "ICMP echo responder \u2014 answers all pings so malware connectivity\n"
             "checks succeed. iptables DNAT redirects forwarded pings here;\n"
             "the kernel issues genuine echo-replies automatically."),
            ("smb",     "\u25c8  SMB",
             "Fake SMB server (TCP/445) \u2014 captures SMBv1/v2 negotiate requests.\n"
             "Flags EternalBlue (MS17-010) probes. Sniff-and-drop mode lets worms\n"
             "bypass the honeypot for lateral spread in Gateway mode."),
            ("rdp",     "\u25c8  RDP",
             "Fake RDP server (TCP/3389) \u2014 extracts Windows username from the\n"
             "TPKT mstshash cookie before any encryption. Used by NLBrute,\n"
             "ransomware operators, RATs."),
            ("vnc",     "\u25c8  VNC",
             "Fake VNC server (TCP/5900) \u2014 RFB 3.8 handshake + VNC Auth\n"
             "challenge. Captures DES response for offline cracking. Used by\n"
             "hVNC RATs and brute-force scanners."),
            ("mysql",   "\u25c8  MySQL",
             "Fake MySQL server (TCP/3306) \u2014 Handshake V10 greeting; captures\n"
             "plaintext username and logs COM_QUERY commands. Used by stealers\n"
             "(RedLine, Raccoon) and web shells."),
            ("mssql",   "\u25c8  MSSQL",
             "Fake MSSQL server (TCP/1433) \u2014 TDS pre-login with ENCRYPT_NOT_SUP\n"
             "causes Login7 to arrive unencrypted; the password is only XOR-\n"
             "obfuscated and is fully recovered. Used by QakBot, Emotet."),
            ("redis",   "\u25c8  Redis",
             "Fake Redis server (TCP/6379) \u2014 RESP protocol; responds to PING,\n"
             "INFO, CONFIG, SLAVEOF, SAVE. Flags write-webshell and SLAVEOF\n"
             "exfil attempts. Used by cryptominers and persistence implants."),
            ("ldap",    "\u25c8  LDAP",
             "Fake LDAP server (TCP/389) \u2014 parses BER BindRequest; captures\n"
             "plaintext SimpleBind DN and password. Used by BloodHound,\n"
             "Cobalt Strike LDAP query BOF, AD-targeting stealers."),
        ]
        for key, label, tip in _net_items:
            self._add_sidebar_btn(sb_inner, key, label, tip)

        self._add_sidebar_section(sb_inner, "MAIL")
        for key, label, tip in [
            ("smtp",  "\u25c8  SMTP",
             "Fake SMTP server \u2014 accepts email submissions and optionally\n"
             "saves them as .eml files for analysis."),
            ("smtps", "\u25c8  SMTPS",
             "Fake SMTPS server (implicit TLS port 465) \u2014 used by stealers\n"
             "such as RedLine, AgentTesla, and FormBook to exfiltrate credentials."),
            ("pop3",  "\u25c8  POP3",
             "Fake POP3 server \u2014 announces an empty mailbox to connecting clients."),
            ("pop3s", "\u25c8  POP3S",
             "Fake POP3S server (implicit TLS port 995)."),
            ("imap",  "\u25c8  IMAP",
             "Fake IMAP server \u2014 announces an empty INBOX to connecting clients."),
            ("imaps", "\u25c8  IMAPS",
             "Fake IMAPS server (implicit TLS port 993)."),
        ]:
            self._add_sidebar_btn(sb_inner, key, label, tip)

        self._add_sidebar_section(sb_inner, "FALLBACK")
        self._add_sidebar_btn(sb_inner, "catch_all", "\u25c8  Catch-All",
                              "TCP/UDP catch-all \u2014 iptables redirects all traffic\n"
                              "not handled by specific services to these ports.")

        self._add_sidebar_section(sb_inner, "ANALYSIS")
        self._add_sidebar_btn(sb_inner, "json_events", "\u25c8  JSON Events",
                              "Live view of structured JSON event log.\n"
                              "Shows every intercepted request with search\n"
                              "and event-type filtering.",
                              show_dot=False)

        # Right: config page container
        right = tk.Frame(body, bg=C_SURFACE)
        body.add(right, minsize=500)

        self._page_container = tk.Frame(right, bg=C_SURFACE)
        self._page_container.pack(fill="both", expand=True)

        self._build_pages()
        self._show_page("general")

    def _add_sidebar_section(self, parent: tk.Misc, title: str) -> None:
        """Small muted category header in the sidebar."""
        f = tk.Frame(parent, bg=C_PANEL, pady=0)
        f.pack(fill="x", pady=(6, 0))
        lbl = tk.Label(f, text=f"  {title}", bg=C_PANEL, fg=C_DIM,
                       font=_f(7, True))
        lbl.pack(anchor="w", padx=4)
        if hasattr(self, "_sb_scroll"):
            for _w in (f, lbl):
                _w.bind(_EVT_MOUSEWHEEL, self._sb_scroll)
                _w.bind(_EVT_BUTTON4,   self._sb_scroll)
                _w.bind(_EVT_BUTTON5,   self._sb_scroll)

    def _add_sidebar_btn(self, parent: tk.Misc, key: str, label: str, tip: str = "",
                         show_dot: bool = True) -> None:
        """Add one sidebar service button with an optional status dot."""
        row = tk.Frame(parent, bg=C_PANEL, cursor="hand2")
        row.pack(fill="x", pady=1)

        btn = tk.Label(
            row, text=f"  {label}",
            bg=C_PANEL, fg=C_SUBTLE, font=_f(9), anchor="w",
        )
        btn.pack(side="left", fill="x", expand=True, ipady=5)

        self._service_btns[key] = (row, btn)

        row.bind(_EVT_BUTTON1, lambda _e=None: self._show_page(key))  # type: ignore[misc]
        btn.bind(_EVT_BUTTON1, lambda _e=None: self._show_page(key))  # type: ignore[misc]
        _hover_bind(row, C_PANEL, C_HOVER)
        _hover_bind(btn, C_PANEL, C_HOVER)

        if tip:
            tooltip(row, tip)
            tooltip(btn, tip)

        dot = None
        if show_dot:
            dot = tk.Label(row, text="\u25cf", bg=C_PANEL, fg=C_DIM,
                           font=_f(8), padx=6)
            dot.pack(side="right")
            dot.bind(_EVT_BUTTON1, lambda _e=None: self._show_page(key))  # type: ignore[misc]
            self._svc_vars[key] = dot

        if hasattr(self, "_sb_scroll"):
            for _w in ([row, btn] + ([dot] if dot else [])):
                _w.bind(_EVT_MOUSEWHEEL, self._sb_scroll)
                _w.bind(_EVT_BUTTON4,   self._sb_scroll)
                _w.bind(_EVT_BUTTON5,   self._sb_scroll)

    # -- Config pages -------------------------------------------------------

    def _build_pages(self) -> None:
        """Create the special pages, then one generic page per SERVICE_PAGES entry."""
        self._pages["general"] = _GeneralPage(self._page_container, self._cfg)
        self._pages["preflight"] = _PreflightPage(
            self._page_container, self._cfg,
            manager_ref=lambda: self._manager,
        )
        self._pages["dns"] = _DNSPage(self._page_container, self._cfg)
        self._json_events_page = _JsonEventsPage(self._page_container, self._cfg)
        self._pages["json_events"] = self._json_events_page
        for section, fields, checks in SERVICE_PAGES:
            self._pages[section] = _ServicePage(
                self._page_container, self._cfg, section, fields, checks
            )

    def _show_page(self, key: str) -> None:
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

    # -- Log panel ----------------------------------------------------------

    def _build_log_panel(self, parent: tk.Misc) -> None:
        """Build the live log panel at the bottom of the window."""
        hdr = tk.Frame(parent, bg=C_BG, pady=4)
        hdr.pack(fill="x")
        tk.Frame(parent, bg=C_BORDER, height=1).pack(fill="x")

        tk.Label(hdr, text="  LIVE LOG", bg=C_BG, fg=C_DIM,
                 font=_f(8, True)).pack(side="left")

        filter_frame = tk.Frame(hdr, bg=C_BG)
        filter_frame.pack(side="left", padx=12)
        self._log_filter_btns: dict[str, tk.Button] = {}
        _pill_tips = {
            "DEBUG":   "Toggle DEBUG messages on/off.\nAny combination of levels can be active simultaneously.",
            "INFO":    "Toggle INFO messages on/off.\nAny combination of levels can be active simultaneously.",
            "WARNING": "Toggle WARNING messages on/off.\nAny combination of levels can be active simultaneously.",
            "ERROR":   "Toggle ERROR messages on/off.\nAny combination of levels can be active simultaneously.",
        }
        for lvl, colour in [("DEBUG", C_DIM), ("INFO", C_SUBTLE),
                            ("WARNING", C_ORANGE), ("ERROR", C_RED)]:
            b = tk.Button(
                filter_frame, text=lvl,
                bg=C_HOVER, fg=colour,
                relief="flat", bd=0, padx=6, pady=2,
                font=_f(7, True), cursor="hand2",
                command=functools.partial(self._toggle_log_filter, lvl),
            )
            b.pack(side="left", padx=2)
            _hover_bind(b, C_HOVER, C_SELECTED)
            tooltip(b, _pill_tips[lvl])
            self._log_filter_btns[lvl] = b

        export_log_btn = tk.Button(
            hdr, text="\U0001f4be Export...",
            bg=C_BG, fg=C_DIM, relief="flat",
            font=_f(8), cursor="hand2",
            command=lambda: self._json_events_page._export_events(),
        )
        export_log_btn.pack(side="right", padx=(0, 2))
        _hover_bind(export_log_btn, C_BG, C_HOVER)
        tooltip(export_log_btn,
                "Save a copy of all loaded JSON events to a .jsonl file "
                "(e.g. alongside your PCAP for use with MalNetInfo).")

        open_logs_btn = tk.Button(
            hdr, text="\U0001f4c1 Open Logs",
            bg=C_BG, fg=C_DIM, relief="flat",
            font=_f(8), cursor="hand2",
            command=self._open_log_folder,
        )
        open_logs_btn.pack(side="right", padx=(0, 2))
        _hover_bind(open_logs_btn, C_BG, C_HOVER)
        tooltip(open_logs_btn, "Open the logs folder in the system file manager.")

        clear_btn = tk.Button(
            hdr, text="\u2715 Clear",
            bg=C_BG, fg=C_DIM, relief="flat",
            font=_f(8), cursor="hand2",
            command=self._clear_log_widget,
        )
        clear_btn.pack(side="right", padx=PAD)
        tooltip(clear_btn, "Clear all messages from the log panel.\n(Log files on disk are not affected.)")

        self._log_widget = scrolledtext.ScrolledText(
            parent,
            bg=C_LOG_BG, fg=C_TEXT, font=_f(9),
            relief="flat", state="disabled", wrap="none",
            highlightthickness=0,
        )
        self._log_widget.pack(fill="both", expand=True)
        self._log_widget.tag_config("ERROR",   foreground=C_RED)
        self._log_widget.tag_config("WARNING", foreground=C_ORANGE)
        self._log_widget.tag_config("INFO",    foreground=C_TEXT)
        self._log_widget.tag_config("DEBUG",   foreground=C_DIM)
        self._log_widget.tag_config("HIDDEN",  elide=True)

    # -- Status bar ---------------------------------------------------------

    def _build_statusbar(self) -> None:
        """Build the thin status bar at the window bottom."""
        tk.Frame(self, bg=C_BORDER, height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(self, bg=C_BG, height=24)
        bar.pack(fill="x", side="bottom")
        self._status_label = tk.Label(
            bar, text="\u25cf  Stopped", bg=C_BG, fg=C_DIM,
            font=_f(8), anchor="w"
        )
        self._status_label.pack(side="left", padx=(PAD + 2, 0))
        tk.Label(
            bar, text="github.com/retr0verride/NotTheNet",
            bg=C_BG, fg=C_DIM, font=_f(8),
        ).pack(side="right", padx=PAD)
