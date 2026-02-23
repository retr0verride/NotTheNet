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

# Colour scheme
C_BG = "#1e1e2e"
C_PANEL = "#2a2a3e"
C_ACCENT = "#89b4fa"
C_GREEN = "#a6e3a1"
C_RED = "#f38ba8"
C_TEXT = "#cdd6f4"
C_DIM = "#6c7086"
C_ENTRY_BG = "#313244"
C_ENTRY_FG = "#cdd6f4"


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
    return tk.Label(parent, text=text, bg=C_PANEL, fg=C_TEXT, **kw)


def _entry(parent, textvariable, width=FIELD_WIDTH):
    return tk.Entry(
        parent,
        textvariable=textvariable,
        width=width,
        bg=C_ENTRY_BG,
        fg=C_ENTRY_FG,
        insertbackground=C_TEXT,
        relief="flat",
        bd=4,
    )


def _check(parent, text, variable):
    return tk.Checkbutton(
        parent,
        text=text,
        variable=variable,
        bg=C_PANEL,
        fg=C_TEXT,
        selectcolor=C_ENTRY_BG,
        activebackground=C_PANEL,
        activeforeground=C_TEXT,
    )


def _section_frame(parent, title: str):
    """Labelled frame for a config group."""
    frame = tk.LabelFrame(
        parent,
        text=f"  {title}  ",
        bg=C_PANEL,
        fg=C_ACCENT,
        relief="flat",
        bd=1,
        highlightbackground=C_DIM,
        highlightthickness=1,
        padx=PAD,
        pady=PAD,
    )
    return frame


def _row(parent, label: str, widget_factory, row: int, col_offset: int = 0):
    """Lay out a label + widget pair in a grid."""
    _label(parent, label).grid(row=row, column=col_offset, sticky="e", padx=(0, 4), pady=3)
    w = widget_factory()
    w.grid(row=row, column=col_offset + 1, sticky="w", pady=3)
    return w


# ─── Per-service configuration pages ─────────────────────────────────────────

class _GeneralPage(tk.Frame):
    def __init__(self, parent, cfg: Config):
        super().__init__(parent, bg=C_PANEL)
        self.cfg = cfg
        self.vars: dict = {}
        self._build()

    def _build(self):
        f = _section_frame(self, "General Settings")
        f.pack(fill="x", padx=PAD, pady=PAD)

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
                row=len(fields) + i, column=0, columnspan=2, sticky="w", pady=3
            )

    def apply_to_config(self):
        for key, var in self.vars.items():
            self.cfg.set("general", key, var.get())


class _ServicePage(tk.Frame):
    """Generic service config page (HTTP, HTTPS, SMTP, FTP, etc.)."""

    def __init__(self, parent, cfg: Config, section: str, fields: list, checks: list):
        super().__init__(parent, bg=C_PANEL)
        self.cfg = cfg
        self.section = section
        self.fields = fields
        self.checks = checks
        self.vars: dict = {}
        self._build()

    def _build(self):
        f = _section_frame(self, self.section.upper() + " Service")
        f.pack(fill="x", padx=PAD, pady=PAD)

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
                row=len(self.fields) + j, column=0, columnspan=2, sticky="w", pady=3
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
        f2.pack(fill="both", expand=True, padx=PAD, pady=(0, PAD))
        self._records_text = scrolledtext.ScrolledText(
            f2, height=6, bg=C_ENTRY_BG, fg=C_ENTRY_FG,
            insertbackground=C_TEXT, relief="flat",
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

        self._build_ui()
        self._poll_log_queue()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_toolbar()
        self._build_body()
        self._build_log_panel()
        self._build_statusbar()

    def _build_toolbar(self):
        bar = tk.Frame(self, bg=C_BG, pady=6)
        bar.pack(fill="x")

        tk.Label(
            bar, text="NotTheNet", font=("monospace", 16, "bold"),
            bg=C_BG, fg=C_ACCENT
        ).pack(side="left", padx=PAD)
        tk.Label(
            bar, text=f"v{APP_VERSION}", font=("monospace", 9),
            bg=C_BG, fg=C_DIM
        ).pack(side="left", padx=(0, PAD))

        # Buttons
        btn_style = dict(relief="flat", bd=0, padx=12, pady=4,
                         font=("monospace", 10, "bold"), cursor="hand2")
        self._btn_start = tk.Button(
            bar, text="▶  Start", bg=C_GREEN, fg="#1e1e2e",
            command=self._on_start, **btn_style
        )
        self._btn_start.pack(side="left", padx=4)

        self._btn_stop = tk.Button(
            bar, text="■  Stop", bg=C_RED, fg="#1e1e2e",
            command=self._on_stop, state="disabled", **btn_style
        )
        self._btn_stop.pack(side="left", padx=4)

        tk.Button(
            bar, text="Save Config", bg=C_PANEL, fg=C_TEXT,
            command=self._on_save, **btn_style
        ).pack(side="left", padx=4)

        tk.Button(
            bar, text="Load Config…", bg=C_PANEL, fg=C_TEXT,
            command=self._on_load, **btn_style
        ).pack(side="left", padx=4)

        # Root warning
        import os
        if os.name != "nt" and os.geteuid() != 0:
            tk.Label(
                bar,
                text="⚠ Not root — ports <1024 may fail",
                bg=C_BG, fg="#fab387",
                font=("monospace", 9),
            ).pack(side="right", padx=PAD)

    def _build_body(self):
        body = tk.PanedWindow(self, orient="horizontal", bg=C_BG, sashwidth=4)
        body.pack(fill="both", expand=True, padx=PAD, pady=(0, PAD))

        # ── Left: service list ──
        left = tk.Frame(body, bg=C_PANEL, width=140)
        body.add(left, minsize=130)

        _label(left, " Services", font=("monospace", 10, "bold")).pack(
            anchor="w", padx=PAD, pady=(PAD, 4)
        )
        ttk.Separator(left, orient="horizontal").pack(fill="x", padx=PAD)

        self._service_btns: dict = {}
        services = [
            ("general", "General"),
            ("dns",     "DNS"),
            ("http",    "HTTP"),
            ("https",   "HTTPS"),
            ("smtp",    "SMTP"),
            ("pop3",    "POP3"),
            ("imap",    "IMAP"),
            ("ftp",     "FTP"),
            ("catch_all", "Catch-All"),
        ]
        for key, label in services:
            indicator = tk.BooleanVar(value=False)
            self._svc_vars[key] = indicator
            btn = tk.Button(
                left, text=f"● {label}",
                bg=C_PANEL, fg=C_DIM,
                relief="flat", anchor="w", padx=PAD,
                font=("monospace", 10),
                cursor="hand2",
                command=lambda k=key: self._show_page(k),
            )
            btn.pack(fill="x", padx=4, pady=1)
            self._service_btns[key] = btn

        # ── Right: config pages ──
        right = tk.Frame(body, bg=C_PANEL)
        body.add(right, minsize=500)

        self._page_container = tk.Frame(right, bg=C_PANEL)
        self._page_container.pack(fill="both", expand=True)

        self._build_pages()
        self._show_page("general")

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

        for k, btn in self._service_btns.items():
            if k == key:
                btn.configure(bg=C_ACCENT, fg="#1e1e2e", font=("monospace", 10, "bold"))
            else:
                btn.configure(bg=C_PANEL, fg=C_DIM, font=("monospace", 10))

    def _build_log_panel(self):
        log_frame = tk.Frame(self, bg=C_BG)
        log_frame.pack(fill="x", padx=PAD, pady=(0, 2))

        hdr = tk.Frame(log_frame, bg=C_BG)
        hdr.pack(fill="x")
        _label(hdr, " Live Log", font=("monospace", 9, "bold")).configure(bg=C_BG)
        _label(hdr, " Live Log", font=("monospace", 9, "bold")).pack(side="left")
        tk.Button(
            hdr, text="Clear", bg=C_BG, fg=C_DIM, relief="flat",
            font=("monospace", 8), cursor="hand2",
            command=lambda: self._log_widget.delete("1.0", "end"),
        ).pack(side="right")

        self._log_widget = scrolledtext.ScrolledText(
            log_frame,
            height=10,
            bg="#11111b",
            fg=C_TEXT,
            font=("monospace", 9),
            relief="flat",
            state="disabled",
        )
        self._log_widget.pack(fill="x")
        self._log_widget.tag_config("ERROR",   foreground=C_RED)
        self._log_widget.tag_config("WARNING", foreground="#fab387")
        self._log_widget.tag_config("INFO",    foreground=C_TEXT)
        self._log_widget.tag_config("DEBUG",   foreground=C_DIM)

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=C_BG, height=22)
        bar.pack(fill="x", side="bottom")
        self._status_label = tk.Label(
            bar, text="● Stopped", bg=C_BG, fg=C_DIM,
            font=("monospace", 9), anchor="w"
        )
        self._status_label.pack(side="left", padx=PAD)
        tk.Label(
            bar, text="github.com/your-org/notthenet",
            bg=C_BG, fg=C_DIM, font=("monospace", 9),
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

        self._log_widget.insert("end", msg + "\n", tag)
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
        self._status_label.configure(text="● Starting…", fg="#fab387")

    def _update_ui_after_start(self, ok: bool):
        if ok:
            self._btn_start.configure(state="disabled")
            self._btn_stop.configure(state="normal")
            self._status_label.configure(text="● Running", fg=C_GREEN)
            self._update_service_indicators()
        else:
            self._status_label.configure(text="● Failed — check log", fg=C_RED)

    def _on_stop(self):
        if self._manager:
            threading.Thread(target=self._manager.stop, daemon=True).start()
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled")
        self._status_label.configure(text="● Stopped", fg=C_DIM)
        for key, btn in self._service_btns.items():
            btn.configure(fg=C_DIM)

    def _update_service_indicators(self):
        """Refresh sidebar dots based on actual service status."""
        if not self._manager:
            return
        status = self._manager.status()
        mapping = {
            "dns": "dns", "http": "http", "https": "https",
            "smtp": "smtp", "pop3": "pop3", "imap": "imap",
            "ftp": "ftp", "catch_tcp": "catch_all",
        }
        for svc_key, page_key in mapping.items():
            colour = C_GREEN if status.get(svc_key) else C_DIM
            btn = self._service_btns.get(page_key)
            if btn:
                current_text = btn.cget("text")
                label = current_text[2:]  # strip "● "
                btn.configure(fg=colour)

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
