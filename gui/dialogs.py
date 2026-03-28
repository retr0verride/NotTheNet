"""Configuration editor pages (General, Service, DNS, JSON Events)."""

from __future__ import annotations

import json
import logging
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import TYPE_CHECKING, Optional

from gui.widgets import (
    C_ACCENT,
    C_BORDER,
    C_DIM,
    C_ENTRY_BG,
    C_ENTRY_FG,
    C_HOVER,
    C_PANEL,
    C_SELECTED,
    C_SUBTLE,
    C_SURFACE,
    C_TEXT,
    PAD,
    _EVT_BUTTON1,
    _EVT_CONFIGURE,
    _JSON_LOG_PATH,
    _STY_JSONLOG_TV,
    _InfoPanel,
    _check,
    _combo,
    _entry,
    _f,
    _hover_bind,
    _open_path_external,
    _row,
    _section_frame,
    tooltip,
)

if TYPE_CHECKING:
    from config import Config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# General Settings page
# ---------------------------------------------------------------------------

class _GeneralPage(tk.Frame):
    """Global configuration page (bind IP, interface, logging, etc.)."""

    def __init__(self, parent, cfg: Config):
        super().__init__(parent, bg=C_SURFACE)
        self.cfg = cfg
        self.vars: dict = {}
        self._build()

    def _build(self):
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
             "IP returned for all DNS A/AAAA queries unless\n"
             "overridden by a custom record in the section below."),
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
        for row_idx, item in enumerate(fields):
            label, key, default, tip = item[0], item[1], item[2], item[3]
            choices = item[4] if len(item) > 4 else None
            val = self.cfg.get("general", key) or default
            v = tk.StringVar(value=str(val))
            self.vars[key] = v
            if choices:
                _row(f, label, lambda v=v, c=choices: _combo(f, v, c), row_idx,
                     tip=tip, info_panel=self._info_panel, default=default, var=v)
            else:
                _row(f, label, lambda v=v: _entry(f, v), row_idx,
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

        # TCP fingerprint OS dropdown
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
        json_path_val = self.cfg.get("general", "json_log_file") or _JSON_LOG_PATH
        v_jp = tk.StringVar(value=str(json_path_val))
        self.vars["json_log_file"] = v_jp
        _row(f, "JSON Log File",
             lambda v=v_jp: _entry(f, v),
             fp_row + 1,
             tip="Path to the JSON Lines event log file.\n"
                 "Each intercepted request is written as one JSON object per line.\n"
                 "Relative to the NotTheNet project root.",
             info_panel=self._info_panel, default=_JSON_LOG_PATH, var=v_jp)

    def apply_to_config(self):
        """Write all field values back to the Config object."""
        for key, var in self.vars.items():
            self.cfg.set("general", key, var.get())


# ---------------------------------------------------------------------------
# JSON Events viewer page
# ---------------------------------------------------------------------------

class _JsonEventsPage(tk.Frame):
    """Live-updating JSON event log viewer with search and event-type filtering."""

    _POLL_MS = 2000
    _MAX_DISPLAY_ROWS = 2000
    _ALL_ROWS_CAP = 20000
    _COLUMNS = ("timestamp", "event", "src_ip", "detail")

    def __init__(self, parent, cfg: Config):
        super().__init__(parent, bg=C_SURFACE)
        self.cfg = cfg
        self._file_pos = 0
        self._all_rows: list = []
        self._poll_job = None
        self._search_var = tk.StringVar()
        self._filter_var = tk.StringVar(value="ALL")
        self._event_types: set = set()
        self._tree_count: int = 0
        self._auto_export_path: Optional[str] = None
        self._auto_exported_count: int = 0
        self._build()

    def _build(self):
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

        btn_style = {"relief": "flat", "bd": 0, "padx": 10, "pady": 3,
                     "font": _f(8), "cursor": "hand2"}
        refresh_btn = tk.Button(
            bar, text="\u27f3 Refresh", bg=C_HOVER, fg=C_TEXT,
            command=self._full_reload, **btn_style,
        )
        refresh_btn.pack(side="left", padx=2)
        _hover_bind(refresh_btn, C_HOVER, C_SELECTED)
        tooltip(refresh_btn, "Re-read the entire JSON log file from disk.")

        clear_btn = tk.Button(
            bar, text="\u2715 Clear View", bg=C_HOVER, fg=C_TEXT,
            command=self._clear_view, **btn_style,
        )
        clear_btn.pack(side="left", padx=2)
        _hover_bind(clear_btn, C_HOVER, C_SELECTED)
        tooltip(clear_btn, "Clear the table (does NOT delete the file on disk).")

        open_btn = tk.Button(
            bar, text="\U0001f4c2 Open File", bg=C_HOVER, fg=C_TEXT,
            command=self._open_file_external, **btn_style,
        )
        open_btn.pack(side="left", padx=2)
        _hover_bind(open_btn, C_HOVER, C_SELECTED)
        tooltip(open_btn, "Open the raw .jsonl file in the system default editor.")

        self._count_label = tk.Label(
            bar, text="0 events", bg=C_SURFACE, fg=C_DIM, font=_f(8),
        )
        self._count_label.pack(side="right")

        # Treeview
        tree_frame = tk.Frame(self, bg=C_SURFACE)
        tree_frame.pack(fill="both", expand=True, padx=PAD, pady=(0, PAD))

        style = ttk.Style(self)
        style.configure(
            _STY_JSONLOG_TV,
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
        style.map(_STY_JSONLOG_TV,
                  background=[("selected", C_SELECTED)],
                  foreground=[("selected", C_TEXT)])

        self._tree = ttk.Treeview(
            tree_frame,
            columns=self._COLUMNS,
            show="headings",
            selectmode="extended",
            style=_STY_JSONLOG_TV,
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

        # Detail panel
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

        self._poll_job = self.after(500, self._poll_file)

    # -- Data loading --

    def _get_log_path(self) -> str:
        return str(self.cfg.get("general", "json_log_file") or _JSON_LOG_PATH)

    def _parse_new_lines(self, new_lines: list[str]) -> list:
        new_parsed: list = []
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
            new_parsed.append((row, obj))

            evt = obj.get("event", "")
            if evt and evt not in self._event_types:
                self._event_types.add(evt)
                choices = ["ALL"] + sorted(self._event_types)
                self._filter_combo.configure(values=choices)
        return new_parsed

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
            new_parsed = self._parse_new_lines(new_lines)

            if len(self._all_rows) > self._ALL_ROWS_CAP:
                overflow = self._all_rows[:-self._ALL_ROWS_CAP]
                self._all_rows = self._all_rows[-self._ALL_ROWS_CAP:]
                self._auto_export_rows(overflow)

            if new_parsed:
                search = self._search_var.get().strip()
                evt_filter = self._filter_var.get()
                if not search and evt_filter == "ALL":
                    self._append_new_rows(new_parsed)
                else:
                    self._apply_filter()

        self._poll_job = self.after(self._POLL_MS, self._poll_file)

    def _full_reload(self):
        """Re-read the entire file from offset 0."""
        self._file_pos = 0
        self._all_rows.clear()
        self._event_types.clear()
        self._filter_combo.configure(values=["ALL"])
        children = self._tree.get_children()
        if children:
            self._tree.delete(*children)
        self._tree_count = 0
        self._poll_file()

    def _auto_export_rows(self, rows: list):
        """Append overflow rows to the session auto-export file."""
        if not rows:
            return
        if self._auto_export_path is None:
            from datetime import datetime as _dt
            ts = _dt.now().strftime("%Y%m%d_%H%M%S")
            log_dir = os.path.dirname(
                os.path.abspath(self._get_log_path())
            )
            self._auto_export_path = os.path.join(
                log_dir, f"events_autoexport_{ts}.jsonl"
            )
            logger.info("JSON Events auto-export started: %s",
                        self._auto_export_path)

        path = self._auto_export_path
        _log = logger

        def _write():
            try:
                with open(path, "a", encoding="utf-8") as fh:
                    for _row_data, obj in rows:
                        fh.write(
                            json.dumps(obj, default=str, ensure_ascii=False)
                            + "\n"
                        )
                _log.debug("Auto-exported %d rows to %s", len(rows), path)
            except OSError as e:
                _log.error("JSON Events auto-export failed: %s", e)

        threading.Thread(target=_write, daemon=True, name="json-autoexport").start()
        self._auto_exported_count += len(rows)

    def _clear_view(self):
        """Clear the table without deleting the file."""
        self._all_rows.clear()
        children = self._tree.get_children()
        if children:
            self._tree.delete(*children)
        self._tree_count = 0
        self._auto_export_path = None
        self._auto_exported_count = 0
        self._count_label.configure(text="0 events")

    @staticmethod
    def _obj_to_row(obj: dict) -> tuple:
        ts = obj.get("timestamp", "")
        evt = obj.get("event", "")
        src = obj.get("src_ip", "")
        skip = {"timestamp", "epoch", "event", "src_ip"}
        parts = [f"{k}={v}" for k, v in obj.items() if k not in skip]
        detail = "  ".join(parts)
        return (ts, evt, src, detail)

    # -- Filtering --

    def _append_new_rows(self, new_rows: list):
        """Fast-path: append only newly received rows to the Treeview."""
        for row, _obj in new_rows:
            self._tree.insert("", "end", values=row)
        self._tree_count += len(new_rows)

        excess = self._tree_count - self._MAX_DISPLAY_ROWS
        if excess > 0:
            children = self._tree.get_children()
            stale = children[:excess]
            self._tree.delete(*stale)
            self._tree_count -= len(stale)

        auto = (f"  +{self._auto_exported_count:,} auto-exported"
                if self._auto_exported_count else "")
        self._count_label.configure(
            text=f"{self._tree_count} event{'s' if self._tree_count != 1 else ''}"
                 f" (of {len(self._all_rows)} total){auto}"
        )
        self._tree.see(self._tree.get_children()[-1] if self._tree_count else "")

    def _apply_filter(self, *_args):
        """Rebuild the Treeview to show only matching rows."""
        search = self._search_var.get().strip().lower()
        evt_filter = self._filter_var.get()

        children = self._tree.get_children()
        if children:
            self._tree.delete(*children)

        count = 0
        start = max(0, len(self._all_rows) - self._MAX_DISPLAY_ROWS)
        for row, obj in self._all_rows[start:]:
            if evt_filter != "ALL" and obj.get("event", "") != evt_filter:
                continue
            if search:
                haystack = " ".join(str(v) for v in obj.values()).lower()
                if search not in haystack:
                    continue
            self._tree.insert("", "end", values=row)
            count += 1

        self._tree_count = count
        auto = (f"  +{self._auto_exported_count:,} auto-exported"
                if self._auto_exported_count else "")
        self._count_label.configure(
            text=f"{count} event{'s' if count != 1 else ''}"
                 f" (of {len(self._all_rows)} total){auto}"
        )
        children = self._tree.get_children()
        if children:
            self._tree.see(children[-1])

    # -- Selection detail --

    def _on_select(self, _event=None):
        sel = self._tree.selection()
        if not sel:
            return
        item = self._tree.item(sel[0])
        values = item.get("values", ())
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

    # -- Export --

    def _export_events(self):
        """Save all loaded events to a user-chosen .jsonl file."""
        if not self._all_rows:
            messagebox.showinfo("No Events",
                                "No events loaded yet -- start a capture session first.")
            return
        from datetime import datetime as _dt
        ts = _dt.now().strftime("%Y%m%d_%H%M%S")
        dest = filedialog.asksaveasfilename(
            title="Export Events Log",
            defaultextension=".jsonl",
            filetypes=[("JSON Lines", "*.jsonl"), ("All files", "*.*")],
            initialfile=f"events_export_{ts}.jsonl",
        )
        if not dest:
            return
        try:
            with open(dest, "w", encoding="utf-8") as fh:
                for _row_data, obj in self._all_rows:
                    fh.write(json.dumps(obj, default=str, ensure_ascii=False) + "\n")
            messagebox.showinfo(
                "Exported",
                f"Exported {len(self._all_rows):,} event(s) to:\n{dest}\n\n"
                "Place this file in the same folder as your PCAP before "
                "opening it in MalNetInfo.",
            )
        except OSError as e:
            messagebox.showerror("Export Failed", f"Could not write file:\n{e}")

    def _open_file_external(self):
        """Open the .jsonl file in the system file manager."""
        path = os.path.abspath(self._get_log_path())
        if not os.path.exists(path):
            messagebox.showinfo("Not Found",
                                f"JSON log file does not exist yet:\n{path}")
            return
        try:
            _open_path_external(path)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file:\n{e}")

    def destroy(self):
        if self._poll_job:
            self.after_cancel(self._poll_job)
            self._poll_job = None
        super().destroy()

    def apply_to_config(self):
        """Read-only page -- nothing to save."""


# ---------------------------------------------------------------------------
# Generic service page
# ---------------------------------------------------------------------------

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
            self._build_field(f, i, item)

        for j, item in enumerate(self.checks):
            self._build_check(f, j, item)

    def _build_field(self, f, row: int, item: tuple):
        label, key, default = item[0], item[1], item[2]
        tip = item[3] if len(item) > 3 else ""
        choices = item[4] if len(item) > 4 else None
        val = self.cfg.get(self.section, key) or default
        v = tk.StringVar(value=str(val))
        self.vars[key] = v
        if choices:
            _row(f, label, lambda v=v, c=choices: _combo(f, v, c), row,
                 tip=tip, info_panel=self._info_panel, default=default, var=v)
        else:
            _row(f, label, lambda v=v: _entry(f, v), row,
                 tip=tip, info_panel=self._info_panel, default=default, var=v)

    def _build_check(self, f, j: int, item: tuple):
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
        """Write all field values back to the Config object."""
        for key, var in self.vars.items():
            self.cfg.set(self.section, key, var.get())


# ---------------------------------------------------------------------------
# DNS page (extends _ServicePage with custom records editor)
# ---------------------------------------------------------------------------

class _DNSPage(_ServicePage):
    """DNS service config page with custom records popup editor."""

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
        self._custom_records_str: str = ""
        self._build_custom_records()

    def _build_custom_records(self):
        records = self.cfg.get("dns", "custom_records") or {}
        self._custom_records_str = "\n".join(f"{k} = {v}" for k, v in records.items())

        btn_row = len(self.fields) + len(self.checks)
        _btn_style = {"relief": "flat", "bd": 0, "padx": 10, "pady": 4,
                      "font": _f(9), "cursor": "hand2"}
        btn = tk.Button(
            self._form_frame,
            text="\u229e  Custom DNS Records\u2026",
            bg=C_HOVER, fg=C_TEXT,
            command=self._open_records_popup,
            **_btn_style,
        )
        btn.grid(row=btn_row, column=0, columnspan=2, sticky="w", pady=(10, 4))
        _hover_bind(btn, C_HOVER, C_SELECTED)
        tooltip(btn, "Edit per-hostname DNS overrides.\nFormat: hostname = IP  (one per line)")

    def _open_records_popup(self):
        """Open the custom DNS records editor dialog."""
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
        """Write DNS fields and custom records to the Config object."""
        super().apply_to_config()
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
