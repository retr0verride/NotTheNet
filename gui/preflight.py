"""Preflight check page for the NotTheNet GUI."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox
from typing import TYPE_CHECKING

from gui.widgets import (
    C_ACCENT,
    C_BORDER,
    C_DIM,
    C_ENTRY_BG,
    C_ENTRY_FG,
    C_GREEN,
    C_HOVER,
    C_ORANGE,
    C_RED,
    C_SELECTED,
    C_SUBTLE,
    C_SURFACE,
    C_TEXT,
    PAD,
    _entry,
    _f,
    _hover_bind,
    _section_frame,
    tooltip,
)

if TYPE_CHECKING:
    from config import Config

logger = logging.getLogger(__name__)

_STATUS_ICONS = {"ok": "\u2714", "warn": "\u26a0", "fail": "\u2718", "info": "\u2139"}
_STATUS_COLORS = {"ok": C_GREEN, "warn": C_ORANGE, "fail": C_RED, "info": C_DIM}


class _PreflightPage(tk.Frame):
    """Preflight check page: local checks and victim IP detection."""

    def __init__(self, parent, cfg: Config, manager_ref=None):
        super().__init__(parent, bg=C_SURFACE)
        self.cfg = cfg
        self._manager_ref = manager_ref  # callable that returns the ServiceManager
        self.vars: dict = {}
        self._local_labels: list[tk.Label] = []
        self._running = False
        self._cert_server_proc: subprocess.Popen | None = None
        self._build()

    def _build(self):
        # Scrollable canvas wrapper
        canvas = tk.Canvas(self, bg=C_SURFACE, highlightthickness=0, bd=0)
        vsb = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self._inner = tk.Frame(canvas, bg=C_SURFACE)
        _win = canvas.create_window((0, 0), window=self._inner, anchor="nw")
        self._inner.bind("<Configure>",
                         lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(_win, width=e.width))

        def _scroll(event):
            if event.num == 4 or getattr(event, "delta", 0) > 0:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5 or getattr(event, "delta", 0) < 0:
                canvas.yview_scroll(1, "units")

        for w in (canvas, self._inner):
            w.bind("<MouseWheel>", _scroll)
            w.bind("<Button-4>", _scroll)
            w.bind("<Button-5>", _scroll)

        self._build_victim_section()
        self._build_cert_section()
        self._build_local_section()
        self._build_buttons()
        self._build_status()

    # ── Victim IP section ─────────────────────────────────────────────────

    def _build_victim_section(self):
        f = _section_frame(self._inner, "Victim IP")
        f.pack(fill="x", padx=PAD + 4, pady=PAD + 4)

        # IP address
        val = self.cfg.get("victim", "ip") or ""
        v_ip = tk.StringVar(value=val)
        self.vars["ip"] = v_ip
        tk.Label(f, text="IP Address", bg=C_SURFACE, fg=C_SUBTLE,
                 font=_f(9), anchor="e").grid(row=0, column=0, sticky="e", padx=(0, 6), pady=4)
        ip_frame = tk.Frame(f, bg=C_SURFACE)
        ip_frame.grid(row=0, column=1, sticky="w", pady=4)
        _entry(ip_frame, v_ip, width=15).pack(side="left")
        detect_btn = tk.Button(
            ip_frame, text="\U0001f50d Detect", bg=C_HOVER, fg=C_TEXT,
            relief="flat", bd=0, padx=8, pady=3, font=_f(8),
            cursor="hand2", command=self._on_detect_ip,
        )
        detect_btn.pack(side="left", padx=(6, 0))
        _hover_bind(detect_btn, C_HOVER, C_SELECTED)
        tooltip(detect_btn,
                "Detect victim IP by reading the ARP table on the lab bridge.\n"
                "The victim VM must be running.")

    def _on_detect_ip(self):
        """Detect victim IP from ARP cache."""
        from utils.victim_remote import arp_scan, detect_victims
        manual_ip = self.vars["ip"].get().strip()
        hosts = arp_scan(self.cfg) or detect_victims(self.cfg)
        if not hosts:
            if manual_ip:
                messagebox.showinfo(
                    "Detect IP",
                    "No hosts found on the lab bridge.\n"
                    f"Keeping manually entered IP: {manual_ip}",
                )
                return
            messagebox.showinfo("Detect IP",
                                "No hosts found on the lab bridge.\n"
                                "Is the victim VM running?")
            return
        if len(hosts) == 1:
            self.vars["ip"].set(hosts[0].ip)
            return
        self._show_ip_picker(hosts)

    def _show_ip_picker(self, hosts):
        dlg = tk.Toplevel()
        dlg.title("Select Victim")
        dlg.configure(bg=C_SURFACE)
        dlg.geometry("320x200")
        dlg.grab_set()

        tk.Label(dlg, text="Multiple hosts found. Select the victim:",
                 bg=C_SURFACE, fg=C_TEXT, font=_f(9)).pack(padx=12, pady=(12, 6))

        listbox = tk.Listbox(dlg, bg=C_ENTRY_BG, fg=C_ENTRY_FG,
                             font=_f(9), selectmode="single",
                             highlightthickness=1, highlightbackground=C_BORDER)
        for h in hosts:
            listbox.insert("end", f"{h.ip}  ({h.mac})")
        listbox.pack(fill="both", expand=True, padx=12, pady=4)

        def _select():
            sel = listbox.curselection()
            if sel:
                self.vars["ip"].set(hosts[sel[0]].ip)
            dlg.destroy()

        bar = tk.Frame(dlg, bg=C_SURFACE)
        bar.pack(fill="x", padx=12, pady=(0, 12))
        tk.Button(bar, text="Cancel", bg=C_HOVER, fg=C_TEXT,
                  relief="flat", font=_f(9), command=dlg.destroy).pack(side="right")
        tk.Button(bar, text="Select", bg=C_ACCENT, fg="#0c0c18",
                  relief="flat", font=_f(9, True), command=_select).pack(side="right", padx=(0, 6))

    # ── CA Cert Distribution section ──────────────────────────────────────

    def _build_cert_section(self):
        f = _section_frame(self._inner, "CA Cert Distribution")
        f.pack(fill="x", padx=PAD + 4, pady=(0, PAD + 4))

        tk.Label(
            f,
            text="Serve certs/ca.crt over HTTP so the victim can install it manually.",
            bg=C_SURFACE, fg=C_SUBTLE, font=_f(8), anchor="w",
        ).pack(anchor="w", pady=(0, 6))

        btn_row = tk.Frame(f, bg=C_SURFACE)
        btn_row.pack(anchor="w")

        self._serve_btn = tk.Button(
            btn_row, text="\u25b6  Serve CA Cert",
            bg=C_HOVER, fg=C_TEXT,
            relief="flat", bd=0, padx=10, pady=4,
            font=_f(9, True), cursor="hand2",
            command=self._on_toggle_cert_server,
        )
        self._serve_btn.pack(side="left")
        _hover_bind(self._serve_btn, C_HOVER, C_SELECTED)
        tooltip(self._serve_btn,
                "Start a temporary HTTP server on port 8080 serving certs/.\n"
                "Browse to the URL on the victim and install ca.crt.")

        self._cert_url_var = tk.StringVar()
        self._cert_url_label = tk.Label(
            f, textvariable=self._cert_url_var,
            bg=C_SURFACE, fg=C_ACCENT, font=_f(9),
            cursor="hand2", anchor="w",
        )
        self._cert_url_label.pack(anchor="w", pady=(6, 0))
        self._cert_url_label.bind("<Button-1>", lambda _e: self._copy_cert_url())
        tooltip(self._cert_url_label, "Click to copy URL to clipboard")

    def _on_toggle_cert_server(self):
        if self._cert_server_proc and self._cert_server_proc.poll() is None:
            self._stop_cert_server()
        else:
            self._start_cert_server()

    def _start_cert_server(self):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        certs_dir = os.path.join(project_root, "certs")
        ca_path = os.path.join(certs_dir, "ca.crt")

        if not os.path.exists(ca_path):
            messagebox.showerror(
                "CA Cert",
                "certs/ca.crt not found.\nRun NotTheNet first to generate certificates.",
            )
            return

        bind_ip = self.cfg.get("general", "bind_ip") or "10.10.10.1"
        port = 8080

        try:
            self._cert_server_proc = subprocess.Popen(
                [sys.executable, "-m", "http.server", str(port),
                 "--bind", bind_ip, "--directory", certs_dir],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            messagebox.showerror("CA Cert Server", f"Failed to start HTTP server:\n{exc}")
            return

        url = f"http://{bind_ip}:{port}/ca.crt"
        self._cert_url_var.set(f"\u2398  {url}")
        self._serve_btn.configure(
            text="\u25a0  Stop Serving", bg=C_RED, fg="#ffffff",
        )
        _hover_bind(self._serve_btn, C_RED, "#ff6060")
        self._set_status(f"Serving CA cert at {url}", C_GREEN)

    def _stop_cert_server(self):
        if self._cert_server_proc:
            self._cert_server_proc.terminate()
            self._cert_server_proc = None
        self._cert_url_var.set("")
        self._serve_btn.configure(
            text="\u25b6  Serve CA Cert", bg=C_HOVER, fg=C_TEXT,
        )
        _hover_bind(self._serve_btn, C_HOVER, C_SELECTED)
        self._set_status("CA cert server stopped.", C_DIM)

    def _copy_cert_url(self):
        raw = self._cert_url_var.get()
        # strip the leading clipboard icon + space
        url = raw.lstrip("\u2398 ").strip()
        if url:
            self.clipboard_clear()
            self.clipboard_append(url)
            self._set_status("URL copied to clipboard.", C_DIM)

    def destroy(self):
        self._stop_cert_server()
        super().destroy()

    # ── Local Checks section ──────────────────────────────────────────────

    def _build_local_section(self):
        f = _section_frame(self._inner, "Local Checks (Kali)")
        f.pack(fill="x", padx=PAD + 4, pady=(0, PAD + 4))
        self._local_frame = f
        self._local_placeholder = tk.Label(
            f, text="Click 'Run Local Checks' or 'Run All Checks' to start.",
            bg=C_SURFACE, fg=C_DIM, font=_f(9),
        )
        self._local_placeholder.pack(anchor="w", pady=4)

    def _populate_local_results(self, results):
        """Display local check results."""
        for lbl in self._local_labels:
            lbl.destroy()
        self._local_labels.clear()
        if self._local_placeholder:
            self._local_placeholder.destroy()
            self._local_placeholder = None

        for r in results:
            icon = _STATUS_ICONS.get(r.status, "?")
            color = _STATUS_COLORS.get(r.status, C_TEXT)
            lbl = tk.Label(
                self._local_frame,
                text=f"  {icon}  {r.message}",
                bg=C_SURFACE, fg=color, font=_f(9), anchor="w",
            )
            lbl.pack(anchor="w", pady=1)
            self._local_labels.append(lbl)

    # ── Buttons ───────────────────────────────────────────────────────────

    def _build_buttons(self):
        bar = tk.Frame(self._inner, bg=C_SURFACE)
        bar.pack(fill="x", padx=PAD + 4, pady=(0, PAD))

        btn_style = {"relief": "flat", "bd": 0, "padx": 12, "pady": 5,
                     "font": _f(9, True), "cursor": "hand2"}

        self._local_btn = tk.Button(
            bar, text="\U0001f50d  Run Checks",
            bg=C_ACCENT, fg="#0c0c18", command=self._on_run_local, **btn_style,
        )
        self._local_btn.pack(side="left", padx=(0, 6))
        _hover_bind(self._local_btn, C_ACCENT, "#33e8c4")
        tooltip(self._local_btn,
                "Run Kali-side checks: config stealth, certs,\n"
                "network, ports, hardening.")

    # ── Status line ───────────────────────────────────────────────────────

    def _build_status(self):
        self._status_label = tk.Label(
            self._inner, text="", bg=C_SURFACE, fg=C_DIM, font=_f(9),
        )
        self._status_label.pack(anchor="w", padx=PAD + 4, pady=(0, PAD))

    def _set_status(self, text: str, color: str = C_DIM):
        self._status_label.configure(text=text, fg=color)

    # ── Check execution ───────────────────────────────────────────────────

    def _is_services_running(self) -> bool:
        if self._manager_ref:
            mgr = self._manager_ref()
            if mgr and hasattr(mgr, "running") and mgr.running:
                return True
        return False

    def _get_victim_creds(self):
        ip = self.vars["ip"].get().strip()
        user = self.vars["username"].get().strip()
        pw = self.vars["password"].get().strip()
        return ip, user, pw

    def _on_run_local(self):
        if self._running:
            return
        self._running = True
        self._set_status("Running checks\u2026", C_ORANGE)
        self._local_btn.configure(state="disabled")

        def _worker():
            from utils.preflight import run_preflight
            self.apply_to_config()
            report = run_preflight(self.cfg)
            all_results = (report.stealth + report.certs + report.network
                           + report.ports + report.hardening)
            self.after(0, self._finish_local, all_results, report)

        threading.Thread(target=_worker, daemon=True).start()

    def _finish_local(self, results, report):
        self._populate_local_results(results)
        failures = len(report.failures)
        warnings = len(report.warnings)
        if failures:
            self._set_status(f"{failures} failure(s), {warnings} warning(s)", C_RED)
        elif warnings:
            self._set_status(f"All passed, {warnings} warning(s)", C_ORANGE)
        else:
            self._set_status("All checks passed", C_GREEN)
        self._local_btn.configure(state="normal")
        self._running = False

    # ── Config persistence ────────────────────────────────────────────────

    def apply_to_config(self):
        """Write victim IP field back to config."""
        for key, var in self.vars.items():
            self.cfg.set("victim", key, var.get())
