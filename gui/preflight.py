"""Preflight check page for the NotTheNet GUI."""

from __future__ import annotations

import logging
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
    _check,
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
    """Preflight check page: victim connection, local checks, remote checks."""

    def __init__(self, parent, cfg: Config, manager_ref=None):
        super().__init__(parent, bg=C_SURFACE)
        self.cfg = cfg
        self._manager_ref = manager_ref  # callable that returns the ServiceManager
        self.vars: dict = {}
        self._local_labels: list[tk.Label] = []
        self._remote_labels: list[tk.Label] = []
        self._fixable_keys: list[str] = []
        self._running = False
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
        self._build_local_section()
        self._build_remote_section()
        self._build_buttons()
        self._build_status()

    # ── Victim Connection section ─────────────────────────────────────────

    def _build_victim_section(self):
        f = _section_frame(self._inner, "Victim Connection")
        f.pack(fill="x", padx=PAD + 4, pady=PAD + 4)

        # Username
        val = self.cfg.get("victim", "username") or ""
        v_user = tk.StringVar(value=val)
        self.vars["username"] = v_user
        tk.Label(f, text="Username", bg=C_SURFACE, fg=C_SUBTLE,
                 font=_f(9), anchor="e").grid(row=0, column=0, sticky="e", padx=(0, 6), pady=4)
        _entry(f, v_user).grid(row=0, column=1, sticky="w", pady=4)

        # Password (masked)
        val = self.cfg.get("victim", "password") or ""
        v_pass = tk.StringVar(value=val)
        self.vars["password"] = v_pass
        tk.Label(f, text="Password", bg=C_SURFACE, fg=C_SUBTLE,
                 font=_f(9), anchor="e").grid(row=1, column=0, sticky="e", padx=(0, 6), pady=4)
        pw_frame = tk.Frame(f, bg=C_SURFACE)
        pw_frame.grid(row=1, column=1, sticky="w", pady=4)
        self._pw_entry = tk.Entry(
            pw_frame, textvariable=v_pass, width=18, show="\u2022",
            bg=C_ENTRY_BG, fg=C_ENTRY_FG, insertbackground=C_ACCENT,
            relief="flat", bd=6, font=_f(9),
            highlightthickness=1, highlightbackground=C_BORDER,
            highlightcolor=C_ACCENT,
        )
        self._pw_entry.pack(side="left")
        self._pw_shown = False
        toggle_btn = tk.Button(
            pw_frame, text="\U0001f441", bg=C_HOVER, fg=C_TEXT,
            relief="flat", bd=0, padx=4, pady=2, font=_f(9),
            cursor="hand2", command=self._toggle_password,
        )
        toggle_btn.pack(side="left", padx=(4, 0))
        tooltip(toggle_btn, "Show/hide password")

        # IP address
        val = self.cfg.get("victim", "ip") or ""
        v_ip = tk.StringVar(value=val)
        self.vars["ip"] = v_ip
        tk.Label(f, text="IP Address", bg=C_SURFACE, fg=C_SUBTLE,
                 font=_f(9), anchor="e").grid(row=2, column=0, sticky="e", padx=(0, 6), pady=4)
        ip_frame = tk.Frame(f, bg=C_SURFACE)
        ip_frame.grid(row=2, column=1, sticky="w", pady=4)
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

        # Auto-detect checkbox
        val = self.cfg.get("victim", "auto_detect_ip")
        if val is None:
            val = True
        v_auto = tk.BooleanVar(value=bool(val))
        self.vars["auto_detect_ip"] = v_auto
        cb = _check(f, "Auto-detect IP from ARP on check", v_auto)
        cb.grid(row=3, column=0, columnspan=2, sticky="w", pady=4)
        tooltip(cb, "Automatically scan the ARP table for victim IP\n"
                    "when running checks. Uses the configured interface.")

        # Lab-only warning
        tk.Label(
            f, text="\u26a0 Victim credentials stored in plaintext \u2014 lab use only",
            bg=C_SURFACE, fg=C_ORANGE, font=_f(8),
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))

    def _toggle_password(self):
        self._pw_shown = not self._pw_shown
        self._pw_entry.configure(show="" if self._pw_shown else "\u2022")

    def _on_detect_ip(self):
        """Detect victim IP from ARP cache."""
        from utils.victim_remote import arp_scan, detect_victims
        if self.vars.get("auto_detect_ip", tk.BooleanVar(value=True)).get():
            hosts = arp_scan(self.cfg)
        else:
            hosts = detect_victims(self.cfg)
        if not hosts:
            messagebox.showinfo("Detect IP",
                                "No hosts found on the lab bridge.\n"
                                "Is the victim VM running?")
            return
        if len(hosts) == 1:
            self.vars["ip"].set(hosts[0].ip)
            return
        # Multiple hosts — show picker
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

    # ── Remote Checks section ─────────────────────────────────────────────

    def _build_remote_section(self):
        f = _section_frame(self._inner, "Remote Checks (Victim)")
        f.pack(fill="x", padx=PAD + 4, pady=(0, PAD + 4))
        self._remote_frame = f
        self._remote_placeholder = tk.Label(
            f, text="Enter victim credentials and click 'Run All Checks'.",
            bg=C_SURFACE, fg=C_DIM, font=_f(9),
        )
        self._remote_placeholder.pack(anchor="w", pady=4)

    def _populate_remote_results(self, results):
        """Display remote check results."""
        for lbl in self._remote_labels:
            lbl.destroy()
        self._remote_labels.clear()
        self._fixable_keys.clear()
        if self._remote_placeholder:
            self._remote_placeholder.destroy()
            self._remote_placeholder = None

        for r in results:
            icon = _STATUS_ICONS.get(r.status, "?")
            color = _STATUS_COLORS.get(r.status, C_TEXT)
            lbl = tk.Label(
                self._remote_frame,
                text=f"  {icon}  {r.message}",
                bg=C_SURFACE, fg=color, font=_f(9), anchor="w",
            )
            lbl.pack(anchor="w", pady=1)
            self._remote_labels.append(lbl)
            if r.fixable and r.fix_key:
                self._fixable_keys.append(r.fix_key)

        self._fix_btn.configure(
            state="normal" if self._fixable_keys else "disabled"
        )

    # ── Buttons ───────────────────────────────────────────────────────────

    def _build_buttons(self):
        bar = tk.Frame(self._inner, bg=C_SURFACE)
        bar.pack(fill="x", padx=PAD + 4, pady=(0, PAD))

        btn_style = {"relief": "flat", "bd": 0, "padx": 12, "pady": 5,
                     "font": _f(9, True), "cursor": "hand2"}

        self._local_btn = tk.Button(
            bar, text="\U0001f50d  Run Local Checks",
            bg=C_HOVER, fg=C_TEXT, command=self._on_run_local, **btn_style,
        )
        self._local_btn.pack(side="left", padx=(0, 6))
        _hover_bind(self._local_btn, C_HOVER, C_SELECTED)
        tooltip(self._local_btn,
                "Run Kali-side checks only: config stealth, certs,\n"
                "network, ports, hardening. No SSH needed.")

        self._all_btn = tk.Button(
            bar, text="\U0001f50d  Run All Checks",
            bg=C_ACCENT, fg="#0c0c18", command=self._on_run_all, **btn_style,
        )
        self._all_btn.pack(side="left", padx=(0, 6))
        _hover_bind(self._all_btn, C_ACCENT, "#33e8c4")
        tooltip(self._all_btn,
                "Local checks + remote victim checks via WMI.\n"
                "Requires victim credentials and IP.")

        self._fix_btn = tk.Button(
            bar, text="\U0001f527  Fix Issues",
            bg=C_ORANGE, fg="#0c0c18", command=self._on_fix,
            state="disabled", **btn_style,
        )
        self._fix_btn.pack(side="left", padx=(0, 6))
        _hover_bind(self._fix_btn, C_ORANGE, "#fcb25c")
        tooltip(self._fix_btn,
                "Connect to the victim via WMI/SMB and fix detected issues:\n"
                "\u2022 Install Root CA cert\n"
                "\u2022 Set DNS to NTN gateway\n"
                "Blocked while services are running.")

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
        self._set_status("Running local checks\u2026", C_ORANGE)
        self._local_btn.configure(state="disabled")
        self._all_btn.configure(state="disabled")

        def _worker():
            from utils.preflight import run_preflight
            # Save current field values to config before checking
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
            self._set_status("All local checks passed", C_GREEN)
        self._local_btn.configure(state="normal")
        self._all_btn.configure(state="normal")
        self._running = False

    def _on_run_all(self):
        if self._running:
            return

        if self._is_services_running():
            messagebox.showwarning("Preflight",
                                   "Cannot run remote checks while services are active.\n"
                                   "Stop services first or revert the victim snapshot.")
            return

        ip, user, pw = self._get_victim_creds()

        # Auto-detect IP if enabled and empty
        if not ip and self.vars.get("auto_detect_ip", tk.BooleanVar(value=True)).get():
            self._on_detect_ip()
            ip = self.vars["ip"].get().strip()

        if not ip or not user or not pw:
            messagebox.showinfo("Preflight",
                                "Enter victim IP, username, and password\n"
                                "to run remote checks.")
            # Still run local checks
            self._on_run_local()
            return

        self._running = True
        self._set_status("Running all checks\u2026", C_ORANGE)
        self._local_btn.configure(state="disabled")
        self._all_btn.configure(state="disabled")
        self._fix_btn.configure(state="disabled")

        def _worker():
            from utils.preflight import run_preflight
            from utils.victim_remote import run_remote_checks

            self.apply_to_config()
            report = run_preflight(self.cfg)
            local_results = (report.stealth + report.certs + report.network
                             + report.ports + report.hardening)
            remote_results = run_remote_checks(ip, user, pw, self.cfg)
            self.after(0, self._finish_all, local_results, remote_results, report)

        threading.Thread(target=_worker, daemon=True).start()

    def _finish_all(self, local_results, remote_results, report):
        self._populate_local_results(local_results)
        self._populate_remote_results(remote_results)

        local_fails = len(report.failures)
        local_warns = len(report.warnings)
        remote_fails = sum(1 for r in remote_results if r.status == "fail")
        remote_warns = sum(1 for r in remote_results if r.status == "warn")

        total_fails = local_fails + remote_fails
        total_warns = local_warns + remote_warns

        if total_fails:
            self._set_status(f"{total_fails} failure(s), {total_warns} warning(s)", C_RED)
        elif total_warns:
            self._set_status(f"All passed, {total_warns} warning(s)", C_ORANGE)
        else:
            self._set_status("All checks passed", C_GREEN)

        self._local_btn.configure(state="normal")
        self._all_btn.configure(state="normal")
        self._running = False

    def _on_fix(self):
        if self._running:
            return
        if self._is_services_running():
            messagebox.showwarning("Preflight",
                                   "Cannot fix issues while services are active.\n"
                                   "Stop services first.")
            return
        if not self._fixable_keys:
            return

        ip, user, pw = self._get_victim_creds()
        if not ip or not user or not pw:
            messagebox.showinfo("Preflight", "Enter victim credentials first.")
            return

        fix_desc = "\n".join(f"  \u2022 {k}" for k in self._fixable_keys)
        if not messagebox.askyesno("Fix Issues",
                                   f"The following fixes will be applied via WMI/SMB:\n\n{fix_desc}\n\n"
                                   "Proceed?"):
            return

        self._running = True
        self._set_status("Applying fixes\u2026", C_ORANGE)
        self._fix_btn.configure(state="disabled")

        def _worker():
            from utils.victim_remote import run_fixes
            self.apply_to_config()
            results = run_fixes(ip, user, pw, self.cfg, self._fixable_keys)
            self.after(0, self._finish_fix, results)

        threading.Thread(target=_worker, daemon=True).start()

    def _finish_fix(self, results):
        # Show results in remote section
        self._populate_remote_results(results)
        ok_count = sum(1 for r in results if r.status == "ok")
        fail_count = sum(1 for r in results if r.status == "fail")
        if fail_count:
            self._set_status(f"Fixes: {ok_count} succeeded, {fail_count} failed", C_RED)
        else:
            self._set_status(f"All {ok_count} fix(es) applied successfully", C_GREEN)
        self._running = False

    # ── Config persistence ────────────────────────────────────────────────

    def apply_to_config(self):
        """Write victim connection fields back to config (password excluded)."""
        for key, var in self.vars.items():
            if key == "password":
                continue
            self.cfg.set("victim", key, var.get())
