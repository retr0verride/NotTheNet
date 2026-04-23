"""
NotTheNet - Preflight Check
Read-only audit of stealth readiness before detonation.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config import Config

logger = logging.getLogger(__name__)

# ── Result types ──────────────────────────────────────────────────────────

OK = "ok"
WARN = "warn"
FAIL = "fail"
INFO = "info"


@dataclass
class CheckResult:
    status: str  # OK | WARN | FAIL | INFO
    message: str
    fixable: bool = False
    fix_key: str = ""  # key for the fix dispatcher


@dataclass
class PreflightReport:
    stealth: list[CheckResult] = field(default_factory=list)
    certs: list[CheckResult] = field(default_factory=list)
    network: list[CheckResult] = field(default_factory=list)
    ports: list[CheckResult] = field(default_factory=list)
    hardening: list[CheckResult] = field(default_factory=list)

    @property
    def failures(self) -> list[CheckResult]:
        all_checks = self.stealth + self.certs + self.network + self.ports + self.hardening
        return [c for c in all_checks if c.status == FAIL]

    @property
    def warnings(self) -> list[CheckResult]:
        all_checks = self.stealth + self.certs + self.network + self.ports + self.hardening
        return [c for c in all_checks if c.status == WARN]

    @property
    def fixable_items(self) -> list[CheckResult]:
        all_checks = self.stealth + self.certs + self.network + self.ports + self.hardening
        return [c for c in all_checks if c.fixable]


# ── Individual checks ─────────────────────────────────────────────────────

def _check_stealth_config(cfg: Config) -> list[CheckResult]:
    results = []

    # tcp_fingerprint
    fp_os = cfg.get("general", "tcp_fingerprint_os") or "windows"
    results.append(
        CheckResult(OK, f"tcp_fingerprint: enabled (os={fp_os})")
        if cfg.get("general", "tcp_fingerprint")
        else CheckResult(WARN, "tcp_fingerprint: disabled — OS detection may reveal Linux")
    )

    # spoof_public_ip
    spoof_ip = str(cfg.get("general", "spoof_public_ip") or "").strip()
    results.append(
        _check_spoof_ip(spoof_ip) if spoof_ip
        else CheckResult(WARN, "spoof_public_ip: not set — IP-check services will return HTML")
    )

    # dynamic_certs
    results.append(_bool_check(
        cfg.get("https", "dynamic_certs"),
        "dynamic_certs: enabled",
        "dynamic_certs: disabled — TLS SNI won't match requested domains",
    ))

    # dynamic_responses
    results.append(_bool_check(
        cfg.get("http", "dynamic_responses"),
        "dynamic_responses: enabled (HTTP)",
        "dynamic_responses: disabled (HTTP) — PE/ELF stubs won't be served",
    ))
    results.append(_bool_check(
        cfg.get("https", "dynamic_responses"),
        "dynamic_responses: enabled (HTTPS)",
        "dynamic_responses: disabled (HTTPS)",
    ))

    # process_masquerade
    results.append(_bool_check(
        cfg.get("general", "process_masquerade"),
        "process_masquerade: enabled",
        "process_masquerade: disabled",
    ))

    # drop_privileges
    results.append(_bool_check(
        cfg.get("general", "drop_privileges"),
        "drop_privileges: enabled",
        "drop_privileges: disabled",
    ))

    # response delay
    results.append(_check_response_delay(cfg.get("http", "response_delay_ms")))

    # public_response_ips
    pool = cfg.get("dns", "public_response_ips") or []
    results.append(
        CheckResult(OK, f"public_response_ips: {len(pool)} IPs configured") if pool
        else CheckResult(INFO, "public_response_ips: empty — all DNS resolves to redirect_ip")
    )

    # kill_switch_domains
    ksd = cfg.get("dns", "kill_switch_domains") or []
    if ksd:
        results.append(CheckResult(OK, f"kill_switch_domains: {len(ksd)} domains"))

    return results


def _check_certs() -> list[CheckResult]:
    results = []

    ca_crt = "certs/ca.crt"
    ca_key = "certs/ca.key"
    server_crt = "certs/server.crt"

    if os.path.exists(ca_crt):
        try:
            import hashlib

            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding
            with open(ca_crt, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            expiry = cert.not_valid_after_utc
            fp = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()[:16].upper()
            results.append(CheckResult(
                OK, f"Root CA: certs/ca.crt (expires {expiry:%Y-%m-%d}, SHA256:{fp})"
            ))
        except Exception as e:
            results.append(CheckResult(OK, f"Root CA: certs/ca.crt exists (parse error: {e})"))
    else:
        results.append(CheckResult(WARN,
            "Root CA: certs/ca.crt not found — will be generated on first HTTPS start"))

    if os.path.exists(ca_key):
        results.append(CheckResult(OK, "Root CA key: certs/ca.key exists"))
    elif os.path.exists(ca_crt):
        results.append(CheckResult(FAIL, "Root CA key: certs/ca.key missing (ca.crt exists but key is gone)"))

    if os.path.exists(server_crt):
        results.append(CheckResult(OK, "Server cert: certs/server.crt exists"))
    else:
        results.append(CheckResult(INFO, "Server cert: will be auto-generated on start"))

    return results


# ── Check helpers (extracted to keep parent-function CC ≤ 15) ─────────────

def _check_spoof_ip(spoof_ip: str) -> CheckResult:
    """Validate and categorise a non-empty spoof_public_ip value."""
    try:
        addr = ipaddress.ip_address(spoof_ip)
        if addr.is_private:
            return CheckResult(WARN, f"spoof_public_ip: {spoof_ip} is RFC-1918 private")
        return CheckResult(OK, f"spoof_public_ip: {spoof_ip} (public)")
    except ValueError:
        return CheckResult(FAIL, f"spoof_public_ip: invalid IP {spoof_ip!r}")


def _bool_check(value: object, ok_msg: str, warn_msg: str) -> CheckResult:
    """Return OK if *value* is truthy, WARN otherwise."""
    return CheckResult(OK, ok_msg) if value else CheckResult(WARN, warn_msg)


def _check_response_delay(delay: object) -> CheckResult:
    """Return a check result for the http.response_delay_ms config value."""
    try:
        d = int(delay or 0)  # type: ignore[arg-type]
        if 50 <= d <= 500:
            return CheckResult(OK, f"response_delay_ms: {d} (realistic)")
        if d == 0:
            return CheckResult(
                WARN,
                "response_delay_ms: 0 — instant responses may trigger sandbox detection",
            )
        return CheckResult(OK, f"response_delay_ms: {d}")
    except (TypeError, ValueError):
        return CheckResult(WARN, f"response_delay_ms: invalid value {delay!r}")


def _check_interface_status(interface: str, bind_ip: str) -> list[CheckResult]:
    """Check whether *interface* exists, is UP, and carries *bind_ip*."""
    results: list[CheckResult] = []
    try:
        out = subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if out.returncode == 0:
            up = "state UP" in out.stdout
            results.append(CheckResult(
                OK if up else WARN,
                f"Interface {interface}: {'UP' if up else 'DOWN'}",
            ))
        else:
            results.append(CheckResult(FAIL, f"Interface {interface}: not found"))
    except Exception as e:
        results.append(CheckResult(FAIL, f"Interface check failed: {e}"))

    if bind_ip != "0.0.0.0":
        try:
            out = subprocess.run(
                ["ip", "addr", "show", interface],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if bind_ip in out.stdout:
                results.append(CheckResult(OK, f"bind_ip {bind_ip} assigned to {interface}"))
            else:
                results.append(CheckResult(FAIL, f"bind_ip {bind_ip} NOT found on {interface}"))
        except Exception as e:
            results.append(CheckResult(FAIL, f"bind_ip check failed: {e}"))

    return results


def _check_remote_tools() -> list[CheckResult]:
    """Check availability of impacket-wmiexec and smbclient."""
    results: list[CheckResult] = []
    wmiexec = shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py")
    if wmiexec:
        results.append(CheckResult(OK, f"impacket-wmiexec: {wmiexec}"))
    else:
        results.append(CheckResult(WARN, "impacket-wmiexec: not found (apt install python3-impacket)"))
    if shutil.which("smbclient"):
        results.append(CheckResult(OK, "smbclient: available"))
    else:
        results.append(CheckResult(
            WARN, "smbclient: not found (apt install smbclient) — needed to push CA cert"
        ))
    return results


def _check_ip_forward() -> list[CheckResult]:
    """Check /proc/sys/net/ipv4/ip_forward; WARN if enabled (sinkhole needs it off)."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", encoding="ascii") as f:
            val = f.read().strip()
        if val == "1":
            return [CheckResult(
                WARN,
                "ip_forward: enabled — NTN does not require it; "
                "disable with: echo 0 > /proc/sys/net/ipv4/ip_forward",
            )]
        return [CheckResult(OK, "ip_forward: disabled (correct for sinkhole mode)")]
    except OSError:
        return [CheckResult(INFO, "ip_forward: could not read")]


def _probe_port(bind_ip: str, port: int, proto: str) -> bool:
    """Return True if *port*/*proto* on *bind_ip* is already in use."""
    sock_type = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    s: socket.socket | None = None
    try:
        s = socket.socket(socket.AF_INET, sock_type)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(2.0)
        s.bind((bind_ip, port))
        return False
    except OSError:
        return True
    finally:
        if s:
            s.close()


def _check_network(cfg: Config) -> list[CheckResult]:
    results = []

    if os.name == "nt":
        results.append(CheckResult(INFO, "Network checks skipped (Windows dev host)"))
        return results

    interface = cfg.get("general", "interface") or ""
    bind_ip = cfg.get("general", "bind_ip") or "0.0.0.0"

    if interface:
        results.extend(_check_interface_status(interface, bind_ip))

    # iptables available
    if shutil.which("iptables"):
        results.append(CheckResult(OK, "iptables: available"))
    else:
        results.append(CheckResult(FAIL, "iptables: not found in PATH"))

    results.extend(_check_remote_tools())
    results.extend(_check_ip_forward())

    return results


def _check_port_conflicts(cfg: Config) -> list[CheckResult]:
    results = []
    bind_ip = cfg.get("general", "bind_ip") or "0.0.0.0"

    # Collect enabled service ports
    services = [
        ("dns", "tcp"), ("dns", "udp"), ("http", "tcp"), ("https", "tcp"),
        ("smtp", "tcp"), ("smtps", "tcp"), ("pop3", "tcp"), ("pop3s", "tcp"),
        ("imap", "tcp"), ("imaps", "tcp"), ("ftp", "tcp"),
        ("ntp", "udp"), ("irc", "tcp"), ("tftp", "udp"), ("telnet", "tcp"),
        ("socks5", "tcp"), ("ircs", "tcp"), ("mysql", "tcp"), ("mssql", "tcp"),
        ("rdp", "tcp"), ("smb", "tcp"), ("vnc", "tcp"), ("redis", "tcp"),
        ("ldap", "tcp"), ("dot", "tcp"),
    ]

    conflicts = []
    checked = 0
    for section, proto in services:
        if not cfg.get(section, "enabled"):
            continue
        port = cfg.get(section, "port")
        if not port:
            continue
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        checked += 1
        if _probe_port(bind_ip, port, proto):
            conflicts.append(f":{port}/{proto} ({section})")

    if conflicts:
        for c in conflicts:
            results.append(CheckResult(FAIL, f"Port conflict: {c} in use"))
    else:
        results.append(CheckResult(OK, f"All {checked} enabled service ports available"))

    return results


def _check_hardening() -> list[CheckResult]:
    results = []

    if os.name == "nt":
        results.append(CheckResult(INFO, "Hardening checks skipped (Windows dev host)"))
        return results

    # Check FORWARD DROP rules
    try:
        out = subprocess.run(
            ["iptables", "-L", "FORWARD", "-n"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if "NOTTHENET_HARDEN" in out.stdout or "DROP" in out.stdout:
            results.append(CheckResult(OK, "FORWARD DROP rules: active"))
        else:
            results.append(CheckResult(INFO,
                "FORWARD DROP rules: not found (auto-applied on service start)"))
    except Exception:
        results.append(CheckResult(WARN, "Could not check FORWARD rules (need root?)"))

    # Check tmpfs on logs/
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            mounts = f.read()
        logs_abs = os.path.abspath("logs")
        if logs_abs in mounts and "tmpfs" in mounts:
            results.append(CheckResult(OK, "logs/ mounted as tmpfs"))
        else:
            results.append(CheckResult(INFO, "logs/ not on tmpfs (optional, recommended by harden-lab.sh)"))
    except OSError:
        pass

    return results


# ── Main entry point ──────────────────────────────────────────────────────

def run_preflight(cfg: Config) -> PreflightReport:
    """Execute all local preflight checks and return a structured report."""
    report = PreflightReport()
    report.stealth = _check_stealth_config(cfg)
    report.certs = _check_certs()
    report.network = _check_network(cfg)
    report.ports = _check_port_conflicts(cfg)
    report.hardening = _check_hardening()
    return report


def format_report(report: PreflightReport) -> str:
    """Format a preflight report as colored terminal output."""
    _ICONS = {OK: "\u2714", WARN: "\u26a0", FAIL: "\u2718", INFO: "\u2139"}
    lines = [
        "",
        "NotTheNet Preflight Check",
        "\u2550" * 26,
        "",
    ]

    sections = [
        ("Config Stealth", report.stealth),
        ("Certificates", report.certs),
        ("Network", report.network),
        ("Port Conflicts", report.ports),
        ("Lab Hardening", report.hardening),
    ]

    for title, checks in sections:
        if not checks:
            continue
        lines.append(title)
        for c in checks:
            icon = _ICONS.get(c.status, "?")
            lines.append(f"  {icon} {c.message}")
        lines.append("")

    failures = report.failures
    warnings = report.warnings
    if failures or warnings:
        lines.append(f"Result: {len(failures)} FAILURE(S), {len(warnings)} WARNING(S)")
        for f in failures:
            lines.append(f"  \u2718 {f.message}")
        for w in warnings:
            lines.append(f"  \u26a0 {w.message}")
    else:
        lines.append("Result: ALL CHECKS PASSED")

    return "\n".join(lines)
