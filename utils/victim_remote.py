"""
NotTheNet - Victim Remote Utilities
ARP-based victim detection and remote setup via WMI/SMB (Impacket).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config import Config

logger = logging.getLogger(__name__)

_CMD_TIMEOUT = 30


def _validate_ip(ip_str: str) -> str:
    """Validate and return a normalised IPv4 address string."""
    return str(ipaddress.ip_address(ip_str))


# ── ARP-based victim detection ────────────────────────────────────────────


@dataclass
class DetectedHost:
    ip: str
    mac: str


def _parse_ip_neigh_output(output: str, bind_ip: str) -> list[DetectedHost]:
    """Parse `ip neigh` output into DetectedHost entries.

    Handles both common formats:
    - "10.10.10.10 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    - "10.10.10.10 dev eth1 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    """
    hosts: list[DetectedHost] = []

    for line in output.strip().splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue

        ip = parts[0]
        if ip == bind_ip:
            continue

        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version != 4:
                continue
        except ValueError:
            continue

        if "lladdr" not in parts:
            continue

        lladdr_idx = parts.index("lladdr")
        if lladdr_idx + 1 >= len(parts):
            continue

        mac = parts[lladdr_idx + 1]
        hosts.append(DetectedHost(ip=ip, mac=mac))

    return hosts


def detect_victims(cfg: Config) -> list[DetectedHost]:
    """Find non-gateway hosts on the lab bridge via ARP cache.

    Returns a list of DetectedHost (IP + MAC) for every host on the
    configured interface that is NOT the bind_ip.
    """
    if os.name == "nt":
        return []

    interface = cfg.get("general", "interface") or ""
    bind_ip = cfg.get("general", "bind_ip") or "0.0.0.0"

    if not interface:
        return []

    # Try ip neigh first
    try:
        out = subprocess.run(
            ["ip", "neigh", "show", "dev", interface],
            capture_output=True, text=True, timeout=5,
        )
        hosts = _parse_ip_neigh_output(out.stdout, bind_ip)
    except Exception as e:
        logger.debug("ip neigh failed: %s", e)
        hosts = []

    return hosts


def arp_scan(cfg: Config) -> list[DetectedHost]:
    """Active ARP sweep of the lab subnet to discover victims.

    Falls back to detect_victims() (passive ARP cache) if nmap/arping
    are not available.
    """
    if os.name == "nt":
        return []

    interface = cfg.get("general", "interface") or ""
    bind_ip = cfg.get("general", "bind_ip") or "0.0.0.0"
    mask = cfg.get("victim", "subnet_mask") or 24

    if not interface or bind_ip == "0.0.0.0":
        return detect_victims(cfg)

    subnet = f"{bind_ip}/{mask}"

    # Try nmap ARP scan (fast, reliable)
    if shutil.which("nmap"):
        try:
            out = subprocess.run(
                ["nmap", "-sn", "-PR", "--interface", interface, subnet],
                capture_output=True, text=True, timeout=15,
            )
            # Parse nmap output for IPs
            hosts: list[DetectedHost] = []
            for match in re.finditer(r"Nmap scan report for (\S+)", out.stdout):
                ip = match.group(1)
                if ip != bind_ip:
                    hosts.append(DetectedHost(ip=ip, mac=""))
            if hosts:
                return hosts
        except Exception as e:
            logger.debug("nmap ARP scan failed: %s", e)

    # Fallback: arping individual IPs (slow but no dependencies)
    if shutil.which("arping"):
        try:
            # Quick ping to the broadcast to populate ARP cache
            subprocess.run(
                ["arping", "-c", "1", "-I", interface, "-b", bind_ip],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as e:
            logger.debug("arping failed: %s", e)

    # Always fall back to reading the ARP cache
    return detect_victims(cfg)


# ── WMI / SMB helpers (Impacket) ─────────────────────────────────────────


def _find_wmiexec() -> str | None:
    """Locate the impacket-wmiexec binary (Kali may use either name)."""
    for name in ("impacket-wmiexec", "wmiexec.py"):
        if shutil.which(name):
            return name
    return None


def _has_impacket() -> bool:
    return _find_wmiexec() is not None


def _has_smbclient() -> bool:
    return shutil.which("smbclient") is not None


def _wmi_cmd(ip: str, user: str, password: str, cmd: str,
             timeout: int = _CMD_TIMEOUT) -> subprocess.CompletedProcess:
    """Execute a single command on the remote host via WMI (Impacket)."""
    wmiexec = _find_wmiexec()
    if not wmiexec:
        raise RuntimeError(
            "impacket-wmiexec not found. Install: apt install python3-impacket"
        )

    ip = _validate_ip(ip)

    result = subprocess.run(
        [wmiexec, f"{user}:{password}@{ip}", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    # Strip Impacket banner / info lines so callers see only command output
    lines = result.stdout.split("\n")
    cleaned_lines = [
        line for line in lines
        if not line.startswith("Impacket v")
        and not line.startswith("[*]")
        and not line.startswith("[+]")
    ]
    cleaned = "\n".join(cleaned_lines).strip()
    return subprocess.CompletedProcess(
        result.args, result.returncode,
        stdout=cleaned + "\n" if cleaned else "",
        stderr=result.stderr,
    )


def _smb_upload(ip: str, user: str, password: str,
                local_path: str, remote_path: str,
                timeout: int = _CMD_TIMEOUT) -> subprocess.CompletedProcess:
    """Upload a file to the remote host via SMB (smbclient)."""
    remote_path = remote_path.replace("/", "\\").strip()
    if len(remote_path) < 3 or remote_path[1] != ":":
        raise ValueError(f"Invalid remote path (expected C:\\...): {remote_path!r}")

    ip = _validate_ip(ip)
    drive = remote_path[0].upper()
    rel = remote_path[2:].lstrip("\\")
    return subprocess.run(
        [
            "smbclient", f"//{ip}/{drive}$",
            "-U", f"{user}%{password}",
            '-c', f'put "{local_path}" "{rel}"',
        ],
        capture_output=True, text=True, timeout=timeout,
    )


# ── Remote check/fix actions ─────────────────────────────────────────────

@dataclass
class RemoteCheckResult:
    status: str  # "ok" | "warn" | "fail"
    message: str
    fixable: bool = False
    fix_key: str = ""


def check_wmi_connectivity(ip: str, user: str, password: str) -> RemoteCheckResult:
    """Test WMI connection to the victim."""
    if not _has_impacket():
        return RemoteCheckResult("fail", "impacket not installed on Kali (apt install python3-impacket)")
    try:
        r = _wmi_cmd(ip, user, password, "echo NTN_OK")
        if "NTN_OK" in r.stdout:
            return RemoteCheckResult("ok", "WMI connection OK")
        if r.returncode != 0:
            err = r.stderr.strip()[:200]
            if "access_denied" in err.lower() or "logon_failure" in err.lower():
                return RemoteCheckResult("fail", "Authentication failed (wrong credentials?)")
            return RemoteCheckResult("fail", f"WMI connection failed: {err}")
        return RemoteCheckResult("fail", f"WMI unexpected output: {r.stdout.strip()[:120]}")
    except subprocess.TimeoutExpired:
        return RemoteCheckResult("fail", f"WMI connection timed out ({ip})")
    except Exception as e:
        return RemoteCheckResult("fail", f"WMI error: {e}")


def check_victim_ca_cert(ip: str, user: str, password: str) -> RemoteCheckResult:
    """Check if the NTN Root CA is installed in the victim's trust store."""
    try:
        r = _wmi_cmd(ip, user, password,
                     'powershell -c "certutil -store Root | Select-String NotTheNet"')
        if "notthenet" in r.stdout.lower():
            return RemoteCheckResult("ok", "Root CA installed in victim trust store")
        return RemoteCheckResult("fail", "Root CA NOT installed on victim",
                                 fixable=True, fix_key="install_ca")
    except Exception as e:
        return RemoteCheckResult("fail", f"CA check failed: {e}")


def check_victim_dns(ip: str, user: str, password: str,
                     expected_dns: str) -> RemoteCheckResult:
    """Check if the victim's DNS points to NTN."""
    try:
        dns_ps = (
            'powershell -c "(Get-DnsClientServerAddress'
            ' -InterfaceAlias Ethernet -AddressFamily IPv4).ServerAddresses"'
        )
        r = _wmi_cmd(ip, user, password, dns_ps)
        if expected_dns in r.stdout:
            return RemoteCheckResult("ok", f"DNS: {expected_dns}")
        # Try all interfaces if Ethernet didn't match
        r2 = _wmi_cmd(ip, user, password,
                      'powershell -c "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses"')
        if expected_dns in r2.stdout:
            return RemoteCheckResult("ok", f"DNS: {expected_dns} (non-Ethernet interface)")
        dns_found = r.stdout.strip() or r2.stdout.strip() or "(could not read)"
        return RemoteCheckResult("fail", f"DNS not pointing to NTN (found: {dns_found})",
                                 fixable=True, fix_key="set_dns")
    except Exception as e:
        return RemoteCheckResult("fail", f"DNS check failed: {e}")


def check_victim_connectivity(ip: str, user: str, password: str,
                              gateway: str) -> RemoteCheckResult:
    """Check basic connectivity from victim to NTN gateway."""
    try:
        r = _wmi_cmd(ip, user, password, f"ping -n 1 -w 2000 {gateway}")
        if "TTL=" in r.stdout:
            return RemoteCheckResult("ok", f"Ping {gateway}: OK")
        return RemoteCheckResult("fail", f"Ping {gateway}: no reply")
    except Exception as e:
        return RemoteCheckResult("fail", f"Ping check failed: {e}")


def run_remote_checks(ip: str, user: str, password: str,
                      cfg: Config) -> list[RemoteCheckResult]:
    """Run all remote victim checks sequentially."""
    results: list[RemoteCheckResult] = []
    bind_ip = cfg.get("general", "bind_ip") or "10.10.10.1"

    # WMI connectivity (must pass before other checks)
    wmi_result = check_wmi_connectivity(ip, user, password)
    results.append(wmi_result)
    if wmi_result.status != "ok":
        return results

    results.append(check_victim_ca_cert(ip, user, password))
    results.append(check_victim_dns(ip, user, password, bind_ip))
    results.append(check_victim_connectivity(ip, user, password, bind_ip))
    return results


# ── Fix actions ───────────────────────────────────────────────────────────

def fix_install_ca(ip: str, user: str, password: str) -> RemoteCheckResult:
    """Push NTN Root CA to victim and install it in the Windows trust store."""
    ca_path = "certs/ca.crt"
    if not os.path.exists(ca_path):
        return RemoteCheckResult("fail", "certs/ca.crt not found locally")
    if not _has_smbclient():
        return RemoteCheckResult("fail", "smbclient not installed on Kali (apt install smbclient)")

    try:
        # Create temp dir on victim
        _wmi_cmd(ip, user, password, 'if not exist C:\\temp mkdir C:\\temp')

        # Upload the cert via SMB
        r = _smb_upload(ip, user, password,
                        os.path.abspath(ca_path), "C:\\temp\\notthenet-ca.crt")
        if r.returncode != 0:
            return RemoteCheckResult("fail", f"SMB upload failed: {r.stderr.strip()[:120]}")

        # Install cert
        r = _wmi_cmd(ip, user, password,
                     'certutil -addstore Root C:\\temp\\notthenet-ca.crt',
                     timeout=30)
        out_lower = r.stdout.lower()
        if any(s in out_lower for s in (
            "command completed successfully",
            "certificate added to store",
            "already in store",
        )):
            return RemoteCheckResult("ok", "Root CA installed successfully")
        return RemoteCheckResult("fail", f"certutil failed: {r.stdout.strip()[:120]} {r.stderr.strip()[:120]}")
    except Exception as e:
        return RemoteCheckResult("fail", f"CA install failed: {e}")


def fix_set_dns(ip: str, user: str, password: str,
                dns_ip: str) -> RemoteCheckResult:
    """Set the victim's DNS server to NTN's bind_ip."""
    try:
        # Try Ethernet first, then fall back to all interfaces
        cmd = (
            f'powershell -c "'
            f"$iface = (Get-NetAdapter | Where-Object Status -eq Up | Select-Object -First 1).Name; "
            f"Set-DnsClientServerAddress -InterfaceAlias $iface -ServerAddresses {dns_ip}"
            f'"'
        )
        r = _wmi_cmd(ip, user, password, cmd)
        if r.returncode == 0:
            return RemoteCheckResult("ok", f"DNS set to {dns_ip}")
        return RemoteCheckResult("fail", f"DNS set failed: {r.stderr.strip()[:120]}")
    except Exception as e:
        return RemoteCheckResult("fail", f"DNS fix failed: {e}")


def fix_set_gateway(ip: str, user: str, password: str,
                    gateway_ip: str) -> RemoteCheckResult:
    """Set the victim's default gateway to NTN's bind_ip."""
    try:
        cmd = (
            f'powershell -c "'
            f"Remove-NetRoute -DestinationPrefix 0.0.0.0/0 -Confirm:$false -ErrorAction SilentlyContinue; "
            f"$iface = (Get-NetAdapter | Where-Object Status -eq Up | Select-Object -First 1).Name; "
            f"New-NetRoute -DestinationPrefix 0.0.0.0/0 -NextHop {gateway_ip} -InterfaceAlias $iface"
            f'"'
        )
        r = _wmi_cmd(ip, user, password, cmd)
        if r.returncode == 0:
            return RemoteCheckResult("ok", f"Gateway set to {gateway_ip}")
        return RemoteCheckResult("fail", f"Gateway set failed: {r.stderr.strip()[:120]}")
    except Exception as e:
        return RemoteCheckResult("fail", f"Gateway fix failed: {e}")


def push_prepare_script(ip: str, user: str, password: str) -> RemoteCheckResult:
    """Push and run the latest prepare-victim.ps1 on the victim via SMB + WMI."""
    script_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "assets", "prepare-victim.ps1",
    )
    if not os.path.exists(script_path):
        return RemoteCheckResult("fail", "assets/prepare-victim.ps1 not found locally")
    if not _has_smbclient():
        return RemoteCheckResult("fail", "smbclient not installed (apt install smbclient)")

    try:
        _wmi_cmd(ip, user, password, "if not exist C:\\temp mkdir C:\\temp")
        r = _smb_upload(ip, user, password, os.path.abspath(script_path),
                        "C:\\temp\\prepare-victim.ps1")
        if r.returncode != 0:
            return RemoteCheckResult("fail", f"SMB upload failed: {r.stderr.strip()[:120]}")
        r = _wmi_cmd(ip, user, password,
                     "powershell -ExecutionPolicy Bypass -File C:\\temp\\prepare-victim.ps1",
                     timeout=60)
        if r.returncode == 0:
            return RemoteCheckResult("ok", "prepare-victim.ps1 pushed and executed successfully")
        return RemoteCheckResult("fail", f"Script execution failed: {r.stdout.strip()[:120]}")
    except Exception as e:
        return RemoteCheckResult("fail", f"push_prepare_script failed: {e}")


def run_fixes(ip: str, user: str, password: str, cfg: Config,
              fix_keys: list[str]) -> list[RemoteCheckResult]:
    """Execute a list of fix actions on the victim."""
    bind_ip = cfg.get("general", "bind_ip") or "10.10.10.1"
    results: list[RemoteCheckResult] = []

    dispatch = {
        "install_ca": lambda: fix_install_ca(ip, user, password),
        "set_dns": lambda: fix_set_dns(ip, user, password, bind_ip),
        "set_gateway": lambda: fix_set_gateway(ip, user, password, bind_ip),
        "push_prepare": lambda: push_prepare_script(ip, user, password),
    }

    for key in fix_keys:
        fn = dispatch.get(key)
        if fn:
            results.append(fn())
        else:
            results.append(RemoteCheckResult("fail", f"Unknown fix action: {key}"))

    return results
