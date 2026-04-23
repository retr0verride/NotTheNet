"""
NotTheNet - Victim Remote Utilities
ARP-based victim detection helpers.
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
            capture_output=True, text=True, timeout=5, check=False,
        )
        hosts = _parse_ip_neigh_output(out.stdout, bind_ip)
    except Exception as e:  # noqa: BLE001
        logger.debug("ip neigh failed: %s", e)
        hosts = []

    return hosts


def _scan_with_nmap(interface: str, bind_ip: str, subnet: str) -> list[DetectedHost]:
    """Run an nmap ARP sweep and return discovered hosts (empty on failure)."""
    try:
        out = subprocess.run(
            ["nmap", "-sn", "-PR", "--interface", interface, subnet],
            capture_output=True, text=True, timeout=15, check=False,
        )
        hosts: list[DetectedHost] = []
        for match in re.finditer(r"Nmap scan report for (\S+)", out.stdout):
            ip = match.group(1)
            if ip != bind_ip:
                hosts.append(DetectedHost(ip=ip, mac=""))
        return hosts
    except Exception as e:  # noqa: BLE001
        logger.debug("nmap ARP scan failed: %s", e)
        return []


def _prime_arp_cache_with_arping(interface: str, bind_ip: str) -> None:
    """Broadcast a single arping to populate the kernel ARP cache."""
    try:
        subprocess.run(
            ["arping", "-c", "1", "-I", interface, "-b", bind_ip],
            capture_output=True, timeout=5, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.debug("arping failed: %s", e)


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

    if shutil.which("nmap"):
        hosts = _scan_with_nmap(interface, bind_ip, subnet)
        if hosts:
            return hosts

    if shutil.which("arping"):
        _prime_arp_cache_with_arping(interface, bind_ip)

    return detect_victims(cfg)
