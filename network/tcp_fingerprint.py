"""
NotTheNet - TCP/IP OS Fingerprint Spoofing

Modern malware can detect that it's running in a Linux-based sandbox by
examining the TCP/IP characteristics of responses from simulated servers:
  - IP TTL:  Windows defaults to 128, Linux to 64
  - TCP Window Size:  Windows typically uses 65535, Linux ~29200
  - Don't Fragment (DF) bit behaviour
  - TCP options ordering and values

When a Windows-targeted piece of malware connects to what it expects to be
a Windows IIS server but receives responses with Linux-style TTL=64 and
window_size=29200, it can infer it's inside a sandbox.

This module patches socket defaults on the listening sockets of NotTheNet's
simulated services so that responses appear to originate from the chosen OS.

Limitations:
  - Full p0f-level fingerprint accuracy requires kernel-level nfqueue
    manipulation (not feasible in a lightweight Python tool).
  - This module covers the most commonly checked fields: TTL, window size,
    and DF bit — which is sufficient to defeat the majority of evasion checks.
  - Works on Linux only (the setsockopt constants are Linux-specific).

Security notes (OpenSSF):
  - No raw sockets required (uses standard setsockopt)
  - No privilege escalation beyond what NotTheNet already requires (root)
  - Profiles are static dicts — no eval/exec
"""

from __future__ import annotations

import logging
import platform
import socket

logger = logging.getLogger(__name__)

# ─── OS Fingerprint Profiles ─────────────────────────────────────────────────
# Each profile defines the socket options that shape TCP/IP stack behaviour.
#
# Fields:
#   ttl          - IP Time-To-Live (hops). Windows=128, Linux=64, macOS=64.
#   window_size  - TCP window size clamp. Windows=65535, Linux=29200.
#   df           - Don't Fragment bit. True sets IP_PMTUDISC_DO.
#   mss          - TCP Maximum Segment Size (optional, applied via TCP_MAXSEG).
#   description  - Human-readable label for the GUI/logs.

OS_PROFILES: dict[str, dict] = {
    "windows": {
        "ttl": 128,
        "window_size": 65535,
        "df": True,
        "mss": 1460,
        "description": "Windows Server 2019 / Windows 10+",
    },
    "linux": {
        "ttl": 64,
        "window_size": 29200,
        "df": True,
        "mss": 1460,
        "description": "Linux 5.x+ (default kernel settings)",
    },
    "macos": {
        "ttl": 64,
        "window_size": 65535,
        "df": True,
        "mss": 1460,
        "description": "macOS 13+ / BSD",
    },
    "solaris": {
        "ttl": 255,
        "window_size": 49640,
        "df": False,
        "mss": 1460,
        "description": "Solaris 10+",
    },
}

# Linux-specific socket constants (may not be in the socket module on all
# Python builds, so define them as fallbacks).
_IP_TTL = getattr(socket, "IP_TTL", 2)
_TCP_WINDOW_CLAMP = getattr(socket, "TCP_WINDOW_CLAMP", 10)
_TCP_MAXSEG = getattr(socket, "TCP_MAXSEG", 2)
_IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
_IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)
_IP_PMTUDISC_DONT = getattr(socket, "IP_PMTUDISC_DONT", 0)


def apply_os_fingerprint(
    sock: socket.socket,
    profile_name: str = "windows",
) -> bool:
    """
    Apply TCP/IP OS fingerprint settings to a socket.

    Call this on the **listening socket** before accept() — child sockets
    inherit the parent's TTL and window settings.

    Args:
        sock:          The socket to modify (usually the server's listening socket).
        profile_name:  Key into OS_PROFILES ("windows", "linux", "macos", "solaris").

    Returns:
        True if all options were applied successfully, False otherwise.
    """
    if platform.system() != "Linux":
        logger.warning(
            "TCP/IP fingerprint spoofing requires Linux; skipping on %s.",
            platform.system(),
        )
        return False

    profile = OS_PROFILES.get(profile_name.lower())
    if not profile:
        logger.warning(
            "Unknown OS fingerprint profile '%s'; available: %s",
            profile_name,
            ", ".join(OS_PROFILES.keys()),
        )
        return False

    logger.info(
        "Applying TCP/IP fingerprint: %s (%s)",
        profile_name,
        profile["description"],
    )

    ok = True

    # 1. IP TTL
    try:
        sock.setsockopt(socket.IPPROTO_IP, _IP_TTL, profile["ttl"])
        logger.debug("  TTL set to %d", profile["ttl"])
    except OSError as e:
        logger.warning("  Failed to set TTL: %s", e)
        ok = False

    # 2. TCP Window Size clamp
    try:
        sock.setsockopt(socket.IPPROTO_TCP, _TCP_WINDOW_CLAMP, profile["window_size"])
        logger.debug("  TCP window clamp set to %d", profile["window_size"])
    except OSError as e:
        logger.warning("  Failed to set TCP_WINDOW_CLAMP: %s", e)
        ok = False

    # 3. Don't Fragment bit
    try:
        df_val = _IP_PMTUDISC_DO if profile["df"] else _IP_PMTUDISC_DONT
        sock.setsockopt(socket.IPPROTO_IP, _IP_MTU_DISCOVER, df_val)
        logger.debug("  DF bit set to %s", "DO" if profile["df"] else "DONT")
    except OSError as e:
        logger.warning("  Failed to set DF bit: %s", e)
        ok = False

    # 4. TCP MSS (before listen/connect)
    if profile.get("mss"):
        try:
            sock.setsockopt(socket.IPPROTO_TCP, _TCP_MAXSEG, profile["mss"])
            logger.debug("  TCP MSS set to %d", profile["mss"])
        except OSError as e:
            # TCP_MAXSEG often fails on listening sockets — non-critical
            logger.debug("  TCP_MAXSEG not applied (common on listen sockets): %s", e)

    return ok


def get_profile_names() -> list[str]:
    """Return sorted list of available OS fingerprint profile names."""
    return sorted(OS_PROFILES.keys())


def get_profile_description(name: str) -> str:
    """Return human-readable description for a profile, or empty string."""
    p = OS_PROFILES.get(name.lower(), {})
    return p.get("description", "")
