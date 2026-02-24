"""
NotTheNet - Input Validation Utilities
Centralized validation for all externally-sourced values.

Design principle: validate at the boundary — never trust input from
the network, config files, or environment variables without checking.
"""

import ipaddress
import os
import re
from typing import Optional

# RFC 1123 hostname pattern
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

# Ports usable without root when auto_iptables is active
PRIVILEGED_PORT_THRESHOLD = 1024
MAX_PORT = 65535


def validate_ip(ip: str) -> tuple[bool, Optional[str]]:
    """Return (True, normalized_ip) or (False, error_message)."""
    try:
        normalized = str(ipaddress.ip_address(ip))
        return True, normalized
    except ValueError:
        return False, f"Invalid IP address: {ip!r}"


def validate_port(port) -> tuple[bool, Optional[int]]:
    """Return (True, int_port) or (False, None)."""
    try:
        p = int(port)
        if 1 <= p <= MAX_PORT:
            return True, p
        return False, None
    except (TypeError, ValueError):
        return False, None


def validate_hostname(hostname: str) -> bool:
    """Return True if hostname matches RFC 1123."""
    if not hostname or len(hostname) > 253:
        return False
    # Strip trailing dot (FQDN)
    h = hostname.rstrip(".")
    return bool(_HOSTNAME_RE.match(h))


def validate_bind_ip(ip: str) -> tuple[bool, Optional[str]]:
    """
    Validate an IP address suitable for binding.
    Allows '0.0.0.0', '::' (wildcard), and valid unicast addresses.
    """
    if ip in ("0.0.0.0", "::"):
        return True, ip
    return validate_ip(ip)


def sanitize_path(base_dir: str, user_path: str) -> Optional[str]:
    """
    Resolve user_path relative to base_dir and reject path traversal attempts.
    Returns the resolved absolute path or None if traversal detected.
    """
    base = os.path.realpath(base_dir)
    candidate = os.path.realpath(os.path.join(base_dir, user_path))
    if not candidate.startswith(base + os.sep) and candidate != base:
        return None  # Path traversal attempt
    return candidate


def validate_http_method(method: str) -> bool:
    """Allowlist HTTP methods."""
    return method.upper() in {
        "GET", "HEAD", "POST", "PUT", "DELETE",
        "PATCH", "OPTIONS", "TRACE", "CONNECT",
    }


def validate_config(config_data: dict) -> list:
    """
    Validate a full configuration dict.
    Returns a list of error strings (empty list = valid).
    """
    errors = []

    general = config_data.get("general", {})
    ok, _ = validate_bind_ip(general.get("bind_ip", "0.0.0.0"))
    if not ok:
        errors.append(f"general.bind_ip is invalid: {general.get('bind_ip')}")

    ok, _ = validate_ip(general.get("redirect_ip", "127.0.0.1"))
    if not ok:
        errors.append(f"general.redirect_ip is invalid: {general.get('redirect_ip')}")

    for service in ("http", "https", "smtp", "pop3", "imap", "ftp", "dns"):
        section = config_data.get(service, {})
        if section.get("enabled", False):
            ok, port = validate_port(section.get("port", 0))
            if not ok:
                errors.append(f"{service}.port is invalid: {section.get('port')}")

    return errors
