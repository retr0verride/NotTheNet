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


def _check_positive_number(section_name: str, section: dict, key: str, errors: list) -> None:
    """Append an error if section[key] is present but not a positive number."""
    val = section.get(key)
    if val is None:
        return
    try:
        if float(val) <= 0:
            raise ValueError
    except (TypeError, ValueError):
        errors.append(f"{section_name}.{key} must be a positive number, got {val!r}")


def _check_no_traversal(section_name: str, section: dict, key: str, errors: list) -> None:
    """Append an error if section[key] contains a path-traversal (..) component."""
    path = section.get(key)
    if not path:
        return
    parts = str(path).replace("\\", "/").split("/")
    if ".." in parts:
        errors.append(f"{section_name}.{key} contains path traversal: {path!r}")


# Services that expose a single "port" key.
_PORT_SERVICES = (
    "http", "https", "smtp", "smtps", "pop3", "pop3s",
    "imap", "imaps", "ftp", "dns", "ntp", "irc", "ircs",
    "tftp", "telnet", "socks5", "smb", "mysql", "mssql",
    "rdp", "vnc", "redis", "ldap", "dot",
)

# Capacity / timeout knobs that must be positive numbers, keyed by section.
_POSITIVE_NUM_FIELDS: dict[str, list[str]] = {
    "smtp":      ["conn_timeout_sec", "max_connections", "max_email_size_bytes", "max_disk_usage_bytes"],
    "smtps":     ["conn_timeout_sec", "max_connections", "max_email_size_bytes", "max_disk_usage_bytes"],
    "pop3":      ["conn_timeout_sec", "max_connections"],
    "pop3s":     ["conn_timeout_sec", "max_connections"],
    "imap":      ["conn_timeout_sec", "max_connections"],
    "imaps":     ["conn_timeout_sec", "max_connections"],
    "ftp":       ["max_connections", "control_timeout_sec", "data_timeout_sec", "pasv_timeout_sec",
                  "max_upload_size_bytes", "max_disk_usage_bytes"],
    "smb":       ["max_connections", "session_timeout_sec"],
    "catch_all": ["max_connections", "max_per_ip", "session_timeout_sec", "peek_timeout_sec"],
}

# Path fields that must not contain traversal sequences.
_PATH_FIELDS: dict[str, list[str]] = {
    "ftp":   ["upload_dir"],
    "tftp":  ["upload_dir"],
    "http":  ["response_body_file"],
    "https": ["response_body_file", "cert_file", "key_file"],
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

    spoof_ip = str(general.get("spoof_public_ip", "") or "").strip()
    if spoof_ip:
        ok, _ = validate_ip(spoof_ip)
        if not ok:
            errors.append(f"general.spoof_public_ip is not a valid IP address: {spoof_ip!r}")

    for service in ("http", "https"):
        section = config_data.get(service, {})
        delay = section.get("response_delay_ms", 0)
        try:
            d = int(delay)
            if not (0 <= d <= 30_000):
                raise ValueError
        except (TypeError, ValueError):
            errors.append(f"{service}.response_delay_ms must be an integer 0–30000, got {delay!r}")

    for service in _PORT_SERVICES:
        section = config_data.get(service, {})
        if section.get("enabled", False):
            ok, _ = validate_port(section.get("port", 0))
            if not ok:
                errors.append(f"{service}.port is invalid: {section.get('port')}")

    # catch_all uses tcp_port / udp_port instead of port
    catch_all = config_data.get("catch_all", {})
    if catch_all.get("enabled", False):
        for key in ("tcp_port", "udp_port"):
            val = catch_all.get(key)
            if val is not None:
                ok, _ = validate_port(val)
                if not ok:
                    errors.append(f"catch_all.{key} is invalid: {val!r}")

    # Capacity and timeout fields must be positive numbers
    for svc_name, fields in _POSITIVE_NUM_FIELDS.items():
        section = config_data.get(svc_name, {})
        for field in fields:
            _check_positive_number(svc_name, section, field, errors)

    # ftp PASV port range cross-field check
    ftp = config_data.get("ftp", {})
    pasv_low = ftp.get("pasv_port_low")
    pasv_high = ftp.get("pasv_port_high")
    if pasv_low is not None or pasv_high is not None:
        ok_low, low = validate_port(pasv_low or 0)
        ok_high, high = validate_port(pasv_high or 0)
        if not ok_low:
            errors.append(f"ftp.pasv_port_low is invalid: {pasv_low!r}")
        if not ok_high:
            errors.append(f"ftp.pasv_port_high is invalid: {pasv_high!r}")
        if ok_low and ok_high and low >= high:
            errors.append(
                f"ftp.pasv_port_low ({low}) must be less than pasv_port_high ({high})"
            )

    # Path fields must not contain traversal sequences
    for svc_name, fields in _PATH_FIELDS.items():
        section = config_data.get(svc_name, {})
        for field in fields:
            _check_no_traversal(svc_name, section, field, errors)

    return errors
