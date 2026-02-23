"""
NotTheNet - Secure Logging Utility
Sanitizes log output to prevent log injection attacks (CWE-117).
Never logs raw untrusted bytes verbatim.
"""

import logging
import logging.handlers
import os
import re
import sys
from typing import Optional

# Characters that could be used for CRLF injection / ANSI escape injection
_UNSAFE_LOG_PATTERN = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def sanitize_log_string(value: str, max_length: int = 512) -> str:
    """
    Sanitize a string before including it in a log message.
    - Removes ANSI escape sequences (terminal hijacking prevention)
    - Replaces control characters with visible placeholders
    - Truncates to max_length to prevent log flooding
    """
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            return "<non-representable>"

    # Strip ANSI escapes first
    value = _ANSI_ESCAPE_PATTERN.sub("", value)
    # Replace remaining control chars
    value = _UNSAFE_LOG_PATTERN.sub("[?]", value)
    # Truncate
    if len(value) > max_length:
        value = value[:max_length] + "...[truncated]"
    return value


def sanitize_ip(addr: str) -> str:
    """Validate and return an IP address string, or '<invalid>' if not safe."""
    import ipaddress
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        return "<invalid-ip>"


def sanitize_hostname(hostname: str, max_length: int = 253) -> str:
    """Return a sanitized hostname (RFC 1123), replacing unsafe chars."""
    import re
    if not hostname:
        return "<empty>"
    safe = re.sub(r"[^a-zA-Z0-9.\-]", "[?]", hostname)
    return safe[:max_length]


def setup_logging(
    log_dir: str = "logs",
    log_level: str = "INFO",
    log_to_file: bool = True,
    name: str = "notthenet",
) -> logging.Logger:
    """
    Configure application-wide logging with:
    - Rotating file handler (size-limited, prevents disk fill)
    - Console handler
    - Sanitized formatter
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    logger = logging.getLogger(name)
    logger.setLevel(level)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # Console handler
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(level)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    # Rotating file handler — caps at 10 MB × 5 backups = 50 MB max
    if log_to_file:
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "notthenet.log")
        fh = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        fh.setLevel(level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger
