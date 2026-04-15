"""Structured logging bootstrap.

Configures Python's built-in ``logging`` with a JSON formatter so that every
log record is machine-parseable.  Console output retains human-readable
formatting when a TTY is detected (12-factor §XI: treat logs as event streams).

Usage (called once at process start, before any other module logs):

    from infrastructure.logging.setup import configure_logging
    configure_logging(level="INFO", json_output=True)
"""

from __future__ import annotations

import contextvars
import json
import logging
import logging.config
import os
import sys
import time
import uuid
from typing import Any

# ── Trace ID context ─────────────────────────────────────────────────────────
# Each request / connection handler calls set_trace_id() at entry.
# The JSON formatter automatically picks it up from the ContextVar.

_trace_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "trace_id", default=""
)


def set_trace_id(trace_id: str | None = None) -> str:
    """Set the trace ID for the current execution context.

    If ``trace_id`` is None a fresh UUID4 is generated.  Returns the
    trace ID that was set so callers can log it alongside their entry event.
    """
    tid = trace_id or uuid.uuid4().hex
    _trace_id_var.set(tid)
    return tid


def get_trace_id() -> str:
    """Return the current trace ID, or an empty string if not set."""
    return _trace_id_var.get()


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line.

    Fields always present:
      ts       — ISO-8601 UTC timestamp
      level    — DEBUG/INFO/WARNING/ERROR/CRITICAL
      logger   — dotted logger name
      msg      — formatted message
      thread   — thread name + id

    Optional (when present in the record):
      exc_info — formatted traceback
      extra    — any extra fields attached via ``logging.extra={}``
    """

    _STDLIB_ATTRS = frozenset(
        logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
    )

    def format(self, record: logging.LogRecord) -> str:
        tid = _trace_id_var.get()
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "thread": f"{record.threadName}/{record.thread}",
        }
        if tid:
            payload["trace_id"] = tid

        # Attach any caller-supplied extra fields.
        for key, val in record.__dict__.items():
            if key not in self._STDLIB_ATTRS and not key.startswith("_"):
                payload[key] = val

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(payload, default=str)


class _HumanFormatter(logging.Formatter):
    """Coloured, human-readable output for interactive TTY sessions."""

    _LEVEL_COLOURS = {
        "DEBUG":    "\033[36m",   # cyan
        "INFO":     "\033[32m",   # green
        "WARNING":  "\033[33m",   # yellow
        "ERROR":    "\033[31m",   # red
        "CRITICAL": "\033[35m",   # magenta
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        colour = self._LEVEL_COLOURS.get(record.levelname, "")
        ts = time.strftime("%H:%M:%S")
        prefix = f"{ts} {colour}{record.levelname:<8}{self._RESET} [{record.name}]"
        return f"{prefix} {record.getMessage()}"


def configure_logging(
    level: str = "INFO",
    json_output: bool | None = None,
    log_file: str | None = None,
) -> None:
    """Configure root logger.

    Args:
        level:       Logging level name (DEBUG/INFO/WARNING/ERROR).
        json_output: Force JSON formatter.  If None (default), JSON is used
                     when stdout is NOT a TTY (i.e. CI, containers, systemd).
        log_file:    Optional path to a rotating log file (plain text).
    """
    level_int = getattr(logging, level.upper(), logging.INFO)

    use_json = json_output if json_output is not None else not sys.stdout.isatty()

    handlers: list[logging.Handler] = []

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(_JsonFormatter() if use_json else _HumanFormatter())
    handlers.append(stdout_handler)

    if log_file:
        from logging.handlers import RotatingFileHandler

        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=50 * 1024 * 1024,  # 50 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(_JsonFormatter())
        handlers.append(file_handler)

    logging.basicConfig(
        level=level_int,
        handlers=handlers,
        force=True,  # override any earlier basicConfig call
    )

    # Suppress noisy third-party loggers.
    for noisy in ("dnslib", "urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger(__name__).debug(
        "Logging configured: level=%s json=%s", level, use_json
    )
