"""Windows-specific logging setup.

Simplified version without OpenTelemetry — direct stdout/file logging.
"""

from __future__ import annotations

import json
import logging
import logging.config
import sys
from typing import Any


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "thread": f"{record.threadName}/{record.thread}",
        }

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        for key, value in record.__dict__.items():
            if key not in (
                "name",
                "msg",
                "args",
                "created",
                "levelno",
                "levelname",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "process",
                "processName",
                "thread",
                "threadName",
                "getMessage",
                "message",
            ):
                payload[key] = value

        return json.dumps(payload)


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Configure Python logging for NotTheNet Windows.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_output: If True, emit JSON lines; otherwise use simple format
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    if json_output:
        formatter = _JsonFormatter()
    else:
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(console_handler)

    # Suppress noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("http.server").setLevel(logging.WARNING)
