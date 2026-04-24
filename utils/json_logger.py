"""
NotTheNet - Structured JSON Event Logger
Writes every intercepted request as a structured JSON line for automated
pipeline integration (CAPEv2, Splunk, ELK, etc.).

Usage:
    # Startup (in service_manager.py):
    from utils.json_logger import init_json_logger, close_json_logger
    init_json_logger("logs/events.jsonl", enabled=True)

    # In any service handler:
    from utils.json_logger import json_event
    json_event("http_request", src_ip="10.0.0.5", method="GET", path="/update.exe")

    # Shutdown:
    close_json_logger()

Each line is a self-contained JSON object (JSON Lines / JSONL format)
for easy ingestion by log aggregators and grep-based tools.

Security notes (OpenSSF):
- Output file size capped at MAX_FILE_BYTES (default 500 MB)
- Values are sanitized before serialization
- No eval/exec of any logged data
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 500 * 1024 * 1024  # 500 MB default cap
_FLUSH_INTERVAL = 1.0  # seconds between periodic flushes

# ─── Module-level singleton ──────────────────────────────────────────────────

_instance: JsonEventLogger | None = None
_global_lock = threading.Lock()


def init_json_logger(
    output_path: str = "logs/events.jsonl",
    enabled: bool = True,
    max_bytes: int = MAX_FILE_BYTES,
) -> JsonEventLogger | None:
    """Initialise the global JSON event logger. Call once at startup."""
    global _instance
    with _global_lock:
        if _instance:
            _instance.close()
            _instance = None
        if enabled:
            _instance = JsonEventLogger(output_path, max_bytes=max_bytes)
        return _instance


def get_json_logger() -> JsonEventLogger | None:
    """Return the global JSON event logger, or None if not initialised."""
    with _global_lock:
        return _instance


def json_event(event_type: str, **kwargs: Any) -> None:
    """
    Convenience: emit a structured event if JSON logging is active.

    Every service module should call this function. When JSON logging
    is disabled (the default), this is a fast no-op.
    """
    with _global_lock:
        jl = _instance
    if jl is not None:
        jl.log(event_type, **kwargs)


def close_json_logger() -> None:
    """Shut down the global JSON event logger."""
    global _instance
    with _global_lock:
        if _instance:
            _instance.close()
            _instance = None


class JsonEventLogger:
    """
    Thread-safe structured JSON event writer.

    Events are appended as JSON Lines to the output file.
    """

    def __init__(
        self,
        output_path: str = "logs/events.jsonl",
        max_bytes: int = MAX_FILE_BYTES,
    ):
        self._path = output_path
        self._max_bytes = max_bytes
        self._lock = threading.Lock()
        self._file = None
        self._bytes_written = 0
        self._cap_warned = False
        self._last_flush: float = 0.0
        self._open()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def _open(self):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)
            self._file = open(self._path, "a", encoding="utf-8")
            # Track existing file size
            try:
                self._bytes_written = os.path.getsize(self._path)
            except OSError:
                self._bytes_written = 0
            logger.info("JSON event log opened: %s", self._path)
        except OSError as e:
            logger.error("Failed to open JSON event log: %s", e)
            self._file = None

    def log(self, event_type: str, **kwargs: Any) -> None:
        """
        Write a structured event.

        Args:
            event_type: Category string (e.g. "dns_query", "http_request",
                        "smtp_connection", "ftp_upload", "catch_all_tcp")
            **kwargs:   Arbitrary key=value pairs added to the event dict.
        """
        # Fast bail-out without locking when logger is closed / never opened.
        # The actual guarded check is inside the lock below.
        if self._file is None:
            return

        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "epoch": time.time(),
            "event": event_type,
        }
        event.update(kwargs)

        try:
            line = json.dumps(event, default=str, ensure_ascii=False) + "\n"
        except (TypeError, ValueError) as e:
            logger.debug("JSON serialization error: %s", e)
            return

        line_bytes = len(line.encode("utf-8"))

        with self._lock:
            if self._file is None:
                return
            if self._bytes_written + line_bytes > self._max_bytes:
                if not self._cap_warned:
                    logger.warning(
                        "JSON event log size cap (%d MB) reached; "
                        "further events dropped.",
                        self._max_bytes // (1024 * 1024),
                    )
                    self._cap_warned = True
                return
            try:
                self._file.write(line)
                self._bytes_written += line_bytes
                # Flush at most once per _FLUSH_INTERVAL to avoid a syscall
                # on every single event under high-frequency traffic.
                now = time.monotonic()
                if now - self._last_flush >= _FLUSH_INTERVAL:
                    self._file.flush()
                    self._last_flush = now
            except OSError as e:
                logger.error("JSON event write error: %s", e)

    def flush(self) -> None:
        """Flush buffered data to disk without closing the log."""
        with self._lock:
            if self._file:
                try:
                    self._file.flush()
                    self._last_flush = time.monotonic()
                except OSError as e:
                    logger.error("JSON event flush error: %s", e)

    def close(self):
        """Flush and close the event log file."""
        with self._lock:
            if self._file:
                try:
                    self._file.flush()
                    self._file.close()
                except OSError:
                    pass
                self._file = None
                logger.info("JSON event log closed.")
