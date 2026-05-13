"""Event sink adapter — JSONL file logging."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)


class JsonlEventSink:
    """Write structured events to a JSONL file."""

    def __init__(self, log_file: str = "logs/events.jsonl") -> None:
        self.log_file = log_file
        self._file = None
        self._ensure_dir()
        self._open()

    def _ensure_dir(self) -> None:
        """Ensure the log directory exists."""
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

    def _open(self) -> None:
        """Open the JSONL file for appending."""
        try:
            self._file = open(self.log_file, "a", encoding="utf-8")
            logger.debug("Event sink opened: %s", self.log_file)
        except OSError as exc:
            logger.error("Failed to open event sink: %s", exc)

    def emit(self, event_type: str, **fields: Any) -> None:
        """Write a structured event."""
        if self._file is None:
            return

        event = {
            "event_type": event_type,
            "timestamp": time.time(),
            **fields,
        }

        try:
            self._file.write(json.dumps(event) + "\n")
        except (OSError, json.JSONEncodeError) as exc:
            logger.error("Failed to emit event: %s", exc)

    def flush(self) -> None:
        """Flush pending events to disk."""
        if self._file is not None:
            try:
                self._file.flush()
            except OSError as exc:
                logger.error("Failed to flush event sink: %s", exc)

    def close(self) -> None:
        """Close the event sink."""
        if self._file is not None:
            try:
                self._file.close()
                logger.debug("Event sink closed")
            except OSError as exc:
                logger.error("Failed to close event sink: %s", exc)
            finally:
                self._file = None
