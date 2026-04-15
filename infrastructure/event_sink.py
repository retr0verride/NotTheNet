"""JsonlEventSink — IEventSink adapter wrapping the existing json_logger.

Satisfies ``domain.ports.event_sink.IEventSink`` by delegating to the
production ``utils.json_logger`` module so that all existing service code
that calls ``json_event()`` continues to work unchanged.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class JsonlEventSink:
    """Write structured audit events to a JSONL file.

    The underlying ``utils.json_logger`` singleton is initialised on first
    ``emit()`` call so that the container can be constructed without
    side-effects (useful in tests).
    """

    def __init__(self, log_dir: str = "logs") -> None:
        self._log_dir = log_dir
        self._initialised = False

    def _ensure_init(self) -> None:
        if self._initialised:
            return
        os.makedirs(self._log_dir, exist_ok=True)
        output_path = os.path.join(self._log_dir, "events.jsonl")

        from utils.json_logger import init_json_logger

        init_json_logger(output_path=output_path, enabled=True)
        self._initialised = True
        logger.debug("JsonlEventSink initialised at %s", output_path)

    def emit(self, event_type: str, **kwargs: Any) -> None:
        self._ensure_init()
        from utils.json_logger import json_event

        json_event(event_type, **kwargs)

    def flush(self) -> None:
        if not self._initialised:
            return
        try:
            from utils.json_logger import get_json_logger

            jl = get_json_logger()
            if jl:
                jl.flush()
        except Exception as exc:
            logger.debug("flush error: %s", exc)

    def close(self) -> None:
        if not self._initialised:
            return
        try:
            from utils.json_logger import close_json_logger

            close_json_logger()
        except Exception as exc:
            logger.debug("close error: %s", exc)
