"""ConfigApplicationService — use-case wrapper around IConfigStore.

Provides change-validation, audit logging, and atomic updates so that
callers (GUI, REST endpoint, CLI) go through a single entry-point and
never manipulate raw config dicts directly.
"""

from __future__ import annotations

import logging
from typing import Any

from domain.ports.config_store import IConfigStore
from domain.ports.event_sink import IEventSink

logger = logging.getLogger(__name__)


class ConfigApplicationService:
    """Apply validated configuration changes and emit audit events."""

    def __init__(self, config: IConfigStore, event_sink: IEventSink) -> None:
        self._config = config
        self._sink = event_sink

    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        return self._config.get(section, key, fallback)

    def get_section(self, section: str) -> dict[str, Any]:
        return self._config.get_section(section)

    def update(self, section: str, key: str, value: Any) -> None:
        """Update a single key and persist.  Emits an audit event."""
        old = self._config.get(section, key)
        self._config.set(section, key, value)
        self._config.save()
        self._sink.emit(
            "config.change",
            section=section,
            key=key,
            old=_redact(key, old),
            new=_redact(key, value),
        )
        logger.info("Config updated: %s.%s", section, key)

    def as_dict(self) -> dict[str, Any]:
        """Snapshot the full config (for display / export)."""
        return self._config.as_dict()


# Keys whose values must never appear in audit logs.
_SENSITIVE_KEYS = frozenset({"password", "secret", "key", "token", "api_key", "passphrase"})


def _redact(key: str, value: Any) -> Any:
    if any(s in key.lower() for s in _SENSITIVE_KEYS):
        return "***REDACTED***"
    return value
