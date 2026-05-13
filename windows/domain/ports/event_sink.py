"""IEventSink — port for structured event logging.

The application layer uses this to emit audit events; infrastructure
provides a concrete adapter (e.g., JSONL file or syslog).
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class IEventSink(Protocol):
    """Emit structured events for audit trails and analysis."""

    def emit(self, event_type: str, **fields: Any) -> None:
        """Record a structured event (non-blocking)."""
        ...

    def flush(self) -> None:
        """Ensure all pending events are written to storage."""
        ...

    def close(self) -> None:
        """Close the sink (called during shutdown)."""
        ...
