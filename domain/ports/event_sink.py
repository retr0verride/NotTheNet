"""IEventSink — port for emitting structured audit events.

Infrastructure adapters implement this to write events to JSONL files,
OpenTelemetry spans, Splunk HEC, or any other backend without the domain
knowing which sink is active.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class IEventSink(Protocol):
    """Emit a structured audit event.

    ``event_type`` is a short dot-separated identifier such as
    ``dns.query``, ``http.request``, or ``ftp.upload``.
    ``kwargs`` are arbitrary key-value pairs that become top-level fields
    in the structured log output.
    """

    def emit(self, event_type: str, **kwargs: Any) -> None:
        ...

    def flush(self) -> None:
        """Ensure all buffered events are written."""
        ...

    def close(self) -> None:
        """Flush and release any held resources."""
        ...
