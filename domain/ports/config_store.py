"""IConfigStore — port/interface for configuration access.

Infrastructure must provide a concrete adapter; the application layer imports
only this interface, never the concrete implementation.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class IConfigStore(Protocol):
    """Read/write access to layered configuration (file + env overrides)."""

    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        """Return a single value identified by ``section.key``."""
        ...

    def set(self, section: str, key: str, value: Any) -> None:
        """Persist a single value under ``section.key``."""
        ...

    def get_section(self, section: str) -> dict[str, Any]:
        """Return a shallow copy of an entire configuration section."""
        ...

    def as_dict(self) -> dict[str, Any]:
        """Return the full config as a plain dict (deep copy)."""
        ...

    def save(self, path: Optional[str] = None) -> bool:
        """Flush current state to persistent storage; return success."""
        ...
