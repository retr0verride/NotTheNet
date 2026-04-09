"""IServiceRepository — port for service lifecycle management.

The application layer uses this to start, stop, and query services without
knowing anything about sockets, threads, or iptables.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from domain.entities.service_status import ServiceStatus


@runtime_checkable
class IServiceRepository(Protocol):
    """Manage the lifecycle of all fake-network services."""

    def start_all(self) -> dict[str, bool]:
        """Start every enabled service. Return {name: success} map."""
        ...

    def stop_all(self) -> None:
        """Stop all running services cleanly."""
        ...

    def start_service(self, name: str) -> bool:
        """Start a single service by name. Return True on success."""
        ...

    def stop_service(self, name: str) -> None:
        """Stop a single service by name."""
        ...

    def get_status(self) -> list[ServiceStatus]:
        """Return a snapshot of every service's current status."""
        ...

    def is_running(self, name: str) -> bool:
        """Return True if the given service is currently running."""
        ...
