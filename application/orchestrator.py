"""ServiceOrchestrator — application-layer use case.

Coordinates service lifecycle using only the domain ports IServiceRepository
and IConfigStore.  Nothing here is aware of sockets, threads, or iptables.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from domain.entities.service_status import ServiceState, ServiceStatus
from domain.ports.config_store import IConfigStore
from domain.ports.event_sink import IEventSink
from domain.ports.service_repo import IServiceRepository

logger = logging.getLogger(__name__)


class ServiceOrchestrator:
    """High-level coordinator for the NotTheNet service lifecycle.

    Receives its dependencies via constructor (Dependency Injection).
    The concrete types that satisfy the port Protocols are wired in
    ``infrastructure/di/container.py``.
    """

    def __init__(
        self,
        config: IConfigStore,
        service_repo: IServiceRepository,
        event_sink: IEventSink,
    ) -> None:
        self._config = config
        self._repo = service_repo
        self._sink = event_sink
        self._started_at: float | None = None

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> dict[str, bool]:
        """Start all enabled services.

        Returns a mapping of ``{service_name: started_successfully}``.
        Emits a structured audit event for each service outcome.
        """
        logger.info("ServiceOrchestrator: starting all services")
        results = self._repo.start_all()
        self._started_at = time.time()

        for name, ok in results.items():
            self._sink.emit(
                "service.start",
                service=name,
                success=ok,
                ts=self._started_at,
            )
            if not ok:
                logger.warning("Service %r failed to start", name)

        return results

    def stop(self) -> None:
        """Stop all running services and flush the event sink."""
        logger.info("ServiceOrchestrator: stopping all services")
        self._repo.stop_all()
        self._sink.flush()
        stopped_at = time.time()
        uptime = round(stopped_at - self._started_at, 1) if self._started_at else 0
        self._sink.emit("orchestrator.stop", uptime_seconds=uptime)
        self._sink.close()
        self._started_at = None

    def restart_service(self, name: str) -> bool:
        """Stop then start a single service. Returns True on success."""
        self._repo.stop_service(name)
        ok = self._repo.start_service(name)
        self._sink.emit("service.restart", service=name, success=ok, ts=time.time())
        return ok

    # ── Queries ──────────────────────────────────────────────────────────────

    def status(self) -> list[ServiceStatus]:
        """Return a point-in-time snapshot of all service states."""
        return self._repo.get_status()

    def uptime_seconds(self) -> float | None:
        """Seconds since the orchestrator last called ``start()``, or None."""
        return round(time.time() - self._started_at, 1) if self._started_at else None

    def summary(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary for health/admin endpoints."""
        statuses = self.status()
        running = [s for s in statuses if s.state == ServiceState.RUNNING]
        failed = [s for s in statuses if s.state == ServiceState.FAILED]
        return {
            "uptime_seconds": self.uptime_seconds(),
            "services_total": len(statuses),
            "services_running": len(running),
            "services_failed": len(failed),
            "services": [
                {
                    "name": s.name,
                    "state": s.state.value,
                    "port": s.port,
                    "protocol": s.protocol,
                    "error": s.error,
                }
                for s in statuses
            ],
        }
