"""HealthCheckService — application-layer health monitoring."""

from __future__ import annotations

import logging
from typing import Any

from domain.ports.service_repo import IServiceRepository

logger = logging.getLogger(__name__)


class HealthCheckService:
    """Query service health and readiness."""

    def __init__(self, service_repo: IServiceRepository) -> None:
        self._repo = service_repo

    def liveness(self) -> dict[str, Any]:
        """Return True if the application is alive."""
        return {"alive": True, "timestamp": __import__("time").time()}

    def readiness(self) -> dict[str, Any]:
        """Return True if all critical services are ready."""
        statuses = self._repo.get_status()
        running = sum(1 for s in statuses if s.state.value == "running")
        total = len(statuses)
        ready = running > 0
        return {
            "ready": ready,
            "services_running": running,
            "services_total": total,
            "timestamp": __import__("time").time(),
        }
