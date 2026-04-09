"""HealthCheckService — application-layer use case.

Aggregates liveness, readiness, and detailed status data for external
probes (Kubernetes, load balancers, uptime monitors).

Liveness  — is the process alive and not deadlocked?
Readiness — are the core services up and able to serve traffic?
"""

from __future__ import annotations

import time
from typing import Any

from domain.entities.service_status import ServiceState
from domain.ports.service_repo import IServiceRepository

# Services that MUST be running for readiness to pass.
# (configurable via constructor; these are the defaults)
_CORE_SERVICES = frozenset({"dns", "http", "https"})


class HealthCheckService:
    """Produce liveness and readiness payloads.

    Constructed with a reference to the service repository so it can query
    service states without coupling to a specific implementation.
    """

    def __init__(
        self,
        service_repo: IServiceRepository,
        core_services: frozenset[str] = _CORE_SERVICES,
    ) -> None:
        self._repo = service_repo
        self._core = core_services
        self._start_time = time.time()

    def liveness(self) -> dict[str, Any]:
        """Always returns OK while the process is alive (used by /health/live)."""
        return {
            "status": "ok",
            "uptime_seconds": round(time.time() - self._start_time, 1),
        }

    def readiness(self) -> tuple[bool, dict[str, Any]]:
        """Returns (is_ready, payload) for /health/ready.

        is_ready is False when any core service is not running, which causes
        a load-balancer to temporarily stop routing traffic.
        """
        statuses = self._repo.get_status()
        state_map = {s.name: s.state for s in statuses}

        missing = [
            name
            for name in self._core
            if state_map.get(name) != ServiceState.RUNNING
        ]
        is_ready = len(missing) == 0

        return is_ready, {
            "status": "ready" if is_ready else "degraded",
            "core_services_required": sorted(self._core),
            "core_services_missing": sorted(missing),
            "uptime_seconds": round(time.time() - self._start_time, 1),
        }

    def detailed(self) -> dict[str, Any]:
        """Full status — used by /health/status (may require auth in prod)."""
        statuses = self._repo.get_status()
        _, ready_payload = self.readiness()
        return {
            **ready_payload,
            "services": [
                {
                    "name": s.name,
                    "state": s.state.value,
                    "port": s.port,
                    "protocol": s.protocol,
                    "connections_total": s.connections_total,
                    "error": s.error,
                }
                for s in statuses
            ],
        }
