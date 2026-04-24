"""ServiceRepoAdapter — IServiceRepository adapter wrapping ServiceManager.

Bridges the application layer's ``IServiceRepository`` port to the existing
``ServiceManager`` class without modifying it.  Translates the concrete
``ServiceProtocol`` instances into ``ServiceStatus`` domain entities.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from domain.entities.service_status import ServiceState, ServiceStatus
from domain.ports.config_store import IConfigStore

if TYPE_CHECKING:
    from service_manager import ServiceManager

logger = logging.getLogger(__name__)


class ServiceRepoAdapter:
    """Adapts the existing ServiceManager to satisfy IServiceRepository.

    ServiceManager is constructed lazily on the first ``start_all()`` call
    so that the container can be built without triggering OS-level side-effects
    (iptables writes, raw sockets) during testing.

    Call ``probe()`` in tests or health checks to force instantiation early
    and surface config errors before the first ``start_all()``.
    """

    def __init__(self, config_store: IConfigStore) -> None:
        self._config = config_store
        # ServiceManager, typed as object to avoid circular import
        self._manager: ServiceManager | None = None

    def probe(self) -> None:
        """Force-instantiate ServiceManager. Use in tests to catch config errors early."""
        self._get_manager()

    def _get_manager(self) -> ServiceManager:
        if self._manager is None:
            from service_manager import ServiceManager

            # Unwrap EnvConfigStore → base Config for ServiceManager
            base = getattr(self._config, "_base", self._config)
            self._manager = ServiceManager(base)  # type: ignore[arg-type]
        return self._manager

    # ── IServiceRepository ────────────────────────────────────────────────────

    def start_all(self) -> dict[str, bool]:
        mgr = self._get_manager()
        try:
            mgr.start()
            return {name: True for name in mgr._services}
        except Exception as exc:
            logger.error("ServiceManager.start() failed: %s", exc, exc_info=True)
            return {}

    def stop_all(self) -> None:
        if self._manager is None:
            return
        try:
            self._manager.stop()  # type: ignore[no-untyped-call]
        except Exception as exc:
            logger.error("ServiceManager.stop() failed: %s", exc, exc_info=True)

    def start_service(self, name: str) -> bool:
        mgr = self._get_manager()
        try:
            svc = mgr._services.get(name)
            if svc is None:
                logger.warning("start_service: unknown service %r", name)
                return False
            return svc.start()
        except Exception as exc:
            logger.error("start_service(%s) failed: %s", name, exc, exc_info=True)
            return False

    def stop_service(self, name: str) -> None:
        if self._manager is None:
            return
        try:
            svc = self._manager._services.get(name)
            if svc:
                svc.stop()
        except Exception as exc:
            logger.debug("stop_service(%s) error: %s", name, exc)

    def get_status(self) -> list[ServiceStatus]:
        if self._manager is None:
            return []
        statuses: list[ServiceStatus] = []
        try:
            from service_manager import _SERVICE_REGISTRY

            for spec in _SERVICE_REGISTRY:
                svc = self._manager._services.get(spec.name)
                st = ServiceStatus(name=spec.name, port=spec.default_port, protocol=spec.protocol)
                if svc is None:
                    st.state = ServiceState.STOPPED
                elif svc.running:
                    st.state = ServiceState.RUNNING
                    st.mark_running(spec.default_port, spec.protocol)
                else:
                    st.state = ServiceState.STOPPED
                statuses.append(st)
        except Exception as exc:
            logger.debug("get_status error: %s", exc)
        return statuses

    def is_running(self, name: str) -> bool:
        if self._manager is None:
            return False
        svc = self._manager._services.get(name)
        return svc is not None and svc.running
