"""Dependency Injection Container — infrastructure wiring.

This module is the *composition root*: the only place in the codebase that
knows about both domain ports and infrastructure adapters simultaneously.

All other modules receive their dependencies via constructor parameters and
never call ``Container`` directly — keeping them testable in isolation by
substituting simple fakes or mocks.

Construction order
──────────────────
1. Config           (EnvConfigStore wrapping the JSON-backed Config)
2. EventSink        (JsonlEventSink wrapping the existing json_logger)
3. ServiceRepo      (ServiceManagerAdapter wrapping ServiceManager)
4. Orchestrator     (ServiceOrchestrator ← config + repo + sink)
5. HealthCheckSvc   (HealthCheckService ← repo)
6. HealthServer     (HealthServer ← health svc + orchestrator)

Usage::

    from infrastructure.di.container import Container

    container = Container.build()
    container.start()
    ...
    container.stop()
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from application.health import HealthCheckService
    from application.orchestrator import ServiceOrchestrator
    from infrastructure.adapters.service_repo_adapter import ServiceRepoAdapter
    from infrastructure.config.env_config import EnvConfigStore
    from infrastructure.event_sink import JsonlEventSink
    from infrastructure.health.server import HealthServer

logger = logging.getLogger(__name__)


class Container:
    """Explicit, lightweight DI container — no reflection, no magic.

    Every dependency is wired manually so that static type checkers (Pylance,
    mypy) can follow the full call graph without guessing.
    """

    def __init__(
        self,
        config: EnvConfigStore,
        event_sink: JsonlEventSink,
        service_repo: ServiceRepoAdapter,
        orchestrator: ServiceOrchestrator,
        health_svc: HealthCheckService,
        health_server: HealthServer,
    ) -> None:
        self.config = config
        self.event_sink = event_sink
        self.service_repo = service_repo
        self.orchestrator = orchestrator
        self.health_svc = health_svc
        self.health_server = health_server

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def build(cls, config_path: str | None = None) -> Container:
        """Assemble the full object graph.

        This is the *only* factory method for the production application.
        Tests create individual objects directly to avoid full graph setup.
        """
        # ── 0. Pydantic Settings — crash-early env validation ─────────────────
        from infrastructure.config.settings import get_settings

        settings = get_settings()  # raises ValidationError on bad env vars
        logger.info(
            "Settings validated: bind_ip=%s log_level=%s health_port=%d",
            settings.bind_ip,
            settings.log_level,
            settings.health_port,
        )

        # Resolve config path from env → arg → default
        path = (
            str(settings.config_path)
            if str(settings.config_path) != "config.json"
            else (config_path or _default_config_path())
        )

        # ── 1. Config ─────────────────────────────────────────────────────────
        from config import Config
        from infrastructure.config.env_config import EnvConfigStore

        base_cfg = Config(path)
        config_store = EnvConfigStore(base_cfg)

        # ── 2. EventSink ──────────────────────────────────────────────────────
        from infrastructure.event_sink import JsonlEventSink

        log_dir = config_store.get("general", "log_dir", "logs")
        sink = JsonlEventSink(log_dir=log_dir)

        # ── 3. Service Repository ─────────────────────────────────────────────
        from infrastructure.adapters.service_repo_adapter import ServiceRepoAdapter

        repo = ServiceRepoAdapter(config_store)

        # ── 4. Orchestrator ───────────────────────────────────────────────────
        from application.orchestrator import ServiceOrchestrator

        orchestrator = ServiceOrchestrator(config_store, repo, sink)

        # ── 5. HealthCheckService ─────────────────────────────────────────────
        from application.health import HealthCheckService

        health_svc = HealthCheckService(repo)

        # ── 6. HealthServer ───────────────────────────────────────────────────
        from infrastructure.health.server import HealthServer

        health_server = HealthServer(
            health_svc,
            orchestrator,
            bind_ip=settings.health_bind,
            port=settings.health_port,
        )

        return cls(config_store, sink, repo, orchestrator, health_svc, health_server)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> dict[str, bool]:
        """Start the health server, then all services."""
        self.health_server.start()
        return self.orchestrator.start()

    def stop(self) -> None:
        """Stop all services, then the health server."""
        self.orchestrator.stop()
        self.health_server.stop()


def _default_config_path() -> str:
    import pathlib
    return str(pathlib.Path(__file__).resolve().parents[2] / "config.json")
