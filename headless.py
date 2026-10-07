"""Headless runner: start every service, block until SIGTERM/SIGINT, stop cleanly.

Used by systemd (``--nogui``) and Docker (``NTN_HEADLESS=1``). Never imports
tkinter, so it runs on hosts without a display or Tk libraries.

The health endpoint (utils/health_server.py) starts only when
``NTN_HEALTH_ENABLED=1``; the Docker image sets it, systemd does not.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
from types import FrameType

from config import Config
from service_manager import ServiceManager
from utils.health_server import HealthServer, HealthSettings

logger = logging.getLogger(__name__)


def run(cfg: Config) -> int:
    """Run all services until a termination signal arrives. Returns the exit code."""
    try:
        health = HealthSettings.from_env(os.environ)
    except ValueError as exc:
        logger.error("Invalid health settings: %s", exc)
        return 1

    manager = ServiceManager(cfg)
    if not manager.start():
        logger.error("No services started; exiting.")
        return 1

    health_server: HealthServer | None = None
    if health.enabled:
        health_server = HealthServer(manager, health)
        try:
            health_server.start()
        except OSError as exc:
            logger.error("Health server could not bind %s:%d: %s", health.bind_ip, health.port, exc)
            manager.stop()
            return 1

    stop_event = threading.Event()

    def _on_signal(signum: int, _frame: FrameType | None) -> None:
        logger.info("Signal %s received; shutting down.", signal.Signals(signum).name)
        stop_event.set()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    logger.info("Running headless. Send SIGINT or SIGTERM to stop.")
    stop_event.wait()
    if health_server is not None:
        health_server.stop()
    manager.stop()
    return 0
