"""Headless runner: start every service, block until SIGTERM/SIGINT, stop cleanly.

Used by systemd (``--nogui``) and Docker (``NTN_HEADLESS=1``). Never imports
tkinter, so it runs on hosts without a display or Tk libraries.
"""

from __future__ import annotations

import logging
import signal
import threading
from types import FrameType

from config import Config
from service_manager import ServiceManager

logger = logging.getLogger(__name__)


def run(cfg: Config) -> int:
    """Run all services until a termination signal arrives. Returns the exit code."""
    manager = ServiceManager(cfg)
    if not manager.start():
        logger.error("No services started; exiting.")
        return 1

    stop_event = threading.Event()

    def _on_signal(signum: int, _frame: FrameType | None) -> None:
        logger.info("Signal %s received; shutting down.", signal.Signals(signum).name)
        stop_event.set()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    logger.info("Running headless. Send SIGINT or SIGTERM to stop.")
    stop_event.wait()
    manager.stop()
    return 0
