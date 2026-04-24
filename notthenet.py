#!/usr/bin/env python3
"""NotTheNet - Fake Internet Simulator.

Thin entry point.  Two runtime modes:

  GUI mode (default)
    Launches the Tkinter dashboard.  Full GUI and CLI logic live in ``gui/``.

  Headless mode  (--headless flag or NTN_HEADLESS=1 env var)
    Starts all services without a GUI, exposes health/metrics on :8080,
    and blocks until SIGTERM/SIGINT.  Suitable for systemd and containers.

Architecture layers (Clean Architecture):
  domain/          Pure business entities, ports (interfaces), value objects
  application/     Use-cases: orchestrator, health, config service
  infrastructure/  Concrete adapters: DI container, env config, OTel, health HTTP
  services/        Fake network protocol handlers
  gui/             Tkinter dashboard (infrastructure detail)
"""

from __future__ import annotations

import os
import signal
import sys

# Ensure the project root is on sys.path so sibling packages resolve correctly.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

# Recover from a stale CWD before anything tries to use a relative path.
# Common trigger: user cloned the repo, then `dpkg -i` overwrote the install
# directory and the shell's CWD now points at a deleted inode.  Every
# subprocess.Popen() call without an explicit cwd= would fail with ENOENT,
# log_dir="logs" creation would crash, etc.
try:
    os.getcwd()
except (FileNotFoundError, OSError):
    print(
        f"[!] Current working directory is stale (deleted) — "
        f"chdir() to {_SCRIPT_DIR}",
        file=sys.stderr,
    )
    os.chdir(_SCRIPT_DIR)

from gui.widgets import APP_VERSION  # noqa: F401,E402  — single source of truth


def _headless_main() -> None:
    """Run in headless / container mode: no GUI, health endpoint active."""
    import logging

    from infrastructure.di.container import Container
    from infrastructure.logging.otel import initialise as otel_init
    from infrastructure.logging.setup import configure_logging

    log_level = os.environ.get("NTN_LOG_LEVEL", "INFO")
    configure_logging(level=log_level)
    logger = logging.getLogger(__name__)

    otel_init()

    container = Container.build(
        config_path=os.environ.get("NTN_CONFIG_PATH")
    )

    stop_event = __import__("threading").Event()

    def _handle_signal(signum, _frame):
        logger.info("Signal %d received — shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info("NotTheNet %s starting in headless mode", APP_VERSION)
    results = container.start()
    started = sum(1 for ok in results.values() if ok)
    logger.info("Services started: %d/%d", started, len(results))

    stop_event.wait()
    logger.info("Stopping …")
    container.stop()
    logger.info("NotTheNet stopped cleanly.")


def main() -> None:
    headless = (
        "--headless" in sys.argv
        or os.environ.get("NTN_HEADLESS", "0").strip().lower() in ("1", "true", "yes")
    )
    if headless:
        _headless_main()
    else:
        from gui.app import main as gui_main
        gui_main()


if __name__ == "__main__":
    main()
