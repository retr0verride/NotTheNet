#!/usr/bin/env python3
"""NotTheNet - Fake Internet Simulator. Command-line entry point.

Modes:
  (default)    Tkinter dashboard (gui/).
  --nogui      Headless: start all services, run until SIGTERM/SIGINT.
               Also selected by --headless or NTN_HEADLESS=1 (Docker).
  --preflight  Print the stealth-readiness report and exit.

Only the GUI mode imports tkinter.

Environment: NTN_HEADLESS, NTN_LOG_LEVEL, NTN_JSON_LOGS, and the
NTN_HEALTH_* / NTN_ADMIN_TOKEN settings read by utils/health_server.py.
"""

from __future__ import annotations

import argparse
import datetime
import logging
import os
import sys
import traceback

# All runtime paths (certs/, logs/, config.json) are relative to the project
# root, so make it both importable and the working directory before anything
# else runs. This also recovers from a stale CWD (e.g. `dpkg -i` replaced the
# directory the shell was sitting in).
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

from version import APP_VERSION  # noqa: E402

_TRUTHY = ("1", "true", "yes")


def print_banner() -> None:
    """Print the NotTheNet ASCII banner to stdout (CLI mode only)."""
    cyan = "\033[36m"
    reset = "\033[0m"
    banner = (
        f"{cyan}"
        "\n"
        "  \u2588\u2588\u2588\u2557   \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557    \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557  \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557    \u2588\u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\n"
        "  \u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d       \u2588\u2588\u2551   \u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d    \u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d\n"
        "  \u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551          \u2588\u2588\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2557      \u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2557     \u2588\u2588\u2551   \n"
        "  \u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551          \u2588\u2588\u2551   \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u255d      \u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u255d     \u2588\u2588\u2551   \n"
        "  \u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d   \u2588\u2588\u2551          \u2588\u2588\u2551   \u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557    \u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557   \u2588\u2588\u2551   \n"
        "  \u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d    \u255a\u2550\u255d          \u255a\u2550\u255d   \u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d    \u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d   \u255a\u2550\u255d  \n"
        "                          Fake Internet Simulator  \u00b7  Malware Analysis\n"
        f"{reset}"
    )
    print(banner)  # noqa: T201


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NotTheNet - Fake Internet Simulator")
    parser.add_argument("--config", default=os.path.join(PROJECT_ROOT, "config.json"),
                        help="Path to config JSON")
    parser.add_argument("--nogui", "--headless", dest="nogui", action="store_true",
                        help="Run headless (no GUI). Also enabled by NTN_HEADLESS=1.")
    parser.add_argument("--preflight", action="store_true",
                        help="Run preflight checks and exit (no services started)")
    parser.add_argument("--loglevel", default=None,
                        help="Override log level (DEBUG/INFO/WARNING/ERROR)")
    parser.add_argument("--version", action="version", version=f"NotTheNet {APP_VERSION}")
    args = parser.parse_args(argv)
    if os.environ.get("NTN_HEADLESS", "").strip().lower() in _TRUTHY:
        args.nogui = True
    return args


def _run(args: argparse.Namespace) -> int:
    from config import Config
    from utils.logging_utils import setup_logging

    cfg = Config(args.config)
    setup_logging(
        log_dir=cfg.get("general", "log_dir") or os.path.join(PROJECT_ROOT, "logs"),
        log_level=(args.loglevel or os.environ.get("NTN_LOG_LEVEL")
                   or cfg.get("general", "log_level") or "INFO"),
        log_to_file=bool(cfg.get("general", "log_to_file")),
        json_console=os.environ.get("NTN_JSON_LOGS", "").strip().lower() in _TRUTHY,
    )
    logging.getLogger(__name__).info("NotTheNet %s", APP_VERSION)

    if args.preflight:
        from utils.preflight import format_report, run_preflight

        print_banner()
        report = run_preflight(cfg)
        print(format_report(report))  # noqa: T201
        if report.failures:
            return 2
        return 1 if report.warnings else 0

    if args.nogui:
        import headless

        print_banner()
        return headless.run(cfg)

    from gui.app import run_gui

    run_gui(args.config)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        return _run(args)
    except Exception:
        # Last-resort record for GUI launches, where stderr is usually invisible.
        crash_log = os.path.join(PROJECT_ROOT, "logs", "notthenet-crash.log")
        try:
            os.makedirs(os.path.dirname(crash_log), exist_ok=True)
            with open(crash_log, "a", encoding="utf-8") as fh:
                fh.write(f"\n--- CRASH {datetime.datetime.now().astimezone().isoformat()} ---\n")
                traceback.print_exc(file=fh)
        except OSError:
            pass
        raise


if __name__ == "__main__":
    sys.exit(main())
