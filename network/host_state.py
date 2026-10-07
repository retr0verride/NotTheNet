"""
NotTheNet - Host state that NotTheNet changes and must put back.

Saves and restores the iptables nat/mangle/filter tables, net.ipv4.ip_forward
and interface promiscuous mode. Snapshots live in a root-owned state/ dir.
An atexit hook restores anything still outstanding if the process exits
without a clean stop; systemd's ExecStopPost covers SIGKILL.

Security notes (OpenSSF):
- subprocess is called with a list (never shell=True), so no shell injection
- Snapshot dir is 0700 root and never chowned to the privilege-drop user
"""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)

_PROC_NET_DEV = "/proc/net/dev"


# Store snapshots in a root-owned state/ directory, NOT logs/.  logs/ is chowned
# to the unprivileged drop user (nobody), so a post-drop compromise could
# overwrite the snapshot that systemd's ExecStopPost feeds to `iptables-restore`
# as root.  state/ is created 0700 root and is never chowned to the drop user.
# Keeping it under the project root (not /tmp/) also avoids symlink races (CWE-59).
_SNAPSHOT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state")
_IPTABLES_SAVE_FILE = os.path.join(_SNAPSHOT_DIR, ".iptables_save.rules")
_MANGLE_SAVE_FILE = os.path.join(_SNAPSHOT_DIR, ".mangle_save.rules")
_FILTER_SAVE_FILE = os.path.join(_SNAPSHOT_DIR, ".filter_save.rules")

# Tracks interfaces whose promisc state was changed at start so atexit can
# restore them if remove_rules() is never called (crash / SIGABRT).
# Maps {iface_name: original_bool}.
_promisc_restore: dict[str, bool] = {}


def _atexit_restore_snapshots() -> None:
    """Last-resort iptables cleanup when the process exits without a clean shutdown.

    If snapshot files still exist at exit, the normal remove_rules() path
    was never called (e.g. unhandled exception, SIGABRT).  Restore them
    now so the lab doesn't keep stale NAT redirects pointing at dead ports.
    SIGKILL cannot be caught — the systemd ExecStopPost handles that case.
    """
    for table, path in [("nat", _IPTABLES_SAVE_FILE),
                        ("mangle", _MANGLE_SAVE_FILE),
                        ("filter", _FILTER_SAVE_FILE)]:
        if os.path.exists(path) and shutil.which("iptables-restore"):
            _run(["iptables", "-t", table, "-F"])
            code, _, err = _run(["iptables-restore", path])
            if code == 0:
                logger.info("atexit: %s table restored from snapshot.", table)
                try:
                    os.unlink(path)
                except OSError:
                    pass
            else:
                logger.error("atexit: %s restore failed: %s", table, err)

    # Restore any promiscuous-mode state that remove_rules() didn't clean up.
    _atexit_restore_promisc()


def _atexit_restore_promisc() -> None:
    """Restore promisc state for any interfaces changed at start but not yet restored."""
    for iface, was_on in _promisc_restore.items():
        if _set_promisc(iface, was_on):
            logger.info("atexit: promisc restored to %s on %s.", "on" if was_on else "off", iface)
    _promisc_restore.clear()


atexit.register(_atexit_restore_snapshots)


def _run(args: list[str]) -> tuple[int, str, str]:
    """
    Run a subprocess command safely (no shell=True).
    Returns (returncode, stdout, stderr).
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,  # returncode handled by callers
            shell=False,  # NEVER shell=True — prevents injection
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error("Command timed out: %s", args[0])
        return 1, "", "timeout"
    except FileNotFoundError:
        logger.error("Command not found: %s", args[0])
        return 127, "", "not found"


def _ensure_snapshot_dir() -> None:
    """Create the root-owned snapshot dir (0700) if absent.

    Snapshots are written here as root before the privilege drop; the dir is
    never chowned to the drop user, so a post-drop compromise cannot tamper with
    what ``ExecStopPost`` later restores as root.
    """
    try:
        os.makedirs(_SNAPSHOT_DIR, mode=0o700, exist_ok=True)
    except OSError as e:
        logger.warning("Could not create snapshot dir %s: %s", _SNAPSHOT_DIR, e)


def _save_nat_snapshot() -> bool:
    """Snapshot the current nat table so it can be fully restored on stop."""
    if not shutil.which("iptables-save"):
        return False
    _ensure_snapshot_dir()
    code, out, _ = _run(["iptables-save", "-t", "nat"])
    if code == 0:
        try:
            # Use os.open with O_CREAT|O_WRONLY|O_TRUNC and mode 0o600 in a
            # single atomic call to avoid the TOCTOU race between open() and
            # a subsequent chmod().  This prevents another process from opening
            # the file in the window between creation and permission tightening.
            fd = os.open(
                _IPTABLES_SAVE_FILE,
                os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
                0o600,
            )
            try:
                os.write(fd, out.encode())
            finally:
                os.close(fd)
            logger.debug("nat table snapshot saved to %s", _IPTABLES_SAVE_FILE)
            return True
        except OSError as e:
            logger.error("Failed to save nat snapshot: %s", e)
    return False


def _restore_nat_snapshot() -> bool:
    """Flush the nat table and restore the pre-start snapshot."""
    if not os.path.exists(_IPTABLES_SAVE_FILE):
        return False
    if not shutil.which("iptables-restore"):
        return False
    # Flush first so no stale rules survive a partial restore
    _run(["iptables", "-t", "nat", "-F"])
    code, _, err = _run(["iptables-restore", _IPTABLES_SAVE_FILE])
    if code == 0:
        logger.info("nat table restored from pre-start snapshot.")
        try:
            os.unlink(_IPTABLES_SAVE_FILE)
        except OSError:
            logger.debug("NAT snapshot cleanup failed", exc_info=True)
        return True
    logger.error("iptables-restore failed: %s", err)
    return False


def _save_mangle_snapshot() -> bool:
    """Snapshot the current mangle table before applying TTL rules."""
    if not shutil.which("iptables-save"):
        return False
    _ensure_snapshot_dir()
    code, out, _ = _run(["iptables-save", "-t", "mangle"])
    if code == 0:
        try:
            fd = os.open(
                _MANGLE_SAVE_FILE,
                os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
                0o600,
            )
            try:
                os.write(fd, out.encode())
            finally:
                os.close(fd)
            logger.debug("mangle table snapshot saved to %s", _MANGLE_SAVE_FILE)
            return True
        except OSError as e:
            logger.error("Failed to save mangle snapshot: %s", e)
    return False


def _restore_mangle_snapshot() -> bool:
    """Restore the mangle table from its pre-start snapshot."""
    if not os.path.exists(_MANGLE_SAVE_FILE):
        return False
    if not shutil.which("iptables-restore"):
        return False
    _run(["iptables", "-t", "mangle", "-F"])
    code, _, err = _run(["iptables-restore", _MANGLE_SAVE_FILE])
    if code == 0:
        logger.info("mangle table restored from pre-start snapshot.")
        try:
            os.unlink(_MANGLE_SAVE_FILE)
        except OSError:
            logger.debug("Mangle snapshot cleanup failed", exc_info=True)
        return True
    logger.error("mangle restore failed: %s", err)
    return False


def _save_filter_snapshot() -> bool:
    """Snapshot the current filter table before harden-lab rules are applied."""
    if not shutil.which("iptables-save"):
        return False
    _ensure_snapshot_dir()
    code, out, _ = _run(["iptables-save", "-t", "filter"])
    if code == 0:
        try:
            fd = os.open(
                _FILTER_SAVE_FILE,
                os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
                0o600,
            )
            try:
                os.write(fd, out.encode())
            finally:
                os.close(fd)
            logger.debug("filter table snapshot saved to %s", _FILTER_SAVE_FILE)
            return True
        except OSError as e:
            logger.error("Failed to save filter snapshot: %s", e)
    return False


def _restore_filter_snapshot() -> bool:
    """Restore the filter table from its pre-start snapshot."""
    if not os.path.exists(_FILTER_SAVE_FILE):
        return False
    if not shutil.which("iptables-restore"):
        return False
    _run(["iptables", "-t", "filter", "-F"])
    code, _, err = _run(["iptables-restore", _FILTER_SAVE_FILE])
    if code == 0:
        logger.info("filter table restored from pre-start snapshot.")
        try:
            os.unlink(_FILTER_SAVE_FILE)
        except OSError:
            logger.debug("Filter snapshot cleanup failed", exc_info=True)
        return True
    logger.error("filter restore failed: %s", err)
    return False


_IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


def _read_ip_forward() -> str | None:
    try:
        with open(_IP_FORWARD_PATH, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def _write_ip_forward(value: str) -> bool:
    try:
        with open(_IP_FORWARD_PATH, "w", encoding="utf-8") as f:
            f.write(value + "\n")
        return True
    except OSError as e:
        logger.warning("Could not write ip_forward: %s", e)
        return False


def _read_promisc(iface: str) -> bool | None:
    """Return current promiscuous-mode state for *iface*, or None on error.

    Reads the IFF_PROMISC bit (0x100) from /sys/class/net/<iface>/flags.
    Only meaningful on Linux; returns None on non-Linux hosts.
    """
    try:
        with open(f"/sys/class/net/{iface}/flags", encoding="utf-8") as f:
            flags = int(f.read().strip(), 16)
        return bool(flags & 0x100)
    except OSError:
        return None


def _set_promisc(iface: str, enabled: bool) -> bool:
    """Enable or disable promiscuous mode on *iface* via `ip link set`.

    Returns True on success.  Uses the `ip` command (no shell=True).
    """
    state = "on" if enabled else "off"
    code, _, err = _run(["ip", "link", "set", iface, "promisc", state])
    if code == 0:
        return True
    logger.warning("Could not set promisc %s on %s: %s", state, iface, err.strip())
    return False
