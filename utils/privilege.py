"""
NotTheNet - Privilege Manager
Drops root privileges to a less-privileged user after binding low ports.

Security notes (OpenSSF):
- Binds privileged ports (< 1024) as root, then drops to nobody/nogroup
- Prevents malware being analyzed from leveraging root during service interaction
- Uses os.setgroups([]) to clear supplementary groups before dropping
- Uses seteuid/setegid (not setuid/setgid) so privileges can be temporarily
  restored for iptables cleanup on stop — the real UID stays root but the
  effective UID is unprivileged during normal operation
"""

import logging
import os

try:
    import grp
    import pwd
    _POSIX = True
except ImportError:
    # grp/pwd are Linux/macOS only — not available on Windows.
    # NotTheNet runs on Kali Linux; these are always present in production.
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]
    _POSIX = False

logger = logging.getLogger(__name__)

# Module-level state for reversible privilege drop
_dropped_uid: int | None = None
_dropped_gid: int | None = None


def drop_privileges(run_as_user: str = "nobody", run_as_group: str = "nogroup") -> bool:
    """
    Drop from root to a less-privileged user (reversible via seteuid/setegid).
    Must be called AFTER binding all ports that need root (port < 1024).

    Uses seteuid/setegid so the real UID remains root and privileges can be
    temporarily restored for cleanup operations (iptables teardown on stop).

    Args:
        run_as_user:  Target username to drop to.
        run_as_group: Target group name to drop to.

    Returns:
        True if successfully dropped, False if already unprivileged or failed.
    """
    global _dropped_uid, _dropped_gid
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        logger.debug("Not running as root; privilege drop skipped.")
        return False

    try:
        pw_entry = pwd.getpwnam(run_as_user)
        target_uid = pw_entry.pw_uid
        target_gid = grp.getgrnam(run_as_group).gr_gid
    except KeyError as e:
        logger.warning(
            f"Could not find user/group '{run_as_user}/{run_as_group}': {e}. "
            "Privilege drop skipped — consider creating a dedicated service account."
        )
        return False

    try:
        # Clear supplementary groups first
        os.setgroups([])
        # Set GID before UID (would lose permission to set GID after UID drop)
        os.setegid(target_gid)
        os.seteuid(target_uid)
        _dropped_uid = target_uid
        _dropped_gid = target_gid
        # Update HOME so Tkinter file dialogs don't try to navigate to the
        # original user's home dir, which the dropped-to user cannot access.
        new_home = pw_entry.pw_dir or "/"
        os.environ["HOME"] = new_home if os.path.isdir(new_home) else "/"
        # NOTE: do NOT chdir("/") here — the service manager ensures parent
        # directories have o+x before we drop, so the CWD remains accessible
        # and relative paths (logs/, config.json, certs/) continue to work.
        logger.info(
            "Privileges dropped to %s:%s (uid=%s, gid=%s)",
            run_as_user, run_as_group, target_uid, target_gid,
        )
        return True
    except OSError as e:
        logger.error("Failed to drop privileges: %s", e, exc_info=True)
        return False


def restore_privileges() -> bool:
    """Temporarily restore root (euid=0) for privileged cleanup operations.

    Only works after a prior ``drop_privileges()`` call that used seteuid.
    Call ``re_drop_privileges()`` when done to return to unprivileged state.
    """
    if not hasattr(os, "seteuid"):
        return False
    if os.geteuid() == 0:
        return True  # already root
    try:
        os.seteuid(0)
        os.setegid(0)
        logger.debug("Privileges temporarily restored to root for cleanup.")
        return True
    except OSError as e:
        logger.warning("Cannot restore root privileges: %s", e)
        return False


def re_drop_privileges() -> bool:
    """Re-drop to the user/group from the most recent ``drop_privileges()`` call."""
    if _dropped_uid is None or _dropped_gid is None:
        return False
    try:
        os.setegid(_dropped_gid)
        os.seteuid(_dropped_uid)
        logger.debug("Privileges re-dropped to uid=%s gid=%s.", _dropped_uid, _dropped_gid)
        return True
    except OSError as e:
        logger.warning("Failed to re-drop privileges: %s", e)
        return False


def is_root() -> bool:
    """Return True if the current process is running as root."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def require_root_or_warn() -> bool:
    """
    Warn the user if not running as root (needed for port 53, 80, 443 etc.)
    Returns True if root, False otherwise.
    """
    if not is_root():
        logger.warning(
            "NotTheNet is NOT running as root. Services on ports < 1024 "
            "(DNS:53, HTTP:80, HTTPS:443, SMTP:25) will fail to bind. "
            "Run with: sudo python notthenet.py"
        )
        return False
    return True
