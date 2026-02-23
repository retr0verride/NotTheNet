"""
NotTheNet - Privilege Manager
Drops root privileges to a less-privileged user after binding low ports.

Security notes (OpenSSF):
- Binds privileged ports (< 1024) as root, then drops to nobody/nogroup
- Prevents malware being analyzed from leveraging root during service interaction
- Uses os.setgroups([]) to clear supplementary groups before dropping
"""

import logging
import os
import pwd
import grp

logger = logging.getLogger(__name__)


def drop_privileges(run_as_user: str = "nobody", run_as_group: str = "nogroup") -> bool:
    """
    Drop from root to a less-privileged user.
    Must be called AFTER binding all ports that need root (port < 1024).

    Args:
        run_as_user:  Target username to drop to.
        run_as_group: Target group name to drop to.

    Returns:
        True if successfully dropped, False if already unprivileged or failed.
    """
    if os.geteuid() != 0:
        logger.debug("Not running as root; privilege drop skipped.")
        return False

    try:
        target_gid = grp.getgrnam(run_as_group).gr_gid
        target_uid = pwd.getpwnam(run_as_user).pw_uid
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
        os.setgid(target_gid)
        os.setuid(target_uid)
        logger.info(
            f"Privileges dropped to {run_as_user}:{run_as_group} "
            f"(uid={target_uid}, gid={target_gid})"
        )
        return True
    except OSError as e:
        logger.error(f"Failed to drop privileges: {e}", exc_info=True)
        return False


def is_root() -> bool:
    """Return True if the current process is running as root."""
    return os.geteuid() == 0


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
