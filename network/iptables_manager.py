"""
NotTheNet - iptables / nftables Rule Manager
Redirects all outbound traffic from monitored processes to local fake services.

Why this avoids INetSim / FakeNet-NG DNS problems:
- We redirect at the network level BEFORE DNS resolution completes
- DNS (port 53) is redirected to our fake DNS which resolves → 127.0.0.1
- All other TCP/UDP traffic is then caught by the catch-all service
- Rules are applied to the OUTPUT/PREROUTING chains based on mode
- All rules are tagged with the NOTTHENET comment for clean removal

Security notes (OpenSSF):
- subprocess is called with a list (never shell=True) — no shell injection
- All arguments are validated before passing to subprocess
- Original rules are saved and restored on stop — no lingering state
- Privilege is checked before attempting iptables operations
"""

import logging
import os
import shutil
import subprocess
import tempfile

from utils.logging_utils import sanitize_log_string
from utils.validators import validate_port

logger = logging.getLogger(__name__)

_RULE_COMMENT = "NOTTHENET"
_IPTABLES_SAVE_FILE = os.path.join(tempfile.gettempdir(), "notthenet_iptables_save.rules")


def _run(args: list[str], check: bool = True) -> tuple[int, str, str]:
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
            shell=False,  # NEVER shell=True — prevents injection
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {args[0]}")
        return 1, "", "timeout"
    except FileNotFoundError:
        logger.error(f"Command not found: {args[0]}")
        return 127, "", "not found"


def _iptables_available() -> bool:
    code, _, _ = _run(["iptables", "--version"])
    return code == 0


def _save_rules() -> bool:
    """Save current iptables rules for restoration on cleanup."""
    if not shutil.which("iptables-save"):
        return False
    code, out, err = _run(["iptables-save"])
    if code == 0:
        try:
            with open(_IPTABLES_SAVE_FILE, "w") as f:
                f.write(out)
            os.chmod(_IPTABLES_SAVE_FILE, 0o600)
            logger.debug(f"iptables rules saved to {_IPTABLES_SAVE_FILE}")
            return True
        except Exception as e:
            logger.error(f"Failed to save iptables rules: {e}")
    return False


def _restore_rules() -> bool:
    """Restore iptables rules from saved snapshot."""
    if not os.path.exists(_IPTABLES_SAVE_FILE):
        return False
    if not shutil.which("iptables-restore"):
        return False
    code, _, err = _run(["iptables-restore", _IPTABLES_SAVE_FILE])
    if code == 0:
        logger.info("iptables rules restored from snapshot.")
        try:
            os.unlink(_IPTABLES_SAVE_FILE)
        except Exception:
            pass
        return True
    logger.error(f"iptables-restore failed: {err}")
    return False


class IPTablesManager:
    """
    Manages iptables rules to redirect traffic to fake services.

    Mode 'loopback' (default):
        Redirects OUTPUT traffic → 127.0.0.1 (local analysis only).

    Mode 'gateway':
        Redirects PREROUTING traffic → local services
        (for use as a network gateway/transparent proxy).
    """

    def __init__(self, config: dict):
        self.enabled = config.get("auto_iptables", True)
        self.interface = config.get("interface", "eth0")
        self.redirect_ip = config.get("redirect_ip", "127.0.0.1")
        self.mode = config.get("iptables_mode", "loopback")
        self._rules_applied: list[list[str]] = []
        self._saved = False

    def _validate_interface(self, iface: str) -> bool:
        """Validate interface name against /proc/net/dev."""
        import re
        if not re.match(r"^[a-zA-Z0-9_\-\.]{1,15}$", iface):
            return False
        # Check it actually exists
        try:
            with open("/proc/net/dev") as f:
                ifaces_raw = f.read()
            return iface in ifaces_raw
        except Exception:
            return True  # /proc not available, assume valid

    def _add_rule(self, rule: list[str]) -> bool:
        """Add an iptables rule and track it for removal."""
        # Validate all args are strings
        if not all(isinstance(a, str) for a in rule):
            logger.error("iptables rule contains non-string argument; skipping.")
            return False

        cmd = ["iptables"] + rule
        code, _, err = _run(cmd)
        if code == 0:
            self._rules_applied.append(rule)
            return True
        else:
            logger.warning(f"iptables rule failed ({err.strip()}): {' '.join(cmd)}")
            return False

    def _del_rule(self, rule: list[str]):
        """Remove a previously-added iptables rule."""
        # Replace -A (append) with -D (delete) to construct removal command
        del_rule = ["-D" if a == "-A" else a for a in rule]
        cmd = ["iptables"] + del_rule
        _run(cmd, check=False)

    def apply_rules(
        self,
        service_ports: dict,
        catch_all_tcp_port: int = 9999,
        excluded_ports: list[int] = None,
    ) -> bool:
        """
        Apply iptables redirect rules.

        Args:
            service_ports: dict of {proto: port}, e.g. {"tcp": [80, 443, 25], "udp": [53]}
            catch_all_tcp_port: TCP port for the catch-all service
            excluded_ports: ports to EXCLUDE from catch-all redirect (e.g. [22])
        """
        if not self.enabled:
            logger.info("Auto-iptables disabled in config; skipping.")
            return False

        if os.geteuid() != 0:
            logger.warning(
                "Not running as root; iptables rules cannot be applied. "
                "Run with sudo or set auto_iptables=false and configure routing manually."
            )
            return False

        if not _iptables_available():
            logger.error("iptables not found; cannot apply network rules.")
            return False

        if not self._validate_interface(self.interface):
            logger.error(
                f"Interface '{sanitize_log_string(self.interface)}' not found; "
                "check config general.interface."
            )
            return False

        self._saved = _save_rules()

        chain = "PREROUTING" if self.mode == "gateway" else "OUTPUT"
        table_flag = ["-t", "nat"]
        excluded_ports = excluded_ports or []

        ok_count = 0

        # --- Redirect known service ports ---
        for proto, ports in service_ports.items():
            for port in ports:
                port_ok, port_int = validate_port(port)
                if not port_ok:
                    continue
                rule = table_flag + [
                    "-A", chain,
                    "-p", proto,
                    "--dport", str(port_int),
                    "-j", "REDIRECT", "--to-ports", str(port_int),
                    "-m", "comment", "--comment", _RULE_COMMENT,
                ]
                if self._add_rule(rule):
                    ok_count += 1

        # --- Catch-all: redirect all OTHER TCP traffic to catch_all_tcp_port ---
        for excl in excluded_ports:
            _, ep = validate_port(excl)
            if not ep:
                continue
            rule = table_flag + [
                "-A", chain,
                "-p", "tcp",
                "--dport", str(ep),
                "-j", "RETURN",
                "-m", "comment", "--comment", _RULE_COMMENT,
            ]
            self._add_rule(rule)

        _, cat_port = validate_port(catch_all_tcp_port)
        if cat_port:
            rule = table_flag + [
                "-A", chain,
                "-p", "tcp",
                "-j", "REDIRECT", "--to-ports", str(cat_port),
                "-m", "comment", "--comment", _RULE_COMMENT,
            ]
            if self._add_rule(rule):
                ok_count += 1

        logger.info(
            f"Applied {ok_count} iptables NAT rules "
            f"(chain={chain}, mode={self.mode})"
        )
        return ok_count > 0

    def remove_rules(self):
        """Remove all rules applied by this session."""
        if not self._rules_applied:
            return
        if os.geteuid() != 0:
            logger.warning("Cannot remove iptables rules: not root.")
            return

        # Prefer full restore if we saved rules
        if self._saved and _restore_rules():
            self._rules_applied.clear()
            return

        # Otherwise delete each rule individually
        for rule in reversed(self._rules_applied):
            self._del_rule(rule)
        count = len(self._rules_applied)
        self._rules_applied.clear()
        logger.info(f"Removed {count} iptables rules.")

    @staticmethod
    def list_notthenet_rules() -> list[str]:
        """Return all currently active NotTheNet iptables NAT rules."""
        code, out, _ = _run(["iptables", "-t", "nat", "-L", "--line-numbers", "-n"])
        if code != 0:
            return []
        return [
            line for line in out.splitlines()
            if _RULE_COMMENT in line
        ]
