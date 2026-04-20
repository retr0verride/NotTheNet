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

from __future__ import annotations

import atexit
import logging
import os
import shutil
import subprocess

from utils.logging_utils import sanitize_log_string
from utils.validators import validate_port

logger = logging.getLogger(__name__)

_RULE_COMMENT = "NOTTHENET"

# Store snapshots in the project's logs/ directory instead of /tmp/ to prevent
# symlink races on shared systems (CWE-59).  The logs/ directory is app-owned
# and already exists by the time iptables rules are applied.
_SNAPSHOT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
_IPTABLES_SAVE_FILE = os.path.join(_SNAPSHOT_DIR, ".iptables_save.rules")
_MANGLE_SAVE_FILE = os.path.join(_SNAPSHOT_DIR, ".mangle_save.rules")
_FILTER_SAVE_FILE = os.path.join(_SNAPSHOT_DIR, ".filter_save.rules")


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
            shell=False,  # NEVER shell=True — prevents injection
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error("Command timed out: %s", args[0])
        return 1, "", "timeout"
    except FileNotFoundError:
        logger.error("Command not found: %s", args[0])
        return 127, "", "not found"


def _iptables_available() -> bool:
    code, _, _ = _run(["iptables", "--version"])
    return code == 0


def _save_nat_snapshot() -> bool:
    """Snapshot the current nat table so it can be fully restored on stop."""
    if not shutil.which("iptables-save"):
        return False
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
        except Exception as e:
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
        except Exception:
            logger.debug("NAT snapshot cleanup failed", exc_info=True)
        return True
    logger.error("iptables-restore failed: %s", err)
    return False


def _save_mangle_snapshot() -> bool:
    """Snapshot the current mangle table before applying TTL rules."""
    if not shutil.which("iptables-save"):
        return False
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
        except Exception as e:
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
        except Exception:
            logger.debug("Mangle snapshot cleanup failed", exc_info=True)
        return True
    logger.error("mangle restore failed: %s", err)
    return False


def _save_filter_snapshot() -> bool:
    """Snapshot the current filter table before harden-lab rules are applied."""
    if not shutil.which("iptables-save"):
        return False
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
        except Exception as e:
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
        except Exception:
            logger.debug("Filter snapshot cleanup failed", exc_info=True)
        return True
    logger.error("filter restore failed: %s", err)
    return False


_IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


def _read_ip_forward() -> str | None:
    try:
        with open(_IP_FORWARD_PATH) as f:
            return f.read().strip()
    except OSError:
        return None


def _write_ip_forward(value: str) -> bool:
    try:
        with open(_IP_FORWARD_PATH, "w") as f:
            f.write(value + "\n")
        return True
    except OSError as e:
        logger.warning("Could not write ip_forward: %s", e)
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
        # When > 0, add a mangle POSTROUTING TTL rule so outgoing packets
        # appear to have traversed internet routing hops rather than being
        # served from a directly-connected host.
        raw_ttl = int(config.get("spoof_ttl", 0) or 0)
        if raw_ttl != 0 and not (1 <= raw_ttl <= 255):
            logger.warning(
                "spoof_ttl=%d is out of range [1-255]; TTL spoofing disabled.",
                raw_ttl,
            )
            raw_ttl = 0
        self.spoof_ttl = raw_ttl
        self._rules_applied: list[list[str]] = []
        self._saved = False
        self._ttl_rule_applied = False
        self._mangle_saved = False
        self._filter_saved = False
        self._filter_icmp_drop_applied = False
        self._prev_ip_forward: str | None = None  # restored on stop

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
            # Fail-closed: if we can't verify the interface exists, reject it.
            # A security tool should not apply iptables rules to a potentially
            # non-existent interface.
            logger.warning("Cannot read /proc/net/dev to verify interface '%s'", iface)
            return False

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
            if err.strip():
                logger.debug("iptables rule applied with warning: %s", err.strip())
            return True
        else:
            logger.warning("iptables rule failed (%s): %s", err.strip(), ' '.join(cmd))
            return False

    def _del_rule(self, rule: list[str]):
        """Remove a previously-added iptables rule."""
        # Replace -A (append) with -D (delete) to construct removal command
        del_rule = ["-D" if a == "-A" else a for a in rule]
        cmd = ["iptables"] + del_rule
        _run(cmd)

    def apply_rules(
        self,
        service_ports: dict,
        catch_all_tcp_port: int = 9999,
        catch_all_udp_port: int = 0,
        excluded_ports: list[int] | None = None,
        icmp_enabled: bool = False,
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

        self._saved = _save_nat_snapshot()
        self._filter_saved = _save_filter_snapshot()

        chain = "PREROUTING" if self.mode == "gateway" else "OUTPUT"
        table_flag = ["-t", "nat"]
        excluded_ports = excluded_ports or []

        ok_count = 0
        # Exempt established/related connections (e.g. DCOM callbacks for WMI)
        # so that tools running on Kali (impacket-wmiexec, smbclient) are not
        # redirected to NTN's fake services.
        conntrack_rule = table_flag + [
            "-I", chain, "1",
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "RETURN",
            "-m", "comment", "--comment", _RULE_COMMENT,
        ]
        self._add_rule(conntrack_rule)
        ok_count += self._apply_service_redirects(service_ports, chain, table_flag)

        ok_count += self._apply_catch_all(
            chain, table_flag, excluded_ports,
            catch_all_tcp_port, catch_all_udp_port,
        )

        ok_count += self._apply_icmp_redirect(chain, table_flag, icmp_enabled)
        ok_count += self._apply_icmp_drop()
        self._apply_ip_forward()

        logger.info(
            f"Applied {ok_count} iptables NAT rules "
            f"(chain={chain}, mode={self.mode})"
        )

        self._apply_ttl_mangle()

        return ok_count > 0

    # -- Extracted helpers for apply_rules (CC reduction) --------------------

    def _apply_service_redirects(
        self,
        service_ports: dict,
        chain: str,
        table_flag: list[str],
    ) -> int:
        """Add per-service DNAT redirect rules; return count of rules applied."""
        count = 0
        for proto, ports in service_ports.items():
            proto = proto.lower()
            if proto not in ("tcp", "udp"):
                logger.warning("Skipping unsupported protocol: %s", proto)
                continue
            for port in ports:
                if not validate_port(port):
                    continue
                rule = table_flag + [
                    "-A", chain,
                    "-p", proto, "--dport", str(port),
                    "-j", "DNAT", "--to-destination",
                    f"{self.redirect_ip}:{port}",
                    "-m", "comment", "--comment", _RULE_COMMENT,
                ]
                if self._add_rule(rule):
                    count += 1
        return count

    def _apply_catch_all(
        self,
        chain: str,
        table_flag: list[str],
        excluded_ports: list[int],
        catch_all_tcp_port: int,
        catch_all_udp_port: int,
    ) -> int:
        """Add catch-all TCP/UDP redirect rules; return count applied."""
        count = 0
        for proto, port in (("tcp", catch_all_tcp_port), ("udp", catch_all_udp_port)):
            if port <= 0:
                continue
            valid_excluded = [str(ep) for ep in excluded_ports if validate_port(ep)]
            # Add one RETURN rule per excluded port.  Using a single multiport
            # "! --dports" rule would hit the 15-port kernel limit with a typical
            # excluded_ports list; individual rules have no such restriction and
            # are tracked in _rules_applied for cleanup.
            for ep in valid_excluded:
                skip_rule = table_flag + [
                    "-A", chain, "-p", proto,
                    "--dport", ep,
                    "-j", "RETURN",
                    "-m", "comment", "--comment", _RULE_COMMENT,
                ]
                self._add_rule(skip_rule)
            # Catch-all DNAT: only reached if the packet didn't match any RETURN rule.
            rule = table_flag + [
                "-A", chain, "-p", proto,
                "-j", "DNAT", "--to-destination",
                f"{self.redirect_ip}:{port}",
                "-m", "comment", "--comment", _RULE_COMMENT,
            ]
            if self._add_rule(rule):
                count += 1
        return count

    def _apply_icmp_redirect(
        self, chain: str, table_flag: list[str], icmp_enabled: bool,
    ) -> int:
        """DNAT echo-requests so pings appear to succeed. Returns 0 or 1."""
        if not icmp_enabled:
            return 0
        icmp_target = (
            "127.0.0.1" if self.mode != "gateway" else self.redirect_ip
        )
        icmp_rule = table_flag + [
            "-A", chain,
            "-p", "icmp", "--icmp-type", "echo-request",
            "-j", "DNAT", "--to-destination", icmp_target,
            "-m", "comment", "--comment", _RULE_COMMENT,
        ]
        return 1 if self._add_rule(icmp_rule) else 0

    def _apply_icmp_drop(self) -> int:
        """DROP outbound ICMP destination-unreachable to hide the gateway."""
        icmp_drop_rule = [
            "-t", "filter",
            "-I", "OUTPUT", "1",
            "-p", "icmp", "--icmp-type", "destination-unreachable",
            "-j", "DROP",
            "-m", "comment", "--comment", _RULE_COMMENT,
        ]
        code, _, err = _run(["iptables"] + icmp_drop_rule)
        if code == 0:
            self._filter_icmp_drop_applied = True
            logger.info("ICMP destination-unreachable DROP rule applied.")
            return 1
        logger.warning(
            "Failed to apply ICMP unreachable DROP rule: %s", err.strip()
        )
        return 0

    def _apply_ip_forward(self) -> None:
        """Enable ip_forward when running in gateway mode."""
        if self.mode != "gateway":
            return
        prev = _read_ip_forward()
        if prev is not None and prev != "1":
            if _write_ip_forward("1"):
                self._prev_ip_forward = prev
                logger.info("ip_forward enabled for gateway mode (was %s).", prev)
            else:
                logger.warning(
                    "Could not enable ip_forward; pings and forwarded traffic "
                    "may not reach fake services."
                )
        elif prev == "1":
            logger.debug("ip_forward already enabled.")

    def _apply_ttl_mangle(self) -> None:
        """Apply TTL-spoofing mangle rule if spoof_ttl > 0."""
        if self.spoof_ttl <= 0:
            return
        self._mangle_saved = _save_mangle_snapshot()
        ttl_rule = [
            "-t", "mangle", "-A", "POSTROUTING",
            "-o", self.interface,
            "-j", "TTL", "--ttl-set", str(self.spoof_ttl),
            "-m", "comment", "--comment", _RULE_COMMENT,
        ]
        code, _, err = _run(["iptables"] + ttl_rule)
        if code == 0:
            self._ttl_rule_applied = True
            logger.info(
                "TTL mangle rule applied: outgoing TTL=%d "
                "(simulates %d routing hops).",
                self.spoof_ttl, 64 - self.spoof_ttl,
            )
        else:
            logger.warning(
                "TTL mangle rule failed -- xt_TTL module may not be loaded "
                "('modprobe xt_TTL' to enable): %s", err.strip()
            )

    def _remove_auxiliary_rules(self) -> None:
        """Remove TTL mangle + ICMP DROP rules (not covered by nat snapshot)."""
        if self._mangle_saved:
            _restore_mangle_snapshot()
            self._mangle_saved = False
        elif self._ttl_rule_applied:
            ttl_del = [
                "-t", "mangle", "-D", "POSTROUTING",
                "-o", self.interface,
                "-j", "TTL", "--ttl-set", str(self.spoof_ttl),
                "-m", "comment", "--comment", _RULE_COMMENT,
            ]
            code, _, err = _run(["iptables"] + ttl_del)
            if code == 0:
                self._ttl_rule_applied = False
                logger.info("TTL mangle rule removed.")
            else:
                logger.warning("Failed to remove TTL mangle rule: %s", err.strip())
        if self._filter_icmp_drop_applied:
            code, _, err = _run(["iptables", "-t", "filter", "-D", "OUTPUT",
                  "-p", "icmp", "--icmp-type", "destination-unreachable",
                  "-j", "DROP",
                  "-m", "comment", "--comment", _RULE_COMMENT])
            if code == 0:
                self._filter_icmp_drop_applied = False
                logger.info("ICMP destination-unreachable DROP rule removed.")
            else:
                logger.warning("Failed to remove ICMP DROP rule: %s", err.strip())

    def remove_rules(self):
        """Stop: restore the nat table to its pre-start state."""
        escalated = False
        if os.geteuid() != 0:
            from utils.privilege import restore_privileges
            escalated = restore_privileges()
            if not escalated:
                logger.warning(
                    "Cannot remove iptables rules: not root and cannot restore privileges."
                )
                return

        try:
            if self._saved and _restore_nat_snapshot():
                self._rules_applied.clear()
            else:
                logger.warning(
                    "No nat snapshot available; flushing entire nat table as fallback."
                )
                _run(["iptables", "-t", "nat", "-F"])
                self._rules_applied.clear()
                logger.info("nat table flushed.")

            if self._filter_saved and _restore_filter_snapshot():
                self._filter_saved = False
            else:
                logger.debug("No filter snapshot available; skipping filter restore.")

            # Restore ip_forward
            if self._prev_ip_forward is not None:
                if _write_ip_forward(self._prev_ip_forward):
                    logger.info("ip_forward restored to %s.", self._prev_ip_forward)
                self._prev_ip_forward = None

            self._remove_auxiliary_rules()
        finally:
            if escalated:
                from utils.privilege import re_drop_privileges
                re_drop_privileges()

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



