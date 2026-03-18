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
from typing import Optional

from utils.logging_utils import sanitize_log_string
from utils.validators import validate_port

logger = logging.getLogger(__name__)

_RULE_COMMENT = "NOTTHENET"
_IPTABLES_SAVE_FILE = os.path.join(tempfile.gettempdir(), "notthenet_iptables_save.rules")
_MANGLE_SAVE_FILE = os.path.join(tempfile.gettempdir(), "notthenet_mangle_save.rules")


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
            logger.debug(f"nat table snapshot saved to {_IPTABLES_SAVE_FILE}")
            return True
        except Exception as e:
            logger.error(f"Failed to save nat snapshot: {e}")
    return False


def _restore_nat_snapshot() -> bool:
    """Flush the nat table and restore the pre-start snapshot."""
    if not os.path.exists(_IPTABLES_SAVE_FILE):
        return False
    if not shutil.which("iptables-restore"):
        return False
    # Flush first so no stale rules survive a partial restore
    _run(["iptables", "-t", "nat", "-F"], check=False)
    code, _, err = _run(["iptables-restore", _IPTABLES_SAVE_FILE])
    if code == 0:
        logger.info("nat table restored from pre-start snapshot.")
        try:
            os.unlink(_IPTABLES_SAVE_FILE)
        except Exception:
            pass
        return True
    logger.error(f"iptables-restore failed: {err}")
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
            logger.debug(f"mangle table snapshot saved to {_MANGLE_SAVE_FILE}")
            return True
        except Exception as e:
            logger.error(f"Failed to save mangle snapshot: {e}")
    return False


def _restore_mangle_snapshot() -> bool:
    """Restore the mangle table from its pre-start snapshot."""
    if not os.path.exists(_MANGLE_SAVE_FILE):
        return False
    if not shutil.which("iptables-restore"):
        return False
    _run(["iptables", "-t", "mangle", "-F"], check=False)
    code, _, err = _run(["iptables-restore", _MANGLE_SAVE_FILE])
    if code == 0:
        logger.info("mangle table restored from pre-start snapshot.")
        try:
            os.unlink(_MANGLE_SAVE_FILE)
        except Exception:
            pass
        return True
    logger.error(f"mangle restore failed: {err}")
    return False


_IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


def _read_ip_forward() -> Optional[str]:
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
        self._filter_icmp_drop_applied = False
        self._prev_ip_forward: Optional[str] = None  # restored on stop

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
            if err.strip():
                logger.debug("iptables rule applied with warning: %s", err.strip())
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

        # --- Catch-all: redirect all OTHER UDP traffic to catch_all_udp_port ---
        _, cat_udp_port = validate_port(catch_all_udp_port)
        if cat_udp_port:
            for excl in excluded_ports:
                _, ep = validate_port(excl)
                if not ep:
                    continue
                rule = table_flag + [
                    "-A", chain,
                    "-p", "udp",
                    "--dport", str(ep),
                    "-j", "RETURN",
                    "-m", "comment", "--comment", _RULE_COMMENT,
                ]
                self._add_rule(rule)

            rule = table_flag + [
                "-A", chain,
                "-p", "udp",
                "-j", "REDIRECT", "--to-ports", str(cat_udp_port),
                "-m", "comment", "--comment", _RULE_COMMENT,
            ]
            if self._add_rule(rule):
                ok_count += 1

        # --- ICMP echo-request redirect (makes pings appear to succeed) ------
        # DNAT redirects all forwarded pings to this host so the kernel can
        # issue echo-replies naturally.  In loopback mode, redirect to
        # localhost; in gateway mode, redirect to redirect_ip.
        if icmp_enabled:
            icmp_target = (
                "127.0.0.1" if self.mode != "gateway" else self.redirect_ip
            )
            icmp_rule = table_flag + [
                "-A", chain,
                "-p", "icmp", "--icmp-type", "echo-request",
                "-j", "DNAT", "--to-destination", icmp_target,
                "-m", "comment", "--comment", _RULE_COMMENT,
            ]
            if self._add_rule(icmp_rule):
                ok_count += 1

        # --- Suppress ICMP destination-unreachable back to monitored hosts -------
        # When the kernel can't route a forwarded packet it generates an ICMP
        # type-3 "destination unreachable" from the gateway IP.  That origin
        # (the gateway itself) reveals the captive network to malware.  DROP
        # these silently so probes time out like a real firewall would.
        #
        # Use -I OUTPUT 1 (insert at position 1 / top of chain) rather than
        # -A (append) so the DROP fires before any ACCEPT rule that may already
        # exist in the OUTPUT chain.  If appended, a prior ACCEPT would allow
        # ICMP unreachables through, making the gateway IP visible again.
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
            ok_count += 1
            logger.info("ICMP destination-unreachable DROP rule applied.")
        else:
            logger.warning(
                "Failed to apply ICMP unreachable DROP rule: %s", err.strip()
            )

        # --- Enable ip_forward in gateway mode (required for PREROUTING DNAT) ---
        # Traffic from FlareVM to a foreign IP arrives on the bridge interface
        # and goes through the kernel forwarding path before DNAT rewrites it.
        # This is true even on a single-NIC bridge setup.
        if self.mode == "gateway":
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

        logger.info(
            f"Applied {ok_count} iptables NAT rules "
            f"(chain={chain}, mode={self.mode})"
        )

        # --- TTL spoofing (mangle table) ---
        # Setting TTL on outgoing packets makes them look like they’ve
        # traversed internet routing hops rather than being sourced locally.
        # Value 54 = 64 - 10 hops (typical Linux server with internet routing).
        # Requires xt_TTL kernel module; silently skipped if unavailable.
        if self.spoof_ttl > 0:
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
                    "TTL mangle rule failed — xt_TTL module may not be loaded "
                    "('modprobe xt_TTL' to enable): %s", err.strip()
                )

        return ok_count > 0

    def remove_rules(self):
        """Stop: restore the nat table to its pre-start state."""
        if os.geteuid() != 0:
            logger.warning("Cannot remove iptables rules: not root.")
            return

        if self._saved and _restore_nat_snapshot():
            # Snapshot restore also flushed the table — we're clean.
            self._rules_applied.clear()
            if self._prev_ip_forward is not None:
                if _write_ip_forward(self._prev_ip_forward):
                    logger.info("ip_forward restored to %s.", self._prev_ip_forward)
                self._prev_ip_forward = None
            # Restore mangle table even when nat snapshot succeeded
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
                _run(["iptables"] + ttl_del, check=False)
                self._ttl_rule_applied = False
                logger.info("TTL mangle rule removed.")
            # Remove filter DROP rule — not covered by the nat snapshot
            if self._filter_icmp_drop_applied:
                _run(["iptables", "-t", "filter", "-D", "OUTPUT",
                      "-p", "icmp", "--icmp-type", "destination-unreachable",
                      "-j", "DROP",
                      "-m", "comment", "--comment", _RULE_COMMENT], check=False)
                self._filter_icmp_drop_applied = False
                logger.info("ICMP destination-unreachable DROP rule removed.")
            return

        # No snapshot available (e.g. iptables-save was missing) — flush the
        # entire nat table.  In a lab this is safe; there are no rules we need
        # to preserve that aren't NotTheNet's own.
        logger.warning(
            "No nat snapshot available; flushing entire nat table as fallback."
        )
        _run(["iptables", "-t", "nat", "-F"], check=False)
        self._rules_applied.clear()
        logger.info("nat table flushed.")

        # Restore ip_forward to its previous value
        if self._prev_ip_forward is not None:
            if _write_ip_forward(self._prev_ip_forward):
                logger.info("ip_forward restored to %s.", self._prev_ip_forward)
            self._prev_ip_forward = None

        # Remove TTL mangle rule if we applied one
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
            _run(["iptables"] + ttl_del, check=False)
            self._ttl_rule_applied = False
            logger.info("TTL mangle rule removed.")

        # Remove filter DROP rule
        if self._filter_icmp_drop_applied:
            _run(["iptables", "-t", "filter", "-D", "OUTPUT",
                  "-p", "icmp", "--icmp-type", "destination-unreachable",
                  "-j", "DROP",
                  "-m", "comment", "--comment", _RULE_COMMENT], check=False)
            self._filter_icmp_drop_applied = False
            logger.info("ICMP destination-unreachable DROP rule removed.")



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



