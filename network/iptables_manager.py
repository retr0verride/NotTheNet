"""NotTheNet - iptables / nftables Rule Manager
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

import logging
import os

from network.host_state import (
    _PROC_NET_DEV,
    _promisc_restore,
    _read_ip_forward,
    _read_promisc,
    _restore_filter_snapshot,
    _restore_mangle_snapshot,
    _restore_nat_snapshot,
    _run,
    _save_filter_snapshot,
    _save_mangle_snapshot,
    _save_nat_snapshot,
    _set_promisc,
    _write_ip_forward,
)
from network.iface_watcher import (
    _NetlinkInterfaceWatcher,
)
from utils.logging_utils import sanitize_log_string
from utils.validators import validate_ip, validate_port

logger = logging.getLogger(__name__)


_RULE_COMMENT = "NOTTHENET"


def _iptables_available() -> bool:
    code, _, _ = _run(["iptables", "--version"])
    return code == 0


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
        self.mode = config.get("iptables_mode", "loopback")
        self.promisc_mode: bool = bool(config.get("promisc_mode", False))
        # Interface: autodetect when blank or when configured value doesn't
        # exist on this host.  Avoids the classic install footgun where a
        # config shipped from one environment (vmbr1, ens33, wlan0, ...) is
        # invalid on the next.
        configured_iface = (config.get("interface") or "").strip()
        # Only attempt autodetect on Linux (where /proc/net/dev exists and
        # `ip` is available).  Off-Linux (tests on Windows/macOS) trust the
        # configured value as-is — runtime validation will catch real errors.
        if not os.path.exists(_PROC_NET_DEV):
            self.interface = configured_iface or "eth0"
        elif configured_iface and self._validate_interface(configured_iface):
            self.interface = configured_iface
        else:
            detected = self._detect_default_interface()
            if detected:
                if configured_iface:
                    logger.warning(
                        "Configured interface '%s' not found; "
                        "auto-detected '%s' from default route.",
                        sanitize_log_string(configured_iface), detected,
                    )
                else:
                    logger.info("Interface auto-detected: %s", detected)
                self.interface = detected
            else:
                # No usable interface found; keep configured value so the
                # later validation in apply_rules surfaces a clean error.
                self.interface = configured_iface or "eth0"
        bind_ip = config.get("bind_ip", "0.0.0.0")
        configured_redirect = config.get("redirect_ip", "")
        # In gateway mode, DNAT must rewrite victim packets to a *real*
        # interface IP — not 127.0.0.1.  Linux drops cross-interface packets
        # routed to loopback unless route_localnet=1, and even then it breaks
        # transparent-proxy semantics for the victim.  Auto-derive the right
        # target so a single IP edit (bind_ip) is sufficient for gateway labs.
        # Sentinels that trigger auto-derive: "", "auto", "127.0.0.1", "0.0.0.0".
        if self.mode == "gateway" and configured_redirect in ("", "auto", "127.0.0.1", "0.0.0.0"):
            derived = self._derive_gateway_ip(bind_ip)
            if derived:
                logger.info(
                    "gateway mode: redirect_ip auto-derived to %s "
                    "(configured value %s is unreachable from victim)",
                    derived, configured_redirect,
                )
                self.redirect_ip = derived
            else:
                logger.warning(
                    "gateway mode but cannot derive a routable redirect_ip "
                    "(bind_ip=%s, interface=%s); victim traffic will not reach services.",
                    bind_ip, self.interface,
                )
                # Fall back to loopback to avoid passing empty string to iptables.
                self.redirect_ip = configured_redirect or "127.0.0.1"
        else:
            # Non-gateway (loopback) mode: empty string would break iptables;
            # default to loopback which is what loopback mode wants anyway.
            self.redirect_ip = configured_redirect or "127.0.0.1"
        # Final boundary check: redirect_ip is interpolated into iptables
        # --to-destination, so revalidate it regardless of how it was derived.
        ok, norm = validate_ip(self.redirect_ip)
        if ok:
            self.redirect_ip = norm
        else:
            logger.warning(
                "redirect_ip %r is not a valid IP; falling back to 127.0.0.1",
                sanitize_log_string(str(self.redirect_ip)),
            )
            self.redirect_ip = "127.0.0.1"
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
        # Subnets whose traffic bypasses DNAT redirect rules (RETURN inserted
        # before service rules in PREROUTING/OUTPUT).  Enables victim-to-victim
        # spread in a lab where bridge-nf-call-iptables=1 routes intra-bridge
        # packets through iptables.
        raw_subnets: list = config.get("passthrough_subnets", []) or []
        self.passthrough_subnets: list[str] = [
            s for s in raw_subnets if isinstance(s, str) and self._valid_cidr(s)
        ]
        skipped = len(raw_subnets) - len(self.passthrough_subnets)
        if skipped:
            logger.warning(
                "passthrough_subnets: %d entry/entries rejected (invalid CIDR).",
                skipped,
            )
        self._rules_applied: list[list[str]] = []
        self._saved = False
        self._ttl_rule_applied = False
        self._mangle_saved = False
        self._filter_saved = False
        self._filter_icmp_drop_applied = False
        self._prev_ip_forward: str | None = None  # restored on stop
        self._prev_promisc: bool | None = None    # restored on stop
        self._iface_watcher: _NetlinkInterfaceWatcher | None = None

    def _derive_gateway_ip(self, bind_ip: str) -> str | None:
        """Pick a routable IP for DNAT targets in gateway mode.

        Prefers an explicit `bind_ip` other than 0.0.0.0/127.0.0.1.  Otherwise
        falls back to the first global IPv4 on `self.interface`, then to any
        non-loopback IPv4 on the host.  Returns None if nothing is usable.
        """
        if bind_ip and bind_ip not in ("0.0.0.0", "127.0.0.1"):
            return bind_ip
        # Try the configured/detected interface first so multi-homed hosts
        # don't pick an unrelated address.
        iface_ip = self._first_ipv4_on(self.interface) if self.interface else None
        if iface_ip:
            return iface_ip
        return self._first_ipv4_on(None)

    @staticmethod
    def _first_ipv4_on(iface: str | None) -> str | None:
        """Return the first global IPv4 on `iface` (or any iface if None)."""
        ip_cidr = IPTablesManager._first_ipv4_cidr_on(iface)
        return ip_cidr.split("/", 1)[0] if ip_cidr else None

    @staticmethod
    def _first_ipv4_cidr_on(iface: str | None) -> str | None:
        """Return the first global IPv4 with prefix on `iface` (e.g. '10.10.10.1/24')."""
        cmd = ["ip", "-4", "-o", "addr", "show", "scope", "global"]
        if iface:
            cmd += ["dev", iface]
        try:
            code, out, _ = _run(cmd)
            if code != 0:
                return None
            for line in out.splitlines():
                # Format: "2: eth0    inet 10.10.10.1/24 brd ..."
                parts = line.split()
                if "inet" in parts:
                    cidr = parts[parts.index("inet") + 1]
                    if cidr and not cidr.startswith("127."):
                        return cidr
        except OSError:
            return None
        return None

    @staticmethod
    def _network_cidr(host_cidr: str) -> str | None:
        """Convert a host CIDR like '10.10.10.1/24' into the network CIDR
        '10.10.10.0/24'. Returns None on parse failure."""
        try:
            import ipaddress
            net = ipaddress.ip_network(host_cidr, strict=False)
            return str(net)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _detect_default_interface() -> str | None:
        """Return the interface used by the host's default IPv4 route, or None."""
        try:
            code, out, _ = _run(["ip", "-4", "route", "show", "default"])
            if code != 0:
                return None
            # Format: "default via 10.10.10.254 dev eth0 proto ..."
            for line in out.splitlines():
                parts = line.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
        except OSError:
            return None
        return None

    @staticmethod
    def _valid_cidr(cidr: str) -> bool:
        """Return True if *cidr* is a valid IPv4 CIDR string (e.g. '10.10.10.0/24')."""
        import re
        m = re.match(
            r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$", cidr
        )
        if not m:
            return False
        octets = [int(m.group(i)) for i in range(1, 5)]
        prefix = int(m.group(5))
        return all(0 <= o <= 255 for o in octets) and 0 <= prefix <= 32

    def _validate_interface(self, iface: str) -> bool:
        """Validate interface name against /proc/net/dev."""
        import re
        if not re.match(r"^[a-zA-Z0-9_\-\.]{1,15}$", iface):
            return False
        # Check it actually exists
        try:
            with open(_PROC_NET_DEV, encoding="utf-8") as f:
                ifaces_raw = f.read()
            return iface in ifaces_raw
        except OSError:
            # Fail-closed: if we can't verify the interface exists, reject it.
            # A security tool should not apply iptables rules to a potentially
            # non-existent interface.
            logger.warning("Cannot read %s to verify interface '%s'", _PROC_NET_DEV, iface)
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

        if os.geteuid() != 0:  # type: ignore[attr-defined]
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
                "Interface '%s' not found; check config general.interface.",
                sanitize_log_string(self.interface),
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
        ok_count += self._apply_passthrough_subnets(chain, table_flag)
        ok_count += self._apply_service_redirects(service_ports, chain, table_flag)

        ok_count += self._apply_catch_all(
            chain, table_flag, excluded_ports,
            catch_all_tcp_port, catch_all_udp_port,
        )

        ok_count += self._apply_icmp_redirect(chain, table_flag, icmp_enabled)
        ok_count += self._apply_icmp_drop()
        self._apply_ip_forward()
        self._apply_extra_pivot_blocks()
        self._apply_promisc()
        self._start_iface_watcher()

        logger.info(
            "Applied %d iptables NAT rules (chain=%s, mode=%s)",
            ok_count, chain, self.mode,
        )

        self._apply_ttl_mangle()

        return ok_count > 0

    # -- Extracted helpers for apply_rules (CC reduction) --------------------

    def _apply_passthrough_subnets(
        self,
        chain: str,
        table_flag: list[str],
    ) -> int:
        """Insert RETURN rules for passthrough_subnets before any DNAT rules.

        Traffic where BOTH source and destination are inside one of these
        CIDRs skips all NTN redirection and is forwarded normally.  The
        primary use case is allowing victim-to-victim SMB/RDP/lateral spread
        in a Proxmox lab where bridge-nf-call-iptables=1 routes intra-bridge
        packets through iptables.

        We require BOTH `-s` and `-d` to match so that victim->Kali traffic
        (where dst is Kali, also inside the LAN CIDR) is still caught by
        NTN's DNAT rules.  Earlier versions used dst-only RETURN, which
        accidentally exempted victim->Kali probes from NTN.

        In gateway mode, if `passthrough_subnets` is empty, auto-derive the
        LAN CIDR from the gateway interface so worm-style /24 scans spread
        out-of-the-box without operator config.
        """
        subnets = list(self.passthrough_subnets)
        if self.mode == "gateway" and not subnets:
            host_cidr = self._first_ipv4_cidr_on(self.interface)
            net_cidr = self._network_cidr(host_cidr) if host_cidr else None
            if net_cidr:
                subnets = [net_cidr]
                logger.info(
                    "Auto-derived passthrough_subnet %s from interface %s "
                    "(intra-LAN traffic will bypass DNAT to enable lateral "
                    "spread between victims).",
                    net_cidr, self.interface,
                )
        count = 0
        for cidr in subnets:
            rule = table_flag + [
                "-I", chain, "2",
                "-s", cidr,
                "-d", cidr,
                "-j", "RETURN",
                "-m", "comment", "--comment", _RULE_COMMENT,
            ]
            if self._add_rule(rule):
                count += 1
                logger.info(
                    "Passthrough (no DNAT) for intra-LAN %s via %s chain.",
                    cidr, chain,
                )
        return count

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

    def _apply_extra_pivot_blocks(self) -> None:
        """In gateway mode, DROP FORWARD between the lab bridge and every
        other routable interface present at start time.

        harden-lab.sh only covers interfaces that are up *before* it runs.
        Interfaces that come up afterwards (e.g. vmbr2 on Proxmox) are not
        covered.  This method runs after ip_forward is enabled so it catches
        whatever is actually present at the moment traffic could start flowing.

        Rules are added to the filter FORWARD chain and are automatically
        reverted by _restore_filter_snapshot() on stop.
        """
        if self.mode != "gateway":
            return

        try:
            code, out, _ = _run(["ip", "-4", "-o", "addr", "show", "scope", "global"])
        except OSError:
            return
        if code != 0:
            return

        blocked = [
            iface
            for iface in self._iter_routable_ifaces(out)
            if self._block_pivot_iface(iface)
        ]

        if blocked:
            logger.info(
                "Extra pivot surfaces blocked (FORWARD DROP on filter): %s",
                ", ".join(sanitize_log_string(i) for i in blocked),
            )
        else:
            logger.debug("No extra routable interfaces found; no additional pivot rules needed.")

    def _iter_routable_ifaces(self, ip_addr_output: str) -> list[str]:
        """Parse `ip -4 -o addr show scope global` output and return interface
        names that are not the lab bridge or its VLAN sub-interfaces."""
        result = []
        for line in ip_addr_output.splitlines():
            parts = line.split()
            # Format: "2: eth0    inet 10.0.0.1/24 ..."
            if len(parts) < 4 or "inet" not in parts:
                continue
            iface = parts[1].rstrip(":")
            if iface in ("lo", self.interface):
                continue
            if iface.startswith(self.interface + "."):
                continue
            result.append(iface)
        return result

    def _block_pivot_iface(self, iface: str) -> bool:
        """Add bidirectional FORWARD DROP rules between the lab bridge and *iface*.
        Returns True if rules were applied without error."""
        ok = True
        for direction in (
            ["-I", "FORWARD", "1", "-i", self.interface, "-o", iface],
            ["-I", "FORWARD", "1", "-i", iface, "-o", self.interface],
        ):
            rule = ["-t", "filter"] + direction + [
                "-j", "DROP",
                "-m", "comment", "--comment", _RULE_COMMENT,
            ]
            rc, _, err = _run(["iptables"] + rule)
            if rc != 0:
                logger.warning(
                    "Could not add pivot DROP for %s: %s",
                    sanitize_log_string(iface), err.strip(),
                )
                ok = False
        return ok

    def _start_iface_watcher(self) -> None:
        """Start the netlink interface watcher in gateway mode only."""
        if self.mode != "gateway":
            return
        self._iface_watcher = _NetlinkInterfaceWatcher(
            bridge=self.interface,
            block_fn=self._block_pivot_iface,
        )
        self._iface_watcher.start()

    def _apply_ip_forward(self) -> None:
        """Enforce ip_forward state based on operating mode.

        Sinkhole mode: explicitly disable ip_forward.  NTN uses REDIRECT/DNAT
        rules (INPUT chain only) and never routes between interfaces.  Keeping
        ip_forward=0 removes the kernel-level escape route even if iptables
        FORWARD rules are flushed after harden-lab.sh ran.

        Gateway mode: enable ip_forward so forwarded packets reach fake services.
        """
        if self.mode == "gateway":
            self._enforce_ip_forward("1")
        else:
            self._enforce_ip_forward("0")

    def _enforce_ip_forward(self, target: str) -> None:
        """Read current ip_forward value, write target if different, save original for restore."""
        prev = _read_ip_forward()
        if prev is None or prev == target:
            if prev == target:
                logger.debug("ip_forward already %s.", target)
            return
        if _write_ip_forward(target):
            self._prev_ip_forward = prev
            if target == "1":
                logger.info("ip_forward enabled for gateway mode (was %s).", prev)
            else:
                logger.warning(
                    "ip_forward was enabled; disabled on start to prevent "
                    "traffic escaping NTN (was 1, now 0)."
                )
        else:
            if target == "1":
                logger.warning(
                    "Could not enable ip_forward; pings and forwarded traffic "
                    "may not reach fake services."
                )
            else:
                logger.error(
                    "Could not disable ip_forward — victim traffic may be able "
                    "to reach the real internet. Run: echo 0 > /proc/sys/net/ipv4/ip_forward"
                )

    def _apply_promisc(self) -> None:
        """Enable promiscuous mode on the lab interface if configured.

        Reads the current state so we only restore what we actually changed.
        No-ops when ``promisc_mode`` is False or the NIC is already promiscuous.
        """
        if not self.promisc_mode:
            return
        current = _read_promisc(self.interface)
        if current is None:
            logger.warning(
                "Cannot read promisc state for %s — /sys unavailable; skipping.",
                self.interface,
            )
            return
        if current:
            logger.debug("promisc already enabled on %s.", self.interface)
            return
        if _set_promisc(self.interface, True):
            self._prev_promisc = False  # was off — restore to off on stop
            _promisc_restore[self.interface] = False  # atexit safety net
            logger.info(
                "Promiscuous mode enabled on %s "
                "(VM-to-VM traffic now visible; will restore on stop).",
                self.interface,
            )
        else:
            logger.warning("Failed to enable promiscuous mode on %s.", self.interface)

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
        if self._iface_watcher is not None:
            self._iface_watcher.stop()
            self._iface_watcher = None

        escalated = False
        if os.geteuid() != 0:  # type: ignore[attr-defined]
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
                # The snapshot restore wipes our ICMP DROP rule too, so the
                # explicit -D in _remove_auxiliary_rules would fail with
                # "Bad rule (does a matching rule exist?)".  Clear the flag.
                self._filter_icmp_drop_applied = False
            else:
                logger.debug("No filter snapshot available; skipping filter restore.")

            # Restore ip_forward
            if self._prev_ip_forward is not None:
                if _write_ip_forward(self._prev_ip_forward):
                    logger.info("ip_forward restored to %s.", self._prev_ip_forward)
                self._prev_ip_forward = None

            # Restore promiscuous mode
            if self._prev_promisc is not None:
                if _set_promisc(self.interface, self._prev_promisc):
                    logger.info(
                        "Promiscuous mode restored to %s on %s.",
                        "on" if self._prev_promisc else "off",
                        self.interface,
                    )
                _promisc_restore.pop(self.interface, None)
                self._prev_promisc = None

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
