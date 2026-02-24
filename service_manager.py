"""
NotTheNet - Service Manager
Orchestrates all fake network services and iptables rules.
"""

import logging
from typing import Optional

from config import Config
from network.iptables_manager import IPTablesManager
from services.catch_all import CatchAllTCPService, CatchAllUDPService
from services.dns_server import DNSService
from services.ftp_server import FTPService
from services.http_server import HTTPService, HTTPSService
from services.mail_server import IMAPService, POP3Service, SMTPService
from utils.cert_utils import ensure_certs
from utils.privilege import drop_privileges, require_root_or_warn
from utils.validators import validate_config

logger = logging.getLogger(__name__)


class ServiceManager:
    """
    Starts, stops, and monitors all NotTheNet fake services.
    Also manages iptables rule lifecycle.
    """

    def __init__(self, config: Config):
        self.config = config
        self._services: dict[str, object] = {}
        self._iptables: Optional[IPTablesManager] = None
        self._running = False

    def validate(self) -> list:
        """Validate configuration; return list of error strings."""
        errors = validate_config(self.config.as_dict())
        return errors

    def start(self) -> bool:
        """Start all enabled services. Returns True if at least one started."""
        errors = self.validate()
        if errors:
            for e in errors:
                logger.error(f"Config error: {e}")
            return False

        require_root_or_warn()

        bind_ip = self.config.get("general", "bind_ip") or "0.0.0.0"

        # --- Ensure TLS certs exist before binding ---
        https_cfg = self.config.get_section("https")
        if https_cfg.get("enabled"):
            ensure_certs(
                https_cfg.get("cert_file", "certs/server.crt"),
                https_cfg.get("key_file", "certs/server.key"),
            )

        # ----- Start services -----
        started = []

        dns = DNSService({**self.config.get_section("dns"), "bind_ip": bind_ip})
        if dns.start():
            self._services["dns"] = dns
            started.append("dns")

        http = HTTPService(self.config.get_section("http"), bind_ip=bind_ip)
        if http.start():
            self._services["http"] = http
            started.append("http")

        https = HTTPSService(self.config.get_section("https"), bind_ip=bind_ip)
        if https.start():
            self._services["https"] = https
            started.append("https")

        smtp = SMTPService(self.config.get_section("smtp"), bind_ip=bind_ip)
        if smtp.start():
            self._services["smtp"] = smtp
            started.append("smtp")

        pop3 = POP3Service(self.config.get_section("pop3"), bind_ip=bind_ip)
        if pop3.start():
            self._services["pop3"] = pop3
            started.append("pop3")

        imap = IMAPService(self.config.get_section("imap"), bind_ip=bind_ip)
        if imap.start():
            self._services["imap"] = imap
            started.append("imap")

        ftp = FTPService(self.config.get_section("ftp"), bind_ip=bind_ip)
        if ftp.start():
            self._services["ftp"] = ftp
            started.append("ftp")

        catch_tcp = CatchAllTCPService(self.config.get_section("catch_all"), bind_ip=bind_ip)
        if catch_tcp.start():
            self._services["catch_tcp"] = catch_tcp
            started.append("catch_tcp")

        catch_udp = CatchAllUDPService(self.config.get_section("catch_all"), bind_ip=bind_ip)
        if catch_udp.start():
            self._services["catch_udp"] = catch_udp
            started.append("catch_udp")

        # --- Apply iptables rules after all services are bound ---
        if self.config.get("general", "auto_iptables"):
            self._apply_iptables()

        # --- Drop privileges now that low ports are bound ---
        drop_privileges()

        self._running = len(started) > 0
        logger.info(f"NotTheNet started: {', '.join(started) if started else 'none'}")
        return self._running

    def _apply_iptables(self):
        """Build the iptables rule set from running services."""
        iptables = IPTablesManager(self.config.get_section("general"))
        service_ports = {
            "tcp": [],
            "udp": [],
        }
        port_map = {
            "http":  ("tcp", self.config.get("http",  "port") or 80),
            "https": ("tcp", self.config.get("https", "port") or 443),
            "smtp":  ("tcp", self.config.get("smtp",  "port") or 25),
            "pop3":  ("tcp", self.config.get("pop3",  "port") or 110),
            "imap":  ("tcp", self.config.get("imap",  "port") or 143),
            "ftp":   ("tcp", self.config.get("ftp",   "port") or 21),
        }
        dns_port = self.config.get("dns", "port") or 53
        service_ports["udp"].append(int(dns_port))
        service_ports["tcp"].append(int(dns_port))

        for svc, (proto, port) in port_map.items():
            if svc in self._services:
                service_ports[proto].append(int(port))

        catch_cfg = self.config.get_section("catch_all")
        catch_tcp_port = int(catch_cfg.get("tcp_port", 9999))
        excluded = catch_cfg.get("excluded_ports", [22])

        iptables.apply_rules(service_ports, catch_tcp_port, excluded)
        self._iptables = iptables

    def stop(self):
        """Stop all services and remove iptables rules."""
        for name, svc in list(self._services.items()):
            try:
                svc.stop()
            except Exception as e:
                logger.warning(f"Error stopping {name}: {e}")
        self._services.clear()

        if self._iptables:
            self._iptables.remove_rules()
            self._iptables = None

        self._running = False
        logger.info("NotTheNet stopped.")

    def status(self) -> dict[str, bool]:
        """Return a dict of {service_name: is_running}."""
        return {name: getattr(svc, "running", False)
                for name, svc in self._services.items()}

    @property
    def running(self) -> bool:
        return self._running
