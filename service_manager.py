"""
NotTheNet - Service Manager
Orchestrates all fake network services and iptables rules.
"""

import logging
import threading
from typing import Optional

from config import Config
from network.iptables_manager import IPTablesManager
from network.tcp_fingerprint import apply_os_fingerprint
from services.catch_all import CatchAllTCPService, CatchAllUDPService
from services.dns_server import DNSService
from services.ftp_server import FTPService
from services.http_server import HTTPService, HTTPSService
from services.icmp_responder import ICMPResponder
from services.irc_server import IRCService, IRCSTLSService
from services.ldap_server import LDAPService
from services.mail_server import (
    IMAPService,
    IMAPSService,
    POP3Service,
    POP3SService,
    SMTPService,
    SMTPSService,
)
from services.mssql_server import MSSQLService
from services.mysql_server import MySQLService
from services.ntp_server import NTPService
from services.rdp_server import RDPService
from services.redis_server import RedisService
from services.smb_server import SMBService
from services.socks5_server import Socks5Service
from services.telnet_server import TelnetService
from services.tftp_server import TFTPService
from services.vnc_server import VNCService
from utils.cert_utils import ensure_certs
from utils.json_logger import close_json_logger, init_json_logger
from utils.privilege import require_root_or_warn
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
        self._lock = threading.Lock()
        self._iptables: Optional[IPTablesManager] = None
        self._running = False

    def validate(self) -> list:
        """Validate configuration; return list of error strings."""
        errors = validate_config(self.config.as_dict())
        return errors

    def _check_port_conflicts(self):
        """Warn about duplicate port/proto assignments across enabled services."""
        port_map: dict[tuple[str, int], str] = {}
        svc_ports = [
            ("http",  "tcp"), ("https", "tcp"), ("smtp",  "tcp"),
            ("smtps", "tcp"), ("pop3",  "tcp"), ("pop3s", "tcp"),
            ("imap",  "tcp"), ("imaps", "tcp"), ("ftp",   "tcp"),
            ("irc",   "tcp"), ("ircs",  "tcp"), ("telnet","tcp"),
            ("socks5","tcp"), ("mysql", "tcp"), ("mssql", "tcp"),
            ("rdp",   "tcp"), ("smb",   "tcp"), ("vnc",   "tcp"),
            ("redis", "tcp"), ("ldap",  "tcp"),
            ("dns",   "tcp"), ("dns",   "udp"),
            ("ntp",   "udp"), ("tftp",  "udp"),
        ]
        for svc, proto in svc_ports:
            cfg = self.config.get_section(svc)
            if cfg.get("enabled") is False:
                continue
            port = int(cfg.get("port", 0))
            if port == 0:
                continue
            key = (proto, port)
            if key in port_map:
                logger.warning(
                    "Port conflict: %s/%d used by both '%s' and '%s'",
                    proto, port, port_map[key], svc,
                )
            else:
                port_map[key] = svc

    def start(self) -> bool:
        """Start all enabled services. Returns True if at least one started."""
        errors = self.validate()
        if errors:
            for e in errors:
                logger.error("Config error: %s", e)
            return False

        require_root_or_warn()

        # --- Pre-flight: detect port conflicts ---
        self._check_port_conflicts()

        bind_ip = self.config.get("general", "bind_ip") or "0.0.0.0"
        spoof_ip = str(self.config.get("general", "spoof_public_ip") or "")

        # --- Start structured JSON event logger if enabled ---
        json_logging = self.config.get("general", "json_logging")
        if json_logging:
            json_path = self.config.get("general", "json_log_file") or "logs/events.jsonl"
            jl = init_json_logger(json_path, enabled=True)
            if jl:
                logger.info("Structured JSON logging enabled → %s", json_path)
            else:
                logger.error("Failed to initialise JSON logger at %s", json_path)

        # --- Ensure TLS certs exist before binding ---
        https_cfg = self.config.get_section("https")
        if https_cfg.get("enabled"):
            ensure_certs(
                https_cfg.get("cert_file", "certs/server.crt"),
                https_cfg.get("key_file", "certs/server.key"),
            )
            # Ensure Root CA exists if dynamic certs enabled
            if https_cfg.get("dynamic_certs"):
                from utils.cert_utils import ensure_ca
                ensure_ca("certs/ca.crt", "certs/ca.key")

        # ----- Build merged config dicts with general settings -----
        redirect_ip = self.config.get("general", "redirect_ip") or "127.0.0.1"
        if not self.config.get("general", "redirect_ip"):
            logger.warning(
                "general.redirect_ip is not set; defaulting to 127.0.0.1. "
                "Services may not be reachable from gateway mode."
            )

        # ----- Start services -----
        started = []
        failed = []

        def _try_start(name: str, svc):
            """Start a service and track success/failure."""
            if svc.start():
                self._services[name] = svc
                started.append(name)
            elif getattr(svc, 'enabled', True):
                failed.append(name)

        _try_start("dns", DNSService({**self.config.get_section("dns"), "bind_ip": bind_ip}))

        http_cfg = {
            **self.config.get_section("http"),
            "spoof_public_ip": spoof_ip,
            "doh_redirect_ip": redirect_ip,
        }
        _try_start("http", HTTPService(http_cfg, bind_ip=bind_ip))

        https_merged = {
            **self.config.get_section("https"),
            "spoof_public_ip": spoof_ip,
            "doh_redirect_ip": redirect_ip,
        }
        _try_start("https", HTTPSService(https_merged, bind_ip=bind_ip))

        _try_start("smtp", SMTPService(self.config.get_section("smtp"), bind_ip=bind_ip))

        smtps_cfg = {
            **self.config.get_section("smtps"),
            "cert_file": https_cfg.get("cert_file", "certs/server.crt"),
            "key_file":  https_cfg.get("key_file",  "certs/server.key"),
        }
        _try_start("smtps", SMTPSService(smtps_cfg, bind_ip=bind_ip))

        _try_start("pop3", POP3Service(self.config.get_section("pop3"), bind_ip=bind_ip))

        pop3s_cfg = {
            **self.config.get_section("pop3s"),
            "cert_file": https_cfg.get("cert_file", "certs/server.crt"),
            "key_file":  https_cfg.get("key_file",  "certs/server.key"),
        }
        _try_start("pop3s", POP3SService(pop3s_cfg, bind_ip=bind_ip))

        _try_start("imap", IMAPService(self.config.get_section("imap"), bind_ip=bind_ip))

        imaps_cfg = {
            **self.config.get_section("imaps"),
            "cert_file": https_cfg.get("cert_file", "certs/server.crt"),
            "key_file":  https_cfg.get("key_file",  "certs/server.key"),
        }
        _try_start("imaps", IMAPSService(imaps_cfg, bind_ip=bind_ip))

        _try_start("ftp", FTPService(self.config.get_section("ftp"), bind_ip=bind_ip))
        _try_start("catch_tcp", CatchAllTCPService(self.config.get_section("catch_all"), bind_ip=bind_ip))
        _try_start("catch_udp", CatchAllUDPService(self.config.get_section("catch_all"), bind_ip=bind_ip))
        _try_start("ntp", NTPService(self.config.get_section("ntp"), bind_ip=bind_ip))
        _try_start("irc", IRCService(self.config.get_section("irc"), bind_ip=bind_ip))
        _try_start("tftp", TFTPService(self.config.get_section("tftp"), bind_ip=bind_ip))

        _try_start("telnet", TelnetService({**self.config.get_section("telnet")}, bind_ip=bind_ip))

        socks5_cfg = {
            **self.config.get_section("socks5"),
            "cert_file": https_cfg.get("cert_file", "certs/server.crt"),
            "key_file":  https_cfg.get("key_file",  "certs/server.key"),
        }
        _try_start("socks5", Socks5Service(socks5_cfg, bind_ip=bind_ip))

        ircs_cfg = {
            **self.config.get_section("ircs"),
            "cert_file": https_cfg.get("cert_file", "certs/server.crt"),
            "key_file":  https_cfg.get("key_file",  "certs/server.key"),
        }
        _try_start("ircs", IRCSTLSService(ircs_cfg, bind_ip=bind_ip))

        _try_start("icmp", ICMPResponder(self.config.get_section("icmp")))
        _try_start("mysql", MySQLService(self.config.get_section("mysql"), bind_ip=bind_ip))
        _try_start("mssql", MSSQLService(self.config.get_section("mssql"), bind_ip=bind_ip))
        _try_start("rdp", RDPService(self.config.get_section("rdp"), bind_ip=bind_ip))
        _try_start("smb", SMBService(self.config.get_section("smb"), bind_ip=bind_ip))
        _try_start("vnc", VNCService(self.config.get_section("vnc"), bind_ip=bind_ip))
        _try_start("redis", RedisService(self.config.get_section("redis"), bind_ip=bind_ip))
        _try_start("ldap", LDAPService(self.config.get_section("ldap"), bind_ip=bind_ip))

        # --- Apply iptables rules after all services are bound ---
        if self.config.get("general", "auto_iptables"):
            self._apply_iptables()

        # --- Apply TCP/IP OS fingerprint spoofing to server sockets ---
        fp_enabled = self.config.get("general", "tcp_fingerprint")
        fp_os = self.config.get("general", "tcp_fingerprint_os") or "windows"
        if fp_enabled:
            for name, svc in self._services.items():
                sock = getattr(getattr(svc, '_server', None), 'socket', None)
                if sock:
                    try:
                        apply_os_fingerprint(sock, fp_os)
                    except Exception as e:
                        logger.debug("TCP fingerprint on %s: %s", name, e)
                else:
                    logger.debug("TCP fingerprint skipped for %s (no server socket)", name)

        self._running = len(started) > 0
        logger.info("NotTheNet started: %s", ', '.join(started) if started else 'none')
        if failed:
            logger.warning("Services FAILED to start: %s", ', '.join(failed))
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
            "smtps": ("tcp", self.config.get("smtps", "port") or 465),
            "pop3":  ("tcp", self.config.get("pop3",  "port") or 110),
            "pop3s": ("tcp", self.config.get("pop3s", "port") or 995),
            "imap":  ("tcp", self.config.get("imap",  "port") or 143),
            "imaps": ("tcp", self.config.get("imaps", "port") or 993),
            "ftp":   ("tcp", self.config.get("ftp",   "port") or 21),
            "irc":   ("tcp", self.config.get("irc",   "port") or 6667),
            "telnet": ("tcp", self.config.get("telnet", "port") or 23),
            "socks5": ("tcp", self.config.get("socks5", "port") or 1080),
            "ircs":   ("tcp", self.config.get("ircs",   "port") or 6697),
            "mysql":  ("tcp", self.config.get("mysql",  "port") or 3306),
            "mssql":  ("tcp", self.config.get("mssql",  "port") or 1433),
            "rdp":    ("tcp", self.config.get("rdp",    "port") or 3389),
            "smb":    ("tcp", self.config.get("smb",    "port") or 445),
            "vnc":    ("tcp", self.config.get("vnc",    "port") or 5900),
            "redis":  ("tcp", self.config.get("redis",  "port") or 6379),
            "ldap":   ("tcp", self.config.get("ldap",   "port") or 389),
        }
        # TFTP uses UDP port 69
        if "tftp" in self._services:
            tftp_port = self.config.get("tftp", "port") or 69
            service_ports["udp"].append(int(tftp_port))
        # NTP uses UDP port 123
        if "ntp" in self._services:
            ntp_port = self.config.get("ntp", "port") or 123
            service_ports["udp"].append(int(ntp_port))
        # Only add DNS port if the DNS service actually started
        if "dns" in self._services:
            dns_port = self.config.get("dns", "port") or 53
            service_ports["udp"].append(int(dns_port))
            service_ports["tcp"].append(int(dns_port))

        for svc, (proto, port) in port_map.items():
            if svc in self._services:
                service_ports[proto].append(int(port))

        catch_cfg = self.config.get_section("catch_all")
        catch_tcp_port = int(catch_cfg.get("tcp_port", 9999))
        catch_udp_port = int(catch_cfg.get("udp_port", 0))
        excluded = catch_cfg.get("excluded_ports", [22])

        # Drive the ICMP DNAT rule from config, not from whether the raw-socket
        # logging service started.  The kernel handles echo-replies without the
        # raw socket; the responder only exists for logging.
        icmp_enabled = bool(self.config.get_section("icmp").get("enabled", False))

        iptables.apply_rules(
            service_ports, catch_tcp_port, catch_udp_port, excluded,
            icmp_enabled=icmp_enabled,
        )
        self._iptables = iptables

    def stop(self):
        """Stop all services and remove iptables rules."""
        with self._lock:
            items = list(self._services.items())
            self._services.clear()
        for name, svc in items:
            try:
                svc.stop()
            except Exception as e:
                logger.warning("Error stopping %s: %s", name, e)

        if self._iptables:
            self._iptables.remove_rules()
            self._iptables = None

        close_json_logger()

        self._running = False
        logger.info("NotTheNet stopped.")

    def status(self) -> dict[str, bool]:
        """Return a dict of {service_name: is_running}."""
        with self._lock:
            return {name: getattr(svc, "running", False)
                    for name, svc in self._services.items()}

    @property
    def running(self) -> bool:
        return self._running
