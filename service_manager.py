"""
NotTheNet - Service Manager
Orchestrates all fake network services and iptables rules.
"""

import logging
import threading
from dataclasses import dataclass
from typing import Optional

from config import Config
from network.iptables_manager import IPTablesManager
from network.tcp_fingerprint import apply_os_fingerprint
from services.base import ServiceProtocol
from services.catch_all import CatchAllTCPService, CatchAllUDPService
from services.dns_server import DNSService
from services.dot_server import DoTService
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

_DEFAULT_CERT = "certs/server.crt"
_DEFAULT_KEY = "certs/server.key"


@dataclass(frozen=True)
class ServiceSpec:
    """Single source of truth for one fake-network service."""
    name: str
    factory: type
    config_section: str
    default_port: int          # 0 = no fixed port (catch-all / ICMP)
    protocol: str              # "tcp" | "udp" | "both"
    tls: bool = False
    bind_ip: bool = True


_SERVICE_REGISTRY: list[ServiceSpec] = [
    # -- Special startup (custom config merging in start()) --
    ServiceSpec("dns",       DNSService,         "dns",       53,   "both"),
    ServiceSpec("dot",       DoTService,         "dot",       853,  "tcp",  tls=True),
    ServiceSpec("http",      HTTPService,        "http",      80,   "tcp"),
    ServiceSpec("https",     HTTPSService,       "https",     443,  "tcp",  tls=True),
    # -- Uniform construction (registry-driven) --
    ServiceSpec("smtp",      SMTPService,        "smtp",      25,   "tcp"),
    ServiceSpec("smtps",     SMTPSService,       "smtps",     465,  "tcp",  tls=True),
    ServiceSpec("pop3",      POP3Service,        "pop3",      110,  "tcp"),
    ServiceSpec("pop3s",     POP3SService,       "pop3s",     995,  "tcp",  tls=True),
    ServiceSpec("imap",      IMAPService,        "imap",      143,  "tcp"),
    ServiceSpec("imaps",     IMAPSService,       "imaps",     993,  "tcp",  tls=True),
    ServiceSpec("ftp",       FTPService,         "ftp",       21,   "tcp"),
    ServiceSpec("catch_tcp", CatchAllTCPService, "catch_all", 0,    "tcp"),
    ServiceSpec("catch_udp", CatchAllUDPService, "catch_all", 0,    "udp"),
    ServiceSpec("ntp",       NTPService,         "ntp",       123,  "udp"),
    ServiceSpec("irc",       IRCService,         "irc",       6667, "tcp"),
    ServiceSpec("tftp",      TFTPService,        "tftp",      69,   "udp"),
    ServiceSpec("telnet",    TelnetService,      "telnet",    23,   "tcp"),
    ServiceSpec("socks5",    Socks5Service,      "socks5",    1080, "tcp",  tls=True),
    ServiceSpec("ircs",      IRCSTLSService,     "ircs",      6697, "tcp",  tls=True),
    ServiceSpec("icmp",      ICMPResponder,      "icmp",      0,    "tcp",  bind_ip=False),
    ServiceSpec("mysql",     MySQLService,       "mysql",     3306, "tcp"),
    ServiceSpec("mssql",     MSSQLService,       "mssql",     1433, "tcp"),
    ServiceSpec("rdp",       RDPService,         "rdp",       3389, "tcp"),
    ServiceSpec("smb",       SMBService,         "smb",       445,  "tcp"),
    ServiceSpec("vnc",       VNCService,         "vnc",       5900, "tcp"),
    ServiceSpec("redis",     RedisService,       "redis",     6379, "tcp"),
    ServiceSpec("ldap",      LDAPService,        "ldap",      389,  "tcp"),
]

# Names of services that require special config merging in start()
_SPECIAL_SERVICES = frozenset({"dns", "dot", "http", "https"})



class ServiceManager:
    """
    Starts, stops, and monitors all NotTheNet fake services.
    Also manages iptables rule lifecycle.
    """

    def __init__(self, config: Config):
        self.config = config
        self._services: dict[str, ServiceProtocol] = {}
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
        for spec in _SERVICE_REGISTRY:
            if spec.default_port == 0:
                continue
            cfg = self.config.get_section(spec.config_section)
            if cfg.get("enabled") is False:
                continue
            port = int(cfg.get("port") or spec.default_port)
            protos = ["tcp", "udp"] if spec.protocol == "both" else [spec.protocol]
            for proto in protos:
                key = (proto, port)
                if key in port_map:
                    logger.warning(
                        "Port conflict: %s/%d used by both '%s' and '%s'",
                        proto, port, port_map[key], spec.name,
                    )
                else:
                    port_map[key] = spec.name

    def _setup_json_logging(self) -> None:
        """Initialise structured JSON event logger if enabled."""
        if not self.config.get("general", "json_logging"):
            return
        json_path = self.config.get("general", "json_log_file") or "logs/events.jsonl"
        jl = init_json_logger(json_path, enabled=True)
        if jl:
            logger.info("Structured JSON logging enabled → %s", json_path)
        else:
            logger.error("Failed to initialise JSON logger at %s", json_path)

    def _setup_certs(self) -> None:
        """Ensure TLS certs exist for HTTPS / DoT / TLS-wrapped services."""
        https_cfg = self.config.get_section("https")
        dot_cfg = self.config.get_section("dot")
        if https_cfg.get("enabled") or dot_cfg.get("enabled"):
            ensure_certs(
                https_cfg.get("cert_file", _DEFAULT_CERT),
                https_cfg.get("key_file", _DEFAULT_KEY),
            )
            if https_cfg.get("dynamic_certs"):
                from utils.cert_utils import ensure_ca
                ensure_ca("certs/ca.crt", "certs/ca.key")

    def start(self) -> bool:
        """Start all enabled services. Returns True if at least one started."""
        errors = self.validate()
        if errors:
            for e in errors:
                logger.error("Config error: %s", e)
            return False

        require_root_or_warn()
        self._check_port_conflicts()

        self._setup_json_logging()
        self._setup_certs()

        started, failed = self._start_all_services()

        # --- Apply iptables rules after all services are bound ---
        if self.config.get("general", "auto_iptables"):
            self._apply_iptables()

        self._apply_fingerprints()

        self._running = len(started) > 0
        logger.info("NotTheNet started: %s", ', '.join(started) if started else 'none')
        if failed:
            logger.warning("Services FAILED to start: %s", ', '.join(failed))
        return self._running

    def _tls_cfg(self, section: str) -> dict:
        """Merge a config section with HTTPS cert/key paths."""
        https_cfg = self.config.get_section("https")
        return {
            **self.config.get_section(section),
            "cert_file": https_cfg.get("cert_file", _DEFAULT_CERT),
            "key_file":  https_cfg.get("key_file",  _DEFAULT_KEY),
        }

    def _build_service(
        self, spec: ServiceSpec, bind_ip: str,
        spoof_ip: str, redirect_ip: str, https_cfg: dict,
    ) -> ServiceProtocol:
        """Build a service instance from its registry spec."""
        builder = self._special_builders(spec, bind_ip, spoof_ip, redirect_ip, https_cfg)
        if builder is not None:
            cfg, extra_kwargs = builder
            return spec.factory(cfg, **extra_kwargs)
        cfg = self._tls_cfg(spec.config_section) if spec.tls else self.config.get_section(spec.config_section)
        return spec.factory(cfg, bind_ip=bind_ip) if spec.bind_ip else spec.factory(cfg)

    def _special_builders(
        self, spec: ServiceSpec, bind_ip: str,
        spoof_ip: str, redirect_ip: str, https_cfg: dict,
    ) -> Optional[tuple[dict, dict]]:
        """Return (config, extra_kwargs) for services needing custom config, or None."""
        if spec.name == "dns":
            return {**self.config.get_section("dns"), "bind_ip": bind_ip}, {}
        if spec.name == "dot":
            return {
                **self.config.get_section("dns"),
                **self.config.get_section("dot"),
                "port":      int(self.config.get("dot", "port") or 853),
                "enabled":   (self.config.get("dot", "enabled")
                              if self.config.get("dot", "enabled") is not None else True),
                "bind_ip":   bind_ip,
                "cert_file": https_cfg.get("cert_file", _DEFAULT_CERT),
                "key_file":  https_cfg.get("key_file",  _DEFAULT_KEY),
            }, {}
        if spec.name == "http":
            return {
                **self.config.get_section("http"),
                "spoof_public_ip": spoof_ip,
                "doh_redirect_ip": redirect_ip,
            }, {"bind_ip": bind_ip}
        if spec.name == "https":
            return {
                **self.config.get_section("https"),
                "spoof_public_ip": spoof_ip,
                "doh_redirect_ip": redirect_ip,
            }, {"bind_ip": bind_ip}
        return None

    def _start_all_services(self) -> tuple[list[str], list[str]]:
        """Instantiate and start every service from the registry.

        Returns (started_names, failed_names).
        """
        bind_ip = self.config.get("general", "bind_ip") or "0.0.0.0"
        spoof_ip = str(self.config.get("general", "spoof_public_ip") or "")
        https_cfg = self.config.get_section("https")
        redirect_ip = self.config.get("general", "redirect_ip") or "127.0.0.1"
        if not self.config.get("general", "redirect_ip"):
            logger.warning(
                "general.redirect_ip is not set; defaulting to 127.0.0.1. "
                "Services may not be reachable from gateway mode."
            )

        started: list[str] = []
        failed: list[str] = []
        started_svcs: dict[str, ServiceProtocol] = {}

        for spec in _SERVICE_REGISTRY:
            svc = self._build_service(spec, bind_ip, spoof_ip, redirect_ip, https_cfg)
            try:
                if svc.start():
                    started_svcs[spec.name] = svc
                    started.append(spec.name)
                elif getattr(svc, 'enabled', True):
                    failed.append(spec.name)
            except Exception:
                logger.exception("Unexpected error starting %s", spec.name)
                failed.append(spec.name)

        with self._lock:
            self._services.update(started_svcs)

        return started, failed

    def _apply_fingerprints(self) -> None:
        """Apply TCP/IP OS fingerprint spoofing to server sockets."""
        fp_enabled = self.config.get("general", "tcp_fingerprint")
        fp_os = self.config.get("general", "tcp_fingerprint_os") or "windows"
        if not fp_enabled:
            return
        for name, svc in self._services.items():
            sock = getattr(getattr(svc, '_server', None), 'socket', None)
            if sock:
                try:
                    apply_os_fingerprint(sock, fp_os)
                except Exception as e:
                    logger.debug("TCP fingerprint on %s: %s", name, e)
            else:
                logger.debug("TCP fingerprint skipped for %s (no server socket)", name)

    def _build_service_ports(self) -> dict[str, list[int]]:
        """Build {tcp: [...], udp: [...]} dynamically from the service registry."""
        ports: dict[str, list[int]] = {"tcp": [], "udp": []}
        for spec in _SERVICE_REGISTRY:
            if spec.name not in self._services or spec.default_port == 0:
                continue
            port = int(self.config.get(spec.config_section, "port") or spec.default_port)
            if spec.protocol == "both":
                ports["tcp"].append(port)
                ports["udp"].append(port)
            else:
                ports[spec.protocol].append(port)
        return ports

    def _apply_iptables(self):
        """Build the iptables rule set from running services."""
        iptables = IPTablesManager(self.config.get_section("general"))
        service_ports = self._build_service_ports()

        catch_cfg = self.config.get_section("catch_all")
        catch_tcp_port = int(catch_cfg.get("tcp_port", 9999))
        catch_udp_port = int(catch_cfg.get("udp_port", 0))
        excluded = catch_cfg.get("excluded_ports", [22])

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
            iptables = self._iptables
            self._iptables = None

        # Stop all services in parallel so total shutdown time is
        # max(individual stop times) rather than their sum.
        def _stop_one(name_svc):
            name, svc = name_svc
            try:
                svc.stop()
            except Exception as e:
                logger.warning("Error stopping %s: %s", name, e)

        from concurrent.futures import ThreadPoolExecutor as _TPE
        with _TPE(max_workers=min(len(items), 16) or 1) as ex:
            list(ex.map(_stop_one, items))

        if iptables:
            iptables.remove_rules()

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
