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
from services.mail_server import IMAPService, IMAPSService, POP3Service, POP3SService, SMTPService, SMTPSService
from services.irc_server import IRCService, IRCSTLSService
from services.telnet_server import TelnetService
from services.socks5_server import Socks5Service
from services.ntp_server import NTPService
from services.tftp_server import TFTPService
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

    def start(self) -> bool:
        """Start all enabled services. Returns True if at least one started."""
        errors = self.validate()
        if errors:
            for e in errors:
                logger.error("Config error: %s", e)
            return False

        require_root_or_warn()

        bind_ip = self.config.get("general", "bind_ip") or "0.0.0.0"
        spoof_ip = str(self.config.get("general", "spoof_public_ip") or "")

        # --- Start structured JSON event logger if enabled ---
        json_logging = self.config.get("general", "json_logging")
        if json_logging:
            json_path = self.config.get("general", "json_log_file") or "logs/events.jsonl"
            init_json_logger(json_path, enabled=True)
            logger.info("Structured JSON logging enabled → %s", json_path)

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

        # ----- Start services -----
        started = []

        dns = DNSService({**self.config.get_section("dns"), "bind_ip": bind_ip})
        if dns.start():
            self._services["dns"] = dns
            started.append("dns")

        http_cfg = {
            **self.config.get_section("http"),
            "spoof_public_ip": spoof_ip,
            "doh_redirect_ip": redirect_ip,
        }
        http = HTTPService(http_cfg, bind_ip=bind_ip)
        if http.start():
            self._services["http"] = http
            started.append("http")

        https_merged = {
            **self.config.get_section("https"),
            "spoof_public_ip": spoof_ip,
            "doh_redirect_ip": redirect_ip,
        }
        https = HTTPSService(https_merged, bind_ip=bind_ip)
        if https.start():
            self._services["https"] = https
            started.append("https")

        smtp = SMTPService(self.config.get_section("smtp"), bind_ip=bind_ip)
        if smtp.start():
            self._services["smtp"] = smtp
            started.append("smtp")

        smtps_cfg = {
            **self.config.get_section("smtps"),
            "cert_file": https_cfg.get("cert_file", "certs/server.crt"),
            "key_file":  https_cfg.get("key_file",  "certs/server.key"),
        }
        smtps = SMTPSService(smtps_cfg, bind_ip=bind_ip)
        if smtps.start():
            self._services["smtps"] = smtps
            started.append("smtps")

        pop3 = POP3Service(self.config.get_section("pop3"), bind_ip=bind_ip)
        if pop3.start():
            self._services["pop3"] = pop3
            started.append("pop3")

        pop3s_cfg = {
            **self.config.get_section("pop3s"),
            "cert_file": https_cfg.get("cert_file", "certs/server.crt"),
            "key_file":  https_cfg.get("key_file",  "certs/server.key"),
        }
        pop3s = POP3SService(pop3s_cfg, bind_ip=bind_ip)
        if pop3s.start():
            self._services["pop3s"] = pop3s
            started.append("pop3s")

        imap = IMAPService(self.config.get_section("imap"), bind_ip=bind_ip)
        if imap.start():
            self._services["imap"] = imap
            started.append("imap")

        imaps_cfg = {
            **self.config.get_section("imaps"),
            "cert_file": https_cfg.get("cert_file", "certs/server.crt"),
            "key_file":  https_cfg.get("key_file",  "certs/server.key"),
        }
        imaps = IMAPSService(imaps_cfg, bind_ip=bind_ip)
        if imaps.start():
            self._services["imaps"] = imaps
            started.append("imaps")

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

        ntp = NTPService(self.config.get_section("ntp"), bind_ip=bind_ip)
        if ntp.start():
            self._services["ntp"] = ntp
            started.append("ntp")

        irc = IRCService(self.config.get_section("irc"), bind_ip=bind_ip)
        if irc.start():
            self._services["irc"] = irc
            started.append("irc")

        tftp = TFTPService(self.config.get_section("tftp"), bind_ip=bind_ip)
        if tftp.start():
            self._services["tftp"] = tftp
            started.append("tftp")

        telnet_cfg = {
            **self.config.get_section("telnet"),
        }
        telnet = TelnetService(telnet_cfg, bind_ip=bind_ip)
        if telnet.start():
            self._services["telnet"] = telnet
            started.append("telnet")

        socks5_cfg = {
            **self.config.get_section("socks5"),
            "cert_file": https_cfg.get("cert_file", "certs/server.crt"),
            "key_file":  https_cfg.get("key_file",  "certs/server.key"),
        }
        socks5 = Socks5Service(socks5_cfg, bind_ip=bind_ip)
        if socks5.start():
            self._services["socks5"] = socks5
            started.append("socks5")

        ircs_cfg = {
            **self.config.get_section("ircs"),
            "cert_file": https_cfg.get("cert_file", "certs/server.crt"),
            "key_file":  https_cfg.get("key_file",  "certs/server.key"),
        }
        ircs = IRCSTLSService(ircs_cfg, bind_ip=bind_ip)
        if ircs.start():
            self._services["ircs"] = ircs
            started.append("ircs")

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

        self._running = len(started) > 0
        logger.info("NotTheNet started: %s", ', '.join(started) if started else 'none')
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
        excluded = catch_cfg.get("excluded_ports", [22])

        iptables.apply_rules(service_ports, catch_tcp_port, excluded)
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
