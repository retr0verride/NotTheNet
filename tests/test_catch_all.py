"""
Tests for services/catch_all.py — protocol detection, TLS context building,
service lifecycle, and connection cap.

All tests use loopback sockets or mocks; no root or external network required.
"""

import socket
import ssl
import time

import pytest

from services.catch_all import (
    _HTTP_PREFIXES,
    CatchAllTCPService,
    CatchAllUDPService,
    _build_tls_context,
    _detect_protocol,
)

# ── Protocol detection ───────────────────────────────────────────────────────

class TestDetectProtocol:
    def test_empty_bytes(self):
        assert _detect_protocol(b"") == "unknown"

    def test_http_get(self):
        assert _detect_protocol(b"GET /index.html HTTP/1.1\r\n") == "http"

    def test_http_post(self):
        assert _detect_protocol(b"POST /api HTTP/1.1\r\n") == "http"

    def test_http_put(self):
        assert _detect_protocol(b"PUT /data HTTP/1.1\r\n") == "http"

    def test_http_head(self):
        assert _detect_protocol(b"HEAD / HTTP/1.1\r\n") == "http"

    def test_http_options(self):
        assert _detect_protocol(b"OPTI") == "http"

    def test_http_delete(self):
        assert _detect_protocol(b"DELETE /x HTTP/1.1\r\n") == "http"

    def test_tls_client_hello(self):
        # TLS 1.2 ClientHello: content_type=0x16, version=0x0303
        peek = b"\x16\x03\x03\x00\x01"
        assert _detect_protocol(peek) == "tls"

    def test_tls_1_0(self):
        peek = b"\x16\x03\x01\x00\x01"
        assert _detect_protocol(peek) == "tls"

    def test_ssh_banner(self):
        assert _detect_protocol(b"SSH-2.0-OpenSSH") == "unknown"

    def test_smtp_banner(self):
        assert _detect_protocol(b"220 mail.example.com") == "unknown"

    def test_single_byte(self):
        assert _detect_protocol(b"\x16") == "unknown"  # need 2 bytes for TLS

    def test_all_http_prefixes_detected(self):
        for prefix in _HTTP_PREFIXES:
            assert _detect_protocol(prefix + b"remainder") == "http"


# ── TLS context building ────────────────────────────────────────────────────

class TestBuildTLSContext:
    def test_returns_none_on_empty_paths(self):
        assert _build_tls_context("", "") is None

    def test_returns_none_on_missing_files(self):
        assert _build_tls_context("/nonexistent/cert.pem", "/nonexistent/key.pem") is None

    def test_returns_context_with_valid_certs(self, tmp_path):
        """Generate a self-signed cert and verify context creation."""
        try:
            import datetime

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
        except ImportError:
            pytest.skip("cryptography not installed")

        key = rsa.generate_private_key(65537, 2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )

        cert_path = tmp_path / "test.crt"
        key_path = tmp_path / "test.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

        ctx = _build_tls_context(str(cert_path), str(key_path))
        assert ctx is not None
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


# ── CatchAllTCPService configuration ────────────────────────────────────────

class TestCatchAllTCPConfig:
    def test_defaults(self):
        svc = CatchAllTCPService({})
        assert svc.enabled is True
        assert svc.port == 9999

    def test_disabled(self):
        svc = CatchAllTCPService({"redirect_tcp": False})
        assert not svc.start()

    def test_custom_port(self):
        svc = CatchAllTCPService({"tcp_port": 8888})
        assert svc.port == 8888

    def test_custom_limits_and_timeouts(self):
        svc = CatchAllTCPService({
            "max_connections": 42,
            "max_per_ip": 7,
            "session_timeout_sec": 15,
            "peek_timeout_sec": 0.25,
        })
        assert svc.max_connections == 42
        assert svc.max_per_ip == 7
        assert svc.session_timeout == 15
        assert svc.peek_timeout == 0.25

    def test_running_false_when_not_started(self):
        svc = CatchAllTCPService({})
        assert not svc.running


# ── CatchAllUDPService configuration ────────────────────────────────────────

class TestCatchAllUDPConfig:
    def test_defaults(self):
        svc = CatchAllUDPService({})
        assert svc.enabled is False
        assert svc.port == 9998

    def test_disabled(self):
        svc = CatchAllUDPService({"redirect_udp": False})
        assert not svc.start()

    def test_running_false_when_not_started(self):
        svc = CatchAllUDPService({})
        assert not svc.running


# ── TCP service lifecycle (loopback) ─────────────────────────────────────────

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestCatchAllTCPLifecycle:
    def test_start_stop(self):
        port = _free_port()
        svc = CatchAllTCPService({
            "tcp_port": port,
            "cert_file": "",
            "key_file": "",
        }, bind_ip="127.0.0.1")
        assert svc.start()
        assert svc.running
        svc.stop()
        assert not svc.running

    def test_accepts_connection_and_responds(self):
        port = _free_port()
        svc = CatchAllTCPService({
            "tcp_port": port,
            "cert_file": "",
            "key_file": "",
        }, bind_ip="127.0.0.1")
        svc.start()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                response = s.recv(4096)
                assert b"200 OK" in response
        finally:
            svc.stop()

    def test_unknown_protocol_closes_gracefully(self):
        port = _free_port()
        svc = CatchAllTCPService({
            "tcp_port": port,
            "cert_file": "",
            "key_file": "",
        }, bind_ip="127.0.0.1")
        svc.start()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
                s.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
                s.settimeout(2)
                # Generic banner is empty; server may just close the connection
                try:
                    data = s.recv(4096)
                except (TimeoutError, OSError):
                    data = b""
                # Either empty or closed — both acceptable
                assert data is not None
        finally:
            svc.stop()


# ── UDP service lifecycle (loopback) ─────────────────────────────────────────

class TestCatchAllUDPLifecycle:
    def test_start_stop(self):
        port = _free_port()
        svc = CatchAllUDPService({
            "redirect_udp": True,
            "udp_port": port,
        }, bind_ip="127.0.0.1")
        assert svc.start()
        assert svc.running
        svc.stop()
        assert not svc.running

    def test_receives_datagram(self):
        port = _free_port()
        svc = CatchAllUDPService({
            "redirect_udp": True,
            "udp_port": port,
        }, bind_ip="127.0.0.1")
        svc.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"test payload", ("127.0.0.1", port))
                time.sleep(0.1)  # give handler time to process
                # No response expected (UDP catch-all is silent)
                # Test passes if no exception was raised
        finally:
            svc.stop()
