"""
Tests for services/http_server.py — IP-check spoofing, NCSI, captive portal,
PKI stubs, handler config, response body loading, and spoof IP validation.

Pure-function tests run without a server.  Integration tests bind to loopback.
"""

import http.client
import os
import socket

import pytest

from services.http_server import (
    _CAPTIVE_PORTAL_HOSTS,
    _DEFAULT_BODY,
    _DEFAULT_SERVER_HEADER,
    _IP_CHECK_HOSTS,
    _NCSI_HOSTS,
    _NCSI_RESPONSES,
    _PKI_HOSTS,
    HTTPService,
    _build_handler_config,
    _fmt_checkip_aws,
    _fmt_httpbin,
    _fmt_ip_api,
    _fmt_ipinfo,
    _HandlerConfig,
    _load_response_body,
    _resolve_pki_response,
    _validate_spoof_ip,
)

# ── IP-check formatters (pure functions) ─────────────────────────────────────

class TestIPCheckFormatters:
    _IP = "98.245.112.43"

    def test_ipinfo(self):
        body, ct, headers = _fmt_ipinfo(self._IP, "/")
        assert self._IP.encode() in body
        assert ct == "application/json"
        assert "Columbus" in body.decode()

    def test_ip_api_json(self):
        body, ct, extra = _fmt_ip_api(self._IP, "/json")
        assert self._IP.encode() in body
        assert ct == "application/json"
        assert extra is not None
        assert "Access-Control-Allow-Origin" in extra

    def test_ip_api_line(self):
        body, ct, _ = _fmt_ip_api(self._IP, "/line?fields=query")
        assert self._IP.encode() in body
        assert "text/plain" in ct

    def test_ip_api_csv(self):
        body, ct, _ = _fmt_ip_api(self._IP, "/csv")
        assert self._IP.encode() in body
        assert ct == "text/csv"

    def test_httpbin(self):
        body, ct, _ = _fmt_httpbin(self._IP, "/")
        assert self._IP.encode() in body
        assert ct == "application/json"

    def test_checkip_aws(self):
        body, ct, _ = _fmt_checkip_aws(self._IP, "/")
        assert self._IP.encode() in body
        assert ct == "text/html"


# ── PKI response resolution ─────────────────────────────────────────────────

class TestPKIResponse:
    def test_ocsp_by_host(self):
        status, body, ct = _resolve_pki_response("ocsp.digicert.com", "/")
        assert status == 200
        assert ct == "application/ocsp-response"

    def test_ocsp_by_path(self):
        status, body, ct = _resolve_pki_response("crl.microsoft.com", "/ocsp/check")
        assert status == 200
        assert ct == "application/ocsp-response"

    def test_crl_by_extension(self):
        status, body, ct = _resolve_pki_response("crl3.digicert.com", "/cert.crl")
        assert status == 200
        assert ct == "application/pkix-crl"

    def test_crl_by_host(self):
        status, _, ct = _resolve_pki_response("crl.microsoft.com", "/certs")
        assert status == 200
        assert ct == "application/pkix-crl"

    def test_cert_download_404(self):
        status, _, _ = _resolve_pki_response("cacerts.digicert.com", "/root.crt")
        assert status == 404

    def test_ctldl_octet_stream(self):
        status, _, ct = _resolve_pki_response("ctldl.windowsupdate.com", "/list.cab")
        assert status == 200
        assert ct == "application/octet-stream"


# ── Spoof IP validation ─────────────────────────────────────────────────────

class TestValidateSpoofIP:
    def test_empty_returns_empty(self):
        assert _validate_spoof_ip("") == ""

    def test_valid_public_ip(self):
        assert _validate_spoof_ip("8.8.8.8") == "8.8.8.8"

    def test_invalid_ip(self):
        assert _validate_spoof_ip("not-an-ip") == ""

    def test_private_ip_still_allowed_with_warning(self):
        # RFC1918 is allowed but should warn (tested by logger)
        assert _validate_spoof_ip("192.168.1.1") == "192.168.1.1"


# ── Handler config ───────────────────────────────────────────────────────────

class TestHandlerConfig:
    def test_frozen(self):
        cfg = _HandlerConfig()
        with pytest.raises(AttributeError):
            cfg.response_code = 404  # type: ignore[misc]

    def test_defaults(self):
        cfg = _HandlerConfig()
        assert cfg.response_code == 200
        assert cfg.server_header == _DEFAULT_SERVER_HEADER
        assert cfg.delay_ms == 0

    def test_build_handler_config(self):
        cfg = _build_handler_config(
            response_code=404,
            response_body="<html>Not Found</html>",
            server_header="nginx/1.24",
            log_requests=False,
            spoof_ip="1.2.3.4",
        )
        assert cfg.response_code == 404
        assert cfg.response_body == b"<html>Not Found</html>"
        assert cfg.server_header == "nginx/1.24"
        assert not cfg.log_requests
        assert cfg.spoof_ip == "1.2.3.4"


# ── Response body loading ───────────────────────────────────────────────────

class TestLoadResponseBody:
    def test_default_body(self):
        body = _load_response_body({})
        assert body == _DEFAULT_BODY

    def test_inline_string(self):
        body = _load_response_body({"response_body": "<h1>Custom</h1>"})
        assert body == "<h1>Custom</h1>"

    def test_file_body(self):
        # Use a file inside the project tree so sanitize_path accepts it.
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        test_file = os.path.join(project_root, "assets", "notthenet-page.html")
        if not os.path.exists(test_file):
            pytest.skip("assets/notthenet-page.html not found")
        body = _load_response_body({
            "response_body_file": "assets/notthenet-page.html",
        })
        assert len(body) > 0
        assert "<" in body  # should be HTML content

    def test_missing_file_falls_back(self):
        body = _load_response_body({
            "response_body_file": "/nonexistent/path.html",
            "response_body": "fallback",
        })
        assert body == "fallback"

    def test_traversal_rejected(self):
        body = _load_response_body({
            "response_body_file": "../../etc/passwd",
            "response_body": "safe",
        })
        assert body == "safe"


# ── Host frozenset coverage ──────────────────────────────────────────────────

class TestHostSets:
    def test_ip_check_hosts_are_frozenset(self):
        assert isinstance(_IP_CHECK_HOSTS, frozenset)
        assert "api.ipify.org" in _IP_CHECK_HOSTS

    def test_ncsi_hosts(self):
        assert isinstance(_NCSI_HOSTS, frozenset)
        assert "www.msftconnecttest.com" in _NCSI_HOSTS

    def test_ncsi_responses_match_hosts(self):
        for host in _NCSI_RESPONSES:
            assert host in _NCSI_HOSTS

    def test_pki_hosts(self):
        assert isinstance(_PKI_HOSTS, frozenset)
        assert "crl.microsoft.com" in _PKI_HOSTS
        assert "ocsp.digicert.com" in _PKI_HOSTS

    def test_captive_portal_hosts(self):
        assert isinstance(_CAPTIVE_PORTAL_HOSTS, frozenset)
        assert "connectivitycheck.gstatic.com" in _CAPTIVE_PORTAL_HOSTS


# ── HTTPService configuration ───────────────────────────────────────────────

class TestHTTPServiceConfig:
    def test_defaults(self):
        svc = HTTPService({})
        assert svc.enabled
        assert svc.port == 80
        assert svc.response_code == 200

    def test_disabled(self):
        svc = HTTPService({"enabled": False})
        assert not svc.start()

    def test_running_false_when_not_started(self):
        svc = HTTPService({})
        assert not svc.running


# ── Integration: real HTTP request to loopback server ────────────────────────

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.limit_memory("20 MB")
class TestHTTPIntegration:
    def test_normal_response(self):
        port = _free_port()
        svc = HTTPService({"port": port, "response_body": "<h1>Test</h1>"}, bind_ip="127.0.0.1")
        svc.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/")
            resp = conn.getresponse()
            assert resp.status == 200
            body = resp.read()
            assert b"<h1>Test</h1>" in body
            conn.close()
        finally:
            svc.stop()

    def test_head_has_no_body(self):
        port = _free_port()
        svc = HTTPService({"port": port}, bind_ip="127.0.0.1")
        svc.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            assert resp.status == 200
            body = resp.read()
            assert body == b""
            conn.close()
        finally:
            svc.stop()

    def test_custom_server_header(self):
        port = _free_port()
        svc = HTTPService(
            {"port": port, "server_header": "nginx/1.24.0"},
            bind_ip="127.0.0.1",
        )
        svc.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/")
            resp = conn.getresponse()
            assert resp.getheader("Server") == "nginx/1.24.0"
            resp.read()
            conn.close()
        finally:
            svc.stop()

    def test_ncsi_response(self):
        port = _free_port()
        svc = HTTPService({"port": port}, bind_ip="127.0.0.1")
        svc.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/connecttest.txt", headers={
                "Host": "www.msftconnecttest.com",
            })
            resp = conn.getresponse()
            body = resp.read()
            assert resp.status == 200
            assert body == b"Microsoft Connect Test"
            conn.close()
        finally:
            svc.stop()

    def test_ip_check_response(self):
        port = _free_port()
        svc = HTTPService(
            {"port": port, "spoof_public_ip": "203.0.113.42"},
            bind_ip="127.0.0.1",
        )
        svc.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/", headers={"Host": "api.ipify.org"})
            resp = conn.getresponse()
            body = resp.read()
            assert resp.status == 200
            assert b"203.0.113.42" in body
            conn.close()
        finally:
            svc.stop()

    def test_connect_method(self):
        port = _free_port()
        svc = HTTPService({"port": port}, bind_ip="127.0.0.1")
        svc.start()
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            resp = s.recv(4096)
            assert b"200" in resp
            s.close()
        finally:
            svc.stop()

    def test_unknown_method_501(self):
        port = _free_port()
        svc = HTTPService({"port": port}, bind_ip="127.0.0.1")
        svc.start()
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.sendall(b"FOOBAR / HTTP/1.1\r\nHost: test\r\n\r\n")
            resp = s.recv(4096)
            assert b"501" in resp
            s.close()
        finally:
            svc.stop()
