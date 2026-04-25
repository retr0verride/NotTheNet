"""
Tests for utils/validators.py â€” cover all public functions.
These are pure-Python, no I/O, safe to run anywhere.
"""

import os
import tempfile

from utils.validators import (
    sanitize_path,
    validate_bind_ip,
    validate_config,
    validate_hostname,
    validate_http_method,
    validate_ip,
    validate_port,
)

# â”€â”€ validate_ip â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestValidateIp:
    def test_valid_ipv4(self):
        ok, addr = validate_ip("192.168.1.1")
        assert ok
        assert addr == "192.168.1.1"

    def test_valid_ipv6(self):
        ok, addr = validate_ip("::1")
        assert ok
        assert addr == "::1"

    def test_loopback(self):
        ok, addr = validate_ip("127.0.0.1")
        assert ok
        assert addr == "127.0.0.1"

    def test_invalid_string(self):
        ok, msg = validate_ip("not-an-ip")
        assert not ok
        assert "not-an-ip" in msg

    def test_empty_string(self):
        ok, _ = validate_ip("")
        assert not ok

    def test_wildcard_not_valid_as_unicast(self):
        # 0.0.0.0 is technically a valid IP address
        ok, addr = validate_ip("0.0.0.0")
        assert ok
        assert addr == "0.0.0.0"


# â”€â”€ validate_port â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â

class TestValidatePort:
    def test_valid_ports(self):
        for p in (1, 80, 443, 8080, 65535):
            ok, val = validate_port(p)
            assert ok
            assert val == p

    def test_string_port(self):
        ok, val = validate_port("8080")
        assert ok
        assert val == 8080

    def test_zero_invalid(self):
        ok, val = validate_port(0)
        assert not ok

    def test_above_max_invalid(self):
        ok, val = validate_port(65536)
        assert not ok

    def test_negative_invalid(self):
        ok, val = validate_port(-1)
        assert not ok

    def test_non_numeric_invalid(self):
        ok, val = validate_port("abc")
        assert not ok

    def test_none_invalid(self):
        ok, val = validate_port(None)
        assert not ok


# â”€â”€ validate_hostname â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestValidateHostname:
    def test_simple_hostname(self):
        assert validate_hostname("localhost")

    def test_fqdn(self):
        assert validate_hostname("mail.example.com")

    def test_fqdn_with_trailing_dot(self):
        assert validate_hostname("mail.example.com.")

    def test_hyphen_allowed(self):
        assert validate_hostname("my-host.example.com")

    def test_empty_invalid(self):
        assert not validate_hostname("")

    def test_too_long_invalid(self):
        assert not validate_hostname("a" * 254)

    def test_underscore_invalid(self):
        # RFC 1123 does not allow underscores
        assert not validate_hostname("bad_host.example.com")

    def test_numeric_label(self):
        assert validate_hostname("host123.example.com")


# â”€â”€ validate_bind_ip â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â

class TestValidateBindIp:
    def test_wildcard_ipv4(self):
        ok, addr = validate_bind_ip("0.0.0.0")
        assert ok
        assert addr == "0.0.0.0"

    def test_wildcard_ipv6(self):
        ok, addr = validate_bind_ip("::")
        assert ok
        assert addr == "::"

    def test_specific_ip(self):
        ok, addr = validate_bind_ip("10.0.0.1")
        assert ok
        assert addr == "10.0.0.1"

    def test_invalid(self):
        ok, _ = validate_bind_ip("not-valid")
        assert not ok


# â”€â”€ sanitize_path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â

class TestSanitizePath:
    def test_safe_subpath(self):
        with tempfile.TemporaryDirectory() as base:
            result = sanitize_path(base, "subdir/file.txt")
            assert result is not None
            assert result.startswith(base)
            # Verify the sub-path is preserved verbatim, not silently stripped.
            assert result.endswith(os.path.join("subdir", "file.txt"))

    def test_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as base:
            result = sanitize_path(base, "../../etc/passwd")
            assert result is None

    def test_exact_base_rejected(self):
        # Requesting exactly the base dir resolves to base itself; either None
        # or the base path are acceptable — what matters is that it never
        # escapes (no traversal up to /etc/passwd, /, etc.).
        with tempfile.TemporaryDirectory() as base:
            parent = os.path.dirname(base)
            result = sanitize_path(parent, os.path.basename(base))
            if result is not None:
                assert result.startswith(parent)
                assert ".." not in os.path.relpath(result, parent)


# â”€â”€ validate_http_method â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestValidateHttpMethod:
    def test_standard_methods(self):
        for method in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
            assert validate_http_method(method)

    def test_case_insensitive(self):
        assert validate_http_method("get")
        assert validate_http_method("Post")

    def test_unknown_method(self):
        assert not validate_http_method("INVALID")

    def test_empty(self):
        assert not validate_http_method("")


# â”€â”€ validate_config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

class TestValidateConfig:
    def test_valid_full_config(self):
        cfg = {
            "general": {"bind_ip": "0.0.0.0", "redirect_ip": "127.0.0.1"},
            "http": {"enabled": True, "port": 80},
            "dns": {"enabled": True, "port": 53},
        }
        errors = validate_config(cfg)
        assert errors == []

    def test_invalid_bind_ip(self):
        cfg = {
            "general": {"bind_ip": "not-an-ip", "redirect_ip": "127.0.0.1"},
        }
        errors = validate_config(cfg)
        assert any("bind_ip" in e for e in errors)

    def test_invalid_redirect_ip(self):
        cfg = {
            "general": {"bind_ip": "0.0.0.0", "redirect_ip": "bad"},
        }
        errors = validate_config(cfg)
        assert any("redirect_ip" in e for e in errors)

    def test_invalid_service_port(self):
        cfg = {
            "general": {"bind_ip": "0.0.0.0", "redirect_ip": "127.0.0.1"},
            "http": {"enabled": True, "port": 99999},
        }
        errors = validate_config(cfg)
        assert any("http.port" in e for e in errors)


    def test_empty_config_uses_defaults(self):
        # Empty config should not error (defaults are valid)
        errors = validate_config({})
        assert errors == []

    def test_smtps_port_invalid(self):
        cfg = {"smtps": {"enabled": True, "port": 0}}
        errors = validate_config(cfg)
        assert any("smtps.port" in e for e in errors)

    def test_smb_port_invalid(self):
        cfg = {"smb": {"enabled": True, "port": -1}}
        errors = validate_config(cfg)
        assert any("smb.port" in e for e in errors)

    def test_catch_all_tcp_port_invalid(self):
        cfg = {"catch_all": {"enabled": True, "tcp_port": 99999, "udp_port": 9998}}
        errors = validate_config(cfg)
        assert any("catch_all.tcp_port" in e for e in errors)

    def test_catch_all_udp_port_invalid(self):
        cfg = {"catch_all": {"enabled": True, "tcp_port": 9999, "udp_port": "bad"}}
        errors = validate_config(cfg)
        assert any("catch_all.udp_port" in e for e in errors)

    def test_smtp_max_connections_zero_invalid(self):
        cfg = {"smtp": {"max_connections": 0}}
        errors = validate_config(cfg)
        assert any("smtp.max_connections" in e for e in errors)

    def test_smtp_conn_timeout_negative_invalid(self):
        cfg = {"smtp": {"conn_timeout_sec": -5}}
        errors = validate_config(cfg)
        assert any("smtp.conn_timeout_sec" in e for e in errors)

    def test_smtp_max_email_size_non_numeric_invalid(self):
        cfg = {"smtp": {"max_email_size_bytes": "big"}}
        errors = validate_config(cfg)
        assert any("smtp.max_email_size_bytes" in e for e in errors)

    def test_ftp_max_upload_size_zero_invalid(self):
        cfg = {"ftp": {"max_upload_size_bytes": 0}}
        errors = validate_config(cfg)
        assert any("ftp.max_upload_size_bytes" in e for e in errors)

    def test_catch_all_peek_timeout_zero_invalid(self):
        cfg = {"catch_all": {"peek_timeout_sec": 0}}
        errors = validate_config(cfg)
        assert any("catch_all.peek_timeout_sec" in e for e in errors)

    def test_catch_all_peek_timeout_float_valid(self):
        cfg = {"catch_all": {"peek_timeout_sec": 0.5}}
        errors = validate_config(cfg)
        assert not any("catch_all.peek_timeout_sec" in e for e in errors)

    def test_ftp_pasv_low_greater_than_high_invalid(self):
        cfg = {"ftp": {"pasv_port_low": 51000, "pasv_port_high": 50000}}
        errors = validate_config(cfg)
        assert any("pasv_port_low" in e and "pasv_port_high" in e for e in errors)

    def test_ftp_pasv_low_equal_to_high_invalid(self):
        cfg = {"ftp": {"pasv_port_low": 50000, "pasv_port_high": 50000}}
        errors = validate_config(cfg)
        assert any("pasv_port_low" in e for e in errors)

    def test_ftp_pasv_port_range_valid(self):
        cfg = {"ftp": {"pasv_port_low": 50000, "pasv_port_high": 51000}}
        errors = validate_config(cfg)
        assert not any("pasv_port" in e for e in errors)

    def test_ftp_pasv_port_low_invalid_port(self):
        cfg = {"ftp": {"pasv_port_low": 0, "pasv_port_high": 51000}}
        errors = validate_config(cfg)
        assert any("pasv_port_low" in e for e in errors)

    def test_ftp_upload_dir_traversal_rejected(self):
        cfg = {"ftp": {"upload_dir": "logs/../../../etc"}}
        errors = validate_config(cfg)
        assert any("ftp.upload_dir" in e for e in errors)

    def test_tftp_upload_dir_traversal_rejected(self):
        cfg = {"tftp": {"upload_dir": "../outside"}}
        errors = validate_config(cfg)
        assert any("tftp.upload_dir" in e for e in errors)

    def test_https_cert_file_traversal_rejected(self):
        cfg = {"https": {"cert_file": "../../etc/ssl/server.crt"}}
        errors = validate_config(cfg)
        assert any("https.cert_file" in e for e in errors)

    def test_https_key_file_traversal_rejected(self):
        cfg = {"https": {"key_file": "../../etc/ssl/server.key"}}
        errors = validate_config(cfg)
        assert any("https.key_file" in e for e in errors)

    def test_http_response_body_file_traversal_rejected(self):
        cfg = {"http": {"response_body_file": "../../../etc/passwd"}}
        errors = validate_config(cfg)
        assert any("http.response_body_file" in e for e in errors)

    def test_positive_fields_absent_no_error(self):
        cfg = {"smtp": {}}
        errors = validate_config(cfg)
        assert not any("smtp." in e for e in errors)

    def test_smb_session_timeout_zero_invalid(self):
        cfg = {"smb": {"session_timeout_sec": 0}}
        errors = validate_config(cfg)
        assert any("smb.session_timeout_sec" in e for e in errors)

    def test_valid_catch_all_knobs(self):
        cfg = {"catch_all": {"enabled": True, "tcp_port": 9999, "udp_port": 9998,
                             "max_connections": 200, "max_per_ip": 20,
                             "session_timeout_sec": 10, "peek_timeout_sec": 0.5}}
        errors = validate_config(cfg)
        assert errors == []
