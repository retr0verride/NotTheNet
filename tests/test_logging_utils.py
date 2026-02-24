"""
Tests for utils/logging_utils.py — CWE-117 log injection prevention.
"""

from utils.logging_utils import (
    sanitize_hostname,
    sanitize_ip,
    sanitize_log_string,
)

# ── sanitize_log_string ───────────────────────────────────────────────────────

class TestSanitizeLogString:
    def test_clean_string_unchanged(self):
        s = "hello world 123"
        assert sanitize_log_string(s) == s

    def test_newline_replaced(self):
        result = sanitize_log_string("foo\nbar")
        assert "\n" not in result
        assert "[?]" in result

    def test_carriage_return_replaced(self):
        result = sanitize_log_string("foo\rbar")
        assert "\r" not in result

    def test_null_byte_replaced(self):
        result = sanitize_log_string("foo\x00bar")
        assert "\x00" not in result

    def test_ansi_escape_stripped(self):
        # ANSI escape: ESC[31m (red) should be removed
        result = sanitize_log_string("\x1b[31mREDTEXT\x1b[0m")
        assert "\x1b" not in result
        assert "REDTEXT" in result

    def test_truncation(self):
        long_str = "A" * 600
        result = sanitize_log_string(long_str, max_length=512)
        assert len(result) <= 512 + len("...[truncated]")
        assert result.endswith("...[truncated]")

    def test_non_string_converted(self):
        result = sanitize_log_string(42)  # type: ignore[arg-type]
        assert result == "42"

    def test_empty_string(self):
        assert sanitize_log_string("") == ""


# ── sanitize_ip ───────────────────────────────────────────────────────────────

class TestSanitizeIp:
    def test_valid_ipv4(self):
        assert sanitize_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6_loopback(self):
        assert sanitize_ip("::1") == "::1"

    def test_invalid_returns_placeholder(self):
        result = sanitize_ip("not-an-ip")
        assert result == "<invalid-ip>"

    def test_ip_with_injection_attempt(self):
        result = sanitize_ip("1.2.3.4\nmalicious")
        assert result == "<invalid-ip>"


# ── sanitize_hostname ─────────────────────────────────────────────────────────

class TestSanitizeHostname:
    def test_valid_hostname_unchanged(self):
        assert sanitize_hostname("example.com") == "example.com"

    def test_with_numbers_and_hyphens(self):
        assert sanitize_hostname("host-1.example.com") == "host-1.example.com"

    def test_control_chars_replaced(self):
        result = sanitize_hostname("evil\r\nhost.com")
        assert "\r" not in result
        assert "\n" not in result

    def test_truncated_to_max_length(self):
        long = "a" * 300
        result = sanitize_hostname(long, max_length=253)
        assert len(result) == 253

    def test_empty_hostname(self):
        assert sanitize_hostname("") == "<empty>"
