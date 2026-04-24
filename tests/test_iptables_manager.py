"""
Tests for network/iptables_manager.py — validation, rule building, snapshot paths.

All tests mock subprocess and /proc so they run without root on any OS.
"""

import os
from unittest.mock import mock_open, patch

import pytest

from network.iptables_manager import (
    _IPTABLES_SAVE_FILE,
    _MANGLE_SAVE_FILE,
    _RULE_COMMENT,
    _SNAPSHOT_DIR,
    IPTablesManager,
)

# ── Snapshot path safety ─────────────────────────────────────────────────────

class TestSnapshotPaths:
    """Verify snapshots are stored in app-owned directory, not /tmp/."""

    def test_snapshot_dir_is_not_tmp(self):
        assert "/tmp" not in _SNAPSHOT_DIR  # noqa: S108
        assert "\\Temp" not in _SNAPSHOT_DIR

    def test_snapshot_dir_is_logs(self):
        assert _SNAPSHOT_DIR.endswith("logs")

    def test_save_file_under_logs(self):
        assert _IPTABLES_SAVE_FILE.startswith(_SNAPSHOT_DIR)
        assert _MANGLE_SAVE_FILE.startswith(_SNAPSHOT_DIR)

    def test_save_files_are_dotfiles(self):
        """Hidden dotfiles reduce accidental exposure in directory listings."""
        assert os.path.basename(_IPTABLES_SAVE_FILE).startswith(".")
        assert os.path.basename(_MANGLE_SAVE_FILE).startswith(".")


# ── Interface validation ─────────────────────────────────────────────────────

class TestValidateInterface:
    """IPTablesManager._validate_interface must reject bad names and fail closed."""

    def _mgr(self) -> IPTablesManager:
        return IPTablesManager({"auto_iptables": False})

    def test_rejects_empty(self):
        assert not self._mgr()._validate_interface("")

    def test_rejects_too_long(self):
        assert not self._mgr()._validate_interface("a" * 16)

    def test_rejects_special_chars(self):
        for bad in ("eth0;rm", "eth0 ", "eth0\n", "../etc", "eth0|cat"):
            assert not self._mgr()._validate_interface(bad), f"accepted {bad!r}"

    def test_accepts_valid_names(self):
        proc_content = "eth0: 0 0\nlo: 0 0\nveth1.2: 0 0\n"
        with patch("builtins.open", mock_open(read_data=proc_content)):
            mgr = self._mgr()
            assert mgr._validate_interface("eth0")
            assert mgr._validate_interface("lo")
            assert mgr._validate_interface("veth1.2")

    def test_rejects_nonexistent_interface(self):
        proc_content = "eth0: 0 0\nlo: 0 0\n"
        with patch("builtins.open", mock_open(read_data=proc_content)):
            assert not self._mgr()._validate_interface("wlan99")

    def test_fail_closed_on_proc_unreadable(self):
        """If /proc/net/dev cannot be read, reject the interface (fail-closed)."""
        with patch("builtins.open", side_effect=PermissionError("denied")):
            assert not self._mgr()._validate_interface("eth0")

    def test_fail_closed_on_oserror(self):
        with patch("builtins.open", side_effect=OSError("no such file")):
            assert not self._mgr()._validate_interface("eth0")


# ── Rule building ────────────────────────────────────────────────────────────

class TestRuleBuilding:
    """Verify iptables rule construction without executing anything."""

    def _mgr(self, **overrides) -> IPTablesManager:
        cfg = {"auto_iptables": True, "interface": "eth0",
               "redirect_ip": "10.0.0.1", "iptables_mode": "gateway"}
        cfg.update(overrides)
        return IPTablesManager(cfg)

    @patch("network.iptables_manager._run", return_value=(0, "", ""))
    def test_add_rule_tracks_applied(self, mock_run):
        mgr = self._mgr()
        rule = ["-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80",
                "-j", "DNAT", "--to-destination", "10.0.0.1:80",
                "-m", "comment", "--comment", _RULE_COMMENT]
        assert mgr._add_rule(rule)
        assert rule in mgr._rules_applied
        mock_run.assert_called_once()

    @patch("network.iptables_manager._run", return_value=(1, "", "error"))
    def test_add_rule_failure_not_tracked(self, mock_run):
        mgr = self._mgr()
        rule = ["-t", "nat", "-A", "PREROUTING", "-p", "tcp"]
        assert not mgr._add_rule(rule)
        assert rule not in mgr._rules_applied

    def test_add_rule_rejects_non_string_args(self):
        mgr = self._mgr()
        assert not mgr._add_rule(["-t", "nat", 42])

    @patch("network.iptables_manager._run", return_value=(0, "", ""))
    def test_del_rule_converts_A_to_D(self, mock_run):
        mgr = self._mgr()
        rule = ["-t", "nat", "-A", "PREROUTING", "-p", "tcp"]
        mgr._del_rule(rule)
        args = mock_run.call_args[0][0]
        assert "-D" in args
        assert "-A" not in args

    @patch("network.iptables_manager._run", return_value=(0, "", ""))
    def test_service_redirects_count(self, mock_run):
        mgr = self._mgr()
        ports = {"tcp": [80, 443], "udp": [53]}
        count = mgr._apply_service_redirects(ports, "PREROUTING", ["-t", "nat"])
        assert count == 3

    @patch("network.iptables_manager._run", return_value=(0, "", ""))
    def test_service_redirects_skip_invalid_proto(self, mock_run):
        mgr = self._mgr()
        count = mgr._apply_service_redirects(
            {"sctp": [80]}, "PREROUTING", ["-t", "nat"])
        assert count == 0

    @patch("network.iptables_manager._run", return_value=(0, "", ""))
    def test_catch_all_creates_return_rules(self, mock_run):
        mgr = self._mgr()
        count = mgr._apply_catch_all(
            "PREROUTING", ["-t", "nat"],
            excluded_ports=[22, 3389],
            catch_all_tcp_port=9999,
            catch_all_udp_port=0,
        )
        # 2 RETURN rules for excluded ports + 1 catch-all DNAT = 3 _add_rule calls
        assert count == 1  # only DNAT rules are counted
        assert mock_run.call_count == 3


# ── TTL validation ───────────────────────────────────────────────────────────

class TestTTLValidation:
    def test_valid_ttl(self):
        mgr = IPTablesManager({"spoof_ttl": 48})
        assert mgr.spoof_ttl == 48

    def test_ttl_zero_disables(self):
        mgr = IPTablesManager({"spoof_ttl": 0})
        assert mgr.spoof_ttl == 0

    def test_ttl_out_of_range_disables(self):
        mgr = IPTablesManager({"spoof_ttl": 300})
        assert mgr.spoof_ttl == 0

    def test_ttl_negative_disables(self):
        mgr = IPTablesManager({"spoof_ttl": -1})
        assert mgr.spoof_ttl == 0


# ── Mode configuration ──────────────────────────────────────────────────────

class TestModeConfig:
    def test_defaults(self):
        mgr = IPTablesManager({})
        assert mgr.enabled is True
        assert mgr.interface == "eth0"
        assert mgr.mode == "loopback"
        assert mgr.redirect_ip == "127.0.0.1"

    def test_gateway_mode(self):
        mgr = IPTablesManager({"iptables_mode": "gateway", "interface": "br0"})
        assert mgr.mode == "gateway"
        assert mgr.interface == "br0"

    @pytest.mark.skipif(not hasattr(os, "geteuid"), reason="os.geteuid unavailable on Windows")
    def test_apply_rules_refuses_without_root(self):
        with patch("os.geteuid", return_value=1000):
            mgr = IPTablesManager({"auto_iptables": True})
            assert not mgr.apply_rules({"tcp": [80]})

    def test_apply_rules_disabled(self):
        mgr = IPTablesManager({"auto_iptables": False})
        assert not mgr.apply_rules({"tcp": [80]})


# ── Auto-detection helpers (interface + gateway IP) ─────────────────────────

class TestAutoDetection:
    """Verify autodetect helpers used to make defaults work across labs."""

    def test_first_ipv4_on_parses_ip_addr_output(self):
        sample = "2: eth0    inet 10.10.10.1/24 brd 10.10.10.255 scope global eth0\n"
        with patch("network.iptables_manager._run", return_value=(0, sample, "")):
            assert IPTablesManager._first_ipv4_on("eth0") == "10.10.10.1"

    def test_first_ipv4_on_skips_loopback(self):
        sample = "1: lo    inet 127.0.0.1/8 scope host lo\n"
        with patch("network.iptables_manager._run", return_value=(0, sample, "")):
            assert IPTablesManager._first_ipv4_on(None) is None

    def test_first_ipv4_on_returns_none_when_ip_missing(self):
        with patch("network.iptables_manager._run", return_value=(127, "", "not found")):
            assert IPTablesManager._first_ipv4_on("eth0") is None

    def test_detect_default_interface_parses_ip_route(self):
        sample = "default via 10.10.10.254 dev eth0 proto dhcp metric 100\n"
        with patch("network.iptables_manager._run", return_value=(0, sample, "")):
            assert IPTablesManager._detect_default_interface() == "eth0"

    def test_detect_default_interface_returns_none_on_failure(self):
        with patch("network.iptables_manager._run", return_value=(2, "", "err")):
            assert IPTablesManager._detect_default_interface() is None

    def test_derive_gateway_ip_prefers_explicit_bind_ip(self):
        mgr = IPTablesManager({"interface": "eth0", "iptables_mode": "loopback"})
        assert mgr._derive_gateway_ip("10.10.10.1") == "10.10.10.1"

    def test_derive_gateway_ip_falls_back_to_interface_ipv4(self):
        sample = "2: eth0    inet 10.10.10.1/24 brd ... scope global eth0\n"
        mgr = IPTablesManager({"interface": "eth0", "iptables_mode": "loopback"})
        with patch("network.iptables_manager._run", return_value=(0, sample, "")):
            assert mgr._derive_gateway_ip("0.0.0.0") == "10.10.10.1"

