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
        # Verify the actual iptables command constructed (not just that _run was called)
        called_args = mock_run.call_args[0][0]
        assert called_args[0] == "iptables"
        assert "-t" in called_args
        assert "DNAT" in called_args
        assert "10.0.0.1:80" in called_args

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
    def test_del_rule_converts_a_to_d(self, mock_run):
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
        # Verify each port appears in exactly one iptables command
        all_args = [call[0][0] for call in mock_run.call_args_list]
        seen_ports = {a for args in all_args for a in args if a in ("80", "443", "53")}
        assert seen_ports == {"80", "443", "53"}

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
        # RETURN rules must reference the excluded ports; DNAT must target catch-all port
        all_args = [call[0][0] for call in mock_run.call_args_list]
        flat = [str(a) for args in all_args for a in args]
        assert "RETURN" in flat
        assert any("9999" in a for a in flat)  # catch-all port in DNAT destination
        assert "22" in flat or "3389" in flat


class TestPassthroughSubnets:
    """Verify passthrough_subnets: valid CIDRs accepted, invalid rejected, RETURN rules emitted."""

    def _mgr(self, **overrides) -> IPTablesManager:
        cfg = {"auto_iptables": True, "interface": "eth0",
               "redirect_ip": "10.0.0.1", "iptables_mode": "gateway"}
        cfg.update(overrides)
        return IPTablesManager(cfg)

    def test_valid_cidr_accepted(self):
        mgr = self._mgr(passthrough_subnets=["10.10.10.0/24"])
        assert mgr.passthrough_subnets == ["10.10.10.0/24"]

    def test_invalid_cidr_rejected(self):
        mgr = self._mgr(passthrough_subnets=["not-a-cidr", "300.0.0.1/24", "10.0.0.0/33"])
        assert mgr.passthrough_subnets == []

    def test_mixed_valid_invalid(self):
        mgr = self._mgr(passthrough_subnets=["10.10.10.0/24", "bad", "192.168.0.0/16"])
        assert mgr.passthrough_subnets == ["10.10.10.0/24", "192.168.0.0/16"]

    @patch("network.iptables_manager._run", return_value=(0, "", ""))
    def test_passthrough_subnets_creates_return_rules(self, mock_run):
        mgr = self._mgr(passthrough_subnets=["10.10.10.0/24"])
        count = mgr._apply_passthrough_subnets("PREROUTING", ["-t", "nat"])
        assert count == 1
        all_args = [call[0][0] for call in mock_run.call_args_list]
        # Rule must require BOTH source and destination inside the LAN so that
        # victim->Kali traffic is still caught by NTN's DNAT (only intra-LAN
        # spread is exempted).
        emitted = next(a for a in all_args if "RETURN" in a)
        assert "-s" in emitted and "-d" in emitted
        s_idx = emitted.index("-s")
        d_idx = emitted.index("-d")
        assert emitted[s_idx + 1] == "10.10.10.0/24"
        assert emitted[d_idx + 1] == "10.10.10.0/24"

    @patch("network.iptables_manager._run", return_value=(0, "", ""))
    def test_gateway_mode_auto_derives_intra_lan_passthrough(self, mock_run):
        """In gateway mode with no explicit passthrough_subnets, the LAN CIDR
        must be auto-derived from the interface so worm-style /24 scans can
        spread between victims out of the box."""
        mgr = self._mgr(passthrough_subnets=[])
        with patch.object(
            IPTablesManager, "_first_ipv4_cidr_on", return_value="10.10.10.1/24",
        ):
            count = mgr._apply_passthrough_subnets("PREROUTING", ["-t", "nat"])
        assert count == 1
        emitted = next(c[0][0] for c in mock_run.call_args_list if "RETURN" in c[0][0])
        # Network CIDR derived from host CIDR (10.10.10.1/24 -> 10.10.10.0/24).
        assert "10.10.10.0/24" in emitted
        assert "-s" in emitted and "-d" in emitted

    @patch("network.iptables_manager._run", return_value=(0, "", ""))
    def test_empty_passthrough_subnets_sinkhole_mode_no_rules(self, mock_run):
        """Sinkhole mode (non-gateway) must NOT auto-derive: NTN is supposed
        to capture everything on the host, including its own LAN."""
        cfg = {"auto_iptables": True, "interface": "eth0",
               "redirect_ip": "10.0.0.1", "iptables_mode": "sinkhole",
               "passthrough_subnets": []}
        mgr = IPTablesManager(cfg)
        count = mgr._apply_passthrough_subnets("PREROUTING", ["-t", "nat"])
        assert count == 0
        mock_run.assert_not_called()


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
        # Patch _validate_interface so the autodetect fallback (added in -8)
        # doesn't override the configured value when br0 isn't a real iface.
        with patch.object(IPTablesManager, "_validate_interface", return_value=True):
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

