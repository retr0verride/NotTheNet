"""
Tests for service_manager.py — ServiceManager orchestration, lifecycle,
config validation, port-conflict detection, log purge, and session paths.
"""

import json
import os
import time
from datetime import date
from unittest.mock import patch

import pytest

from config import Config
from service_manager import (
    _CONFLICTING_SYSTEM_SERVICES,
    _SERVICE_REGISTRY,
    ServiceManager,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _cfg(tmp_path, overrides=None):
    """Create a minimal Config with ALL services disabled."""
    # Start with every registered service disabled to prevent real port binding.
    data: dict = {"general": {
        "bind_ip": "127.0.0.1",
        "redirect_ip": "127.0.0.1",
        "spoof_public_ip": "1.2.3.4",
        "auto_iptables": False,
        "auto_evict_services": False,
        "json_logging": False,
        "drop_privileges": False,
        "tcp_fingerprint": False,
        "process_masquerade": False,
        "log_dir": str(tmp_path / "logs"),
    }}
    for spec in _SERVICE_REGISTRY:
        section = spec.config_section
        data.setdefault(section, {})["enabled"] = False
        if spec.default_port:
            data[section]["port"] = spec.default_port
    # catch_all needs extra keys
    data.setdefault("catch_all", {}).update({"tcp_port": 9999, "udp_port": 9998})
    data.setdefault("https", {}).update({"dynamic_certs": False})
    if overrides:
        for section, keys in overrides.items():
            data.setdefault(section, {}).update(keys)
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(data))
    return Config(str(cfg_path))


# ── ServiceSpec ───────────────────────────────────────────────────────────────

class TestServiceSpec:
    def test_spec_is_frozen(self):
        spec = _SERVICE_REGISTRY[0]
        with pytest.raises(AttributeError):
            spec.name = "hacked"  # type: ignore[misc]

    def test_registry_has_expected_services(self):
        names = {s.name for s in _SERVICE_REGISTRY}
        for expected in ("dns", "http", "https", "smtp", "ftp", "icmp", "catch_tcp"):
            assert expected in names, f"Missing expected service: {expected}"

    def test_spec_tls_flag_matches_port(self):
        tls_ports = {443, 465, 993, 995, 853, 1080, 6697}
        for spec in _SERVICE_REGISTRY:
            if spec.default_port in tls_ports:
                assert spec.tls, f"{spec.name} (port {spec.default_port}) should have tls=True"


# ── Session log path ─────────────────────────────────────────────────────────

class TestSessionLogPath:
    def test_first_session_returns_s1(self, tmp_path):
        log_dir = str(tmp_path)
        path = ServiceManager._session_log_path(log_dir)
        assert path.endswith("_s1.jsonl")
        assert date.today().isoformat() in path

    def test_increments_existing_sessions(self, tmp_path):
        today = date.today().isoformat()
        for n in (1, 2, 3):
            (tmp_path / f"events_{today}_s{n}.jsonl").touch()
        path = ServiceManager._session_log_path(str(tmp_path))
        assert path.endswith("_s4.jsonl")

    def test_ignores_other_date_files(self, tmp_path):
        (tmp_path / "events_1999-01-01_s5.jsonl").touch()
        path = ServiceManager._session_log_path(str(tmp_path))
        assert path.endswith("_s1.jsonl")


# ── Log purge ────────────────────────────────────────────────────────────────

class TestPurgeOldLogs:
    def test_deletes_old_files(self, tmp_path):
        old = tmp_path / "events_2020-01-01_s1.jsonl"
        old.touch()
        # Backdate mtime by 30 days
        old_ts = time.time() - 86400 * 30
        os.utime(str(old), (old_ts, old_ts))
        ServiceManager._purge_old_logs(str(tmp_path), max_age_days=14)
        assert not old.exists()

    def test_keeps_recent_files(self, tmp_path):
        recent = tmp_path / f"events_{date.today().isoformat()}_s1.jsonl"
        recent.touch()
        ServiceManager._purge_old_logs(str(tmp_path), max_age_days=14)
        assert recent.exists()

    def test_ignores_non_matching_files(self, tmp_path):
        other = tmp_path / "debug.log"
        other.write_text("keep me")
        old_ts = time.time() - 86400 * 30
        os.utime(str(other), (old_ts, old_ts))
        ServiceManager._purge_old_logs(str(tmp_path), max_age_days=14)
        assert other.exists()


# ── Config validation ────────────────────────────────────────────────────────

class TestValidation:
    def test_valid_config_returns_no_errors(self, tmp_path):
        cfg = _cfg(tmp_path)
        sm = ServiceManager(cfg)
        assert sm.validate() == []


# ── Port conflict detection ──────────────────────────────────────────────────

class TestPortConflicts:
    def test_duplicate_port_logs_warning(self, tmp_path, caplog):
        """Two enabled services with the same port should produce a warning."""
        cfg = _cfg(tmp_path, overrides={
            "smtp": {"enabled": True, "port": 80},
            "http": {"enabled": True, "port": 80},
        })
        sm = ServiceManager(cfg)
        import logging
        with caplog.at_level(logging.WARNING):
            sm._check_port_conflicts()
        assert any("Port conflict" in r.message for r in caplog.records)


# ── Evict conflicting services ───────────────────────────────────────────────

class TestEvictConflicting:
    def test_all_system_services_listed(self):
        """Verify the list includes key known conflicts."""
        for svc in ("bind9", "systemd-resolved", "apache2", "smbd"):
            assert svc in _CONFLICTING_SYSTEM_SERVICES

    @patch("service_manager.shutil.which", return_value=None)
    @patch("service_manager.subprocess.run")
    def test_no_systemctl_is_noop(self, mock_subprocess, mock_which, tmp_path):
        cfg = _cfg(tmp_path)
        sm = ServiceManager(cfg)
        sm._evict_conflicting_services()
        # Without systemctl, no subprocess calls should be made
        mock_subprocess.assert_not_called()


# ── Start / stop lifecycle ───────────────────────────────────────────────────

class TestLifecycle:
    def test_start_with_all_disabled_runs_cleanly(self, tmp_path):
        """start() should not crash even with all services disabled."""
        cfg = _cfg(tmp_path)
        sm = ServiceManager(cfg)
        # Some services may still start if they ignore 'enabled'; that's OK.
        # The important thing is no unhandled exception.
        sm.start()
        sm.stop()
        assert sm.running is False

    def test_status_empty_when_nothing_running(self, tmp_path):
        cfg = _cfg(tmp_path)
        sm = ServiceManager(cfg)
        assert sm.status() == {}

    def test_stop_idempotent(self, tmp_path):
        """Calling stop() when nothing is running should not raise."""
        cfg = _cfg(tmp_path)
        sm = ServiceManager(cfg)
        sm.stop()
        assert sm.running is False


# ── prepare_dirs_for_drop helpers ────────────────────────────────────────────

class TestPrepareDirs:
    def test_chown_log_dirs_creates_subdirs(self, tmp_path):
        log_dir = str(tmp_path / "logs")
        # On Windows, os.chown doesn't exist; just verify makedirs works.
        with patch("os.chown", create=True):
            ServiceManager._chown_log_dirs(log_dir, uid=65534, gid=65534)
        assert os.path.isdir(os.path.join(log_dir, "emails"))
        assert os.path.isdir(os.path.join(log_dir, "ftp_uploads"))
        assert os.path.isdir(os.path.join(log_dir, "tftp_uploads"))

    @pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX only")
    def test_ensure_parent_traversal_adds_ox(self, tmp_path):
        import stat
        log_dir = tmp_path / "a" / "b"
        log_dir.mkdir(parents=True)
        # Remove o+x from parent
        parent = tmp_path / "a"
        parent.chmod(parent.stat().st_mode & ~stat.S_IXOTH)
        ServiceManager._ensure_parent_traversal(str(log_dir))
        assert parent.stat().st_mode & stat.S_IXOTH


# ── build_service_ports ──────────────────────────────────────────────────────

class TestBuildServicePorts:
    def test_returns_tcp_udp_keys(self, tmp_path):
        cfg = _cfg(tmp_path)
        sm = ServiceManager(cfg)
        ports = sm._build_service_ports()
        assert "tcp" in ports
        assert "udp" in ports
        # No services running → both empty
        assert ports["tcp"] == []
        assert ports["udp"] == []


# ── ServiceRepoAdapter ────────────────────────────────────────────────────────

class TestServiceRepoAdapter:
    """Verify adapter lifecycle and lazy-init contract."""

    def _adapter(self, tmp_path):
        from config import Config
        from infrastructure.adapters.service_repo_adapter import ServiceRepoAdapter

        cfg = Config.__new__(Config)
        cfg._data = _cfg(tmp_path)._data
        cfg._path = str(tmp_path / "config.json")
        return ServiceRepoAdapter(cfg)

    def test_manager_not_created_at_init(self, tmp_path):
        adapter = self._adapter(tmp_path)
        assert adapter._manager is None

    def test_probe_instantiates_manager(self, tmp_path):
        adapter = self._adapter(tmp_path)
        adapter.probe()
        assert adapter._manager is not None

    def test_stop_all_before_start_is_noop(self, tmp_path):
        """stop_all() before start_all() must not raise (manager is None)."""
        adapter = self._adapter(tmp_path)
        adapter.stop_all()  # should not raise

    def test_is_running_before_start_returns_false(self, tmp_path):
        adapter = self._adapter(tmp_path)
        assert adapter.is_running("dns") is False

    def test_get_status_before_start_returns_empty(self, tmp_path):
        adapter = self._adapter(tmp_path)
        assert adapter.get_status() == []


# ── DNS resolve_to auto-derive in gateway mode ───────────────────────────────

class TestDnsResolveTo:
    """Regression: gateway mode must derive resolve_to from redirect_ip, not loopback."""

    def _sm(self, tmp_path, overrides=None):
        cfg = _cfg(tmp_path, overrides)
        return ServiceManager(cfg)

    def test_gateway_mode_overrides_loopback_resolve_to(self, tmp_path):
        """When iptables_mode=gateway and resolve_to=127.0.0.1, DNS builder must
        replace resolve_to with the derived redirect_ip so malware following
        DNS-discovered targets reaches NTN instead of the victim's loopback."""
        sm = self._sm(tmp_path, {
            "general": {"iptables_mode": "gateway", "redirect_ip": "10.10.10.1"},
            "dns": {"resolve_to": "127.0.0.1", "enabled": False},
        })
        from service_manager import _SERVICE_REGISTRY
        dns_spec = next(s for s in _SERVICE_REGISTRY if s.name == "dns")
        cfg_out, _ = sm._special_builders(
            dns_spec, "0.0.0.0", "98.6.112.145", "10.10.10.1",
            {"cert_file": "", "key_file": ""},
        )
        assert cfg_out["resolve_to"] == "10.10.10.1"

    def test_gateway_mode_respects_explicit_resolve_to(self, tmp_path):
        """An explicit non-loopback resolve_to must be preserved in gateway mode."""
        sm = self._sm(tmp_path, {
            "general": {"iptables_mode": "gateway", "redirect_ip": "10.10.10.1"},
            "dns": {"resolve_to": "192.168.1.99", "enabled": False},
        })
        from service_manager import _SERVICE_REGISTRY
        dns_spec = next(s for s in _SERVICE_REGISTRY if s.name == "dns")
        cfg_out, _ = sm._special_builders(
            dns_spec, "0.0.0.0", "98.6.112.145", "10.10.10.1",
            {"cert_file": "", "key_file": ""},
        )
        assert cfg_out["resolve_to"] == "192.168.1.99"

    def test_sinkhole_mode_keeps_loopback_resolve_to(self, tmp_path):
        """In sinkhole mode, resolve_to=127.0.0.1 must NOT be replaced."""
        sm = self._sm(tmp_path, {
            "general": {"iptables_mode": "sinkhole", "redirect_ip": "127.0.0.1"},
            "dns": {"resolve_to": "127.0.0.1", "enabled": False},
        })
        from service_manager import _SERVICE_REGISTRY
        dns_spec = next(s for s in _SERVICE_REGISTRY if s.name == "dns")
        cfg_out, _ = sm._special_builders(
            dns_spec, "127.0.0.1", "1.2.3.4", "127.0.0.1",
            {"cert_file": "", "key_file": ""},
        )
        assert cfg_out["resolve_to"] == "127.0.0.1"

