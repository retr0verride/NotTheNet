"""
Tests for config.py — Config load / get / set / save / reset.
"""

import json

from config import Config


def _write_json(path: str, data: dict):
    with open(path, "w") as f:
        json.dump(data, f)


# ── Loading ───────────────────────────────────────────────────────────────────

class TestConfigLoad:
    def test_load_valid_file(self, tmp_path):
        cfg_file = tmp_path / "config.json"
        _write_json(str(cfg_file), {"general": {"bind_ip": "0.0.0.0"}})
        cfg = Config(str(cfg_file))
        assert cfg.get("general", "bind_ip") == "0.0.0.0"

    def test_missing_file_returns_empty(self, tmp_path):
        cfg = Config(str(tmp_path / "nonexistent.json"))
        assert cfg.as_dict() == {}

    def test_malformed_json_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json}")
        cfg = Config(str(bad))
        assert cfg.as_dict() == {}

    def test_reload_different_path(self, tmp_path):
        f1 = tmp_path / "a.json"
        f2 = tmp_path / "b.json"
        _write_json(str(f1), {"section": {"key": "original"}})
        _write_json(str(f2), {"section": {"key": "reloaded"}})
        cfg = Config(str(f1))
        cfg.load(str(f2))
        assert cfg.get("section", "key") == "reloaded"


# ── get / set / get_section / set_section ────────────────────────────────────

class TestConfigGetSet:
    def test_get_existing_key(self, tmp_path):
        f = tmp_path / "c.json"
        _write_json(str(f), {"dns": {"port": 5353}})
        cfg = Config(str(f))
        assert cfg.get("dns", "port") == 5353

    def test_get_missing_key_returns_fallback(self, tmp_path):
        cfg = Config(str(tmp_path / "x.json"))
        assert cfg.get("missing", "key", fallback=42) == 42

    def test_set_creates_section(self, tmp_path):
        cfg = Config(str(tmp_path / "y.json"))
        cfg.set("http", "port", 8080)
        assert cfg.get("http", "port") == 8080

    def test_set_overwrites_existing(self, tmp_path):
        f = tmp_path / "z.json"
        _write_json(str(f), {"http": {"port": 80}})
        cfg = Config(str(f))
        cfg.set("http", "port", 8080)
        assert cfg.get("http", "port") == 8080

    def test_get_section(self, tmp_path):
        f = tmp_path / "sec.json"
        _write_json(str(f), {"ftp": {"port": 21, "enabled": True}})
        cfg = Config(str(f))
        section = cfg.get_section("ftp")
        assert section == {"port": 21, "enabled": True}

    def test_get_section_missing_returns_empty(self, tmp_path):
        cfg = Config(str(tmp_path / "empty.json"))
        assert cfg.get_section("nonexistent") == {}

    def test_set_section(self, tmp_path):
        cfg = Config(str(tmp_path / "w.json"))
        cfg.set_section("smtp", {"port": 25, "enabled": False})
        assert cfg.get("smtp", "port") == 25

    def test_all_sections(self, tmp_path):
        f = tmp_path / "multi.json"
        _write_json(str(f), {"a": {}, "b": {}, "c": {}})
        cfg = Config(str(f))
        assert set(cfg.all_sections()) == {"a", "b", "c"}


# ── Save ──────────────────────────────────────────────────────────────────────

class TestConfigSave:
    def test_save_and_reload(self, tmp_path):
        f = tmp_path / "save.json"
        cfg = Config(str(f))
        cfg.set("general", "bind_ip", "127.0.0.1")
        assert cfg.save()

        cfg2 = Config(str(f))
        assert cfg2.get("general", "bind_ip") == "127.0.0.1"

    def test_save_to_alternate_path(self, tmp_path):
        f1 = tmp_path / "orig.json"
        f2 = tmp_path / "copy.json"
        _write_json(str(f1), {"k": {"v": 1}})
        cfg = Config(str(f1))
        assert cfg.save(str(f2))
        assert f2.exists()


# ── Reset ─────────────────────────────────────────────────────────────────────

class TestConfigReset:
    def test_reset_restores_original_values(self, tmp_path):
        f = tmp_path / "reset.json"
        _write_json(str(f), {"general": {"log_level": "INFO"}})
        cfg = Config(str(f))
        cfg.set("general", "log_level", "DEBUG")
        assert cfg.get("general", "log_level") == "DEBUG"

        cfg.reset_to_defaults()
        assert cfg.get("general", "log_level") == "INFO"

    def test_as_dict_returns_deep_copy(self, tmp_path):
        f = tmp_path / "copy.json"
        _write_json(str(f), {"section": {"key": "value"}})
        cfg = Config(str(f))
        d = cfg.as_dict()
        d["section"]["key"] = "mutated"
        # Original should be unchanged
        assert cfg.get("section", "key") == "value"
