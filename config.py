"""
NotTheNet - Configuration Manager
Handles loading, saving, and accessing configuration settings.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


class Config:
    """Manages NotTheNet configuration with load/save/get/set support."""

    # Path to the repo-shipped config.json (used as the canonical defaults).
    _REPO_DEFAULT_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "config.json"
    )

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self._data: dict[str, Any] = {}
        self._defaults: dict[str, Any] = {}
        self._write_lock = threading.Lock()
        self.load()
        # When the user points at a custom config file that predates the
        # current release, merge any newly-added default keys so the GUI
        # and services see them without requiring a manual edit.
        self._merge_repo_defaults()
        self._defaults = copy.deepcopy(self._data)

    def load(self, path: str | None = None) -> bool:
        """Load configuration from a JSON file."""
        target = path or self.config_path
        try:
            with open(target) as f:
                self._data = json.load(f)
            logger.debug(f"Config loaded from {target}")
            return True
        except FileNotFoundError:
            logger.warning(f"Config file not found at {target}, using empty config.")
            self._data = {}
            return False
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse config file: {e}")
            self._data = {}
            return False

    def save(self, path: str | None = None) -> bool:
        """Save current configuration to a JSON file."""
        target = path or self.config_path
        try:
            with self._write_lock:
                snapshot = copy.deepcopy(self._data)
                tmp = target + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(snapshot, f, indent=2)
                os.replace(tmp, target)  # atomic on POSIX; near-atomic on Windows
            logger.debug(f"Config saved to {target}")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False

    def get(self, section: str, key: str, fallback=None):
        """Get a value from the config with an optional fallback."""
        return self._data.get(section, {}).get(key, fallback)

    def set(self, section: str, key: str, value):
        """Set a value in the config."""
        if section not in self._data:
            self._data[section] = {}
        self._data[section][key] = value

    def get_section(self, section: str) -> dict:
        """Return an entire section as a dict."""
        return self._data.get(section, {})

    def set_section(self, section: str, data: dict):
        """Replace an entire section."""
        self._data[section] = data

    def reset_to_defaults(self):
        """Reset the configuration to the built-in defaults."""
        self._data = copy.deepcopy(self._defaults)

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = copy.deepcopy(self._data)
        return result

    def all_sections(self) -> list:
        return list(self._data.keys())

    # ── internal helpers ──────────────────────────────────────────────────────

    def _merge_repo_defaults(self) -> None:
        """Deep-merge missing keys from the repo default config.json.

        For every section/key present in the repo defaults but absent in the
        loaded user config, insert the default value.  Existing user values
        are never overwritten.  Skipped when the loaded config is empty
        (file missing or malformed) to avoid polluting error cases.
        """
        if not self._data:
            return  # nothing loaded — don't inject defaults into an empty config

        try:
            with open(self._REPO_DEFAULT_PATH) as f:
                defaults = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return  # nothing to merge from

        changed = False
        for section, keys in defaults.items():
            if section not in self._data:
                # Don't inject entire sections the user never had — they may
                # have been deliberately omitted.
                continue
            if not isinstance(keys, dict) or not isinstance(self._data[section], dict):
                continue
            for key, val in keys.items():
                if key not in self._data[section]:
                    self._data[section][key] = val
                    changed = True

        if changed:
            logger.info("Config migrated — new default keys merged into user config")
