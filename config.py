"""
NotTheNet - Configuration Manager
Handles loading, saving, and accessing configuration settings.
"""

from __future__ import annotations

import copy
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


class Config:
    """Manages NotTheNet configuration with load/save/get/set support."""

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self._data: dict[str, Any] = {}
        self._defaults: dict[str, Any] = {}
        self.load()
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
            with open(target, "w") as f:
                json.dump(self._data, f, indent=2)
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
