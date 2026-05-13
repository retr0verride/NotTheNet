"""Windows-specific configuration adapter.

Simple JSON-based config with optional environment variable overrides.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class Config:
    """Load and store configuration from a JSON file."""

    def __init__(self, config_path: str = "config.json") -> None:
        self.config_path = config_path
        self._config: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load configuration from JSON file."""
        if not os.path.exists(self.config_path):
            logger.warning("Config file not found: %s", self.config_path)
            return

        try:
            with open(self.config_path) as f:
                self._config = json.load(f)
            logger.info("Config loaded from %s", self.config_path)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Failed to load config: %s", exc)

    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        """Get a configuration value."""
        if section not in self._config:
            return fallback
        return self._config[section].get(key, fallback)

    def set(self, section: str, key: str, value: Any) -> None:
        """Set a configuration value in memory."""
        if section not in self._config:
            self._config[section] = {}
        self._config[section][key] = value

    def get_section(self, section: str) -> dict[str, Any]:
        """Get an entire configuration section."""
        return dict(self._config.get(section, {}))

    def as_dict(self) -> dict[str, Any]:
        """Return the full config as a dict."""
        return json.loads(json.dumps(self._config))

    def save(self, path: str | None = None) -> bool:
        """Save configuration to file."""
        target_path = path or self.config_path
        try:
            with open(target_path, "w") as f:
                json.dump(self._config, f, indent=2)
            logger.info("Config saved to %s", target_path)
            return True
        except OSError as exc:
            logger.error("Failed to save config: %s", exc)
            return False
