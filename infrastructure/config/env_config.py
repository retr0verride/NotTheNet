"""EnvConfigStore — IConfigStore adapter that layers environment variables
over a JSON-backed config file (the existing ``Config`` class).

Twelve-Factor App §III: config in the environment.

Environment variable mapping
────────────────────────────
NTN_BIND_IP          → general.bind_ip
NTN_REDIRECT_IP      → general.redirect_ip
NTN_SPOOF_PUBLIC_IP  → general.spoof_public_ip
NTN_INTERFACE        → general.interface
NTN_PROCESS_MASQ     → general.process_masquerade
NTN_DROP_PRIVS       → general.drop_privileges       (1/true/yes → True)
NTN_LOG_DIR          → general.log_dir
NTN_CONFIG_PATH      → (sets the JSON file path at init)
NTN_CERT_PATH        → general.cert_path
NTN_KEY_PATH         → general.key_path
NTN_HEALTH_PORT      → health_api.port
NTN_HEALTH_BIND      → health_api.bind_ip
NTN_OTEL_ENDPOINT    → otel.endpoint
NTN_OTEL_ENABLED     → otel.enabled                  (1/true/yes → True)

Any env var takes precedence over the JSON file value for the same key.
The JSON file is never written back with env-var values to avoid leaking
secrets into version-controlled files.
"""

from __future__ import annotations

import copy
import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _to_bool(v: str) -> bool:
    return v.strip().lower() in ("1", "true", "yes", "on")


# Map: env-var name  →  (section, key, coerce_fn)
_ENV_MAP: dict[str, tuple[str, str, Any]] = {
    "NTN_BIND_IP":         ("general",    "bind_ip",            str),
    "NTN_REDIRECT_IP":     ("general",    "redirect_ip",        str),
    "NTN_SPOOF_PUBLIC_IP": ("general",    "spoof_public_ip",    str),
    "NTN_INTERFACE":       ("general",    "interface",          str),
    "NTN_PROCESS_MASQ":    ("general",    "process_masquerade", str),
    "NTN_DROP_PRIVS":      ("general",    "drop_privileges",    _to_bool),
    "NTN_LOG_DIR":         ("general",    "log_dir",            str),
    "NTN_CERT_PATH":       ("general",    "cert_path",          str),
    "NTN_KEY_PATH":        ("general",    "key_path",           str),
    "NTN_HEALTH_PORT":     ("health_api", "port",               int),
    "NTN_HEALTH_BIND":     ("health_api", "bind_ip",            str),
    "NTN_OTEL_ENDPOINT":   ("otel",       "endpoint",           str),
    "NTN_OTEL_ENABLED":    ("otel",       "enabled",            _to_bool),
}


class EnvConfigStore:
    """Wrap an existing ``Config`` instance and layer env-var overrides.

    This class satisfies the ``IConfigStore`` Protocol by delegation.
    """

    def __init__(self, base_config) -> None:  # base_config: Config (avoid circular import)
        self._base = base_config
        self._overrides: dict[tuple[str, str], Any] = {}
        self._load_env_overrides()

    def _load_env_overrides(self) -> None:
        """Read all NTN_* environment variables and cache the overrides."""
        for env_var, (section, key, coerce) in _ENV_MAP.items():
            raw = os.environ.get(env_var)
            if raw is not None:
                try:
                    self._overrides[(section, key)] = coerce(raw)
                    logger.debug("Env override applied: %s → %s.%s", env_var, section, key)
                except (ValueError, TypeError) as exc:
                    logger.warning(
                        "Invalid env var %s=%r (%s) — using config file value",
                        env_var, raw, exc,
                    )

    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        if (section, key) in self._overrides:
            return self._overrides[(section, key)]
        return self._base.get(section, key, fallback)

    def set(self, section: str, key: str, value: Any) -> None:
        # Writes go to the base (JSON file) only.  Env overrides always win
        # on reads, so a set() that is "shadowed" by an env var logs a warning.
        if (section, key) in self._overrides:
            logger.warning(
                "set(%s, %s) is shadowed by env var — write will NOT take effect "
                "until the env var is removed",
                section, key,
            )
        self._base.set(section, key, value)

    def get_section(self, section: str) -> dict[str, Any]:
        data = self._base.get_section(section)
        for (s, k), v in self._overrides.items():
            if s == section:
                data[k] = v
        return data

    def as_dict(self) -> dict[str, Any]:
        data = self._base.as_dict()
        for (section, key), value in self._overrides.items():
            data.setdefault(section, {})[key] = value
        return data

    def save(self, path: Optional[str] = None) -> bool:
        return self._base.save(path)
