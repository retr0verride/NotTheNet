"""Pydantic Settings — startup environment validation.

This module validates all ``NTN_*`` environment variables at process start.
If any required variable is missing or has the wrong type, the process exits
with a clear message rather than failing silently at runtime.

Call ``get_settings()`` once during DI container construction (before any
other object is built).  Subsequent calls return the cached singleton.

Example::

    from infrastructure.config.settings import get_settings

    s = get_settings()
    print(s.bind_ip, s.log_level)

All fields have sensible defaults so the tool works out-of-the-box without
any ``.env`` file.  Sensitive fields (``admin_token``) are declared as
``SecretStr`` so they are never printed in logs or tracebacks.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class NTNSettings(BaseSettings):  # type: ignore[misc]
    """Validated configuration backed by environment variables.

    All NTN_* env vars are read from the environment (or a .env file).
    ``model_config`` sets the prefix so you write ``NTN_LOG_LEVEL=debug``
    rather than ``LOG_LEVEL=debug``.
    """

    model_config = SettingsConfigDict(
        env_prefix="NTN_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        # Don't raise for extra env vars — only validate what we declare.
        extra="ignore",
    )

    # ── Core ────────────────────────────────────────────────────────────────
    headless: bool = Field(
        default=False,
        description="Run without GUI (also set by --headless CLI flag).",
    )
    config_path: Path = Field(
        default=Path("config.json"),
        description="Path to the JSON configuration file.",
    )

    # ── Network ─────────────────────────────────────────────────────────────
    bind_ip: str = Field(
        default="0.0.0.0",
        description="IP address to bind all services to.",
    )
    iface: str = Field(
        default="eth0",
        description="Network interface for iptables redirect rules.",
    )

    # ── Logging ─────────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Root log level.",
    )
    log_dir: Path = Field(
        default=Path("logs"),
        description="Directory for JSONL event logs.",
    )
    json_logs: bool = Field(
        default=False,
        description="Emit JSON log lines to stdout (ideal for log aggregators).",
    )

    # ── Health API ───────────────────────────────────────────────────────────
    health_port: int = Field(
        default=8080,
        ge=1,
        le=65535,
        description="Port for the health/metrics HTTP server.",
    )
    health_bind: str = Field(
        default="127.0.0.1",
        description="Address for the health server (never expose externally).",
    )
    admin_token: SecretStr | None = Field(
        default=None,
        description="Bearer token for /health/status and /metrics (optional).",
    )

    # ── OpenTelemetry ────────────────────────────────────────────────────────
    otel_enabled: bool = Field(
        default=False,
        description="Enable OpenTelemetry tracing/metrics export.",
    )
    otel_endpoint: str = Field(
        default="http://localhost:4317",
        description="OTLP gRPC endpoint (used when NTN_OTEL_ENABLED=1).",
    )
    otel_service_name: str = Field(
        default="notthenet",
        description="Service name reported to the OTLP collector.",
    )

    # ── Resilience ───────────────────────────────────────────────────────────
    circuit_failure_threshold: int = Field(
        default=5,
        ge=1,
        description="Consecutive failures before a circuit opens.",
    )
    circuit_reset_timeout: float = Field(
        default=30.0,
        gt=0,
        description="Seconds to wait in OPEN state before probing.",
    )

    # ── Validators ──────────────────────────────────────────────────────────

    @field_validator("bind_ip", "health_bind", mode="before")  # type: ignore[untyped-decorator]
    @classmethod
    def _valid_ip(cls, v: object) -> str:
        if not isinstance(v, str):
            raise ValueError("Must be a string IP address")
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"'{v}' is not a valid IP address") from exc
        return v

    @field_validator("log_level", mode="before")  # type: ignore[untyped-decorator]
    @classmethod
    def _upper_log_level(cls, v: object) -> object:
        if isinstance(v, str):
            return v.upper()
        return v

    @field_validator("config_path", "log_dir", mode="before")  # type: ignore[untyped-decorator]
    @classmethod
    def _expand_paths(cls, v: object) -> object:
        if isinstance(v, str):
            return Path(v).expanduser()
        return v

    @model_validator(mode="after")  # type: ignore[untyped-decorator]
    def _log_dir_accessible(self) -> NTNSettings:
        """Warn (don't fail) if log_dir cannot be created."""
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Non-fatal: log_dir might be a tmpfs or NFS mount point.
            pass
        return self


@lru_cache(maxsize=1)
def get_settings() -> NTNSettings:
    """Return the validated settings singleton.

    Parsing and validation happen only on the first call.  If validation
    fails, ``pydantic_settings.ValidationError`` is raised immediately so
    the operator sees a clear error before any service binds a socket.
    """
    return NTNSettings()
