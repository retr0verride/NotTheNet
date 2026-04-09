"""Domain exception hierarchy.

All exceptions raised by domain and application logic inherit from
``NotTheNetError``.  Infrastructure adapters wrap OS/third-party errors
in the appropriate domain type before re-raising so that callers never
need to import ``socket``, ``OSError``, or library-specific exceptions.

Usage::

    from domain.exceptions import ServiceBindError

    try:
        svc.start()
    except ServiceBindError as exc:
        logger.error("Could not bind port %d: %s", exc.port, exc)

Rules enforced throughout the codebase:
- No bare ``except:`` or ``except Exception: pass``
- Every caught exception is either logged with ``exc_info=True`` or
  wrapped in a domain exception and re-raised with ``raise ... from exc``
"""

from __future__ import annotations

from typing import Optional


# ── Base ─────────────────────────────────────────────────────────────────────

class NotTheNetError(Exception):
    """Root exception for all NotTheNet domain and application errors.

    Attributes:
        message: Human-readable description.
        code:    Machine-readable error code (e.g. ``"ERR_SERVICE_BIND"``).
    """

    code: str = "ERR_INTERNAL"

    def __init__(self, message: str, code: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code


# ── Config errors ─────────────────────────────────────────────────────────────

class ConfigError(NotTheNetError):
    """Raised when configuration is invalid or cannot be loaded."""

    code = "ERR_CONFIG"


class ConfigValidationError(ConfigError):
    """Raised when Pydantic Settings validation fails at startup.

    Attributes:
        field:  The field name that failed validation.
        detail: The Pydantic error detail string.
    """

    code = "ERR_CONFIG_VALIDATION"

    def __init__(self, field: str, detail: str) -> None:
        super().__init__(f"Config validation failed for '{field}': {detail}")
        self.field = field
        self.detail = detail


class SecretMissingError(ConfigError):
    """Raised when a required secret environment variable is absent."""

    code = "ERR_SECRET_MISSING"

    def __init__(self, var_name: str) -> None:
        super().__init__(
            f"Required secret '{var_name}' is not set. "
            "Check .env.example for required variables."
        )
        self.var_name = var_name


# ── Service lifecycle errors ──────────────────────────────────────────────────

class ServiceError(NotTheNetError):
    """Base for all service lifecycle errors."""

    code = "ERR_SERVICE"

    def __init__(self, message: str, service_name: str = "", code: Optional[str] = None) -> None:
        super().__init__(message, code)
        self.service_name = service_name


class ServiceBindError(ServiceError):
    """Raised when a service cannot bind its socket.

    Attributes:
        port:     The port that could not be bound.
        protocol: ``"tcp"`` or ``"udp"``.
    """

    code = "ERR_SERVICE_BIND"

    def __init__(self, service_name: str, port: int, protocol: str, cause: str = "") -> None:
        super().__init__(
            f"Service '{service_name}' could not bind {protocol.upper()}:{port}"
            + (f": {cause}" if cause else ""),
            service_name=service_name,
        )
        self.port = port
        self.protocol = protocol


class ServiceAlreadyRunningError(ServiceError):
    """Raised when ``start()`` is called on an already-running service."""

    code = "ERR_SERVICE_ALREADY_RUNNING"

    def __init__(self, service_name: str) -> None:
        super().__init__(
            f"Service '{service_name}' is already running",
            service_name=service_name,
        )


class ServiceNotFoundError(ServiceError):
    """Raised when an operation targets a service name that does not exist."""

    code = "ERR_SERVICE_NOT_FOUND"

    def __init__(self, service_name: str) -> None:
        super().__init__(
            f"No service named '{service_name}' is registered",
            service_name=service_name,
        )


# ── Network / iptables errors ─────────────────────────────────────────────────

class NetworkError(NotTheNetError):
    """Base for network-level infrastructure errors."""

    code = "ERR_NETWORK"


class IPTablesError(NetworkError):
    """Raised when an iptables operation fails."""

    code = "ERR_IPTABLES"


class PrivilegeError(NetworkError):
    """Raised when a privilege operation (drop/restore) fails."""

    code = "ERR_PRIVILEGE"


# ── Certificate / TLS errors ──────────────────────────────────────────────────

class CertError(NotTheNetError):
    """Base for TLS certificate errors."""

    code = "ERR_CERT"


class CertGenerationError(CertError):
    """Raised when certificate or key generation fails."""

    code = "ERR_CERT_GENERATION"


# ── Resilience errors ─────────────────────────────────────────────────────────

class CircuitOpenError(NotTheNetError):
    """Raised by CircuitBreaker when a call is rejected (circuit is open).

    Re-exported here so callers import from ``domain.exceptions`` only.
    """

    code = "ERR_CIRCUIT_OPEN"

    def __init__(self, name: str, retry_after: float) -> None:
        super().__init__(f"Circuit '{name}' is OPEN — retry after {retry_after:.1f}s")
        self.name = name
        self.retry_after = retry_after


class RetryExhausted(NotTheNetError):
    """Raised when all retry attempts are spent."""

    code = "ERR_RETRY_EXHAUSTED"

    def __init__(self, attempts: int, last_exc: Exception) -> None:
        super().__init__(f"All {attempts} attempt(s) failed. Last: {last_exc}")
        self.attempts = attempts
        self.last_exc = last_exc
