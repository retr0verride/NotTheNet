"""Circuit Breaker — infrastructure resilience pattern.

Implements the classic three-state circuit breaker:

    CLOSED  → the operation is allowed through (normal mode)
    OPEN    → the operation is rejected immediately (fast-fail)
    HALF-OPEN → a single probe is allowed; success → CLOSED, failure → OPEN

Thread-safe; uses only stdlib (no third-party dependencies).

Usage::

    breaker = CircuitBreaker("dns_upstream", failure_threshold=5, reset_timeout=30)

    try:
        with breaker:            # or: breaker.call(my_func, *args)
            result = dns_query()
    except CircuitOpenError:
        return cached_fallback()
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from enum import Enum
from typing import Any, Callable, Generator, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


# Re-export from canonical location so existing imports keep working.
from domain.exceptions import CircuitOpenError as CircuitOpenError  # noqa: F401


class CircuitBreaker:
    """Thread-safe circuit breaker for wrapping unreliable external calls.

    Args:
        name:              Human-readable name for logging.
        failure_threshold: Consecutive failures before opening the circuit.
        reset_timeout:     Seconds to wait in OPEN state before probing.
        success_threshold: Consecutive successes in HALF-OPEN before closing.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        reset_timeout: float = 30.0,
        success_threshold: int = 2,
    ) -> None:
        self.name = name
        self._failure_threshold = failure_threshold
        self._reset_timeout = reset_timeout
        self._success_threshold = success_threshold

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._state

    @contextmanager
    def __call__(self) -> Generator[None, None, None]:
        """Context-manager entry point.  Raises ``CircuitOpenError`` if open."""
        self._before_call()
        try:
            yield
            self._on_success()
        except CircuitOpenError:
            raise
        except Exception:
            self._on_failure()
            raise

    def call(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Execute *fn* under circuit-breaker protection."""
        with self():
            return fn(*args, **kwargs)

    def reset(self) -> None:
        """Manually force the circuit to CLOSED state (e.g. after a fix)."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            logger.info("Circuit '%s' manually reset to CLOSED", self.name)

    # ── Internal state machine ────────────────────────────────────────────────

    def _before_call(self) -> None:
        with self._lock:
            if self._state == CircuitState.CLOSED:
                return

            if self._state == CircuitState.OPEN:
                elapsed = time.monotonic() - (self._last_failure_time or 0)
                remaining = self._reset_timeout - elapsed
                if remaining > 0:
                    raise CircuitOpenError(self.name, remaining)
                # Timeout expired — probe one request
                logger.info("Circuit '%s' → HALF-OPEN (probe)", self.name)
                self._state = CircuitState.HALF_OPEN
                self._success_count = 0
                return

            # HALF_OPEN: allow through
            return

    def _on_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self._success_threshold:
                    logger.info("Circuit '%s' → CLOSED (recovered)", self.name)
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0  # reset on any success

    def _on_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                logger.warning(
                    "Circuit '%s' → OPEN (probe failed)", self.name
                )
                self._state = CircuitState.OPEN
                return

            if (
                self._state == CircuitState.CLOSED
                and self._failure_count >= self._failure_threshold
            ):
                logger.warning(
                    "Circuit '%s' → OPEN (%d consecutive failures)",
                    self.name, self._failure_count,
                )
                self._state = CircuitState.OPEN
