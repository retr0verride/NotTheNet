"""Retry with exponential back-off and optional jitter.

Pure stdlib — no third-party dependencies.

Usage::

    from infrastructure.resilience.retry import retry_with_backoff

    @retry_with_backoff(max_attempts=5, base_delay=1.0, exceptions=(OSError,))
    def bind_socket(port):
        ...

    # or call imperatively:
    result = retry_with_backoff(max_attempts=3)(risky_call)(arg1)
"""

from __future__ import annotations

import functools
import logging
import random
import time
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


# Re-export from canonical location so existing imports keep working.
from domain.exceptions import RetryExhausted as RetryExhausted  # noqa: E402, F401


def retry_with_backoff(
    max_attempts: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 60.0,
    multiplier: float = 2.0,
    jitter: bool = True,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator factory that retries *fn* on transient errors.

    Back-off formula (with jitter):
        delay = min(base_delay * multiplier^(attempt-1) + rand(0, 0.5), max_delay)

    Args:
        max_attempts: Maximum total call attempts (1 = no retry).
        base_delay:   Initial delay in seconds between retries.
        max_delay:    Hard cap on any single delay.
        multiplier:   Exponential growth factor (≥1.0).
        jitter:       Add ±25% random variation to avoid thundering herd.
        exceptions:   Tuple of exception types that trigger a retry.
                      Any other exception propagates immediately.
    """

    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exc: Exception = RuntimeError("unreachable")
            for attempt in range(1, max_attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt == max_attempts:
                        break
                    delay = min(base_delay * (multiplier ** (attempt - 1)), max_delay)
                    if jitter:
                        delay *= 0.75 + random.random() * 0.5  # ±25% jitter  # noqa: S311
                    logger.warning(
                        "Attempt %d/%d for %s failed (%s). Retrying in %.2fs",
                        attempt, max_attempts, fn.__qualname__, exc, delay,
                    )
                    time.sleep(delay)

            raise RetryExhausted(max_attempts, last_exc)

        return wrapper

    return decorator
