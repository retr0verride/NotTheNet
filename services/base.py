"""
NotTheNet - Service protocol.

ServiceProtocol is the contract every service in _SERVICE_REGISTRY
(service_manager.py) satisfies: an ``enabled`` flag, ``start() -> bool``,
``stop()`` and a ``running`` property.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class ServiceProtocol(Protocol):
    """Minimal interface all NotTheNet services must satisfy.

    Used by ServiceManager for type-safe service orchestration.
    Pylance validates that every service in _SERVICE_REGISTRY conforms.
    """

    enabled: bool

    def start(self) -> bool: ...
    def stop(self) -> None: ...

    @property
    def running(self) -> bool: ...
