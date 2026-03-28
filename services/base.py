"""
NotTheNet - Service Protocol & Base Class

Provides the formal contract (ServiceProtocol) that all services must satisfy,
and a concrete BaseService that implements the common TCP accept-loop boilerplate
shared by the majority of services.
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Optional, Protocol, runtime_checkable

from utils.logging_utils import sanitize_ip

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
