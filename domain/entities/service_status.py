"""Domain entities — mutable objects with identity."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ServiceState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPING = "stopping"
    FAILED = "failed"


@dataclass
class ServiceStatus:
    """Runtime status snapshot for a single service."""

    name: str
    state: ServiceState = ServiceState.STOPPED
    port: int = 0
    protocol: str = "tcp"
    started_at: float | None = None   # epoch seconds
    error: str | None = None
    connections_total: int = 0

    def mark_running(self, port: int, protocol: str) -> None:
        self.state = ServiceState.RUNNING
        self.port = port
        self.protocol = protocol
        self.started_at = time.time()
        self.error = None

    def mark_failed(self, reason: str) -> None:
        self.state = ServiceState.FAILED
        self.error = reason
        self.started_at = None

    def mark_stopped(self) -> None:
        self.state = ServiceState.STOPPED
        self.started_at = None
        self.error = None


@dataclass
class ConnectionRecord:
    """One intercepted network connection recorded for audit purposes."""

    event_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    service: str
    payload_bytes: int = 0
    tls: bool = False
    extra: dict[str, Any] = field(default_factory=dict)
