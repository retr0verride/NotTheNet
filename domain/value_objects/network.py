"""Domain value objects — immutable, self-validating."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    BOTH = "both"
    ICMP = "icmp"


@dataclass(frozen=True)
class Port:
    """A validated network port number (0 = unassigned / wildcard)."""

    value: int

    def __post_init__(self) -> None:
        if not (0 <= self.value <= 65535):
            raise ValueError(f"Port must be 0–65535, got {self.value}")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True)
class BindAddress:
    """A validated IP address string suitable for socket binding."""

    ip: str

    def __post_init__(self) -> None:
        import ipaddress

        if self.ip not in ("0.0.0.0", "::"):
            try:
                ipaddress.ip_address(self.ip)
            except ValueError as exc:
                raise ValueError(f"Invalid bind address: {self.ip!r}") from exc

    def __str__(self) -> str:
        return self.ip
