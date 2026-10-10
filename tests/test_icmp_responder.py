"""Tests for services/icmp_responder.py lifecycle (no raw socket or root needed)."""

from __future__ import annotations

import socket

import pytest

from services.base import ServiceProtocol
from services.icmp_responder import ICMPResponder


class _FakeRawSocket:
    """Stands in for a raw ICMP socket: every read times out until closed."""

    def settimeout(self, _timeout: float) -> None:
        pass

    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
        raise TimeoutError

    def close(self) -> None:
        pass


def test_satisfies_service_protocol() -> None:
    assert isinstance(ICMPResponder({}), ServiceProtocol)


def test_running_tracks_start_and_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("services.icmp_responder.socket.socket", lambda *_a: _FakeRawSocket())
    svc = ICMPResponder({"enabled": True})
    assert svc.running is False
    assert svc.start() is True
    assert svc.running is True
    svc.stop()
    assert svc.running is False


def test_disabled_never_runs() -> None:
    svc = ICMPResponder({"enabled": False})
    assert svc.start() is False
    assert svc.running is False


def test_permission_error_reports_not_running(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_raw_socket(*_args: object) -> socket.socket:
        raise PermissionError

    monkeypatch.setattr("services.icmp_responder.socket.socket", _no_raw_socket)
    svc = ICMPResponder({"enabled": True})
    assert svc.start() is False
    assert svc.running is False
