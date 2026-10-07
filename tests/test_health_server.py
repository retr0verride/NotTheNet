"""Tests for the health server's admin-token gate on /health/status and /metrics."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from infrastructure.health.server import HealthServer

TOKEN = "s3cret-token"  # noqa: S105 — test fixture, not a real credential


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NTN_HEALTH_BIND", raising=False)
    monkeypatch.delenv("NTN_HEALTH_PORT", raising=False)


def _server(bind_ip: str, token: str | None) -> HealthServer:
    return HealthServer(health_svc=None, orchestrator=None, bind_ip=bind_ip, admin_token=token)


def _req(headers: dict[str, str]) -> Any:
    return SimpleNamespace(headers=headers)


class TestNoTokenConfigured:
    def test_loopback_bind_is_open(self) -> None:
        assert _server("127.0.0.1", None)._require_auth(_req({})) is None

    @pytest.mark.parametrize("bind_ip", ["0.0.0.0", "::", "10.10.10.1", "lab-host"])  # noqa: S104
    def test_non_loopback_bind_is_forbidden(self, bind_ip: str) -> None:
        denied = _server(bind_ip, None)._require_auth(_req({}))
        assert denied is not None
        assert denied[1] == 403


class TestTokenConfigured:
    @pytest.mark.parametrize(
        "headers",
        [
            {"X-Admin-Token": TOKEN},
            {"Authorization": f"Bearer {TOKEN}"},
            {"Authorization": f"bearer {TOKEN}"},
        ],
    )
    def test_valid_token_is_accepted(self, headers: dict[str, str]) -> None:
        assert _server("0.0.0.0", TOKEN)._require_auth(_req(headers)) is None  # noqa: S104

    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"X-Admin-Token": "wrong"},
            {"Authorization": "Bearer wrong"},
            {"Authorization": f"Basic {TOKEN}"},
            {"Authorization": TOKEN},
        ],
    )
    def test_missing_or_wrong_token_is_rejected(self, headers: dict[str, str]) -> None:
        denied = _server("0.0.0.0", TOKEN)._require_auth(_req(headers))  # noqa: S104
        assert denied is not None
        assert denied[1] == 401

    def test_token_required_even_on_loopback(self) -> None:
        denied = _server("127.0.0.1", TOKEN)._require_auth(_req({}))
        assert denied is not None
        assert denied[1] == 401
