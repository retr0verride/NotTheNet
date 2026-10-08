"""Tests for utils/health_server.py: env settings, auth gate, routes, import hygiene."""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from utils.health_server import CORE_SERVICES, HealthServer, HealthSettings

TOKEN = "0123456789abcdef-token"  # noqa: S105 (test fixture, not a real credential)
REPO_ROOT = Path(__file__).resolve().parent.parent


class _FakeManager:
    def __init__(self, running: set[str], failed: set[str] | None = None) -> None:
        self.running = running
        self.failed = failed or set()

    def service_report(self) -> list[dict[str, Any]]:
        names = [*CORE_SERVICES, "ftp", "smtp"]
        return [{"name": n, "state": self._state(n), "port": 0, "protocol": "tcp"} for n in names]

    def _state(self, name: str) -> str:
        if name in self.running:
            return "running"
        return "failed" if name in self.failed else "stopped"


def _server(
    bind_ip: str = "127.0.0.1", token: str = "", manager: Any = None, **kw: Any,
) -> HealthServer:
    settings = HealthSettings(enabled=True, bind_ip=bind_ip, port=1, admin_token=token, **kw)
    return HealthServer(manager or _FakeManager(set(CORE_SERVICES)), settings)


# ── HealthSettings.from_env ─────────────────────────────────────────────────────

class TestSettings:
    def test_defaults_are_disabled_and_loopback(self) -> None:
        s = HealthSettings.from_env({})
        assert s == HealthSettings()
        assert s.enabled is False
        assert s.bind_ip == "127.0.0.1"

    def test_full_env(self) -> None:
        s = HealthSettings.from_env({
            "NTN_HEALTH_ENABLED": "true",
            "NTN_HEALTH_BIND": "0.0.0.0",  # noqa: S104
            "NTN_HEALTH_PORT": "9090",
            "NTN_ADMIN_TOKEN": TOKEN,
            "NTN_HEALTH_CORS_ORIGINS": "http://a, http://b ,",
        })
        assert s == HealthSettings(True, "0.0.0.0", 9090, TOKEN, frozenset({"http://a", "http://b"}))  # noqa: S104

    @pytest.mark.parametrize(
        ("env", "fragment"),
        [
            ({"NTN_HEALTH_BIND": "lab-host"}, "NTN_HEALTH_BIND"),
            ({"NTN_HEALTH_PORT": "0"}, "NTN_HEALTH_PORT"),
            ({"NTN_HEALTH_PORT": "70000"}, "NTN_HEALTH_PORT"),
            ({"NTN_HEALTH_PORT": "80x"}, "NTN_HEALTH_PORT"),
            ({"NTN_ADMIN_TOKEN": "short"}, "NTN_ADMIN_TOKEN"),
        ],
    )
    def test_invalid_values_fail_fast(self, env: dict[str, str], fragment: str) -> None:
        with pytest.raises(ValueError, match=fragment):
            HealthSettings.from_env(env)


# ── Auth gate ───────────────────────────────────────────────────────────────────

class TestAuth:
    def test_no_token_loopback_is_open(self) -> None:
        assert _server("127.0.0.1").check_auth({}) is None

    @pytest.mark.parametrize("bind_ip", ["0.0.0.0", "::", "10.10.10.1"])  # noqa: S104
    def test_no_token_off_loopback_is_forbidden(self, bind_ip: str) -> None:
        denied = _server(bind_ip).check_auth({})
        assert denied is not None
        assert denied[1] == 403

    @pytest.mark.parametrize(
        "headers",
        [
            {"X-Admin-Token": TOKEN},
            {"Authorization": f"Bearer {TOKEN}"},
            {"Authorization": f"bearer {TOKEN}"},
        ],
    )
    def test_valid_token_accepted(self, headers: dict[str, str]) -> None:
        assert _server("0.0.0.0", TOKEN).check_auth(headers) is None  # noqa: S104

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
    def test_missing_or_wrong_token_rejected(self, headers: dict[str, str]) -> None:
        denied = _server("0.0.0.0", TOKEN).check_auth(headers)  # noqa: S104
        assert denied is not None
        assert denied[1] == 401

    def test_token_required_on_loopback_when_configured(self) -> None:
        denied = _server("127.0.0.1", TOKEN).check_auth({})
        assert denied is not None
        assert denied[1] == 401


# ── Routes (direct) ─────────────────────────────────────────────────────────────

class TestRoutes:
    def test_ready_when_core_running(self) -> None:
        body, status, _ = _server().routes["/health/ready"]({})
        assert status == 200
        assert json.loads(body)["status"] == "ready"

    def test_degraded_when_core_missing(self) -> None:
        srv = _server(manager=_FakeManager({"http", "https"}))
        body, status, _ = srv.routes["/health/ready"]({})
        assert status == 503
        payload = json.loads(body)
        assert payload["status"] == "degraded"
        assert payload["core_services_missing"] == ["dns"]

    def test_status_counts(self) -> None:
        srv = _server(manager=_FakeManager(set(CORE_SERVICES), failed={"ftp"}))
        payload = json.loads(srv.routes["/health/status"]({})[0])
        assert payload["services_total"] == 5
        assert payload["services_running"] == 3
        assert payload["services_failed"] == 1

    def test_metrics_is_prometheus_text(self) -> None:
        body, status, ctype = _server().routes["/metrics"]({})
        assert status == 200
        assert ctype.startswith("text/plain")
        assert "notthenet_services_running 3\n" in body

    def test_cors_only_for_allowlisted_origin(self) -> None:
        srv = _server(cors_origins=frozenset({"http://ok"}))
        assert srv.cors_headers("http://ok")["Access-Control-Allow-Origin"] == "http://ok"
        assert srv.cors_headers("http://evil") == {}
        assert _server().cors_headers("http://ok") == {}


# ── Over real HTTP ──────────────────────────────────────────────────────────────

@pytest.fixture
def live_server() -> Any:
    # Port 0: the OS picks a free port (validation only applies to from_env).
    settings = HealthSettings(enabled=True, bind_ip="127.0.0.1", port=0, admin_token=TOKEN)
    srv = HealthServer(_FakeManager(set(CORE_SERVICES)), settings)
    srv.start()
    assert srv._server is not None
    yield f"http://127.0.0.1:{srv._server.server_address[1]}"
    srv.stop()


def _get(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, headers=headers or {})  # noqa: S310 (loopback test server)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode()


class TestHttp:
    def test_live_is_open(self, live_server: str) -> None:
        status, headers, body = _get(f"{live_server}/health/live")
        assert status == 200
        assert json.loads(body)["status"] == "ok"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Cache-Control"] == "no-store"

    def test_metrics_requires_token(self, live_server: str) -> None:
        assert _get(f"{live_server}/metrics")[0] == 401
        status, headers, _ = _get(f"{live_server}/metrics", {"Authorization": f"Bearer {TOKEN}"})
        assert status == 200
        assert headers["Content-Type"].startswith("text/plain")

    def test_unknown_path_is_404(self, live_server: str) -> None:
        assert _get(f"{live_server}/nope")[0] == 404


# ── Import hygiene ──────────────────────────────────────────────────────────────

def test_headless_path_imports_neither_tkinter_nor_pydantic() -> None:
    """Headless/Docker must run from a bare requirements.txt install with no Tk libs."""
    code = (
        "import sys, headless, notthenet; "
        "bad = sorted(m for m in ('tkinter', 'pydantic') if m in sys.modules); "
        "sys.exit(f'loaded: {bad}' if bad else 0)"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
