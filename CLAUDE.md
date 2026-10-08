# NotTheNet

Fake-internet simulator for malware analysis labs (Kali). Architecture, code map and "adding a service": `docs/architecture.md`.

## Gate

- `bash predeploy.sh` runs `scripts/checks.py`, the same gate CI runs. It must pass before any commit.
- Subset: `python scripts/checks.py --skip-install --only ruff,pytest` (`--help` lists step names).
- Tests run without root or network. iptables tests stub `_run` in both `network.iptables_manager` and `network.host_state`.

## Rules that are easy to break

- Only `gui/` may import tkinter. Headless and Docker run without Tk; `tests/test_health_server.py` enforces this.
- Every subprocess call is a list with `shell=False`. Host commands go through `network/host_state.py:_run`.
- `version.py` is the only place `APP_VERSION` is assigned; shell scripts grep `^APP_VERSION = "`. Keep it a one-line literal.
- New services register a `ServiceSpec` in `_SERVICE_REGISTRY` (`service_manager.py`); iptables redirects and the health report come from the registry.
- GUI service pages are data: `gui/service_pages.py`. The sidebar key must equal the `ServiceSpec` name.
- All application code is strict-typed; tests, tools and scripts pass mypy with `check_untyped_defs`. New app modules go in `STRICT_MYPY_FILES` (`scripts/checks.py`) and the strict override in `pyproject.toml`. No new `# type: ignore` without a reason (`warn_unused_ignores` is on). Never use `strict = true` in an override: mypy applies it globally.
- With `drop_privileges` on (the default), a failed drop while root must abort startup, never continue as root.
- Health endpoint auth fails closed: no `NTN_ADMIN_TOKEN` means 403 off-loopback.

## Release

`bash ship.sh` on a clean `main`. CI builds the offline-capable `.deb` and drafts the release from the tag. Add user-facing changes under `## [Unreleased]` in `CHANGELOG.md`.
