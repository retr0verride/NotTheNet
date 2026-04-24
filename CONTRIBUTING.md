# Contributing to NotTheNet

Thank you for your interest in improving NotTheNet! This guide explains how to contribute.

---

## Reporting Bugs

Open an issue on the [GitHub Issue Tracker](https://github.com/retr0verride/NotTheNet/issues) with:

1. **NotTheNet version** (`notthenet --version`)
2. **OS and Python version** (`python3 --version`)
3. **Steps to reproduce** (config excerpt, CLI invocation, expected vs actual behaviour)
4. **Log output** (sanitise any sensitive data)

## Reporting Vulnerabilities

**Do NOT open a public issue.** See [SECURITY.md](SECURITY.md) for the private reporting process.

---

## Contributing Code

### 1. Fork and branch

```bash
git clone https://github.com/<you>/NotTheNet
cd NotTheNet
git checkout -b feat/my-change
```

### 2. Set up the development environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install ruff mypy bandit pytest
```

### 3. Make your changes

- Follow the existing code style (PEP 8, enforced by Ruff).
- Line length limit: **120 characters** (see `pyproject.toml [tool.ruff]`).
- All `subprocess` calls must use `shell=False` — no exceptions.
- All user-facing strings must be validated through `utils/validators.py`.

### 4. Add or update tests

**Every pull request that adds or changes functionality must include tests.**

- Tests live in `tests/` and are run with `pytest tests/ -v`.
- Name test files `test_<module>.py` and test functions `test_<behaviour>`.
- Tests must be pure Python — no network access, no root, no external services.
- Aim for both positive (happy path) and negative (error/edge case) coverage.

### 5. Run the full pre-deploy gate

```bash
# Linux
bash predeploy.sh

# Windows dev machine
.\predeploy.ps1
```

Both wrappers invoke `scripts/checks.py` — the same script CI runs. It executes 12 steps: secret scan, ruff, mypy (informational + strict on `domain/application/infrastructure`), bandit, pip-audit, OpenAPI validation, shellcheck, placeholder audit, pytest with coverage gate, version consistency, CHANGELOG check, Python floor check, and stale `_dyn_*` cert sweep. Use `--skip-tests` for a fast pass or `--only 1,3` for a subset.

All steps must pass before submitting a PR.

### 6. Commit and push

Write clear commit messages following [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat: add SOCKS5 proxy sinkhole
fix: prevent race condition in DNS server shutdown
docs: update configuration reference for new field
ci: add Python 3.13 to test matrix
```

### 7. Open a Pull Request

- Target the `master` branch.
- Describe **what** changed and **why**.
- Reference any related issue (`Closes #42`).
- CI must pass (lint + type check + security scan + tests + build).

---

## Test Policy

| Rule | Detail |
| ------ | -------- |
| New features | Must include tests covering the primary behaviour |
| Bug fixes | Must include a regression test that fails without the fix |
| Refactors | Existing tests must continue to pass; add tests if coverage gaps are revealed |
| Minimum | `pytest tests/ -v` must report **0 failures** |

---

## Code Review

All contributions are reviewed before merge. Reviewers check for:

- Correctness and security (no shell injection, no unsanitised input)
- Test coverage for new behaviour
- Documentation updates if user-facing behaviour changed
- Clean CI (all checks green)

---

## Architecture: Adding a New Service

### ServiceProtocol

Every service in `services/` implements the **`ServiceProtocol`** interface
defined in `services/base.py`:

```python
class ServiceProtocol(Protocol):
    name: str
    port: int
    running: bool
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def status(self) -> dict: ...
```

Your service class does **not** need to explicitly inherit from
`ServiceProtocol`; Python's structural subtyping (duck typing) is sufficient.
Just ensure you expose the three attributes and three methods above.

### Step-by-step

1. **Create** `services/my_service.py` with a class that satisfies
   `ServiceProtocol`.
   - **Every service must implement a `threading.BoundedSemaphore`** to cap
     concurrent connections/transfers. Acquire the semaphore before spawning
     a handler thread and release it in the handler's `finally` block. Use
     `_MAX_CONNECTIONS = 50` as the default unless the protocol requires a
     different cap. This prevents thread exhaustion under flood conditions.
2. **Register** it in `service_manager.py`:
   - Add an entry to `_SERVICE_REGISTRY` (maps config section → service class).
   - Add the class to `_SERVICE_CLASSES` if it needs special start/stop
     ordering.
3. **Add a config section** in `config.json` with at least `enabled` and
   `port`.
4. **Add a GUI page** (optional):
   - In `gui/views.py → DashboardMixin._build_pages()`, add a `_ServicePage`
     with the appropriate fields and checks.
   - Add a sidebar button in `_build_body()` under the appropriate section.
5. **Write tests** in `tests/test_my_service.py`.
6. **Run** `pytest tests/ -v` — all tests must pass.

### GUI Package Layout

The Tkinter GUI is split into a `gui/` package for maintainability:

| Module | Purpose |
| -------- | --------- |
| `gui/widgets.py` | Constants, colours, reusable widget factories, tooltip |
| `gui/dialogs.py` | `_GeneralPage`, `_JsonEventsPage`, `_ServicePage`, `_DNSPage` |
| `gui/views.py` | `DashboardMixin` — all `_build_*` layout methods |
| `gui/logic.py` | `ServiceControlMixin` — service lifecycle, log polling |
| `gui/app.py` | `NotTheNetApp` class (combines both mixins) + `main()` |
| `notthenet.py` | Thin entry point (~24 lines) |

---

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
