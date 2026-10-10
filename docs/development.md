# Development Setup

How to set up a local development environment for contributing to NotTheNet.

> **Note:** NotTheNet **runs** on Kali Linux only (it needs Linux iptables). However, you can write and test code on Windows, then deploy to Kali to verify end-to-end behaviour.

---

## Linux / Kali

### 1. Install VS Code

```bash
sudo apt install code
```

Or download the `.deb` directly from [code.visualstudio.com](https://code.visualstudio.com) and install with:

```bash
sudo dpkg -i code_*.deb
```

### 2. Clone and set up the environment

```bash
cd ~
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Open in VS Code

```bash
code .
```

VS Code will detect the `.venv` automatically. If prompted, select it as the Python interpreter (`Python: Select Interpreter` → `./.venv/bin/python`).

### 4. Run predeploy checks before committing

```bash
bash predeploy.sh
```

Thin wrapper around `scripts/checks.py` (the same script CI runs). Executes ruff, mypy (strict on all application code, enforced on tests and tools), bandit, pip-audit, OpenAPI validation, shellcheck, placeholder audit, pytest with coverage, version/changelog/python-floor/cert-freshness checks. **All checks must pass before pushing.** Use `--skip-tests` for a fast lint-only pass, or `--only ruff,pytest` to run named steps (`--help` lists them).

---

## Cutting a release

```bash
bash ship.sh                # bump version, run checks, commit, tag, push
bash ship.sh --no-push      # commit and tag locally only
bash ship.sh --skip-checks  # skip scripts/checks.py (use sparingly)
```

`ship.sh` must run on a clean `main`. It bumps `version.py` and `pyproject.toml` to today's `YYYY.MM.DD-N`, runs `scripts/checks.py` (reverting the bump if it fails), commits `chore(release): <ver>`, tags `v<ver>` and pushes branch and tag. On the tag, CI re-runs the checks, builds the `.deb` (with dependency wheels vendored for offline installs), builds the sdist/wheel with SLSA provenance, and drafts the GitHub Release.

---

## Running Tests

All tests are pure-Python, require no root access or real network, and complete in under a second.

```bash
# Kali / Debian / Ubuntu
pytest tests/ -v

# Windows (dev-only)
.venv\Scripts\python.exe -m pytest tests/ -v
```

> Running with `-v` (verbose) shows each test name. Without it you just see a pass/fail summary.

| Test file | What it covers |
|-----------|----------------|
| `tests/test_config.py` | `Config` load, get/set, save, reset, deep-copy isolation |
| `tests/test_logging_utils.py` | CWE-117 log injection prevention; `sanitize_log_string`, `sanitize_ip`, `sanitize_hostname` |
| `tests/test_validators.py` | `validate_ip`, `validate_port`, `validate_hostname`, `validate_bind_ip`, `sanitize_path`, `validate_http_method`, `validate_config` |
| `tests/test_connection_caps.py` | FTP and mail server connection-cap enforcement (socket-level) |
| `tests/test_irc_session_timeout.py` | IRC PING/PONG lifecycle, session timeout |
| `tests/test_json_logger_flush.py` | Periodic flush, concurrent write safety, size cap |
| `tests/test_dns_server.py` | DNS resolver: A/PTR/MX/TXT/NS/SOA/SRV/CAA, DGA entropy, kill-switch, NCSI, FCrDNS |
| `tests/test_http_server.py` | IP-check spoofing, NCSI, captive portal, PKI stubs, handler config, response loading |
| `tests/test_catch_all.py` | Protocol detection, TLS context, TCP/UDP lifecycle, connection handling |
| `tests/test_iptables_manager.py` | Snapshot paths, interface validation, rule building, TTL validation, mode config |
| `tests/test_service_manager.py` | ServiceManager lifecycle, log purge, session paths, port conflicts, config validation |
| `tests/test_cert_utils.py` | Self-signed certs, CA generation, per-domain forging, DynamicCertCache, key permissions |

---

## Recommended VS Code Extensions
These extensions give you inline lint and type errors as you code:
| Extension | Purpose |
|-----------|---------|
| `ms-python.python` | Python language support, IntelliSense, venv detection |
| `ms-python.mypy-type-checker` | Inline mypy type errors |
| `charliermarsh.ruff` | Inline ruff lint errors |
| `ms-python.black-formatter` | Auto-format on save (optional) |

---

## Project Structure

See [architecture.md](architecture.md) for the code map, startup sequence, and how to add a service.

------|----------|
| `notthenet.py` | Main entry point — GUI, config, orchestration |
| `services/` | One module per fake service (DNS, HTTP, SMTP, FTP, catch-all, DoH/WebSocket, dynamic responses) |
| `network/` | iptables management, TCP/IP OS fingerprint spoofing |
| `utils/` | Certificates (static + dynamic CA), logging, JSON event logger, privilege drop, validators |
| `tests/` | pytest test suite (validators, logging utils, config) |
| `config.json` | Default runtime configuration |
| `docs/` | Documentation |
| `man/` | Man page |
| `assets/` | Desktop integration files |

---

## Notes

- The GUI uses **Tkinter** only — no extra GUI dependencies beyond the Python standard library.
- Services require **root** to bind to ports below 1024 (like 53, 80, 443). Run with `sudo` when testing services end-to-end; the GUI itself can be developed as a normal user with services disabled.
- mypy checks the code as Linux on every OS (`platform = "linux"` in `pyproject.toml`), so Linux-only calls like `os.geteuid` type-check on a Windows dev box too.
