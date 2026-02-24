# Development Setup

How to set up a local development environment for working on NotTheNet.

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

This runs ruff (lint), mypy (type check), bandit (security scan), pytest (70 tests), and builds the package.

---

## Windows

### 1. Clone and set up the environment

```powershell
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Open in VS Code

```powershell
code .
```

### 3. Run predeploy checks before committing

```powershell
.\predeploy.ps1
```

This runs ruff (lint), mypy (type check), bandit (security scan), pytest (70 tests), and builds the package.

---

## Running Tests

All tests are pure-Python, require no root access or network, and complete in under a second:

```bash
# Linux / macOS
pytest tests/ -v

# Windows
.venv\Scripts\python.exe -m pytest tests/ -v
```

| Test file | What it covers |
|-----------|----------------|
| `tests/test_config.py` | `Config` load, get/set, save, reset, deep-copy isolation |
| `tests/test_logging_utils.py` | CWE-117 log injection prevention; `sanitize_log_string`, `sanitize_ip`, `sanitize_hostname` |
| `tests/test_validators.py` | `validate_ip`, `validate_port`, `validate_hostname`, `validate_bind_ip`, `sanitize_path`, `validate_http_method`, `validate_config` |

---

## Recommended VS Code Extensions

| Extension | Purpose |
|-----------|---------|
| `ms-python.python` | Python language support, IntelliSense, venv detection |
| `ms-python.mypy-type-checker` | Inline mypy type errors |
| `charliermarsh.ruff` | Inline ruff lint errors |
| `ms-python.black-formatter` | Auto-format on save (optional) |

---

## Project Structure

| Path | Contents |
|------|----------|
| `notthenet.py` | Main entry point — GUI, config, orchestration |
| `services/` | One module per fake service (DNS, HTTP, SMTP, FTP, catch-all) |
| `network/` | iptables management |
| `utils/` | Certificates, logging, privilege drop, validators |
| `tests/` | pytest test suite (validators, logging utils, config) |
| `config.json` | Default runtime configuration |
| `docs/` | Documentation |
| `man/` | Man page |
| `assets/` | Desktop integration files |

---

## Notes

- The GUI uses **Tkinter** only — no extra GUI dependencies beyond the Python standard library.
- Services require **root** (or iptables redirect) to bind to ports below 1024. Run with `sudo` when testing services end-to-end; the GUI itself can be developed and launched as a normal user with services disabled.
- `network/iptables_manager.py` and `utils/privilege.py` are Linux-only — mypy suppresses errors on those modules when running on Windows (configured in `pyproject.toml`).
