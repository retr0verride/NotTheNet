#!/usr/bin/env python3
"""
NotTheNet — single source of truth for all pre-merge / pre-release checks.

Runs the same 12 checks executed by CI. Used by:
  - .github/workflows/ci.yml  (lint job)
  - predeploy.ps1             (Windows local thin wrapper)
  - predeploy.sh              (Linux/macOS local thin wrapper)

Usage:
    python scripts/checks.py                # run everything
    python scripts/checks.py --skip-tests   # skip pytest (CI matrix runs it separately)
    python scripts/checks.py --skip-install # don't install/upgrade tool versions
    python scripts/checks.py --only 1,3,7   # run only specific step numbers

Exit code: 0 on success, 1 on first failure (informational steps never fail).
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

# ── Pinned tool versions — must match .github/workflows/ci.yml ───────────────
PINNED_TOOLS = [
    "ruff==0.15.2",
    "bandit[toml]==1.9.4",
    "bandit-sarif-formatter==1.1.1",
    "pip-audit==2.10.0",
    "mypy==1.19.1",
    "pydantic==2.13.2",
    "pydantic-settings==2.13.1",
    "openapi-spec-validator==0.8.4",
    "pytest==9.0.3",
    "pytest-cov==7.1.0",
    "pytest-timeout==2.4.0",
]

REPO_ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
IS_WINDOWS = os.name == "nt"
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

# Force UTF-8 stdout/stderr on Windows so the box-drawing characters used in
# step headers don't blow up under cp1252 when output is piped or redirected.
if IS_WINDOWS:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    # Subprocesses (bandit, mypy, etc.) also need UTF-8 stdout to avoid
    # charmap encoding errors when their output contains non-ASCII chars.
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    os.environ.setdefault("PYTHONUTF8", "1")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def step(num: str, msg: str) -> None:
    print(_c("36", f"\n── {num}  {msg} ──"))


def passed(msg: str) -> None:
    print(_c("32", f"  PASS: {msg}"))


def warn(msg: str) -> None:
    print(_c("33", f"  WARN: {msg}"))


def info(msg: str) -> None:
    print(f"  {msg}")


def fail(msg: str) -> None:
    print(_c("31", f"  FAIL: {msg}"))
    sys.exit(1)


def run(cmd: list[str], *, check: bool = True, cwd: Path | None = None) -> int:
    """Stream a subprocess and optionally fail on non-zero exit."""
    print(_c("90", f"  $ {' '.join(cmd)}"))
    rc = subprocess.call(cmd, cwd=str(cwd or REPO_ROOT))
    if check and rc != 0:
        fail(f"command exited {rc}: {cmd[0]}")
    return rc


# ── Steps ────────────────────────────────────────────────────────────────────


def step_install() -> None:
    step("--", "Ensuring dev tools are installed (pinned versions)")
    run([PY, "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
    run([PY, "-m", "pip", "install", "--quiet", *PINNED_TOOLS])
    passed("tools ready")


def step_0_secrets() -> None:
    step("0/12", "Secret scan (gitleaks)")
    if not shutil.which("gitleaks"):
        warn("gitleaks not installed — skipping (optional locally; required in CI)")
        return
    rc = subprocess.call(
        ["gitleaks", "detect", "--source", str(REPO_ROOT), "--no-banner"],
        cwd=str(REPO_ROOT),
    )
    if rc != 0:
        fail("gitleaks found secrets")
    passed("gitleaks")


def step_1_ruff() -> None:
    step("1/12", "Lint (ruff)")
    run([PY, "-m", "ruff", "check", "."])
    passed("ruff")


def step_2a_mypy_legacy() -> None:
    step("2a/12", "Type check — legacy (mypy, informational)")
    subprocess.call([PY, "-m", "mypy", "notthenet.py", "services/", "network/", "utils/"])
    info("(informational — legacy code lacks strict annotations)")


def step_2b_mypy_strict() -> None:
    step("2b/12", "Type check — new layers (mypy --strict)")
    run([
        PY, "-m", "mypy",
        "domain/", "application/", "infrastructure/",
        "--strict", "--ignore-missing-imports", "--explicit-package-bases",
    ])
    passed("mypy strict")


def step_3_bandit() -> None:
    step("3/12", "Security scan (bandit — fail on HIGH severity)")
    # -c pyproject.toml picks up [tool.bandit] exclude_dirs/skips. The CI
    # runner has no .venv so this defence-in-depth keeps local + CI parity.
    run([
        PY, "-m", "bandit", "-r", ".",
        "-c", "pyproject.toml",
        "--severity-level", "high",
    ])
    passed("bandit")


def step_4_pip_audit() -> None:
    step("4/12", "SCA (pip-audit)")
    run([PY, "-m", "pip_audit", "--requirement", "requirements.txt", "--strict"])
    passed("pip-audit")


def step_5_openapi() -> None:
    step("5/12", "OpenAPI spec validation")
    run([PY, "-m", "openapi_spec_validator", "openapi.yaml"])
    passed("openapi-spec-validator")


def step_6_shellcheck() -> None:
    step("6/12", "Shellcheck")
    if not shutil.which("shellcheck"):
        warn("shellcheck not installed — skipping (optional locally; required in CI)")
        return
    excluded = {"notthenet-bundle.sh"}
    targets = [
        str(p) for p in REPO_ROOT.rglob("*.sh")
        if ".git" not in p.parts
        and ".venv" not in p.parts
        and p.name not in excluded
    ]
    if not targets:
        info("(no .sh files found)")
        return
    rc = subprocess.call(
        ["shellcheck", "--severity=warning", *targets], cwd=str(REPO_ROOT),
    )
    if rc != 0:
        fail("shellcheck found warnings/errors")
    passed("shellcheck")


def step_7_placeholders() -> None:
    step("7/12", "Placeholder consistency audit")
    pattern = re.compile(r"[A-Z][A-Z_]*_PLACEHOLDER")
    placeholders: set[str] = set()
    assets = REPO_ROOT / "assets"
    if not assets.is_dir():
        info("(no assets/ — skipping)")
        return
    for f in assets.rglob("*"):
        if f.is_file():
            try:
                placeholders.update(pattern.findall(f.read_text(encoding="utf-8", errors="ignore")))
            except OSError:
                continue
    if not placeholders:
        info("(no placeholders found in assets/ — skipping)")
        return
    install_scripts = ["build-deb.sh", "notthenet-install.sh"]
    failed = False
    for p in sorted(placeholders):
        for s in install_scripts:
            content = (REPO_ROOT / s).read_text(encoding="utf-8", errors="ignore")
            if f"s|{p}|" not in content:
                print(_c("31", f"  MISSING: {p} not substituted in {s}"))
                failed = True
    if failed:
        fail("placeholder substitution audit failed")
    passed(f"placeholder audit ({len(placeholders)} tokens)")


def step_8_pytest() -> None:
    step("8/12", "Tests (pytest)")
    tests_dir = REPO_ROOT / "tests"
    if not tests_dir.is_dir() or not list(tests_dir.glob("test_*.py")):
        info("(no tests found — skipping)")
        return
    cmd = [
        PY, "-m", "pytest", "tests/", "-v",
        "--timeout=60", "--cov", "--cov-fail-under=35",
    ]
    if IS_WINDOWS:
        # Known Windows port-collision flake; passes in isolation, fails in suite.
        cmd += ["--deselect",
                "tests/test_catch_all.py::TestCatchAllUDPLifecycle::test_start_stop"]
    run(cmd)
    passed("pytest")


def step_9_version() -> None:
    step("9/12", "Version consistency")
    widget = (REPO_ROOT / "gui" / "widgets.py").read_text(encoding="utf-8")
    toml = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    nt = (REPO_ROOT / "notthenet.py").read_text(encoding="utf-8")
    m_widget = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', widget)
    m_toml = re.search(r'(?m)^version\s*=\s*"([^"]+)"', toml)
    if not m_widget or not m_toml:
        fail("could not parse version from gui/widgets.py or pyproject.toml")
    assert m_widget and m_toml
    if m_widget.group(1) != m_toml.group(1):
        fail(
            f"version mismatch: gui/widgets.py={m_widget.group(1)} "
            f"vs pyproject.toml={m_toml.group(1)}"
        )
    if re.search(r"(?m)^APP_VERSION\s*=", nt):
        fail("notthenet.py has a local APP_VERSION assignment (should import from gui.widgets)")
    passed(f"all files at v{m_widget.group(1)}")


def step_10_changelog() -> None:
    step("10/12", "CHANGELOG check")
    cl = REPO_ROOT / "CHANGELOG.md"
    if not cl.is_file():
        info("(no CHANGELOG.md — skipping)")
        return
    widget = (REPO_ROOT / "gui" / "widgets.py").read_text(encoding="utf-8")
    m = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', widget)
    if not m:
        info("(could not read version — skipping)")
        return
    ver = m.group(1)
    if ver in cl.read_text(encoding="utf-8"):
        passed(f"v{ver} in CHANGELOG.md")
    else:
        warn(f"v{ver} not found in CHANGELOG.md")


def step_11_python_floor() -> None:
    step("11/12", "pyproject.toml Python version floor")
    toml = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'requires-python\s*=\s*"([^"]+)"', toml)
    py_min = m.group(1) if m else ""
    if "3.9" in py_min:
        fail("pyproject.toml still targets Python 3.9 (EOL); update requires-python")
    passed(f"Python version floor OK ({py_min or 'unset'})")


def step_12_stale_certs() -> None:
    step("12/12", "Stale temp-cert check")
    certs = REPO_ROOT / "certs"
    stale = list(certs.glob("_dyn_*")) if certs.is_dir() else []
    if stale:
        warn("stale dynamic cert files found:")
        for f in stale[:5]:
            warn(f"  {f.name}")
    else:
        passed("no stale _dyn_* cert files")


# ── Step registry ────────────────────────────────────────────────────────────
STEPS: dict[int, tuple[str, Callable[[], None]]] = {
    0:  ("secrets",       step_0_secrets),
    1:  ("ruff",          step_1_ruff),
    2:  ("mypy-legacy",   step_2a_mypy_legacy),  # 2a
    3:  ("mypy-strict",   step_2b_mypy_strict),  # 2b
    4:  ("bandit",        step_3_bandit),
    5:  ("pip-audit",     step_4_pip_audit),
    6:  ("openapi",       step_5_openapi),
    7:  ("shellcheck",    step_6_shellcheck),
    8:  ("placeholders",  step_7_placeholders),
    9:  ("pytest",        step_8_pytest),
    10: ("version",       step_9_version),
    11: ("changelog",     step_10_changelog),
    12: ("python-floor",  step_11_python_floor),
    13: ("stale-certs",   step_12_stale_certs),
}


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--skip-install", action="store_true",
        help="don't install/upgrade pinned tool versions",
    )
    p.add_argument(
        "--skip-tests", action="store_true",
        help="skip pytest step (CI matrix runs it separately)",
    )
    p.add_argument(
        "--only",
        help="comma-separated step indices to run (see registry, 0-13)",
    )
    args = p.parse_args()

    os.chdir(REPO_ROOT)

    if not args.skip_install:
        step_install()

    selected: list[int]
    if args.only:
        try:
            selected = [int(x.strip()) for x in args.only.split(",")]
        except ValueError:
            print("--only must be a comma-separated list of integers", file=sys.stderr)
            return 2
    else:
        selected = list(STEPS.keys())

    for idx in selected:
        name, fn = STEPS[idx]
        if args.skip_tests and name == "pytest":
            step("8/12", "Tests (pytest) — SKIPPED via --skip-tests")
            continue
        fn()

    print(_c("32", "\nAll predeploy checks passed."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
