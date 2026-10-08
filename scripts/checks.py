#!/usr/bin/env python3
"""
NotTheNet — single source of truth for all pre-merge / pre-release checks.

Runs the same checks executed by CI (see STEPS at the bottom). Used by:
  - .github/workflows/ci.yml  (lint job)
  - predeploy.sh              (local thin wrapper)
  - ship.sh                   (release gate)

Usage:
    python scripts/checks.py                # run everything
    python scripts/checks.py --skip-tests   # skip pytest (CI matrix runs it separately)
    python scripts/checks.py --skip-install # don't install/upgrade tool versions
    python scripts/checks.py --only ruff,pytest  # run only the named steps

Exit code: 0 on success, 1 on first failure (informational steps never fail).
"""
from __future__ import annotations

import argparse
import io
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

# ── Pinned tool versions — must match .github/workflows/ci.yml ───────────────
PINNED_TOOLS = [
    "vulture==2.14",
    "ruff==0.15.2",
    "bandit[toml]==1.9.4",
    "bandit-sarif-formatter==1.1.1",
    "pip-audit==2.10.0",
    "mypy==1.19.1",
    "openapi-spec-validator==0.8.4",
    "pytest==9.0.3",
    "pytest-cov==7.1.0",
    "pytest-timeout==2.4.0",
]

# Fully annotated modules held to mypy --strict. Keep in sync with the strict
# override in pyproject.toml and the mypy hook in .pre-commit-config.yaml.
STRICT_MYPY_FILES = [
    "notthenet.py", "headless.py", "version.py", "config.py", "service_manager.py",
    "services/", "utils/", "network/",
]
# All Python in the repo; must pass mypy (check_untyped_defs) with zero errors.
MYPY_PATHS = [
    "notthenet.py", "headless.py", "version.py", "config.py", "service_manager.py",
    "services/", "network/", "utils/", "gui/", "tests/", "tools/", "scripts/",
]

REPO_ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
IS_WINDOWS = os.name == "nt"
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

# Force UTF-8 stdout/stderr on Windows so the box-drawing characters used in
# step headers don't blow up under cp1252 when output is piped or redirected.
if IS_WINDOWS:
    for _stream in (sys.stdout, sys.stderr):
        if isinstance(_stream, io.TextIOWrapper):
            _stream.reconfigure(encoding="utf-8", errors="replace")
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


def step_secrets() -> None:
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


def step_ruff() -> None:
    run([PY, "-m", "ruff", "check", "."])
    passed("ruff")


def step_mypy() -> None:
    run([PY, "-m", "mypy", *MYPY_PATHS])
    passed("mypy")


def step_mypy_strict() -> None:
    # Strictness comes from the per-module override in pyproject.toml; a CLI
    # --strict would also apply to every module these files import.
    run([PY, "-m", "mypy", *STRICT_MYPY_FILES])
    passed("mypy strict")


def step_bandit() -> None:
    # -c pyproject.toml picks up [tool.bandit] exclude_dirs/skips. The CI
    # runner has no .venv so this defence-in-depth keeps local + CI parity.
    run([
        PY, "-m", "bandit", "-r", ".",
        "-c", "pyproject.toml",
        "--severity-level", "high",
    ])
    passed("bandit")


def step_vulture() -> None:
    rc = subprocess.call(
        [
            PY, "-m", "vulture", ".",
            "--min-confidence", "80",
            "--exclude", ".venv,tools",
        ],
        cwd=str(REPO_ROOT),
    )
    if rc != 0:
        fail("vulture found dead code")
    passed("vulture")


def step_pip_audit() -> None:
    run([PY, "-m", "pip_audit", "--requirement", "requirements.txt", "--strict"])
    passed("pip-audit")


def step_openapi() -> None:
    run([PY, "-m", "openapi_spec_validator", "openapi.yaml"])
    passed("openapi-spec-validator")


def step_shellcheck() -> None:
    if not shutil.which("shellcheck"):
        warn("shellcheck not installed — skipping (optional locally; required in CI)")
        return
    targets = [
        str(p) for p in REPO_ROOT.rglob("*.sh")
        if ".git" not in p.parts
        and ".venv" not in p.parts
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


def step_placeholders() -> None:
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


def step_pytest() -> None:
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


def step_version() -> None:
    source = (REPO_ROOT / "version.py").read_text(encoding="utf-8")
    toml = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m_source = re.search(r'(?m)^APP_VERSION = "([^"]+)"$', source)
    m_toml = re.search(r'(?m)^version\s*=\s*"([^"]+)"', toml)
    if not m_source or not m_toml:
        fail("could not parse version from version.py or pyproject.toml")
    assert m_source and m_toml
    if m_source.group(1) != m_toml.group(1):
        fail(
            f"version mismatch: version.py={m_source.group(1)} "
            f"vs pyproject.toml={m_toml.group(1)}"
        )
    dupes = [
        str(p.relative_to(REPO_ROOT))
        for p in REPO_ROOT.rglob("*.py")
        if p.name != "version.py"
        and not any(part.startswith(".") for part in p.relative_to(REPO_ROOT).parts)
        and re.search(r"(?m)^\s*APP_VERSION\s*=", p.read_text(encoding="utf-8"))
    ]
    if dupes:
        fail(f"APP_VERSION assigned outside version.py: {', '.join(dupes)}")
    passed(f"all files at v{m_source.group(1)}")


def step_changelog() -> None:
    cl = REPO_ROOT / "CHANGELOG.md"
    if not cl.is_file():
        info("(no CHANGELOG.md — skipping)")
        return
    source = (REPO_ROOT / "version.py").read_text(encoding="utf-8")
    m = re.search(r'(?m)^APP_VERSION = "([^"]+)"$', source)
    if not m:
        info("(could not read version — skipping)")
        return
    ver = m.group(1)
    if ver in cl.read_text(encoding="utf-8"):
        passed(f"v{ver} in CHANGELOG.md")
    else:
        warn(f"v{ver} not found in CHANGELOG.md")


def step_python_floor() -> None:
    toml = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'requires-python\s*=\s*"([^"]+)"', toml)
    py_min = m.group(1) if m else ""
    if "3.9" in py_min:
        fail("pyproject.toml still targets Python 3.9 (EOL); update requires-python")
    passed(f"Python version floor OK ({py_min or 'unset'})")


def step_stale_certs() -> None:
    certs = REPO_ROOT / "certs"
    stale = list(certs.glob("_dyn_*")) if certs.is_dir() else []
    if stale:
        warn("stale dynamic cert files found:")
        for f in stale[:5]:
            warn(f"  {f.name}")
    else:
        passed("no stale _dyn_* cert files")


# ── Step registry ────────────────────────────────────────────────────────────
STEPS: list[tuple[str, str, Callable[[], None]]] = [
    ("secrets", "Secret scan (gitleaks)", step_secrets),
    ("ruff", "Lint (ruff)", step_ruff),
    ("mypy", "Type check (mypy, all code)", step_mypy),
    ("mypy-strict", "Type check — strict modules (mypy --strict)", step_mypy_strict),
    ("bandit", "Security scan (bandit — fail on HIGH severity)", step_bandit),
    ("vulture", "Dead code detection (vulture)", step_vulture),
    ("pip-audit", "SCA (pip-audit)", step_pip_audit),
    ("openapi", "OpenAPI spec validation", step_openapi),
    ("shellcheck", "Shellcheck", step_shellcheck),
    ("placeholders", "Placeholder consistency audit", step_placeholders),
    ("pytest", "Tests (pytest)", step_pytest),
    ("version", "Version consistency", step_version),
    ("changelog", "CHANGELOG check", step_changelog),
    ("python-floor", "pyproject.toml Python version floor", step_python_floor),
    ("stale-certs", "Stale temp-cert check", step_stale_certs),
]
STEP_NAMES = [name for name, _, _ in STEPS]


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
        help=f"comma-separated step names to run: {','.join(STEP_NAMES)}",
    )
    args = p.parse_args()

    os.chdir(REPO_ROOT)

    selected = STEP_NAMES
    if args.only:
        selected = [x.strip() for x in args.only.split(",") if x.strip()]
        unknown = sorted(set(selected) - set(STEP_NAMES))
        if unknown:
            print(f"unknown step(s): {', '.join(unknown)}; valid: {', '.join(STEP_NAMES)}",
                  file=sys.stderr)
            return 2

    if not args.skip_install:
        step_install()

    plan = [(n, t, fn) for n, t, fn in STEPS if n in selected]
    for i, (name, title, fn) in enumerate(plan, 1):
        if args.skip_tests and name == "pytest":
            step(f"{i}/{len(plan)}", f"{title} — SKIPPED via --skip-tests")
            continue
        step(f"{i}/{len(plan)}", f"{title} [{name}]")
        fn()

    print(_c("32", "\nAll predeploy checks passed."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
