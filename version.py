"""NotTheNet release version (CalVer YYYY.MM.DD-N).

Single source of truth. ship.ps1 bumps this and pyproject.toml together;
scripts/checks.py fails the gate if they drift. Shell scripts read it with
grep, so keep the exact ``APP_VERSION = "..."`` form on one line.
"""

APP_VERSION = "2026.05.13-19"
