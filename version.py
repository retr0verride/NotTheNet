"""NotTheNet release version (CalVer YYYY.MM.DD-N).

Single source of truth. ship.sh bumps this and pyproject.toml together;
scripts/checks.py fails the gate if they drift. Shell scripts grep for the
assignment at the start of a line, so keep it a single-line string literal.
"""

APP_VERSION = "2026.10.08-rc1"
