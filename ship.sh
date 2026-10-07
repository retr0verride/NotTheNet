#!/usr/bin/env bash
# ship.sh: cut a NotTheNet release.
#
# Bumps the CalVer version (YYYY.MM.DD-N: same day -> N+1, new day -> 1) in
# version.py and pyproject.toml, runs the full gate, commits, tags vVERSION and
# pushes main + tag. CI then builds the .deb, sdist/wheel and drafts the
# GitHub Release from the tag.
#
# Usage: bash ship.sh [--skip-checks] [--no-push]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SKIP_CHECKS=0
NO_PUSH=0
for arg in "$@"; do
    case "$arg" in
        --skip-checks) SKIP_CHECKS=1 ;;
        --no-push)     NO_PUSH=1 ;;
        *) echo "usage: bash ship.sh [--skip-checks] [--no-push]" >&2; exit 2 ;;
    esac
done

step() { printf '\n==> %s\n' "$1"; }
fail() { printf '    FAIL: %s\n' "$1" >&2; exit 1; }

# Release exactly what is committed on main, so the gate checks what gets tagged.
[[ "$(git rev-parse --abbrev-ref HEAD)" == "main" ]] || fail "not on main"
[[ -z "$(git status --porcelain)" ]] || fail "working tree not clean; commit or stash first"

cur=$(grep -oP '^APP_VERSION = "\K[^"]+' version.py) || fail "cannot read APP_VERSION from version.py"
toml=$(grep -oP '^version = "\K[^"]+' pyproject.toml) || fail "cannot read version from pyproject.toml"
[[ "$cur" == "$toml" ]] || fail "version.py ($cur) and pyproject.toml ($toml) disagree"

today=$(date +%Y.%m.%d)
if [[ "$cur" =~ ^([0-9]{4}\.[0-9]{2}\.[0-9]{2})-([0-9]+)$ && "${BASH_REMATCH[1]}" == "$today" ]]; then
    ver="$today-$((BASH_REMATCH[2] + 1))"
else
    ver="$today-1"
fi
tag="v$ver"
[[ -z "$(git tag -l "$tag")" ]] || fail "tag $tag already exists"

step "Shipping $ver (was $cur)"
sed -i -E "s/^APP_VERSION = \"[^\"]*\"$/APP_VERSION = \"$ver\"/" version.py
sed -i -E "s/^version = \"[^\"]*\"$/version = \"$ver\"/" pyproject.toml

if [[ "$SKIP_CHECKS" -eq 0 ]]; then
    step "Running scripts/checks.py"
    PYTHON="python3"
    [[ -x .venv/bin/python ]] && PYTHON=".venv/bin/python"
    if ! "$PYTHON" scripts/checks.py; then
        git checkout -- version.py pyproject.toml
        fail "checks failed; version bump reverted"
    fi
else
    echo "    (checks skipped)"
fi

step "Committing and tagging $tag"
git add version.py pyproject.toml
git commit -q -m "chore(release): $ver"
git tag -a "$tag" -m "Release $ver"

if [[ "$NO_PUSH" -eq 1 ]]; then
    echo "    (push skipped; run: git push origin main $tag)"
    exit 0
fi

step "Pushing main and $tag"
git push origin main
git push origin "$tag"
echo
echo "Watch CI: https://github.com/retr0verride/NotTheNet/actions/workflows/ci.yml"
