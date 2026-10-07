## Description

<!--- What does this PR do? Describe the problem it solves and the solution. -->

Fixes # (issue)

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] Refactor (no functional change — code quality / structure improvement)
- [ ] Documentation / chore

## Checklist

### Code quality
- [ ] `python scripts/checks.py` passes (ruff, strict mypy, bandit, pip-audit, tests, version)
- [ ] New fully annotated modules are added to `STRICT_MYPY_FILES` in `scripts/checks.py`
- [ ] `bandit` reports no new HIGH/MEDIUM findings
- [ ] New logic is covered by unit tests
- [ ] Cyclomatic complexity of changed functions ≤ 12 (ruff `C901`)

### Security
- [ ] No secrets, tokens, or credentials committed (gitleaks clean)
- [ ] All new network-facing inputs are validated at the system boundary
- [ ] No new bare `except:` or `except Exception: pass` clauses
- [ ] If iptables rules are modified: net-admin privilege is the minimum required

### Structure
- [ ] Nothing outside `gui/` imports tkinter (headless and Docker run without it)
- [ ] New services are registered in `_SERVICE_REGISTRY` in `service_manager.py`

### Tests
- [ ] Unit tests added / updated
- [ ] If Kali-only behaviour: guarded with `@pytest.mark.kali` or `test_kali_fidelity.py`
- [ ] CI passes locally: `python scripts/checks.py`

### Documentation
- [ ] `CHANGELOG.md` entry added under **[Unreleased]** (Conventional Commits format)
- [ ] `docs/` updated if public-facing behaviour changed
- [ ] `openapi.yaml` updated if health API changed

## Breaking changes

<!--- If this is a breaking change, describe the migration path. -->

N/A

## Deployment notes

<!--- Any manual steps required on the target host (Kali, systemd reload, etc.)? -->

N/A
