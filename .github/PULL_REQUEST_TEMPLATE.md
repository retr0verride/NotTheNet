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
- [ ] `ruff` passes with no errors (run via `pre-commit run ruff`)
- [ ] `mypy --strict` passes for all changed files under `domain/`, `application/`, `infrastructure/`
- [ ] `bandit` reports no new HIGH/MEDIUM findings
- [ ] New logic is covered by unit tests (≥80% branch coverage maintained)
- [ ] Cyclomatic complexity of changed functions ≤ 10

### Security
- [ ] No secrets, tokens, or credentials committed (gitleaks clean)
- [ ] All new network-facing inputs are validated at the system boundary
- [ ] No new bare `except:` or `except Exception: pass` clauses
- [ ] If iptables rules are modified: net-admin privilege is the minimum required

### Domain integrity
- [ ] Domain layer (`domain/`) imports **nothing** from `infrastructure/` or `gui/`
- [ ] Application layer imports only `domain/` ports
- [ ] New exceptions inherit from `domain.exceptions.NotTheNetError`

### Tests
- [ ] Unit tests added / updated
- [ ] If Kali-only behaviour: guarded with `@pytest.mark.kali` or `test_kali_fidelity.py`
- [ ] CI passes locally: `pytest --cov --cov-fail-under=80`

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
