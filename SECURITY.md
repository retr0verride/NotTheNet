# Security Policy

## Common Platform Enumeration (CPE)

```
cpe:2.3:a:retr0verride:notthenet:*:*:*:*:*:python:*:*
```

Use this CPE to track NotTheNet in vulnerability databases (NVD, OSV, etc.).

## Supported Versions

| Version | Supported |
|---------|----------|
| 2026.x  | ✅ Yes   |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via one of:
- **GitHub Private Advisory**: [Security → Advisories → Report a vulnerability](../../security/advisories/new)

Include:
1. A clear description of the vulnerability
2. Steps to reproduce (proof-of-concept if available)
3. Affected version(s) and configuration
4. Potential impact and attack vector

We target:
- **Initial response**: within 48 hours
- **Triage + severity assessment**: within 7 days
- **Fix / release**: within 30 days for Critical/High

## Security Design Principles

NotTheNet is a **malware analysis sandbox tool**, not a production service.
It is intentionally designed to run on **isolated networks** only.

### What we harden anyway (defense-in-depth)

| Concern | Mitigation |
|---------|-----------|
| Log injection (CWE-117) | All untrusted strings sanitized before logging (`utils/logging_utils.py`) |
| Shell injection (CWE-78) | `subprocess` always called with a list, `shell=False` enforced |
| Path traversal (CWE-22) | `utils/validators.sanitize_path()` resolves real paths under a strict base |
| Disk exhaustion (CWE-400) | Per-file and total caps on email saves and FTP uploads |
| Privilege escalation | Privileges dropped via `seteuid`/`setegid` after binding low ports (`utils/privilege.py`); `NoNewPrivileges=no` in the systemd unit is required for the drop and is justified in the service file |
| Weak TLS | TLS 1.2+ enforced; SSLv2/v3/TLS1.0/1.1 disabled; strong ECDHE+AEAD ciphers only |
| Insecure key storage | Private key written with mode `0o600` (owner-read only) |
| Attacker-controlled filenames | All saved files use UUID names; attacker input never used in file paths |
| Resource exhaustion (connections) | Bounded `ThreadPoolExecutor` on HTTP; per-session timeouts on all services |
| Malformed DNS packets | `dnslib` handles parsing; exceptions caught and return SERVFAIL — server never crashes |
| SSRF via FTP PORT | Active mode (PORT command) is intentionally not implemented |

### What is explicitly out of scope

- Authentication bypass: NotTheNet has no authentication (it's a fake network, not a real service)
- Data confidentiality of captured traffic: captured malware traffic is the *intended* output

## Supply Chain Security

- Python dependencies are pinned in `requirements.txt`
- Only two external runtime dependencies (`dnslib`, `cryptography`) — minimal attack surface
- The `cryptography` package is the [PyCA cryptography library](https://cryptography.io/), which follows its own rigorous security process

## OpenSSF Scorecard

This project aims to achieve a high [OpenSSF Scorecard](https://securityscorecards.dev/) score:

| Check | Status |
|-------|--------|
| CI / SAST | ✅ GitHub Actions (ruff + mypy + bandit + pytest) on every push & PR |
| Branch protection | Recommended: protect `master` |
| Code review | Recommended: require PRs |
| Dependency update tool | ✅ Dependabot enabled for pip + GitHub Actions |
| Pinned dependencies | ✅ `requirements.txt` pinned |
| Vulnerability disclosure | ✅ This `SECURITY.md` |
| Contribution process | ✅ `CONTRIBUTING.md` with PR process, code style, and test policy |
| Changelog | ✅ `CHANGELOG.md` following Keep a Changelog format |
| Signed releases | Recommended: GPG-sign tags |

## Recommended Deployment Hardening

When deploying NotTheNet in a malware analysis lab:

```bash
# Run in an isolated VM / network namespace
# Loopback mode — only intercept traffic from this host
sudo notthenet --config config.json

# Gateway mode — intercept traffic from other VMs
# Edit config.json: "iptables_mode": "gateway"
# and ensure the analysis VM routes through this host

# Restrict the iptables interface to the internal-only adapter
# e.g., "interface": "virbr0"  NOT "eth0" if eth0 is your real network!
```

> ⚠️ **Never run NotTheNet on a machine connected to the production internet without strict interface filtering in `config.json`.**
