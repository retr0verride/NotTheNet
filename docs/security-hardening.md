# Security Hardening Guide

NotTheNet runs in an **isolated malware analysis lab**. This guide covers how to lock down your lab so malware cannot escape the sandbox and reach your real network or the internet.

> See also: [SECURITY.md](../SECURITY.md) for reporting security vulnerabilities in NotTheNet itself.

## Table of Contents

- [Lab Network Isolation](#lab-network-isolation)
- [Interface Binding](#interface-binding)
- [Privilege Model](#privilege-model)
- [TLS Certificate Security](#tls-certificate-security)
- [Log Security](#log-security)
- [Captured Artifact Handling](#captured-artifact-handling)
- [Limiting the Attack Surface](#limiting-the-attack-surface)
- [OpenSSF Practices Implemented](#openssf-practices-implemented)
- [Recommended Lab Checklist](#recommended-lab-checklist)

---

## Lab Network Isolation

**This is the single most important security step.** Everything else is secondary.

NotTheNet intercepts and fakes traffic — but it does **not** block real internet access by itself. If the host machine has a route to the real internet, malware could potentially use it.

### Rules

1. **Never run NotTheNet on a machine that is connected to the real internet** unless the internet-facing interface is firewalled off from the lab network.
2. The network interface in `general.interface` should be a **host-only** or **internal-only** virtual adapter (e.g. `vmbr1` on Proxmox with no physical uplink).
3. The victim VM (where malware runs) should have **no route to the real internet** — only to Kali.

### How to verify isolation

On the victim VM, after NotTheNet is running:
```bash
# This must NOT work (real internet must be unreachable):
curl --max-time 5 https://1.1.1.1/
# Expected: timeout or connection refused

# This should work (it's hitting NotTheNet's fake HTTP server):
curl --max-time 5 http://evil.example.com/
# Expected: 200 OK
```

If the first command succeeds, your network is not properly isolated — check your interface config and firewall rules.

---

## Interface Binding

### Bind to the isolated interface only

By default, `bind_ip` can be set to `0.0.0.0` which means "listen on all network interfaces". This is convenient but means NotTheNet also listens on any internet-facing interface.

For a properly isolated lab, set `bind_ip` to the specific IP of your lab adapter:

```json
"general": {
  "bind_ip": "10.0.0.1",
  "interface": "eth0"
}
```

### Block traffic on other interfaces

As an extra layer of protection, add firewall rules to block any traffic between the lab network and the real internet:

```bash
# Block all outbound on real internet interface (eth0) from the analysis subnet
sudo iptables -A FORWARD -i virbr0 -o eth0 -j DROP
sudo iptables -A FORWARD -i eth0 -o virbr0 -j DROP
```

---

## Privilege Model

NotTheNet follows a **"start privileged, then drop privileges"** model:

1. **Starts as root** — required to bind standard ports (53, 80, 443, etc.) and set up traffic redirection rules.
2. **Drops to an unprivileged user** — after all ports are bound and rules are set, NotTheNet switches to the `nobody` user. This limits the damage if a bug or exploit is found.

Before dropping privileges, the service manager:
- Changes ownership of the `logs/` directory so logs can still be written
- Adds permissions on parent directories so config and certificate files remain accessible

To disable privilege dropping (not recommended):
```json
"general": { "drop_privileges": false }
```

Or drop to a dedicated service account instead of `nobody`:
```json
"general": {
  "drop_privileges": true,
  "drop_privileges_user": "notthenet-svc",
  "drop_privileges_group": "notthenet-svc"
}
```

> **Note:** Privilege drop persists for the lifetime of the process. If you click Stop and then Start again, the GUI relaunches the service process, so root is re-acquired and then dropped again.

### Desktop launch (password prompt)

When launched from the app menu, a password prompt appears (via `pkexec`) asking for root access. The prompt says:

```
NotTheNet needs root access to bind privileged ports and manage iptables rules.
```

---

## TLS Certificate Security

NotTheNet generates TLS certificates for its fake HTTPS server. These are intentionally self-signed — they don't need to be trusted by real browsers, they just need to make the TLS handshake succeed so malware will talk to the fake server.

### Certificate defaults

| Property | Value |
|----------|-------|
| Key type | RSA |
| Key size | 4096 bits |
| Signature | SHA-256 |
| Validity | 825 days |
| Hostnames | localhost, notthenet.local, 127.0.0.1 |

### Private key permissions

The private key is created with strict permissions so only root can read it:
```bash
ls -la certs/server.key
# Should show: -rw------- 1 root root ...
```

### Replacing with a custom certificate

You can use any PEM certificate/key pair:
```json
"https": {
  "cert_file": "/etc/notthenet/custom.crt",
  "key_file": "/etc/notthenet/custom.key"
}
```

Keep custom keys outside the project directory and out of version control (they are already in `.gitignore`).

### Do malware samples trust these certificates?

Usually, yes — most malware either:
- **Doesn't validate TLS certificates at all** (very common for C2 traffic)
- **Uses certificate pinning** (won't connect to anything fake regardless)
- **Trusts on first connect** (accepts self-signed on the first connection)

For malware that does strict CA validation, install NotTheNet's Root CA (`certs/ca.crt`) in the victim VM's trust store. When `https.dynamic_certs` is enabled, NotTheNet generates a Root CA and forges per-domain certificates signed by it — installing the CA once makes all forged certs trusted.

### Dynamic Certificate Forging (advanced)

When `https.dynamic_certs` is enabled:

- **Root CA** (`certs/ca.crt`, `certs/ca.key`) — auto-generated with 4096-bit RSA and 10-year validity. Private key written with mode `0o600`.
- **Per-domain certs** — generated on-the-fly via `DynamicCertCache`, a thread-safe LRU cache (max 500 entries). Temp cert files use sanitised hostnames (path traversal characters stripped) and mode `0o600`.
- **SNI-based cert switching** — an `ssl.SSLContext` SNI callback reads the requested hostname from `ClientHello` and selects the matching forged cert. Unknown hostnames get the default self-signed cert.
- **AuthorityKeyIdentifier** extension links each forged cert to the Root CA for proper chain validation.

---

## Log Security

### Protection against log injection (CWE-117)

Malware can try to inject fake log entries by putting special characters in hostnames, URLs, or commands. NotTheNet sanitises all untrusted data before writing it to logs:

- Strips ANSI escape sequences (prevents terminal colour hijacking when viewing logs)
- Replaces control characters (`\r`, `\n`, null bytes) with `[?]`
- Truncates overly long strings (512-character limit)

### Log file permissions

Log directories are created with restricted permissions (`0o700` — only the owner can read/write/enter). Before dropping privileges, NotTheNet changes log directory ownership so the unprivileged process can still write to them.

### Session-labeled JSON event logs

When JSON logging is enabled, each NotTheNet session writes to a new file:

```
logs/events_2026-04-01_s1.jsonl   ← first session today
logs/events_2026-04-01_s2.jsonl   ← second session today
```

The session number increments each time you click Start on the same day.

### Log rotation

Logs automatically rotate at 10 MB with 5 backups (50 MB maximum). This prevents a verbose malware sample from filling up your disk.

### JSON event log safety

When JSON logging is enabled:

- **Size cap:** 500 MB — logging stops when the cap is reached to prevent disk exhaustion
- **Thread-safe:** All writes go through a single logger with proper locking so events aren't corrupted
- **No code execution:** Events are serialised with `json.dumps()` — malware data is never evaluated as code
- **Immediate flush:** Events are written immediately so nothing is lost if NotTheNet crashes

If you need longer retention, archive logs before the backups roll over:
```bash
# Cron: archive logs daily
0 0 * * * cp /opt/NotTheNet/logs/notthenet.log /opt/notthenet-archive/$(date +%Y%m%d).log
```

---

## Captured Artifact Handling

Emails saved to `logs/emails/` and FTP uploads in `logs/ftp_uploads/` **may contain live malware**. Treat them with caution:

- Only open these directories in a sandboxed environment
- Don't double-click `.bin` or `.exe` files
- Use command-line tools (`file`, `strings`, `xxd`) to inspect files without executing them
- Always compress and password-protect before transferring off the analysis machine:
  ```bash
  zip -P infected --encrypt artifacts.zip logs/emails/ logs/ftp_uploads/
  ```
- The `.gitignore` already prevents `logs/` from being committed to version control

---

## Limiting the Attack Surface

### Disable services you don't need

Only enable the services relevant to the malware you're analysing. For example, if you're analysing ransomware that only uses HTTP for C2, you don't need SMTP, POP3, IMAP, or FTP:

```json
{
  "dns":   { "enabled": true },
  "http":  { "enabled": true },
  "https": { "enabled": true },
  "smtp":  { "enabled": false },
  "pop3":  { "enabled": false },
  "imap":  { "enabled": false },
  "ftp":   { "enabled": false }
}
```

### Minimal external dependencies

NotTheNet uses only **two** external Python packages:
- `dnslib` — for parsing DNS packets
- `cryptography` — for generating TLS certificates

Everything else (HTTP server, SMTP server, FTP server, GUI, traffic redirection) uses Python's built-in standard library. Fewer dependencies means fewer potential supply-chain vulnerabilities.

---

## OpenSSF Practices Implemented

This section is for security auditors and contributors. It lists the security engineering practices built into NotTheNet, following the [OpenSSF](https://openssf.org/) framework.

| Practice | How NotTheNet implements it |
|-----------------|----------------|
| Vulnerability disclosure policy | `SECURITY.md` with private reporting channel |
| Contribution process | `CONTRIBUTING.md` with PR process, code style, and test policy |
| Changelog | `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/) format |
| Pinned dependencies | `requirements.txt` with pinned versions |
| Dependency monitoring | Dependabot enabled for pip + GitHub Actions (`.github/dependabot.yml`) |
| CI / SAST on every commit | GitHub Actions runs ruff + mypy + bandit + pytest on every push & PR |
| Static analysis config | `pyproject.toml` configures Ruff (linting) + Bandit (security scanning) |
| No shell injection | All `subprocess` calls use lists, `shell=False` enforced in `iptables_manager.py` |
| Input validation | `utils/validators.py` validates all external inputs at the boundary |
| Least privilege | Runs as root only for port binding and iptables; isolated to the analysis network interface via `bind_ip` |
| Secure defaults | TLS 1.2+, 4096-bit keys, ECDHE ciphers by default |
| Dynamic cert security | Hostname sanitisation prevents path traversal in temp cert filenames |
| JSON log size cap | 500 MB cap prevents disk exhaustion from verbose malware traffic |
| WebSocket frame handling | Minimal parsing (4 KB drain limit), no execution of frame payloads |
| `SECURITY.md` | Present in repo root |
| `.gitignore` | Blocks private keys and captured malware artifacts |

### Running Bandit (security linter)

```bash
source venv/bin/activate
pip install bandit
bandit -r . -c pyproject.toml
```

### Running Ruff (code linter including security rules)

```bash
pip install ruff
ruff check .
```

---

## Recommended Lab Checklist

Run through this checklist before each analysis session:

- [ ] Victim VM is **snapshotted** (so you can revert after detonation)
- [ ] Victim VM has **no route to the real internet**
- [ ] Victim VM's DNS is set to the **NotTheNet host IP** (e.g. `10.0.0.1`)
- [ ] `config.json` interface is set to the **isolated lab adapter** (not an internet-connected one)
- [ ] `redirect_ip` matches Kali's IP on the isolated network
- [ ] NotTheNet is running and **all expected services show green**
- [ ] DNS test works: `dig @10.0.0.1 test.com +short` returns the expected IP
- [ ] Log directory is **writable** and has sufficient free disk space
- [ ] If using `dynamic_certs`, the Root CA (`certs/ca.crt`) is installed in the victim VM's trust store
- [ ] If using `tcp_fingerprint`, the profile matches the victim OS (e.g. `"windows"` for FlareVM)
- [ ] Artifacts from **previous sessions** are archived or cleared
