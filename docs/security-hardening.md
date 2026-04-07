# Security Hardening Guide

NotTheNet is designed for use in **isolated malware analysis environments**. This guide covers how to harden your lab to prevent malware from escaping the sandbox.

> See also: [SECURITY.md](../SECURITY.md) for the vulnerability disclosure policy.

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

**This is the most important security step.**

NotTheNet intercepts fake traffic — it does not prevent real network access if the host itself is connected to the internet.

### Rules

1. **Never run NotTheNet on a machine with a real internet-connected interface that is not firewalled off from the analysis network.**
2. The network interface specified in `general.interface` should be a **host-only** or **internal-only** virtual adapter.
3. The analysis VM should have **no** route to the real internet.

### Verifying isolation

On the victim VM, after NotTheNet is running:
```bash
# This must NOT succeed (real internet must be blocked)
curl --max-time 5 https://1.1.1.1/
# Expected: timeout or connection refused

# This should succeed (fake HTTP)
curl --max-time 5 http://evil.example.com/
# Expected: 200 OK from NotTheNet
```

If the real internet request succeeds, your iptables interface config is wrong — traffic is leaking through a different adapter.

---

## Interface Binding

### Bind to the isolated interface only

In `config.json`:
```json
"general": {
  "bind_ip": "192.168.100.1",
  "interface": "virbr0"
}
```

Setting `bind_ip` to `0.0.0.0` is convenient but binds to **all** interfaces including real network adapters. On machines with internet access, tighten this to the specific isolated interface IP.

### Block traffic on other interfaces

Even with `bind_ip` set correctly, add an explicit iptables rule to block unwanted outbound traffic:

```bash
# Block all outbound on real internet interface (eth0) from the analysis subnet
sudo iptables -A FORWARD -i virbr0 -o eth0 -j DROP
sudo iptables -A FORWARD -i eth0 -o virbr0 -j DROP
```

---

## Privilege Model

NotTheNet performs a **bind-then-drop** privilege model:

1. **Starts as root** — required to bind privileged ports (53, 80, 443, 25, 110, 143, 21) and apply iptables NAT rules.
2. **Drops to `nobody:nogroup`** — immediately after all ports are bound and iptables rules are applied (`general.drop_privileges: true`, the default). Uses `seteuid`/`setegid` (not permanent `setuid`/`setgid`) so root can be temporarily restored for iptables cleanup on stop.

Before dropping, the service manager:
- `chown`s `logs/` and all subdirs (`emails/`, `ftp_uploads/`, `tftp_uploads/`) to the target user/group, so file saves (JSON events, emails, uploads) continue to work after the drop.
- Adds `o+x` traversal permission on each parent directory in the path to the project root (e.g. `/home/kali/`) so the dropped process can still access config and cert files by relative path.

Disable with:
```json
"general": { "drop_privileges": false }
```

Or drop to a custom account instead of `nobody`:
```json
"general": {
  "drop_privileges": true,
  "drop_privileges_user": "notthenet-svc",
  "drop_privileges_group": "notthenet-svc"
}
```

> **Note:** Privilege drop is permanent within a process — clicking Stop and Start again requires a full process relaunch (the GUI's Stop/Start cycle already does this).

### Desktop launch (pkexec)

When launched from the app menu, `pkexec` is used to acquire root for the session rather than running permanently as root in the user session. The polkit action provides a descriptive auth dialog:

```
NotTheNet needs root access to bind privileged ports and manage iptables rules.
```

---

## TLS Certificate Security

### Certificate generation defaults

| Property | Value |
|----------|-------|
| Key type | RSA |
| Key size | 4096 bits |
| Signature | SHA-256 |
| Validity | 825 days |
| SAN | localhost, notthenet.local, 127.0.0.1 |
| CN-only | No (SAN is included, as required by RFC 2818) |

### Private key permissions

The private key is written with mode `0o600` (owner read/write only). Verify:
```bash
ls -la certs/server.key
# -rw------- 1 root root ... certs/server.key
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

### Certificate is NOT trusted by malware by default

That's fine — most malware either:
- Does not validate TLS certificates (common for C2)
- Uses certificate pinning (won't connect to anything fake anyway)
- Validates trust on first connect (TOFU) — accepts self-signed on first connection

For malware that does strict CA validation, install the Root CA (`certs/ca.crt`) in the analysis VM's trust store. When `https.dynamic_certs` is enabled, NotTheNet auto-generates a Root CA at `certs/ca.crt` / `certs/ca.key` and forges per-domain certs signed by it — installing the CA once makes all forged certs trusted.

### Dynamic Certificate Security

When `https.dynamic_certs` is enabled:

- **Root CA** (`certs/ca.crt`, `certs/ca.key`) — auto-generated with 4096-bit RSA and 10-year validity. Private key written with mode `0o600`.
- **Per-domain certs** — generated on-the-fly via `DynamicCertCache`, a thread-safe LRU cache (max 500 entries). Temp cert files use sanitised hostnames (path traversal characters stripped) and mode `0o600`.
- **SNI-based cert switching** — an `ssl.SSLContext` SNI callback reads the requested hostname from `ClientHello` and selects the matching forged cert. Unknown hostnames get the default self-signed cert.
- **AuthorityKeyIdentifier** extension links each forged cert to the Root CA for proper chain validation.

---

## Log Security

### Log injection prevention (CWE-117)

All untrusted data (IP addresses, hostnames, HTTP paths, DNS query names, SMTP commands, FTP commands) is passed through `sanitize_log_string()` before being written to logs. This function:

- Strips ANSI escape sequences (prevents terminal hijacking via log viewing)
- Replaces ASCII control characters (`\r`, `\n`, `\x00`–`\x1f`) with `[?]`
- Truncates strings longer than 512 characters

### Log file permissions

Log directories are created with mode `0o700`. Before privilege drop, the service manager `chown`s `logs/` and its subdirectories to the drop target user (default `nobody`) so the dropped process retains write access. Log files inherit the umask of the running process.

### Session-labeled JSON event logs

When `general.json_logging` is enabled, each session writes to a new date/session-labeled file:

```
logs/events_2026-04-01_s1.jsonl   ← first session today
logs/events_2026-04-01_s2.jsonl   ← second session today
```

The session number increments for each Start within the same calendar day. The active session path is written back to in-memory config at runtime — the GUI JSON Events viewer and export dialog always reference the current session.

### Rotating logs

Logs rotate at 10 MB with 5 backups (50 MB maximum total). This prevents disk exhaustion from captured verbose malware traffic.

### JSON Event Log Security

When `general.json_logging` is enabled:

- **File size cap:** 500 MB — logging stops when the cap is reached to prevent disk exhaustion
- **Thread-safe writes:** All log writes go through a single `JsonEventLogger` singleton with proper locking
- **No eval/exec:** JSON events are serialised with `json.dumps()` — no user-controlled data is ever evaluated as code
- **Auto-flush:** Events are flushed immediately so data is not lost on crash

If you need longer retention, archive logs before the backups roll over:
```bash
# Cron: archive logs daily
0 0 * * * cp /opt/NotTheNet/logs/notthenet.log /opt/notthenet-archive/$(date +%Y%m%d).log
```

---

## Captured Artifact Handling

Emails saved to `logs/emails/` and FTP uploads saved to `logs/ftp_uploads/` **may contain malware binaries or scripts**. Handle accordingly:

- Open these directories only in a sandboxed environment
- Do not double-click `.bin` files
- Use `file`, `strings`, and `xxd` to inspect rather than executing
- Compress and password-protect before transferring off the analysis host:
  ```bash
  zip -P infected --encrypt artifacts.zip logs/emails/ logs/ftp_uploads/
  ```
- The `.gitignore` already blocks `logs/` from being committed to version control

---

## Limiting the Attack Surface

### Disable services you don't need

Only enable services relevant to the malware being analyzed. For ransomware studying HTTP C2 only:

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
- `dnslib` — DNS packet parsing
- `cryptography` — TLS certificate generation

Everything else (HTTP, SMTP, FTP, TCP/UDP servers, iptables management, GUI) uses Python's standard library. This minimises supply-chain risk.

---

## OpenSSF Practices Implemented

| OpenSSF Practice | Implementation |
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

Before each analysis session:

- [ ] Victim VM is **snapshotted** before execution
- [ ] Victim VM has **no route** to real internet
- [ ] Victim VM DNS is **set to NotTheNet host IP**
- [ ] `config.json` interface is set to the **isolated adapter** (not `eth0` connected to real internet)
- [ ] `redirect_ip` matches the **NotTheNet host's IP** on the isolated network
- [ ] NotTheNet is running and **all expected services show green** in the sidebar
- [ ] Verified DNS resolution: `dig @<notthenet-ip> test.com +short` returns expected IP
- [ ] Log directory is **writable** and has sufficient disk space
- [ ] If using `dynamic_certs`, install `certs/ca.crt` in the analysis VM's **trust store** for seamless HTTPS interception
- [ ] If using `tcp_fingerprint`, set `tcp_fingerprint_os` to match the **expected OS** of the analysis target (e.g. `"windows"` for FlareVM)
- [ ] If using `json_logging`, confirm `json_log_file` path is writable and monitor disk usage (500 MB cap)
- [ ] Malware artifacts (`logs/emails`, `logs/ftp_uploads`) from **previous sessions are archived** or cleared
