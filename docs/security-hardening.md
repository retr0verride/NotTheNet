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

NotTheNet uses a **bind-then-drop** privilege model:

1. Process starts as `root` (required to bind ports < 1024 and apply iptables rules)
2. All service sockets are bound
3. All iptables rules are applied
4. **`setgroups([])`** clears supplementary groups
5. **`setgid(target_gid)`** drops to the target group (default: `nogroup`)
6. **`setuid(target_uid)`** drops to the target user (default: `nobody`)

After this point, the process has no root capabilities. Malware interacting with the fake services is doing so through a process running as `nobody:nogroup`.

### Verifying the privilege drop

```bash
# After starting NotTheNet
ps aux | grep notthenet
# Should show: nobody  ... python3 notthenet.py
```

### Dedicated service account (recommended)

Instead of `nobody`, create a dedicated account:
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin notthenet
```

Then set `run_as_user` to `notthenet` in `utils/privilege.py` or add it to config in a future release.

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

For malware that does strict CA validation, configure your analysis environment to trust the self-signed cert, or use a CA-signed cert from a private CA you control.

---

## Log Security

### Log injection prevention (CWE-117)

All untrusted data (IP addresses, hostnames, HTTP paths, DNS query names, SMTP commands, FTP commands) is passed through `sanitize_log_string()` before being written to logs. This function:

- Strips ANSI escape sequences (prevents terminal hijacking via log viewing)
- Replaces ASCII control characters (`\r`, `\n`, `\x00`–`\x1f`) with `[?]`
- Truncates strings longer than 512 characters

### Log file permissions

Log directories are created with mode `0o700`. Log files inherit the umask of the running process. After privilege drop, logs are owned by `nobody`.

### Rotating logs

Logs rotate at 10 MB with 5 backups (50 MB maximum total). This prevents disk exhaustion from captured verbose malware traffic.

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
| Pinned dependencies | `requirements.txt` with pinned versions |
| Static analysis config | `pyproject.toml` configures Ruff (linting) + Bandit (security scanning) |
| No shell injection | All `subprocess` calls use lists, `shell=False` enforced in `iptables_manager.py` |
| Input validation | `utils/validators.py` validates all external inputs at the boundary |
| Least privilege | Privilege dropped to `nobody:nogroup` after binding |
| Secure defaults | TLS 1.2+, 4096-bit keys, ECDHE ciphers by default |
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
- [ ] Malware artifacts (`logs/emails`, `logs/ftp_uploads`) from **previous sessions are archived** or cleared
