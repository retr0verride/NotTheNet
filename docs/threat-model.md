# NotTheNet — STRIDE Threat Model

## System Overview

NotTheNet is a **malware analysis sinkhole** that impersonates network
services on an isolated lab network.  All traffic from a victim VM is
redirected (via iptables NAT) to NotTheNet's fake services, which log
every connection for post-incident analysis.

### Trust Boundaries

```
┌──────────────────────────────────────────────────────┐
│  Analyst Workstation (trusted)                       │
│  └─ GUI / CLI   ──▶  config.json (filesystem)       │
└────────────┬─────────────────────────────────────────┘
             │ SSH / local access
┌────────────▼─────────────────────────────────────────┐
│  Kali Gateway (NotTheNet host)                       │
│  ┌────────────────────────────────────────────────┐  │
│  │ NotTheNet process (root → drops to user)       │  │
│  │  ├─ DNS :53        ├─ SMTP :25                 │  │
│  │  ├─ HTTP :80       ├─ FTP  :21                 │  │
│  │  ├─ HTTPS :443     ├─ Telnet :23               │  │
│  │  ├─ Catch-all TCP :9999                        │  │
│  │  ├─ Catch-all UDP :9998                        │  │
│  │  └─ iptables NAT rules                        │  │
│  └────────────────────────────────────────────────┘  │
│       ▲                                              │
│       │ Redirected traffic                           │
└───────┼──────────────────────────────────────────────┘
        │
┌───────┴──────────────────────────────────────────────┐
│  Victim VM (untrusted — runs malware)                │
│  All outbound traffic NATed to NotTheNet             │
└──────────────────────────────────────────────────────┘
```

### Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Captured traffic logs | High | `logs/`, JSON log file |
| TLS private key | High | `certs/server.key` (mode 0600) |
| Configuration | Medium | `config.json` |
| iptables rules | Medium | In-kernel (managed by NotTheNet) |
| Analyst host OS | Critical | Kali gateway |

---

## STRIDE Analysis

### S — Spoofing

| # | Threat | Component | Mitigation | Status |
|---|--------|-----------|------------|--------|
| S1 | Malware spoofs source IP to bypass per-IP rate limits | Catch-all TCP | iptables NAT rewrites src to the real victim IP; spoofed packets from outside the subnet are dropped by `harden-lab.sh` | ✅ Mitigated |
| S2 | Attacker impersonates the analyst GUI | GUI / config.json | GUI runs locally on the analyst's machine; config.json is filesystem-protected | ✅ Mitigated |
| S3 | Malware forges DNS responses to poison NotTheNet's own lookups | DNS server | NotTheNet never makes outbound DNS queries; it only *answers* them | ✅ N/A |

### T — Tampering

| # | Threat | Component | Mitigation | Status |
|---|--------|-----------|------------|--------|
| T1 | Malware modifies log files to hide its activity | JSON logger, FTP uploads | Logs written to analyst-owned directories with restricted permissions; malware runs in a separate VM with no filesystem access to the host | ✅ Mitigated |
| T2 | Path traversal via FTP upload filenames | FTP server | `sanitize_path()` resolves real paths and rejects traversal; uploads use UUID filenames | ✅ Mitigated |
| T3 | Config file tampering | config.json | File is on the host filesystem, inaccessible from the victim VM; atomic writes prevent partial corruption | ✅ Mitigated |

### R — Repudiation

| # | Threat | Component | Mitigation | Status |
|---|--------|-----------|------------|--------|
| R1 | Malware denies making a connection | All services | Every connection is logged with timestamp, source IP, port, protocol, and payload preview in the JSON event log | ✅ Mitigated |
| R2 | Log entries forged or injected | Logging subsystem | `sanitize_log_string()` strips control characters (CWE-117); structured JSON format prevents log injection | ✅ Mitigated |

### I — Information Disclosure

| # | Threat | Component | Mitigation | Status |
|---|--------|-----------|------------|--------|
| I1 | TLS private key leaked to malware | HTTPS / Catch-all | Key file stored with `0o600` permissions; never transmitted in protocol responses | ✅ Mitigated |
| I2 | Malware fingerprints NotTheNet as a sinkhole | All services | Realistic protocol banners (Apache, Microsoft-IIS, Postfix); TCP fingerprint spoofing; NCSI/connectivity-check honoring | ✅ Mitigated |
| I3 | Log files contain sensitive lab topology | JSON logger | Logs are on the isolated host; `harden-lab.sh` blocks all outbound traffic from the gateway | ✅ Mitigated |

### D — Denial of Service

| # | Threat | Component | Mitigation | Status |
|---|--------|-----------|------------|--------|
| D1 | Malware opens thousands of TCP connections to exhaust resources | Catch-all TCP | Global `BoundedSemaphore(200)` + per-IP limit of 20 concurrent connections; 10-second session timeout | ✅ Mitigated |
| D2 | Malware sends huge HTTP request bodies to exhaust memory | HTTP server | All `Content-Length` reads capped at `_MAX_BODY_FILE_SIZE` (10 MB) | ✅ Mitigated |
| D3 | Malware floods DNS queries | DNS server | Each query is stateless (UDP); `dnslib` parsing is fast; malformed packets return SERVFAIL | ⚠️ Accepted (no per-IP DNS throttle; lab has single victim) |
| D4 | Disk exhaustion via email/FTP spam | SMTP, FTP | Per-file size caps and total storage caps enforced | ✅ Mitigated |
| D5 | Malware crashes NotTheNet via malformed input | All services | All handlers wrapped in try/except; fuzz-resistant parsing; no `shell=True` | ✅ Mitigated |

### E — Elevation of Privilege

| # | Threat | Component | Mitigation | Status |
|---|--------|-----------|------------|--------|
| E1 | Malware exploits a service to gain host-level access | All services | NotTheNet drops root privileges after binding ports (`seteuid`/`setegid`); `setgroups([])` clears supplementary groups | ✅ Mitigated |
| E2 | Shell injection via subprocess calls | iptables manager, service manager | All `subprocess` calls use `shell=False` with list arguments; `sanitize_path()` on all file paths | ✅ Mitigated |
| E3 | Malware escapes VM and accesses host | VM hypervisor | Out of scope for NotTheNet; mitigated at the hypervisor level (Proxmox/VirtualBox isolation) | ⚠️ Out of scope |

---

## Risk Summary

| STRIDE Category | Threats | Mitigated | Accepted | Out of Scope |
|-----------------|---------|-----------|----------|--------------|
| **S**poofing | 3 | 2 | 0 | 1 |
| **T**ampering | 3 | 3 | 0 | 0 |
| **R**epudiation | 2 | 2 | 0 | 0 |
| **I**nformation Disclosure | 3 | 3 | 0 | 0 |
| **D**enial of Service | 5 | 4 | 1 | 0 |
| **E**levation of Privilege | 3 | 2 | 0 | 1 |
| **Total** | **19** | **16** | **1** | **2** |

## References

- Microsoft STRIDE: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling
- OpenSSF Scorecard: https://securityscorecards.dev/
- NotTheNet SECURITY.md: [SECURITY.md](../SECURITY.md)
