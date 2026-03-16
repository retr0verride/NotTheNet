# Changelog

All notable changes to NotTheNet are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/). Versioning uses [CalVer](https://calver.org/) (`YYYY.MM.DD-N`).

---

## [Unreleased]

### Fixed
- **HTTP/HTTPS: Thread-unsafe CRL stub cache** — `_STUB_CRL_CACHE` and `_EXTENSION_MAP` (dynamic_response) were lazily initialised without locking; under concurrent connections multiple threads could simultaneously enter the initialisation branch, generating redundant RSA keys (expensive) and leaving the module in an inconsistent state. Both are now protected by a `threading.Lock()` with double-checked locking so only one thread performs the work.
- **HTTP/HTTPS: Artificial delay blocked OS connectivity probes** — the per-request `response_delay_ms` was applied unconditionally *before* routing, so Windows NCSI (`www.msftconnecttest.com`), Windows PKI CRL/OCSP (`crl.microsoft.com`, `ocsp.digicert.com`, etc.), and Google/Apple captive portal probes were subjected to the full artificial latency; these endpoints have strict timeout expectations and would silently fail at delays ≥ 300 ms. The `Host` header is now parsed before entering the delay block, and the delay is skipped entirely for `_NCSI_HOSTS`, `_PKI_HOSTS`, and `_CAPTIVE_PORTAL_HOSTS`.
- **HTTP/HTTPS: `urllib.parse` imported inside hot-path handler** — `from urllib.parse import urlparse, parse_qs` was deferred inside `_send_ip_check_response()` (a PLC0415 suppressed with a `# noqa`); the import machinery acquires a global lock on each call and adds measurable latency under concurrent requests. Moved to module-level imports.
- **HTTP/HTTPS: `spoof_public_ip` not validated** — the config value was accepted as-is and forwarded to the response formatter; an invalid or RFC-1918 address would not be caught until malware flagged the non-public IP. `HTTPService` and `HTTPSService` now call `_validate_spoof_ip()` at init time: unparseable values are rejected with an error and IP spoofing is disabled; RFC-1918 / loopback values are accepted but produce a warning.
- **iptables: TOCTOU race in nat table snapshot** — `_save_nat_snapshot()` used `open(..., 'w')` followed by `os.chmod(..., 0o600)`, leaving a window between file creation (world-readable) and permission tightening. Replaced with a single `os.open(path, O_CREAT|O_WRONLY|O_TRUNC, 0o600)` call; the file is created with the correct permissions atomically. Same fix applied to `_save_mangle_snapshot()`.
- **iptables: Mangle table TTL rule not snapshotted** — the mangle POSTROUTING TTL rule was tracked only via the in-memory `_ttl_rule_applied` flag, which is lost on crash or unexpected exit; the rule would persist across reboots if the system was killed mid-session. A `_save_mangle_snapshot()` / `_restore_mangle_snapshot()` pair now wraps TTL rule management, mirroring the nat table approach. Both the normal stop path and the no-snapshot fallback path restore/remove the mangle rule.
- **iptables: `spoof_ttl` not range-validated** — bare `int()` conversion was applied to the config value with no bounds check; values outside `[1, 255]` are invalid TTLs and would cause `iptables` to reject the rule with a cryptic error at runtime. Added a range check at `IPTablesManager.__init__`; out-of-range values emit a warning and disable TTL spoofing.
- **DNS: `_shannon_entropy()` called twice per DGA candidate** — the entropy value was computed once in the `if` condition and again in the `logger.debug()` format string, doubling the work for every A query that triggered DGA evaluation. Result is now cached in a local `entropy` variable and reused in both places.
- **DNS: FCrDNS inconsistency with public IP pool** — when `public_response_ips` is configured, A queries return a pool IP deterministically. A PTR lookup for that pool IP synthesises a plausible ISP hostname (e.g. `static-72-21-215-232.res.example.net`). A forward-confirmed reverse DNS (FCrDNS) check then resolves that hostname; our A handler would return a *different* pool IP (hash of the synthesised name ≠ hash of the original domain), breaking the check. The A handler now detects the `static-A-B-C-D.res.example.net` pattern via regex and returns the IP embedded in the hostname, making FCrDNS checks pass.
- **config.json: DGA entropy threshold missed short random labels** — `nxdomain_entropy_threshold: 3.8` / `nxdomain_label_min_length: 12` would not flag canonical 8-9 character DGA test domains (e.g. `djqkeqjwe.com`, Shannon entropy ≈ 3.17). Lowered to `3.2` / `8` to catch these while still preserving short real-word domains (entropy typically < 2.9 for common 6-8 char English words).
- **service_manager: silent fallback for missing `redirect_ip`** — `self.config.get("general", "redirect_ip") or "127.0.0.1"` silently substituted `127.0.0.1` when the config key was absent or empty; gateway-mode deployments where redirect_ip must be the Kali box's LAN IP would silently misconfigure. A `logger.warning()` is now emitted when the value is absent so the operator is not surprised by the fallback.

---

## [2026.03.15-1] — 2026-03-15

### Added
- **DNS: DGA / canary-domain NXDOMAIN** — new `dns.nxdomain_entropy_threshold` (default `3.8`) and `dns.nxdomain_label_min_length` (default `12`) config keys; when set, A queries whose second-level domain exceeds the Shannon entropy threshold and minimum length receive NXDOMAIN instead of a resolved address; defeats malware that issues a random-looking domain query (canary check) before detonating to confirm DNS is being sinkholed
- **DNS: Public IP pool for A responses** — new `dns.public_response_ips` list; when populated, A query responses rotate through plausible public IPs (e.g. `142.250.x.x`, `104.x.x.x`) instead of the private `redirect_ip`; iptables REDIRECT rules intercept all traffic by destination port regardless of IP, so routing is unaffected; defeats the trivial heuristic where every domain resolves to a single RFC 1918 address
- **HTTP/HTTPS: Google / Android / Apple captive portal handlers** — `connectivitycheck.gstatic.com`, `connectivitycheck.android.com`, `clients1.google.com`, `clients3.google.com`, `ipv4.google.com` respond to `GET /generate_204` with HTTP 204 (empty body, `Server: GFE/2.0`); `captive.apple.com` and `www.apple.com` respond to `/hotspot-detect.html` and `/library/test/success.html` with HTTP 200 and the exact Apple success payload (`Server: AkamaiGHost`); OS-level connectivity indicators on Android, ChromeOS, macOS, and iOS now show "Connected" — malware waiting for full connectivity before detonating is unblocked
- **HTTP/HTTPS: Response delay jitter** — new `response_delay_jitter_ms` config key (default `30`); the per-response delay is now `delay_ms ± random(0..jitter)` ms; randomised latency defeats timing-based sandbox fingerprinting where a laboratory simulator responds with suspiciously consistent sub-millisecond precision
- **Network: Packet TTL mangle rule** — new `general.spoof_ttl` config key (default `54`); when nonzero, adds `iptables -t mangle -A POSTROUTING -o <interface> -j TTL --ttl-set <value>` so outgoing packets carry a TTL consistent with ~10 internet routing hops rather than the `64` of a directly-connected host; requires `xt_TTL` kernel module (`modprobe xt_TTL`); gracefully skipped with a warning if unavailable; rule is cleanly removed on stop

### Fixed
- **NTP: Stratum 2 Reference ID was `b"LOCL"`** — RFC 5905 §7.3 reserves kiss-o'-death / reference clock keywords (LOCL, GPS, PPS, etc.) for Stratum 1; a Stratum 2 server must encode the IPv4 address of its upstream reference clock as the 4-byte Reference ID; changed to `\xd8\xef\x23\x00` (216.239.35.0 = `time.google.com` Stratum 1); NTP clients and analysis tools that inspect the refid field no longer see the simulator fingerprint

---

## [2026.03.13-1] — 2026-03-13

### Fixed
- **iptables rules not removed on Stop** — `remove_rules()` had an early-exit guard that silently skipped all cleanup when `_rules_applied` was empty (e.g. after a crash, double-start, or session mismatch), leaving NOTTHENET NAT redirect rules active so the victim machine retained simulated internet access after NotTheNet was stopped. Replaced the tracked-rule-deletion approach with a snapshot/flush/restore strategy: the full nat table is saved via `iptables-save -t nat` immediately before any rules are applied, and on Stop the nat table is flushed and the snapshot is restored via `iptables-restore`. If no snapshot is available (e.g. `iptables-save` was not found), the entire nat table is flushed as a safe fallback. This guarantees a clean state regardless of how the session ended.

---

## [2026.03.12-1] — 2026-03-12

### Fixed
- **`ip_forward` left enabled after stop** — in gateway mode, `ip_forward` was enabled on start but only restored via the individual-rule-removal code path; when `iptables-restore` succeeded the early `return` skipped the restore, leaving `/proc/sys/net/ipv4/ip_forward` at `1` so the victim machine could still reach the real internet after NotTheNet stopped
- **`ip_forward` not required for REDIRECT rules** — `iptables` `REDIRECT` and `DNAT-to-localhost` rules redirect packets to local ports via `INPUT`, not `FORWARD`; `ip_forward` is only needed to route packets between two interfaces and was being set unnecessarily; all `ip_forward` read/write logic removed from `iptables_manager.py`, eliminating any risk of it lingering after a crash or `SIGKILL`
- **Invalid DNS label accepted in dynamic cert forger** — `forge_domain_cert()` now validates each hostname label against RFC 1123 (labels must not start or end with a hyphen) before loading the CA and issuing a certificate; raises `ValueError` on malformed input
- **`ip-api.com` `/line/` endpoint not handled** — the previous handler only returned the `/json/` body for all paths; malware families (AgentTesla, FormBook) that use `GET /line/?fields=hosting` received a JSON object as `text/plain`, which they parse as `"true"` and abort C2 activation; handler now branches on `/line/`, `/csv/`, and JSON paths, returning the correct format and `hosting=false` / `"hosting":false` for each

---

## [2026.03.09-1] — 2026-03-09

### Fixed
- **`update.sh` dirty-file abort** — git pull aborted when tracked files other than `config.json` had local modifications (e.g. `notthenet-uninstall.sh`); those files are now reset before the pull, matching the existing `config.json` preservation logic

---

## [2026.03.06-13] — 2026-03-06

### Added
- **Telnet service (TCP/23)** — fake Telnet server targeting Mirai and IoT botnet families; sends RFC 854 IAC option negotiation, configurable device banner, accepts any credentials (logs username + password), simulates a BusyBox root shell; shell commands (id, uname, ls, wget, curl, etc.) return plausible-but-harmless output so bots keep executing
- **SOCKS5 proxy service (TCP/1080)** — fake SOCKS5 server (RFC 1928) for malware families that tunnel C2 through SOCKS5 (SystemBC, QakBot, Cobalt Strike, DarkComet, Emotet); logs the real destination host and port from every CONNECT request — the highest-value intelligence captured; after handshake behaves like the catch-all (TLS wrap if TLS ClientHello, HTTP 200 for HTTP, generic banner otherwise)
- **IRC/TLS service (TCP/6697)** — TLS-wrapped IRC sinkhole (`IRCSTLSService`); wraps accepted connections with existing certs before delegating to the full RFC 1459 handler; modern botnets using SSL IRC are now fully captured
- **GUI sidebar entries** — Telnet, SOCKS5, and IRC/TLS added to the NETWORK group with status dots and configurable pages
- **`max_connections` config key** — all manual-accept services (Telnet, SOCKS5, IRC, IRC/TLS) now respect a `max_connections` limit; CatchAllTCP enforces its limit via `_ReuseServer.process_request` override

### Fixed
- **Catch-all TLS fallthrough** — when certs are present but the TLS handshake fails (non-standard malware TLS stacks), the session now closes immediately instead of sending plaintext into a corrupted TLS stream
- **SOCKS5 TLS fallthrough** — same fix applied to `_snoop_tunnel`; partial-handshake failure now returns immediately
- **SMTP STARTTLS always returned 454** — now completes a real in-place TLS upgrade when certs are available; stealers (AgentTesla, FormBook) no longer bail before sending credentials
- **IMAP/POP3 STARTTLS/STLS missing** — CAPABILITY/CAPA now advertises STARTTLS/STLS; both commands perform a real socket upgrade
- **IRC silent crash** — `jl.log_event()` called in three places but `JsonEventLogger` only has `log()`; `AttributeError` was silently killing every IRC handler thread before the welcome burst was sent; fixed to `jl.log()`
- **Telnet IAC stripping** — `_recv_line` now correctly handles 2-byte IAC commands (NOP, BRK, GA) and 3-byte WILL/WONT/DO/DONT sequences; previously always consumed 2 bytes regardless, corrupting credentials containing embedded option bytes
- **`ServiceManager._services` dict race** — `start()` runs in a background thread while the GUI can call `status()` concurrently; added `threading.Lock`; `stop()` snapshots the dict before iterating and clearing to prevent `RuntimeError: dictionary changed size during iteration`
- **`excluded_ports` missing TFTP and NTP** — added 69 and 123; if `redirect_udp` is enabled, TFTP uploads and NTP responses no longer fall through to the UDP catch-all
- **Connection limit enforcement** — all services previously spawned unbounded threads per `accept()`; worm-phase malware could exhaust file descriptors and thread count; bounded semaphores now enforce limits

### Changed
- `config.json`: added `telnet`, `socks5`, `ircs` sections; `excluded_ports` sorted numerically
- `service_manager.py`: imports and starts Telnet, SOCKS5, IRC/TLS; iptables `port_map` includes ports 23, 1080, 6697

---

## [2026.03.06-12] — 2026-03-06

### Changed
- **↺ restore button** — moved from the info panel's fixed position to the bottom-right corner of the panel; activates with the currently focused field and restores only that field's default on click; section-level "Defaults" buttons removed

---

## [2026.03.06-11] — 2026-03-06

### Added
- **↺ Defaults button** — every service config section (General, DNS, HTTP, HTTPS, SMTP, FTP, etc.) now has a "↺ Defaults" button in the bottom-right corner of the form that resets all fields and checkboxes in that section to their suggested defaults in one click

### Changed
- DNS page: "Custom DNS Records…" button shares the defaults footer row (left side) rather than spanning the full width

---

## [2026.03.06-10] — 2026-03-06

### Fixed
- **Headless mode crash** — removed invalid `name=` keyword argument from `setup_logging()` call that caused a `TypeError` on startup with `--nogui`
- **Protected member access** — GUI now reads running service state via the public `ServiceManager.status()` API instead of `_services` directly
- **Logging performance** — converted f-string arguments in `service_manager.py` log calls to lazy `%`-style formatting
- **Spurious `list()` copy** — removed unnecessary `list()` wrap on `dict.items()` in `ServiceManager.stop()`
- **Pylance false positive** — added `# type: ignore[attr-defined]` to `os.geteuid()` call that is already guarded by `os.name != "nt"`

---

## [2026.03.06-2] — 2026-03-06

### Fixed
- **Log level filter pills** — clicking a pill now immediately hides/shows all existing lines in the live log, not just lines arriving after the click; clearing the filter restores all previously hidden lines

### Added
- **Scrollable sidebar** — sidebar service list is now wrapped in a scrollable canvas; mouse wheel scrollable on both Linux and Windows; SERVICES header remains pinned while items scroll

---

## [2026.03.06-1] — 2026-03-06

### Fixed
- **Silent log loss** — `setup_logging` and the GUI live-log queue handler now attach to the root logger instead of the named `"notthenet"` logger; module loggers (`services.*`, `service_manager`, `network.*`) propagate correctly so all service bind messages, connection events, and iptables output now appear in the live log and `logs/notthenet.log`
- **Sidebar service indicators** — per-service `●` dot added to the right of each sidebar row; turns green for running services after ▶ Start, resets to grey on ■ Stop

---

## [2026.03.05-1] — 2026-03-05

### Added
- **IRC server** (port 6667) — full RFC 1459 registration burst, CAP negotiation, channel JOIN with NAMREPLY/TOPIC, PRIVMSG/NOTICE JSON logging; captures botnet C2 traffic (`irc_server.py`)
- **TFTP server** (port 69) — RFC 1350 RRQ/WRQ; stub read response; WRQ uploads saved to `logs/tftp_uploads/` with UUID prefix and 10 MB cap; path traversal protection (`tftp_server.py`)
- **SMTPS** (port 465), **POP3S** (port 995), **IMAPS** (port 993) — implicit TLS variants of all three mail services using existing cert infrastructure
- **Offline / air-gap USB install tooling** — `make-bundle.ps1` generates a single self-contained `notthenet-bundle.sh` with Linux Python wheels embedded as base64; `install-offline.sh` and `prepare-usb.ps1` as lighter-weight alternatives

### Changed
- Lab defaults: `redirect_ip` and `dns.resolve_to` → `10.10.10.1`; `iptables_mode` → `gateway`; `json_logging` → `true`; `tcp_fingerprint` → `true`
- GUI sidebar groups updated to include SMTPS, POP3S, IMAPS, IRC, TFTP

### Fixed
- DNS AAAA queries now return empty NOERROR (correct fallback to A) instead of wrong record type
- SMTP AUTH state checked before command dispatch to prevent auth bypass
- IMAP missing EXAMINE and STATUS commands added
- HTTP HEAD requests no longer include a body in NCSI and IP-check response paths

---

## [2026.03.04-1] — 2026-03-04

### Added
- **Dynamic TLS certificate forging** — auto-generated Root CA + per-domain certs via SNI callback (`https.dynamic_certs`)
- **DNS-over-HTTPS sinkhole** — intercepts `application/dns-message` GET and POST requests (`http.doh_sinkhole`)
- **WebSocket sinkhole** — completes RFC 6455 handshake, drains frames, logs hex preview, clean close (`http.websocket_sinkhole`)
- **Dynamic response engine** — extension-based MIME types + minimal valid file stubs for 70+ extensions (`http.dynamic_responses`); custom regex rules supported
- **TCP/IP OS fingerprint spoofing** — TTL, TCP window, DF bit, MSS per-socket to mimic Windows/Linux/macOS/Solaris (`general.tcp_fingerprint`)
- **JSON structured event logging** — per-request JSONL output, pipeline-ready for CAPEv2/Splunk/ELK (`general.json_logging`)
- JSON Events viewer in the GUI sidebar with search and filtering
- Zoom controls (70%–200%) in the GUI toolbar
- New config fields: `doh_sinkhole`, `websocket_sinkhole`, `dynamic_responses`, `dynamic_response_rules`, `dynamic_certs`, `tcp_fingerprint`, `tcp_fingerprint_os`, `json_logging`, `json_log_file`

### Changed
- Comprehensive documentation rewrite (all 11 doc files updated for new features)

---

## [2026.02.24-2] — 2026-02-24

### Added
- **Public-IP spoof** for 20+ well-known IP-check services (`general.spoof_public_ip`)
- **Response delay** — configurable per-millisecond delay on HTTP/HTTPS to defeat timing detection (`http.response_delay_ms`, `https.response_delay_ms`)
- .deb package builder (`build-deb.sh`)
- `notthenet-uninstall` system command (available after install)
- Square globe icon SVG for desktop integration

### Fixed
- Restart `xfce4-panel` after icon cache rebuild to prevent gear icon fallback
- `chmod -R u+w` before `rm -rf` in update.sh to avoid permission denied on `.git` objects
- `update.sh` re-syncs icon, desktop entry, and polkit after pull

### Changed
- Privilege model documentation corrected (no setuid drop)
- Removed unused asset files (icon.png, logo.txt, notthenet-icon.png)

---

## [2026.02.24-1] — 2026-02-24

### Added
- Initial public release
- DNS server (UDP + TCP, all hostnames → redirect_ip, PTR/rDNS, per-host overrides)
- HTTP/HTTPS server (configurable response, TLS 1.2+ ECDHE+AEAD)
- SMTP server (email archival to `logs/emails/`, UUID filenames, disk cap)
- POP3 / IMAP minimal state machines
- FTP server (PASV only, PORT disabled, UUID filenames, size caps)
- TCP and UDP catch-all services
- iptables NAT manager with save/restore
- Dark GUI with grouped sidebar, live colour-coded log, level filters
- Desktop integration (app menu icon, pkexec/polkit)
- `config.json`-driven configuration with GUI editor
- Man page (`man/notthenet.1`)
- Full documentation suite (10 guides)
- Test suite (validators, logging_utils, config)
- Pre-deploy gate scripts (`predeploy.sh`, `predeploy.ps1`)

[Unreleased]: https://github.com/retr0verride/NotTheNet/compare/v2026.03.04-1...HEAD
[2026.03.04-1]: https://github.com/retr0verride/NotTheNet/compare/v2026.02.24-2...v2026.03.04-1
[2026.02.24-2]: https://github.com/retr0verride/NotTheNet/compare/v2026.02.24-1...v2026.02.24-2
[2026.02.24-1]: https://github.com/retr0verride/NotTheNet/releases/tag/v2026.02.24-1
