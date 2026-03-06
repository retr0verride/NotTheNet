# Changelog

All notable changes to NotTheNet are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/). Versioning uses [CalVer](https://calver.org/) (`YYYY.MM.DD-N`).

---

## [Unreleased]

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
