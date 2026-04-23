# Changelog

All notable changes to NotTheNet are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/). Versioning uses [CalVer](https://calver.org/) (`YYYY.MM.DD-N`).

---

## [Unreleased]

---

## [2026.04.22-2] — 2026-04-22

### Added
- **CI: `.deb` package built and attached to every GitHub Release** — new `build-deb` job (ubuntu-22.04, tags only) runs `bash build-deb.sh` and uploads the `.deb` as a release artifact; `build-deb.sh` now auto-detects the version from `gui/widgets.py` instead of a hardcoded string.
- **CI: offline bundle built and attached to every GitHub Release** — new `build-bundle` job (windows-latest, tags only) runs `.\make-bundle.ps1 -SkipChecks` and uploads `NotTheNet-<ver>.zip` as a release artifact.
- **Release job updated** — now waits on `build-deb` and `build-bundle` in addition to `build-dist`/`provenance`; downloads all three artifact sets and attaches them to the draft GitHub Release. All three install methods (`.deb`, offline zip, script) now have a downloadable artifact on every tagged release.

---

## [2026.04.22-1] — 2026-04-22

### Fixed
- **`build-deb.sh`: `.deb` written to repo root instead of `dist/`** — `dpkg-deb` output was `${SCRIPT_DIR}/${DEB_NAME}`; changed to `dist/${DEB_NAME}` with `mkdir -p dist` guard; usage comment updated accordingly. `installation.md` already documented `dist/notthenet_*.deb` as the expected path.
- **`requirements.txt`: `--require-hashes` mode broke installs on all platforms** — any package entry containing `--hash=sha256:` automatically enables pip's `--require-hashes` mode, which then requires every transitive dependency (including platform-compiled `cffi`, `pycparser`) to also carry hashes. Since `cffi` has dozens of platform-specific wheels per release it cannot be sanely pinned in a cross-platform file. All `--hash=sha256:` entries removed; version pins (`==`) retained. `setproctitle` is now an explicit entry (previously excluded because it couldn't be hash-pinned).
- **`Dockerfile`: `sed` hash-stripping workaround removed** — `Dockerfile` and both CI jobs stripped hash lines via `sed '/--hash=sha256:/d'` before running `pip install`; workaround no longer needed and removed.
- **`harden-lab.sh`: IPv6 traffic not blocked** — `ip6tables` rules were absent; added `ip6tables` FORWARD DROP rules on the isolated bridge (mirroring the existing `iptables` IPv4 rules) and added `ip6tables -L FORWARD` to the verify step.

### Added
- **`docs/lab-setup.md`: mouse/keyboard idle activity row** — §8.4 pre-detonation checklist now includes an AutoHotkey loop (`Loop { MouseMove, 1, 0, 0, R | Sleep 30000 }`) to keep the victim session alive and defeat idle-detection sandbox evasion.

---

## [2026.04.21-1] — 2026-04-21

### Added
- **GUI: Check for Updates button** — right-aligned toolbar button (`⟳ Updates`) queries the GitHub Releases API in a background daemon thread; compares `tag_name` against `APP_VERSION` and shows an informational dialog when already up to date, or offers to open the releases page via `webbrowser.open()` when a newer version is available; button disables itself while the network call is in flight; zero new dependencies (pure stdlib: `urllib.request`, `json`, `webbrowser`).
- **Resource-cleanup regression tests** (`tests/test_resource_cleanup.py`, 13 tests) — `TestDynamicCertCacheEviction`: LRU eviction bound, FIFO order, no `_dyn_*` temp files left on disk after `_build_ctx_for_hostname`, tracemalloc-bounded growth < 5 MB; `TestJsonEventLoggerCap`: byte-cap enforced on both file size and `_bytes_written` counter, `_cap_warned` flag set exactly once, tracemalloc-bounded < 2 MB, `close()` idempotent; `TestPerIpCounterCleanup`: `_per_ip` dict empty after all connections closed (serial + concurrent), per-IP limit rejects excess without accumulating counter entries.

### Changed
- **`predeploy.ps1` / `predeploy.sh` synced to CI** — both scripts pin all tool versions to match CI (`ruff==0.15.2`, `bandit[toml]==1.9.4`, `pip-audit==2.10.0`, `mypy==1.19.1`, `openapi-spec-validator==0.8.4`, `pytest==9.0.3`, `pytest-cov==7.1.0`, `pytest-timeout==2.4.0`); add mypy `--strict` step for `domain/` `application/` `infrastructure/`; add `openapi-spec-validator openapi.yaml` step; add `--timeout=60 --cov --cov-fail-under=35` to pytest; add stale `_dyn_*` cert-file check; `predeploy.sh` additionally adds `pip-audit`, version-consistency check, and CHANGELOG check (previously absent); step count 7 → 9 on both scripts.
- **`pyproject.toml`: Python 3.9 removed** from classifiers — EOL October 2025; now reflects CI matrix (3.10, 3.11, 3.12).

---

## [2026.04.19-2] — 2026-04-19

### Fixed
- **CI: bandit SARIF format** — `bandit-sarif-formatter` package was not installed in the lint job; `--format sarif` raised `invalid choice: 'sarif'`; added to CI pip install
- **CI: coverage gate unreachable** — `--cov-fail-under=80` with `--cov=.` measured GUI, infrastructure, and domain layers (all 0%); added `[tool.coverage.run]` source/omit in `pyproject.toml` to scope measurement to tested packages (`config`, `service_manager`, `services`, `network`, `utils`); gate set to 35% (actual: 42%)
- **CI: GHCR login** — Docker build used `GHCR_TOKEN` secret (not set); switched to `GITHUB_TOKEN` which has `packages:write` via job permissions
- **Dockerfile: pip hash-mode error** — `requirements.txt` contains `--hash=sha256:` lines which trigger pip's `--require-hashes` mode, failing on unhashed transitive deps (`cffi`, `pycparser`); Dockerfile now strips hash lines before install (same approach used in CI lint/test steps)

### Changed
- **CI: Python 3.9 removed from matrix** — EOL October 2025; matrix now covers 3.10, 3.11, 3.12

---

## [2026.04.19-1] — 2026-04-19

### Added
- **Memory leak detection** — `tests/conftest.py` implements a cross-platform `limit_memory` marker backed by `stdlib tracemalloc` (Windows dev) and `pytest-memray` (Linux/CI); `TestHTTPIntegration` (20 MB), `TestIRCPingTimeout` (10 MB), and `TestPeriodicFlush` (10 MB) are gated; `pytest-memray>=1.5` added to `requirements-dev.txt` with `sys_platform != "win32"` guard

### Changed
- **`ship.ps1` fixed** — version source switched from `notthenet.py` (now imports `APP_VERSION`) to `gui/widgets.py` (source of truth); bundle step updated to use `make-bundle.ps1 -SkipChecks` (correct switch)
- **`predeploy.ps1` step 8 removed** — memory gate was redundant; `limit_memory` markers enforced inline in step 5 on both Windows (`tracemalloc`) and Linux (`pytest-memray`)
- **README**: updated offline bundle command to `make-bundle.ps1 -SkipChecks`

### Fixed
- **HTTP: hardcoded fallback spoof IP replaced** — `services/http_server.py` and `tests/test_http_server.py` used a real public IP (`98.245.112.43`) as the default spoof-IP fallback; replaced with `203.0.113.1` (RFC 5737 TEST-NET-3, reserved for documentation and examples)

---

## [2026.04.08-2] — 2026-04-19

### Added
- **HTTP: File-hosting payload-staging handler** — new `_FILE_HOSTING_HOSTS` frozenset and `_route_file_hosting` handler covers `catbox.moe`, `files.catbox.moe`, `litterbox.catbox.moe`, `anonfiles.com`, `gofile.io`, `transfer.sh`, `file.io`, and `tmpfiles.org`; returns HTTP 200 `application/octet-stream` with a minimal stub body so Agent Tesla's pre-detonation connectivity check passes and the fetch is logged as `file_hosting_fetch` in the JSON event log.

### Fixed
- **DNS: `nxdomain_entropy_threshold` too high to catch short canary domains** — default config was `4.0`; canonical 8-9 character DGA canary domains (e.g. `asdfg123.com`, Shannon entropy ≈ 3.0) resolved instead of returning NXDOMAIN, allowing LockBit-style "fake network" detection to succeed; lowered to `3.2` (matches the value documented in CHANGELOG since the `3.8→3.2` tuning commit).
- **predeploy: pip-audit hash mismatch on Windows** — `requirements.txt` contains Linux-only wheel hashes (deployment target is Kali); pip-audit's temp-venv strategy resolved the Windows `win_amd64` wheel whose hash is absent, failing the check; step 4 now audits the active venv directly (`pip_audit --skip-editable`) instead of re-installing from requirements.txt.

---

## [2026.04.15-1] — 2026-04-15

### Fixed
- **CI: ruff clean (55 → 0 violations)** — auto-fixed `UP045`/`UP037`/`UP035`/`I001`/`F401` across `domain/`, `application/`, `infrastructure/`; wrapped long lines in `gui/dialogs.py`, `infrastructure/health/server.py`, `infrastructure/adapters/service_repo_adapter.py`, `network/iptables_manager.py`, and `service_manager.py`; added `E501` exemptions for service, tool, preflight, and test-fidelity files whose long lines are protocol-data byte strings or diagnostic messages; fixed `F821` (missing `os` import removed by unsafe-fix in `utils/victim_remote.py`); added `# noqa: E402` on re-export stubs in `circuit_breaker.py` and `retry.py`; added `# noqa: S311` on non-cryptographic jitter in `retry.py`.
- **CI: mypy strict clean (70 → 0 errors)** — typed all constructor parameters in `EnvConfigStore`, `ServiceRepoAdapter`, and `Container` via `TYPE_CHECKING` imports; added `dict[str, Any]` type parameters where missing; annotated all `_NoOp*` stub methods in `otel.py` with full signatures; fixed `Callable` missing type params in `health/server.py`; replaced stale `# type: ignore[override]` in `logging/setup.py` (override is now compatible); added targeted `# type: ignore[misc,untyped-decorator]` on Pydantic validators in `settings.py`; broadened `pyproject.toml` `ignore_errors` override to cover all legacy modules (`config`, `service_manager`, `services.*`, `network.*`, `utils.*`, `gui.*`, `tools.*`, `tests.*`) so transitive imports from un-annotated code no longer pollute the strict-checked layers.
- **`JsonEventLogger.flush()` missing** — `infrastructure/event_sink.py` called `jl.flush()` but `JsonEventLogger` had no `flush()` method; added `flush()` that acquires the write lock, calls `file.flush()`, and updates `_last_flush`.

---

## [2026.04.07-3] — 2026-04-07

### Added
- **Preflight readiness mode (`--preflight`)** — new CLI path that runs local readiness checks and exits with status codes (`0` pass, `1` warnings, `2` failures). Covers stealth config, cert presence/parse, interface/bind readiness, port conflicts, and hardening checks.
- **GUI Preflight page** — added a dedicated sidebar page for local and remote readiness checks with one-click fix actions.
- **Victim config section** — new `victim` settings (`username`, `ip`, `auto_detect_ip`, `subnet_mask`) used for preflight remote checks.

### Changed
- **Remote preflight transport moved from SSH to WMI/SMB** — remote checks/fixes now use Impacket WMI execution and SMB file upload, removing the need to install OpenSSH on the victim.
- **Password persistence tightened** — victim passwords are no longer written to `config.json`; they are kept in-session only.

### Fixed
- **Remote helper robustness** — added IP validation, stricter SMB remote path validation, improved Impacket banner filtering, case-insensitive CA cert detection, and clearer missing-tool/runtime messages.
- **Preflight socket probing cleanup** — port conflict probes now close sockets reliably even on bind failure.
- **Build/lint pipeline alignment** — resolved predeploy lint regressions and a Bandit false positive in Discord snowflake generation.

---

## [2026.03.30-3] — 2026-03-30

### Added
- **Session-labeled JSON event logs** — each Start now creates a new log file named `logs/events_YYYY-MM-DD_sN.jsonl` (N increments per session per day) instead of overwriting `logs/events.jsonl`. `ServiceManager._session_log_path()` scans for existing files and returns the next available path; the resolved path is written back to the in-memory config so the GUI `_JsonEventsPage` picks it up automatically. `_poll_file()` detects when the path changes between sessions and resets its file position to zero.

### Fixed
- **Privilege drop: permission denied on JSONL export** — after dropping to `nobody:nogroup`, all relative paths were broken because `drop_privileges()` called `os.chdir("/")`. The `chdir` call has been removed; instead, `ServiceManager._prepare_dirs_for_drop()` is called before the drop: it `chown`s `logs/`, `logs/emails/`, `logs/ftp_uploads/`, and `logs/tftp_uploads/` to the target uid/gid, and adds `o+x` on every parent directory up to `/` so the low-privilege process can still traverse the path. The GUI export dialog now opens directly in the log directory (`os.path.dirname(os.path.abspath(json_log_file))`) rather than `os.getcwd()`.

---

## [2026.03.29-6] — 2026-03-29

### Added
- **Security: privilege drop after port binding** — `ServiceManager.start()` now calls `drop_privileges()` (defined but previously unused in `utils/privilege.py`) immediately after all ports are bound and iptables rules are applied. Root is held only for the privileged operations; the process then drops to `nobody:nogroup` (configurable via `general.drop_privileges_user` / `general.drop_privileges_group`). Controlled by new `general.drop_privileges` config key (default: `true`).
- **Security: process masquerade via setproctitle** — after startup the process title is renamed to a kernel-thread-looking string (default `[kworker/u2:1-events]`) so it does not appear as `python3 notthenet.py` in process monitors on the analysis host. Controlled by `general.process_masquerade` and `general.process_name`. Requires the `setproctitle` package (now bundled in the offline installer).
- **Security: lab hardening script (`harden-lab.sh`)** — new standalone bash script that stops all conflicting system services (including `systemd-resolved` DNSStubListener), applies iptables `FORWARD DROP` rules to block bridge ↔ management interface pivoting, and mounts `logs/` as `tmpfs` with `noexec,nosuid,nodev` flags to prevent accidental execution of captured malware artifacts. Idempotent — safe to re-run.
- **Security: systemd unit (`assets/notthenet.service`)** — production-ready unit file with `ExecStartPre` steps mirroring `harden-lab.sh` (service eviction + tmpfs mount), `ProtectHome`, `ProtectSystem=strict`, `ReadWritePaths`, `PrivateTmp`, and a `CapabilityBoundingSet` scoped to only the capabilities NotTheNet needs.
- **Docs: safe detonation guide (`docs/safe-detonation.md`)** — new guide covering Proxmox RAM-inclusive snapshots, network isolation verification, KVM cloaking (`kvm=off`, `hv_vendor_id`, SMBIOS spoofing via QEMU args), post-session artifact handling, and a quick-reference detonation flow card.
- **make-bundle: bundle `setproctitle` wheel** — the offline bundle now downloads and embeds a `setproctitle` Linux wheel alongside `dnslib`, `cryptography`, and `cffi` so the process masquerade feature works on air-gapped Kali hosts.

### Changed
- **config.json: secure defaults** — `general.bind_ip` changed from `0.0.0.0` to `10.10.10.1` (isolated gateway IP); `general.interface` changed from `eth0` to `vmbr1` (Proxmox isolated bridge); HTTP/HTTPS `response_delay_ms` increased from `50` to `120` and `response_delay_jitter_ms` from `30` to `80` to produce realistic WAN-like latency (40–200 ms range) and better defeat timing-based sandbox fingerprinting.

---

## [2026.03.29-2] — 2026-03-29

### Added
- **Service eviction: auto-stop conflicting system services on startup** — NotTheNet now calls `systemctl stop` on any system service that would prevent it from binding its ports before attempting to start. Covered services: `apache2`, `nginx`, `lighttpd` (ports 80/443), `bind9`, `dnsmasq`, `systemd-resolved` (port 53), `exim4`, `postfix` (port 25), `smbd`, `nmbd` (port 445), `mariadb`, `mysql` (port 3306). Controlled by new `auto_evict_services` config key (default: `true`). Silently skipped on non-systemd hosts.

### Fixed
- **make-bundle: cryptography download failed on Python 3.14 hosts** — `pip download cryptography` without `--no-deps` attempted to resolve `cffi` against the host Python version; on Python 3.14 only `cffi 2.0.0b1` is available but pip rejected it; added `--no-deps` to the cryptography download since cffi is already handled separately in the next step.

---

## [2026.03.19-19] — 2026-03-19

### Fixed
- **GUI: High CPU under load from Treeview churn** — `_JsonEventsPage._poll_file()` rebuilt the JSON events Treeview by deleting items one at a time in a Python loop (O(n) widget operations per poll cycle); replaced with a single bulk `tree.delete(*stale_ids)` call; locally tracked `_tree_count` eliminates two redundant `get_children()` O(n) scans per poll; max displayed rows reduced from 5,000 to 2,000; poll interval relaxed from 1,000 ms to 2,000 ms; `_apply_filter()` and `_clear_view()` updated to the same bulk-delete pattern
- **GUI: High CPU from log queue over-polling** — `_poll_log_queue()` fired unconditionally every 100 ms regardless of queue depth, invoking Tkinter widget open/close on every tick under flood-level traffic; replaced with adaptive timing: 250 ms when messages are flowing, 500 ms when idle; batch size increased from 75 to 200 messages per drain, reducing the number of widget layout cycles by 4×

---

## [Unreleased] (carry-forward)

### Added

- **DoT: DNS-over-TLS service (RFC 7858, port 853)** — new `services/dot_server.py`; shares `_FakeResolver` with the plain DNS server so DGA entropy detection, FCrDNS, NCSI overrides, public IP pool, and custom record overrides all apply identically over TLS; each DNS message is length-prefixed per RFC 1035 §4.2.2; TLS 1.2 minimum with ALPN `"dot"` as required by RFC 7858; bounded to `ThreadPoolExecutor(50)` workers; reuses the HTTPS cert/key pair; adds iptables port 853 to `excluded_ports` so the catch-all does not shadow it
- **HTTPS: ALPN advertisement and HTTP/2 preface handling** — HTTPS SSL context now advertises `h2` and `http/1.1` via `set_alpn_protocols`; HTTP/2 clients that negotiate `h2` immediately receive a SETTINGS frame followed by GOAWAY(HTTP_1_1_REQUIRED) per RFC 7540 §3.5, satisfying stacks that require a graceful downgrade rather than an abrupt close
- **Certificates: Signed Certificate Timestamp (SCT) extension** — all dynamically forged certs and the static server cert now include a fake `SignedCertificateTimestampList` (OID 1.3.6.1.4.1.11129.2.4.2, RFC 6962 v1); CT-aware malware and tooling that inspects extension presence will see a valid, parseable SCT structure

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
- **DoT: unbounded thread creation** — the original implementation spawned a new `threading.Thread` per connection with no cap; replaced with `ThreadPoolExecutor(max_workers=50)` so the server degrades gracefully under load instead of exhausting OS thread limits
- **DoT: accept loop swallowed `OSError`** — `ssl.SSLContext.wrap_socket()` can raise `OSError` (e.g. `ECONNRESET` during handshake) as well as `ssl.SSLError`; the accept loop now catches `(ssl.SSLError, OSError)` so a failed handshake no longer kills the loop
- **DoT: clean stop race** — `stop()` tore down the thread pool while the accept thread could still be blocking on `accept()`; fixed by calling `socket.shutdown(SHUT_RDWR)` before `close()` to force the accept to unblock, joining the thread with a 2 s timeout, using `cancel_futures=True` on pool shutdown, and setting the pool to `None` before shutdown to guard any concurrent `pool.submit()` calls
- **TLS cert cache: temp files retained after load** — `DynamicCertCache` wrote cert/key to temporary files for `load_cert_chain()` and never deleted them, leaving private key material on disk; both files are now removed immediately after `load_cert_chain()` returns via `try/finally`
- **HTTP: no socket timeout on accepted connections** — `_ThreadedServer` dispatched to the HTTP handler with no socket-level timeout; a stalled client holding a half-open TCP connection would retain a thread pool slot indefinitely; a 30 s `settimeout()` is now applied to every accepted socket before handler dispatch
- **HTTP: unconstrained method dispatch** — `BaseHTTPRequestHandler` dispatches via `getattr(self, "do_" + method)` where `method` comes directly from the request line; an unexpected method string could reach unintended attributes; a strict `_ALLOWED_METHODS` allowlist is now checked first and returns 405 for anything outside the standard set
- **HTTP: `ip-api.com` handler skipped when `spoof_public_ip` not configured** — `_IP_CHECK_HOSTS` interception was gated on `if self._spoof_ip`, so when `spoof_public_ip` was absent from `config.json` the handler was never entered; AgentTesla and similar malware received the NotTheNet HTML page instead of the expected JSON with `"hosting":false`, causing them to detect a sandbox environment and halt C2 activation; the guard is removed — the handler fires unconditionally, and `spoof_public_ip` is now treated as optional (defaults to a plausible residential IP when absent)
- **GUI: window close freezes Tkinter when services are running** — `_on_close` (the `WM_DELETE_WINDOW` handler) called `self._manager.stop()` directly on the Tkinter main thread; `service_manager.stop()` calls `socketserver.BaseServer.shutdown()` for each running service, each of which blocks for up to 0.5 s — with ~20 services active the window would hard-freeze for up to 10 s and appear crashed; `_on_close` now backgrounds the stop in a daemon thread and calls `root.destroy()` via `after(0, …)` once complete; `service_manager.stop()` also parallelises service shutdown via `ThreadPoolExecutor`, reducing worst-case wall time from ~10 s to ~0.5 s
- **GUI log view: auto-scroll disrupts manual scrolling** — `_append_log()` called `see('end')` unconditionally, snapping the log back to the bottom on every new line even while the user was reading history; `see('end')` is now gated on `yview()[1] >= 0.99` so auto-scroll only fires when the view is already at (or within 1% of) the bottom
- **Config.save(): non-atomic write risked JSON corruption** — `Config.save()` wrote directly to the config file with `open(path, 'w')`; a concurrent save or crash mid-write could produce a truncated or partially-merged JSON file; writes are now serialised by a per-instance `threading.Lock` and committed via a `.tmp` file + `os.replace()` for atomic promotion
- **Desktop launcher: hard-coded path and username** — `notthenet-gui-launcher` hard-coded `/home/kali` in the `pkexec` self-call; installs to other directories or non-`kali` usernames would silently fail; the script now uses `readlink -f "$0"` to resolve its own path; when no polkit agent is available (`pkexec` exits 126) it falls back to `xterm -e sudo` so the GUI still launches
- **Installer: config.json and logs/ owned by root after install** — running `sudo bash notthenet-bundle.sh` creates `config.json` and `logs/` owned by `root:root`; the regular-user GUI cannot write the config; the installer now resolves the real user from `$SUDO_USER` / `logname`, validates with `id`, and `chown`s both paths back — works for any username, not just `kali`
- **Desktop icon: DISPLAY/XAUTHORITY not forwarded via pkexec** — moving pkexec into the `.desktop Exec=` line and making the launcher a thin root wrapper means polkit's `exec.path` matches the launcher directly, so `DISPLAY` and `XAUTHORITY` are forwarded automatically without environment hacks; polkit policy `exec.path` updated to `/usr/local/bin/notthenet-gui`
- **CRLF line endings in launcher assets** — `notthenet-gui-launcher`, `notthenet.desktop`, and `com.retr0verride.notthenet.policy` were committed with CRLF line endings; `bash` on Kali treated the trailing `\r` as part of variable values and command names, breaking the launcher; all three files converted to LF-only; `tr -d '\r'` safety net added to the installer for future protection

---

## [2026.03.18-1] — 2026-03-18

### Added
- **GUI: Live log LIVE/PAUSED scroll indicator** — log panel header now shows a `⬇ LIVE` badge that switches to `⏸ PAUSED` (orange) when the user scrolls up to review history; clicking the badge or scrolling back to the bottom resumes auto-scroll; events continue flowing regardless of scroll position

### Fixed
- **GUI: Process remains after window close** — closing the window after stopping services left the Python process and the `notthenet-gui` bash launcher alive; `_on_close` now calls `os._exit(0)` via a new `_quit_process()` helper, guaranteeing the entire process exits immediately on window close

---

## [2026.03.17-1] — 2026-03-17

### Added
- **GUI: Elapsed running timer** — status bar shows elapsed time in `Xm YYs` / `Xh YYm ZZs` format (via `time.monotonic()`) while services are running; updated every second via `after()` and cleanly cancelled on stop
- **GUI: JSON events auto-export on cap** — when in-memory row history reaches 20,000 rows the trimmed overflow is written to `logs/events_autoexport_<ts>.jsonl` in a background daemon thread so the Tkinter main thread is never blocked; count label shows `+N auto-exported`; export file is created on first overflow and appended on subsequent rollovers; resets on Clear View
- **GUI: Open Logs folder button** — log panel header now has a "📁 Open Logs" button that opens the configured `log_dir` in the system file manager (`xdg-open`), creating the directory if it does not yet exist
- **GUI: Timestamped Export default filename** — Export dialog defaults to `events_export_<YYYYMMDD_HHMMSS>.jsonl` to prevent accidentally overwriting the live `events.jsonl`

### Fixed
- **GUI: Kali-only platform cleanup** — removed all `sys.platform == "win32"` / `"darwin"` branches from `_open_file_external()` and `_open_log_folder()`; both methods now unconditionally call `subprocess.Popen(["xdg-open", …])` — the correct launcher on all supported platforms (Kali Linux, Debian, Ubuntu); `subprocess` promoted to top-level import and local inline imports removed
- **GUI: `logger` undefined in auto-export inner function** — ruff F821: `_write()` closure used module-level `logger` which is unreachable at that scope; fixed by capturing `_log = logger` before the inner function definition and using `_log` throughout
- **GUI: `logger` not defined at module level** — `notthenet.py` was missing `logger = logging.getLogger(__name__)` at module scope; added after service_manager import
- **ICMP: iptables DROP rule not inserted at chain head** — the ICMP DROP rule was appended (`-A`) instead of inserted at position 1 (`-I 1`), so any preceding ACCEPT rules could match first; rule now uses `-I 1` to guarantee it fires before other rules in the chain

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
- **HTTP/HTTPS/SMTP/SMTPS/POP3/POP3S/IMAP/IMAPS/FTP/Catch-all: `server.shutdown()` blocked Stop for up to 30 s** — `socketserver.BaseServer.shutdown()` blocks until the serve thread exits; the serve thread is blocked in `accept()`, which will not unblock until a connection arrives or the socket is closed; without closing the socket first, pressing Stop while any client was connected caused a 30 s UI freeze; all ten service classes now call `socket.shutdown(SHUT_RDWR)` on the listening socket before `server.shutdown()`, forcing `accept()` to raise `OSError` immediately so `shutdown()` returns in microseconds

### Changed
- **`ship.ps1`: version auto-bumped on every run** — running `.\ship.ps1` no longer requires a manual version bump; the script reads the current version from `pyproject.toml`, increments the build counter if the date matches today (`YYYY.MM.DD-N` → `YYYY.MM.DD-(N+1)`), or resets to `YYYY.MM.DD-1` on a new date; both `pyproject.toml` and `notthenet.py` (`APP_VERSION`) are patched atomically before predeploy runs

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

[Unreleased]: https://github.com/retr0verride/NotTheNet/compare/v2026.04.22-2...HEAD
[2026.04.22-2]: https://github.com/retr0verride/NotTheNet/compare/v2026.04.22-1...v2026.04.22-2
[2026.04.22-1]: https://github.com/retr0verride/NotTheNet/compare/v2026.04.21-1...v2026.04.22-1
[2026.04.21-1]: https://github.com/retr0verride/NotTheNet/compare/v2026.03.04-1...v2026.04.21-1
[2026.03.04-1]: https://github.com/retr0verride/NotTheNet/compare/v2026.02.24-2...v2026.03.04-1
[2026.02.24-2]: https://github.com/retr0verride/NotTheNet/compare/v2026.02.24-1...v2026.02.24-2
[2026.02.24-1]: https://github.com/retr0verride/NotTheNet/releases/tag/v2026.02.24-1
