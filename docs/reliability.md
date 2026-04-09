# Reliability: SLIs, SLOs, and Runbooks

NotTheNet is a **lab tool**, not a production service.  The SLOs below apply
to an *active detonation session* (the window during which malware is executing
and NotTheNet is capturing its network behaviour).  Outside an active session
the tool may be stopped and restarted freely.

---

## Service Level Indicators (SLIs)

| ID | What we measure | How we measure it |
|----|-----------------|-------------------|
| SLI-1 | **Availability** — fraction of time the health `/health/live` probe returns HTTP 200 | Health server uptime ÷ session window |
| SLI-2 | **DNS response latency (p99)** — time from query receipt to response | Measured per-query in `services/dns_server.py` |
| SLI-3 | **HTTP response latency (p99)** — time from TCP accept to response sent | Measured in `services/http_server.py` |
| SLI-4 | **Error rate** — fraction of service threads in FAILED state | `services_failed / services_total` from `/metrics` |
| SLI-5 | **Service start success rate** — `start()` calls that succeed | `ServiceOrchestrator.start()` return value |

---

## Service Level Objectives (SLOs)

| ID | SLI | Target | Error budget (per session) |
|----|-----|--------|---------------------------|
| SLO-1 | SLI-1 | ≥ 99.9 % availability during session | < 0.1 % downtime |
| SLO-2 | SLI-2 | DNS p99 < 50 ms | ≤ 1 % of queries may exceed 50 ms |
| SLO-3 | SLI-3 | HTTP p99 < 200 ms | ≤ 1 % of requests may exceed 200 ms |
| SLO-4 | SLI-4 | Error rate < 5 % | At most 5 % of registered services may be FAILED |
| SLO-5 | SLI-5 | ≥ 95 % of services start successfully | Up to 5 % of services may fail on a given start (e.g. port already bound) |

---

## Alerting Thresholds

These thresholds should be wired into your monitoring stack (Prometheus
alert rules if using the `observability` docker-compose profile).

| Alert | Condition | Severity |
|-------|-----------|----------|
| `NTNHealthDown` | `/health/live` returns non-200 for > 30 s | CRITICAL |
| `NTNReadinessLost` | `/health/ready` returns 503 for > 60 s | HIGH |
| `NTNDNSLatencyHigh` | DNS p99 > 100 ms over 5 min | MEDIUM |
| `NTNHTTPLatencyHigh` | HTTP p99 > 500 ms over 5 min | MEDIUM |
| `NTNServicesFailedHigh` | `notthenet_services_failed / notthenet_services_total > 0.1` | HIGH |

Prometheus rule file location (created by the `observability` profile):
`docs/prometheus.yml`

---

## Circuit Breaker Thresholds

The `CircuitBreaker` in `infrastructure/resilience/circuit_breaker.py` uses
the following defaults.  Tune via environment variables if needed.

| Parameter | Default | Env var |
|-----------|---------|---------|
| Failure threshold | 5 consecutive failures | `NTN_CIRCUIT_FAILURE_THRESHOLD` |
| Reset timeout | 30 s | `NTN_CIRCUIT_RESET_TIMEOUT` |
| Success threshold (half-open) | 2 consecutive successes | — |

---

## Runbooks

### RB-1: Health server not responding
1. Check if the process is alive: `ps aux | grep notthenet`
2. Verify the health port is bound: `ss -tlnp | grep 8080`
3. Check for port conflict: `sudo lsof -i :8080`
4. Review logs: `tail -f logs/notthenet.jsonl | python -m json.tool`
5. Restart: `sudo systemctl restart notthenet` or re-run the process.

### RB-2: DNS service failing to bind
**Symptom**: SLO-5 breached; DNS service shows state `FAILED`.

1. Check if another resolver is on port 53:
   ```bash
   sudo ss -ulnp | grep :53
   sudo systemctl status systemd-resolved
   ```
2. Disable systemd-resolved if it conflicts:
   ```bash
   sudo systemctl stop systemd-resolved
   sudo systemctl disable systemd-resolved
   ```
3. Restart notthenet.

### RB-3: iptables rules not applied
**Symptom**: Services are running but traffic is not being intercepted.

1. Verify rules: `sudo iptables -t nat -L PREROUTING -n -v`
2. Check for conflicting rules: `sudo iptables -L -n -v`
3. Run with `--log-level DEBUG` to see iptables rule application.
4. On Kali: some kernel module combinations block the `udp match --dport`
   syntax; all NAT rules fall back to `iptables` CLI (not python-iptables).

### RB-4: Certificate generation failure
**Symptom**: HTTPS / DoT / DoH services fail; logs show `CertGenerationError`.

1. Check `certs/` directory is writable: `ls -la certs/`
2. Verify `cryptography` library is installed: `pip show cryptography`
3. Check CA cert exists: `openssl x509 -in certs/ca.crt -noout -text`
4. Delete and regenerate: `rm -rf certs/mitm && restart notthenet`.

### RB-5: Circuit breaker open and stuck
**Symptom**: `CircuitOpenError` logged repeatedly; service appears dead.

1. Identify the stuck breaker in logs: `grep "OPEN" logs/notthenet.jsonl`
2. The circuit auto-probes after `reset_timeout` (default 30 s).
3. If the underlying cause is fixed (e.g. port conflict resolved), the next
   probe should close the circuit.
4. If not self-healing, restart the affected service: use the `restart_service`
   API call or restart the whole process.

---

## Prometheus Scrape Config (`docs/prometheus.yml`)

Create this file to use with the `observability` docker-compose profile:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: notthenet
    static_configs:
      - targets: ["notthenet:8080"]
    metrics_path: /metrics
```
