# Reliability & Troubleshooting Runbooks

NotTheNet is a **lab tool**, not a production service.  These runbooks cover
the most common failure modes encountered during malware detonation sessions.

---

## RB-1: DNS service failing to bind

**Symptom**: DNS service shows state `FAILED` on startup.

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

## RB-2: iptables rules not applied

**Symptom**: Services are running but traffic is not being intercepted.

1. Verify rules: `sudo iptables -t nat -L PREROUTING -n -v`
2. Check for conflicting rules: `sudo iptables -L -n -v`
3. Run with `--log-level DEBUG` to see iptables rule application.
4. On Kali: some kernel module combinations block the `udp match --dport`
   syntax; all NAT rules fall back to `iptables` CLI (not python-iptables).

## RB-3: Certificate generation failure

**Symptom**: HTTPS / DoT / DoH services fail; logs show cert errors.

1. Check `certs/` directory is writable: `ls -la certs/`
2. Verify `cryptography` library is installed: `pip show cryptography`
3. Check CA cert exists: `openssl x509 -in certs/ca.crt -noout -text`
4. Delete and regenerate: `rm -rf certs/mitm && restart notthenet`.

## RB-4: Health server not responding (headless mode)

1. Check if the process is alive: `ps aux | grep notthenet`
2. Verify the health port is bound: `ss -tlnp | grep 8080`
3. Check for port conflict: `sudo lsof -i :8080`
4. Review logs: `tail -f logs/notthenet.jsonl | python -m json.tool`
5. Restart: `sudo systemctl restart notthenet` or re-run the process.
