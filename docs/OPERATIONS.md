# Tachyon Operations Runbook

Audience: on-call SRE.  Goal: get a Tachyon tunnel back to healthy in
under 15 minutes without paging the protocol team.

This runbook assumes you have shell access on the host running the
control plane and that the tunnel was deployed via the bundled
`systemd` unit (`systemd/tachyon@.service`) or the Helm chart
(`deploy/helm/tachyon`).

---

## 1. Service Lifecycle

The control plane runs as a `Type=notify` systemd unit, one instance
per tunnel (template `tachyon@<name>.service`).  The instance name
matches the config file: `/etc/tachyon/<name>.conf`.

### Start, stop, restart

```bash
# Start tunnel "wg0" (reads /etc/tachyon/wg0.conf)
sudo systemctl start  tachyon@wg0.service

# Stop and tear down BPF maps/veth
sudo systemctl stop   tachyon@wg0.service

# Restart (drains existing flows, see ShutdownDrainSeconds)
sudo systemctl restart tachyon@wg0.service

# Enable on boot
sudo systemctl enable tachyon@wg0.service
```

### Verifying status

```bash
# Unit status incl. last-N journal lines
systemctl status tachyon@wg0.service

# Live data-plane counters (BPF map dump + handshake state)
sudo tachyon show /etc/tachyon/wg0.conf
```

A healthy unit reports `Active: active (running)` and the
`WatchdogSec=30` timer is being kicked (no `Watchdog timeout!` lines
in the journal).

### Where logs go

| Stream | Destination |
|---|---|
| stdout / stderr | `journalctl -u tachyon@wg0.service` |
| Structured JSON | same journal stream when `LogFormat=json` |
| Audit events | `/var/log/tachyon-audit.log` (if `AuditLog=` set) and `LOG_AUTH` syslog facility |
| Kernel-side BPF | `dmesg` / `/sys/kernel/debug/tracing/trace_pipe` |

```bash
# Tail JSON logs and pretty-print
journalctl -u tachyon@wg0 -f -o cat | jq .
```

---

## 2. Configuration

Tachyon uses an INI-style file.  See `tun.conf.example` for the
authoritative annotated copy.  Keys are case-sensitive; the parser
rejects unknown keys to catch typos early.

### Key files

| Path | Purpose |
|---|---|
| `/etc/tachyon/<name>.conf` | Per-tunnel config |
| `/etc/tachyon/<name>.key` | X25519 private key (mode 0600, root-only) |
| `/var/log/tachyon-audit.log` | Audit log (if configured) |
| `/sys/fs/bpf/tachyon/<name>/` | Pinned BPF maps (cleared on `down`) |

### Environment variable overrides

The following env vars override the matching INI key.  Set them in a
`drop-in` (`systemctl edit tachyon@wg0`) so they survive package
upgrades:

| Variable | INI key |
|---|---|
| `TACHYON_LOG_FORMAT` | `LogFormat` |
| `TACHYON_LOG_LEVEL`  | `LogLevel` |
| `TACHYON_AUDIT_LOG`  | `AuditLog` |
| `TACHYON_PRIVATE_KEY` | `PrivateKey` (also accepts `file:///path`) |
| `TACHYON_PRESHARED_KEY` | `PresharedKey` |

Keys may be supplied as `file:///etc/tachyon/wg0.key`; the file is
read once at startup, then the buffer is `mlock()`ed and zeroed on
exit (see `loader/secmem.cpp`).

### Hot reload (SIGHUP)

```bash
sudo systemctl reload tachyon@wg0.service
# or
sudo kill -HUP $(systemctl show -p MainPID --value tachyon@wg0)
```

`SIGHUP` re-reads the config and applies changes that are safe to
swap online: log level, rate-limit thresholds, cover-traffic rate,
peer endpoint IP/MAC, audit log path.  Changes that require a full
restart (cipher suite, listen port, virtual IP) are logged with
`reload: ignored, restart required` and are NOT silently dropped.

---

## 3. Health Monitoring

Three HTTP endpoints are exposed on `MetricsPort` (default `9090`,
bound to `127.0.0.1` only).

| Endpoint | Returns | Use |
|---|---|---|
| `/health` | `200 OK` if process is alive and watchdog-fed | Liveness probe |
| `/ready`  | `200 OK` only after first successful handshake | Readiness probe |
| `/metrics`| Prometheus text exposition | Scrape target |

### Examples

```bash
# Liveness — must return 200 within 1s
curl -fsS http://127.0.0.1:9090/health
# {"status":"ok","uptime_seconds":1234}

# Readiness — returns 503 until handshake completes
curl -i http://127.0.0.1:9090/ready

# Scrape metrics
curl -s http://127.0.0.1:9090/metrics | grep tachyon_
```

### Key metrics

| Metric | Meaning | Alert if |
|---|---|---|
| `tachyon_handshake_completed_total` | Successful AKE | flat for >5 min on busy link |
| `tachyon_handshake_failed_total`    | Failed AKE     | rate > 0.1/s |
| `tachyon_rx_replay_drops_total`     | Replay-window rejects | any increase |
| `tachyon_rx_crypto_errors_total`    | AEAD failures  | rate > 0.01/s |
| `tachyon_rx_ratelimit_drops_total`  | DDoS drops     | sustained > 1/s |
| `tachyon_tx_bytes_total`, `_rx_bytes_total` | Throughput | unexpected zero |
| `tachyon_last_handshake_timestamp`  | Unix seconds | older than 10 min |

A complete dashboard is provided in
`docs/grafana/tachyon-dashboard.json` and matching alert rules in
`deploy/prometheus/alerts.yaml`.

---

## 4. Key Rotation

### Automatic ratchet (every 5 minutes)

The control plane derives a new traffic key every `300 s` using
HKDF-SHA256 with the current chain key as salt.  Rotation is
RCU-protected in the kernel module: the new key becomes active
atomically with no in-flight packet loss.  No operator action is
required.

You can confirm by watching `tachyon_key_rotations_total` — it
should increment roughly every 5 minutes per active tunnel.

### Explicit (forced) rotation

Trigger an immediate rekey, e.g. before maintenance windows:

```bash
sudo tachyon rotate /etc/tachyon/wg0.conf
# or
sudo kill -USR1 $(systemctl show -p MainPID --value tachyon@wg0)
```

Verify the rotation counter advanced:

```bash
curl -s http://127.0.0.1:9090/metrics | grep tachyon_key_rotations_total
```

### Suspected key compromise

Treat any of the following as compromise: stolen private key file,
unauthorised root access on the host, AEAD tag mismatches without an
obvious cause, audit log gaps.

Procedure:

1. **Isolate** — stop the unit on the affected host:
   `sudo systemctl stop tachyon@wg0`.
2. **Revoke** on the peer side — remove the compromised
   `PeerPublicKey` from the peer's config and reload.
3. **Generate a new keypair** on a fresh, trusted host:
   ```bash
   tachyon genkey > new.key
   chmod 600 new.key
   tachyon pubkey < new.key > new.pub
   ```
4. **Distribute** the public half over an out-of-band channel
   (signed email, hardware token, MDM push).
5. **Rotate** PSKs as well — `PresharedKey` should also be regenerated
   if shared with the compromised host.
6. **Preserve evidence** — copy `/var/log/tachyon-audit.log` and the
   journal for the relevant time window before redeploying.
7. **Forensics** — see §6.

---

## 5. Troubleshooting

### `Tunnel 'X' already exists`

The veth pair or BPF pin from a previous run is still present.
Common causes: previous `tachyon` process crashed; the unit was
killed with `SIGKILL` skipping cleanup.

```bash
sudo tachyon down /etc/tachyon/X.conf   # idempotent cleanup
# If the above fails because the conf file vanished:
sudo ip link del X-tun 2>/dev/null
sudo rm -rf /sys/fs/bpf/tachyon/X
sudo systemctl restart tachyon@X
```

### `DPD timeout` (Dead Peer Detection)

No authenticated packet seen from the peer for 35 s.  Check:

- Layer-3 reachability: `ping <Peer.EndpointIP>`
- Firewall: outbound and inbound UDP on `ListenPort`
- Peer process is alive: ask the remote on-call to confirm
  `tachyon@<name>.service` is `active`
- NAT rebinding: the peer's source port may have changed; check
  `tachyon_peer_endpoint_changes_total` — if it climbs continuously,
  the NAT box is dropping idle conntrack entries.  Mitigation: set
  `KeepaliveSeconds = 15` on the side behind the NAT.

### `Cookie validation failed`

The stateless cookie attached to a handshake initiation didn't
verify.  Three possible causes:

1. **Clock skew** — cookies embed a 30-second timestamp.  Run
   `chronyc tracking`; offset must be < 5 s.
2. **Replay** — an attacker is replaying captured initiations.  If
   accompanied by source-IP churn, expect rate-limiter drops to
   spike — that's the system working as designed.
3. **NAT rebinding mid-handshake** — peer's source IP changed
   between the cookie issue and the cookie return.  Usually
   self-recovering; if persistent, set a longer
   `CookieLifetimeSeconds` (max 120).

### `Crypto error` (AEAD authentication failure)

Either the keys disagree or the ciphertext was tampered with.
Procedure:

1. Compare `tachyon pubkey < /etc/tachyon/wg0.key` on both ends with
   the `PeerPublicKey` configured on the other side.  They must be
   identical.
2. Confirm both peers use the same `CipherType`.
3. If keys match, count the rate of failures —
   `rate(tachyon_rx_crypto_errors_total[1m])`.  A small steady
   trickle (≤ 0.001/s) can be path-induced corruption upstream of
   us; a sustained high rate is an attack signal: page security and
   follow §4 *Suspected key compromise*.

### `Rate limit exceeded` from a single source IP

Expected during opportunistic scanning.  Investigate only if the
source is a legitimate peer:
`grep <ip> /var/log/tachyon-audit.log` and consider raising
`PerIpHandshakesPerMinute` for that prefix via configuration.

---

## 6. Incident Response

### Indicators of compromise

- Sustained `tachyon_rx_crypto_errors_total` rate > 0.01/s with no
  config change.
- New `peer_endpoint_changes` events from IPs outside the expected
  ASN.
- Audit log gaps (timestamps not monotonic, missing `handshake_*`
  events around traffic spikes).
- Unexpected `key_rotation` events (more than ~12/hour per tunnel).

### Extracting the audit log

```bash
# Snapshot from the file logger (if AuditLog= is set)
sudo cp /var/log/tachyon-audit.log /tmp/incident-$(date +%s).log

# Pull the last 24 h from syslog/journal (LOG_AUTH facility)
sudo journalctl --facility=auth --since '24 hours ago' \
                SYSLOG_IDENTIFIER=tachyon \
                -o json > /tmp/incident-journal.json

# Hash for chain-of-custody
sha256sum /tmp/incident-*.log /tmp/incident-journal.json \
   > /tmp/incident-hashes.txt
```

Ship to your SIEM bucket; do NOT delete the originals until the
investigation is closed.

### Key revocation

See §4 *Suspected key compromise*.  Note that revocation is
*per-peer* — a compromised host's keypair must be removed from
every peer's `PeerPublicKey` field, not just the local config.

### After the incident

1. Rotate all PSKs across the fleet.
2. Re-issue host certificates if you wrap Tachyon under a PKI.
3. Add the attacker source ranges to your edge ACL (Tachyon's
   per-IP rate limiter is mitigation, not a substitute for
   perimeter blocking).
4. Open a postmortem ticket within 48 h.

---

## 7. Performance Issues

For tuning advice see `docs/PERFORMANCE.md`.  This section covers
*recognising* a perf problem in production.

### High CPU on the control plane

Symptoms: `tachyon` process > 100 % CPU sustained.

Likely causes:
- Handshake storm (DDoS) — check
  `rate(tachyon_handshake_failed_total[1m])`.  If high, the
  per-IP rate limiter is doing its job; the cost is CPU spent
  validating cookies.  Tighten `PerIpHandshakesPerMinute` or move
  the limiter to a hardware load balancer.
- Cover-traffic too aggressive — lower `CoverRateHz`.
- Excessive logging — set `LogLevel=info` (not `debug`).

### Packet drops on the data plane

Symptoms: `tachyon_rx_dropped_total` climbing,
`ethtool -S <iface>` shows `rx_no_buffer` or `rx_missed_errors`.

Likely causes:
- XDP queue → CPU mapping skewed.  See `docs/PERFORMANCE.md` §1.
- NIC ring buffer too small.  `ethtool -G <iface> rx 4096`.
- Replay window thrashing — increase `ReplayWindowSize` if
  reordering exceeds 1024 packets (rare; usually a sign of
  bad path).

### High latency

Symptoms: tunnel ping RTT > path RTT + 1 ms.

Likely causes:
- AES-NI not detected; ChaCha20 software path is in use.  Check
  `tachyon_cipher_in_use` metric.  Enable `AutoConfig=true` and
  restart, or set `CipherType=aes256gcm` explicitly.
- Constant-rate shaping with too low a PPS — raise
  `TrafficShapingPPS` or disable for latency-sensitive workloads.
- IRQ coalescing too aggressive — `ethtool -C <iface>
  rx-usecs 8`.
