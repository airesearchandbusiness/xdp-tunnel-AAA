# Migrating from Tachyon v4 to v5 ("Ghost-PQ")

v5 introduces post-quantum hybrid KEX (ML-KEM-768), pluggable
outer-packet obfuscation (REALITY), and traffic-analysis-resistant
padding (PADME).  The on-wire protocol is **backwards compatible**:
a v5 peer detects a v4 peer at handshake time and falls back
automatically.  This guide describes the safe rolling-upgrade path
for production fleets.

Estimated time per peer: 5 minutes.  Tunnel downtime per peer: ~2 s
(restart of the control plane; data plane keeps running until
explicit `down`).

---

## Step 1 — Backup the current configuration

On every host, snapshot the existing config and the running BPF
state:

```bash
sudo install -d -m 0700 /var/backups/tachyon
sudo cp /etc/tachyon/*.conf /var/backups/tachyon/$(date +%F)/
sudo tachyon show /etc/tachyon/wg0.conf \
    > /var/backups/tachyon/$(date +%F)/wg0.show.txt
```

Verify the backup is readable: `sudo ls -l /var/backups/tachyon/`.

---

## Step 2 — Verify v5 backwards compatibility

Install the v5 binary on a single non-production host and run:

```bash
tachyon --version          # must print 1.2.0 or later
tachyon --features         # lists compiled-in feature flags
```

The `--features` output enumerates which v5 features are available.
A typical v5 build prints:

```
features: pqc_hybrid pqc_classical obfs_reality obfs_quic obfs_none
          padding_padme padding_constant padding_none
          metrics audit_log shutdown_drain
```

If `pqc_hybrid` is missing, your OpenSSL is < 3.5 and was not built
with liboqs.  v5 will still run in classical mode; PQC is opt-in
(`Pqc = hybrid`).

---

## Step 3 — Generate v5 fields

v5 introduces three new INI keys.  All default to v4-compatible
values, so omitting them is safe.

```ini
# Optional: post-quantum hybrid KEX (X25519 ‖ ML-KEM-768)
Pqc = hybrid               # default: classical

# Optional: outer-packet obfuscation
Obfuscation = reality      # default: none (or quic if v4 had MimicryType=1)
ObfuscationSNI = www.microsoft.com   # required when Obfuscation=reality

# Optional: traffic-analysis padding
Padding = padme            # default: none
CoverRateHz = 5            # only meaningful with padme/random
```

For an apples-to-apples upgrade, do NOT change semantics — just add
the keys with v4-equivalent defaults:

| v4 setting | v5 equivalent |
|---|---|
| `MimicryType = 0` | `Obfuscation = none` |
| `MimicryType = 1` | `Obfuscation = quic` |
| no padding        | `Padding = none` |
| classical only    | `Pqc = classical` |

This makes Step 5 a pure binary swap with zero behavioural delta.

---

## Step 4 — Test in a lab

Bring up two hosts with the v5 binary and the migrated configs.
Verify:

```bash
# Both peers handshake successfully
sudo tachyon up /etc/tachyon/wg0.conf
sudo tachyon show /etc/tachyon/wg0.conf | grep "handshake.*ok"

# Throughput baseline matches v4
iperf3 -c <peer-inner-ip> -t 30      # within 5 % of v4

# Negotiated parameters
curl -s http://127.0.0.1:9090/metrics | grep -E \
    'tachyon_(pqc_mode|obfuscation_mode|padding_mode)'
```

Run `tests/integration/run.sh` end-to-end if available.

---

## Step 5 — Rolling restart (one peer at a time)

The on-wire format is wire-compatible: a v5 peer talking to a v4
peer renegotiates down to v4.  This makes an in-place rolling
upgrade safe — both endpoints do NOT need to be upgraded
simultaneously.

For each peer:

1. Drain & stop the v4 tunnel:
   ```bash
   sudo systemctl stop tachyon@wg0
   ```
2. Install the v5 package:
   ```bash
   sudo dpkg -i tachyon_1.2.0_amd64.deb     # or rpm/helm equivalent
   ```
3. Start the v5 tunnel (still on v4-equivalent settings from
   Step 3):
   ```bash
   sudo systemctl start tachyon@wg0
   ```
4. Verify the tunnel re-establishes:
   ```bash
   curl -fsS http://127.0.0.1:9090/ready    # 200 within 5 s
   ```
5. Move to the next peer.

During this phase your fleet will be a mix of v4 and v5 nodes
talking v4 protocol.  This is supported indefinitely.

---

## Step 6 — Enable v5 features one at a time

Only after **every** peer is on v5 can you turn on v5-only
features.  Enable them one at a time and verify between each step;
do NOT flip multiple flags at once.

### 6a. Hybrid PQC

On both ends, set `Pqc = hybrid` and `systemctl reload tachyon@wg0`.
After the next handshake (within 5 min), confirm:

```bash
curl -s http://127.0.0.1:9090/metrics | grep tachyon_pqc_mode
# tachyon_pqc_mode{mode="hybrid"} 1
```

If the metric reports `mode="classical"`, one of the peers is still
on v4 or has `pqc_hybrid` missing from its build (Step 2).

### 6b. REALITY obfuscation

```ini
Obfuscation = reality
ObfuscationSNI = <a real SNI you can plausibly camouflage as>
```

Choose an SNI that is reachable from both endpoints (the protocol
performs a TLS-1.3 ClientHello mimicking that destination).
Confirm post-reload:

```bash
sudo tcpdump -i <iface> -nn -X port 443 | head -20
# Must look like a TLS 1.3 ClientHello, not a UDP/QUIC blob
```

### 6c. PADME padding & cover traffic

```ini
Padding = padme
CoverRateHz = 5    # optional; ~15 % bandwidth overhead
```

Reload and verify `tachyon_padding_mode{mode="padme"} 1` on both
sides.  Watch `tachyon_cover_frames_sent_total` increment if
`CoverRateHz > 0`.

---

## Rollback

At any step, roll back by restoring the previous config and
re-installing the v4 package:

```bash
sudo systemctl stop tachyon@wg0
sudo cp /var/backups/tachyon/<date>/wg0.conf /etc/tachyon/wg0.conf
sudo dpkg -i tachyon_1.1.0_amd64.deb
sudo systemctl start tachyon@wg0
```

Because Steps 5 and 6 keep the on-wire protocol at v4 until 6a, a
rollback can never strand a peer in a broken state — the worst case
is a handshake renegotiation when its remote partner returns to v4.

---

## Common pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| `pqc_mode` stuck on `classical` after 6a | One peer not yet on v5 binary | Finish Step 5 fleet-wide first |
| `obfs handshake failed: SNI unreachable` | `ObfuscationSNI` blocks at firewall | Pick a publicly-resolvable SNI |
| Throughput drops 30 % after 6c | `Padding=constant_rate` accidentally | Use `padme`; reserve `constant_rate` for highest-assurance flows only |
| Audit log floods with `feature_negotiation` | Peer flapping between v4 and v5 | Pin one side; check binary version with `tachyon --version` |
