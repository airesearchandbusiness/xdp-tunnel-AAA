# Tachyon Performance Tuning Guide

Tachyon is designed for line-rate operation on commodity 25/100 GbE
NICs.  In practice, getting there requires deliberate placement of
work onto the right CPUs and the right rings.  This document covers
the tuning levers, in order of typical impact.

A quick reference table is at the end.

---

## 1. CPU Affinity

The control plane is single-process, multi-threaded; the data plane
is one BPF program per RX queue.  These should not share cores.

### Pinning the control plane

Reserve two cores for control work and pin the process there.  Use
`CPUAffinity=` in a `systemctl edit tachyon@wg0` drop-in:

```
[Service]
CPUAffinity=2 3
```

Or, ad-hoc:

```bash
sudo taskset -cp 2,3 $(pidof tachyon)
```

These cores should be on the **same NUMA node as the NIC** (see §2)
and should NOT be in the XDP RX-queue affinity set — let the data
plane have its own private cores.

### Pinning XDP RX queues

Each NIC RX queue runs napi/XDP on the CPU listed in
`/proc/interrupts`.  For maximum cache locality, distribute queues
1:1 across cores on the NIC's NUMA node:

```bash
# 8 RX queues, NIC on NUMA0 (cores 0-15)
for q in 0 1 2 3 4 5 6 7; do
    irq=$(grep -oP "^\s*\K[0-9]+(?=:.*<iface>-rx-${q}\b)" /proc/interrupts)
    echo "$((1 << (q + 4)))" | sudo tee /proc/irq/${irq}/smp_affinity > /dev/null
done
```

Cores 4–11 now exclusively service RX, leaving 0–3 for the kernel
and 2–3 for the control plane.

### Receive Side Scaling (RSS) hash

Tachyon expects 4-tuple hashing.  Verify with:

```bash
sudo ethtool -n <iface> rx-flow-hash udp4
# IP SA  IP DA  L4 SA  L4 DA   ← required for even distribution
```

If you see only `IP SA  IP DA`, set
`sudo ethtool -N <iface> rx-flow-hash udp4 sdfn`.

---

## 2. NUMA

On dual-socket servers, both the NIC IRQs and the control-plane
threads must land on the socket physically wired to the NIC.

```bash
# Find NIC's NUMA node
cat /sys/class/net/<iface>/device/numa_node    # e.g. 0

# List that node's CPUs
numactl --hardware | grep "node 0 cpus"
```

Then ensure all three of the following match that node:

1. `CPUAffinity=` in the systemd drop-in.
2. NIC RX-queue IRQs (`smp_affinity` writes from §1).
3. Memory allocation policy:
   ```
   [Service]
   ExecStart=/usr/bin/numactl --membind=0 -- /usr/bin/tachyon up /etc/tachyon/wg0.conf
   ```

Cross-socket QPI/UPI traffic typically halves throughput; getting
this right is the single biggest win.

---

## 3. BPF Buffer Sizes

### XSK ring sizes

Tachyon's data plane uses AF_XDP socket rings sized at compile time
in `src/common.h`:

```
#define XSK_RING_SIZE       4096   /* descriptors per ring */
#define XSK_FRAME_SIZE      2048   /* one MTU-friendly slot */
```

For 100 GbE you may need 8192 or 16384.  Larger rings consume more
locked memory (`size = ring × frame × 2 (TX+RX) × queues`).

### NAPI thresholds

Lower NAPI weight reduces tail latency at the cost of throughput.

```bash
echo 32 | sudo tee /sys/class/net/<iface>/napi_defer_hard_irqs  # default 0
echo 8  | sudo tee /sys/class/net/<iface>/gro_flush_timeout     # ns/100
```

Start with defaults and only tune if you see > 100 µs RX softirq
spikes in `perf top`.

### NIC ring sizes

```bash
sudo ethtool -G <iface> rx 4096 tx 4096
```

Anything below 1024 will drop under microbursts on 25 GbE+.

---

## 4. Replay Window

The userspace replay window (`ReplayWindowSize` in `tun.conf`) is a
per-sender bitmap of recently-seen sequence numbers.

| Window size | Memory per peer | Reordering tolerated |
|---|---|---|
|  64  |   8 B   | trivial |
| 1024 | 128 B   | typical WAN |
| 4096 | 512 B   | bursty wireless / multipath |
|65536 |   8 KB  | extreme; rarely needed |

Memory cost is `WindowSize / 8` bytes **per active sender**, so a
hub with 10 000 peers and `ReplayWindowSize=1024` consumes ~1.25 MB.

Increase if `tachyon_rx_replay_drops_total` rises despite no
attack — that means legitimate reordering exceeded the window.

---

## 5. Rate Limits

Two rate limiters exist:

1. **Per-IP handshake limiter** (`loader/ip_rate_limiter.cpp`) —
   defends the cookie machinery from brute force.  Default:
   60 handshakes/min/IP.
2. **Per-session token bucket** (`loader/rate_limiter.cpp`) —
   data-plane bandwidth cap, set with `RateLimitMbps` per peer.

### When to relax

- Behind a CGNAT, many legitimate clients share a public IP.  Raise
  the per-IP limit to ~600/min and rely on the cookie cost itself
  for back-pressure.
- During a maintenance restart of a downstream cluster, expect a
  thundering-herd of handshakes.  Pre-raise the limit, then revert.

### When to tighten

- After observing a handshake DDoS in `tachyon_handshake_failed_total`,
  drop the limit to 10/min/IP and raise the circuit-breaker
  trip threshold.

Token-bucket size: aim for `bucket = rate × 200 ms` so short bursts
go unmetered but sustained overshoot is shaped.

---

## 6. Cover Traffic

Cover traffic injects dummy frames to obscure the real packet rate.
It is configured by `CoverRateHz` and the `Padding=` mode.

| Mode | Bandwidth overhead | Anonymity gain |
|---|---|---|
| `none`            |   0 % | none |
| `padme`           |  ~10 %| size-only obfuscation (good ROI) |
| `random` + 5 Hz   |  ~15 %| size + light timing |
| `constant_rate`   | 100 % of `TrafficShapingPPS × MTU` | timing immunity |

Recommendations:

- **Default** (general operations): `Padding=padme`, no cover.
- **Privacy-sensitive**: `Padding=padme`, `CoverRateHz=5`.
- **Highest assurance** (long-lived covert channels):
  `TrafficShapingPPS=1000`, `TrafficShapingPktLen=1400` — locks
  bandwidth but burns CPU and link.

Cover traffic is ALWAYS encrypted and replay-protected like real
traffic; it is indistinguishable on the wire.

---

## 7. Hardware Recommendations

### CPU

- AES-NI is required for `aes128gcm` / `aes256gcm` to outperform
  ChaCha20 — verify with `grep -m1 aes /proc/cpuinfo`.  Modern
  AMD EPYC and Intel Xeon Gold/Platinum all qualify.
- AVX-512 is not required but speeds up Poly1305 by ~25 %.
- Disable `intel_pstate=disable` and pin the governor to
  `performance` for predictable latency.

### NIC

| Vendor / model | XDP native | Recommended |
|---|---|---|
| Mellanox ConnectX-5 / 6 (mlx5) | yes | yes (best driver maturity) |
| Intel E810 (ice)                | yes | yes |
| Broadcom BCM57414 (bnxt_en)     | yes | OK |
| Intel X710 (i40e)               | yes | OK (older) |
| Realtek r8169                   | generic only | NO — generic XDP is slow |

For 25 GbE, ConnectX-5 Lx or E810-XXVDA2.  For 100 GbE,
ConnectX-6 Dx or E810-CQDA2.

### Memory

- 16 GB minimum on a hub serving > 1 000 peers.
- HugePages are NOT required — Tachyon does not benefit from
  2 MiB pages on the BPF maps used today.

### Storage

The audit log writes ~200 bytes per handshake event.  At 1 000
events/s sustained, plan for ~17 GB/day; rotate with logrotate's
`size 1G` + `compress`.

---

## Quick Reference

| Lever | Where | Default | Tune to |
|---|---|---|---|
| Control-plane CPU pin | `systemctl edit` | unpinned | 2 cores on NIC's NUMA node |
| RX-queue IRQ pin | `/proc/irq/N/smp_affinity` | round-robin | 1:1 per core, NIC's node |
| NIC ring size | `ethtool -G` | driver default (256) | 4096 |
| `ReplayWindowSize` | `tun.conf` | 4096 | 1024 (LAN) – 16384 (mobile) |
| `PerIpHandshakesPerMinute` | `tun.conf` | 60 | 10 (under attack) – 600 (CGNAT) |
| `CoverRateHz` | `tun.conf` | 0 | 5 (privacy) |
| `CipherType` | `tun.conf` | `chacha20` | `aes256gcm` if AES-NI |
