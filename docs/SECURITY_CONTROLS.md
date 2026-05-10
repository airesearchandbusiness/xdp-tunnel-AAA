# Tachyon Security Controls — Defence in Depth

This document maps each class of attack we anticipate against
Tachyon to the specific control(s) that mitigate it, and to the
exact source-code location implementing each control.  Use it for
threat-model reviews, audit responses, and onboarding new
engineers.

The goal of defence-in-depth is that no single failure (a CVE in
one library, a config mistake, a side-channel) should compromise
the whole system.  Every row below should have at least two
independent layers; where it does not, the gap is called out
explicitly at the bottom.

---

## Attack-to-Control Matrix

| # | Attack | Control | Where (file) |
|---|---|---|---|
| 1 | Quantum harvest-now-decrypt-later | ML-KEM-768 hybrid KEX (X25519 ‖ ML-KEM, HKDF-SHA384 combined secret) | `loader/hybrid_kex.cpp`, `loader/pq_kem.h` |
| 2 | Replay of captured ciphertext | Per-sender sliding bitmap window, default 1024 packets | `loader/replay.cpp`, `loader/replay.h` |
| 3 | DDoS of handshake (CPU exhaustion) | Per-IP token-bucket rate limiter with LRU eviction, plus circuit breaker with exponential back-off | `loader/ip_rate_limiter.cpp`, `loader/circuit_breaker.cpp` |
| 4 | Brute-force / state-amplification on initiator cookies | Stateless server cookie (HMAC-SHA256 over `srcIP ‖ ts`, 30 s lifetime) | `loader/network.cpp` (cookie issue + verify) |
| 5 | Traffic analysis (size + timing fingerprinting) | PADME size bucketing, configurable cover traffic, REALITY TLS-1.3 ClientHello mimicry | `loader/padding.cpp`, `loader/obfs.cpp` |
| 6 | DPI / protocol-classifier blocking | QUIC, DoH, HTTP/2, STUN mimicry modules; smart-obfs auto-selection | `loader/quic_mimic.cpp`, `loader/doh_mimic.cpp`, `loader/http2_mimic.cpp`, `loader/stun_mimic.cpp`, `loader/smart_obfs.h` |
| 7 | Side-channel timing on secret comparison / cleanup | `CRYPTO_memcmp`, `OPENSSL_cleanse` for all secret material | `loader/secmem.cpp`, `loader/crypto.cpp` |
| 8 | Memory disclosure via core dump or swap | `mlock()` on key buffers, `madvise(MADV_DONTDUMP)`, `prctl(PR_SET_DUMPABLE, 0)` | `loader/secmem.cpp` |
| 9 | Compromise forensics (post-incident attribution) | Structured audit log to `LOG_AUTH` syslog facility with monotonic event sequence | `loader/audit.cpp`, `loader/audit.h` |
| 10 | Stolen long-term key → past-traffic decryption | 5-minute automatic ratchet (HKDF over chain key); explicit rotation via SIGUSR1 | `loader/ratchet.cpp`, `loader/ratchet.h` |
| 11 | NIC fingerprinting (MAC, TTL, IP-ID) | Per-rekey MAC randomisation, per-packet TTL jitter [50,64], IP-ID randomisation, DF-bit variation | `loader/network.cpp`, `src/xdp_core.c` |
| 12 | Source-port correlation across sessions | HMAC-driven UDP source-port hopping (shared `PresharedKey`) | `loader/network.cpp` (port hop scheduler) |
| 13 | Active probing / response fingerprinting | No response to any unauthenticated packet that fails cookie check; identical drop path for malformed and replayed | `loader/network.cpp`, `src/xdp_core.c` |
| 14 | Path-MTU bias attacks | Constant-size padding mode, MSS clamp on inner TCP | `loader/padding.cpp`, `src/xdp_core.c` |
| 15 | Misconfiguration leaking plaintext | INI parser rejects unknown keys; `EnableEncryption=false` is gated behind a build-time flag in production builds | `loader/config.cpp` |
| 16 | Supply-chain tampering of secrets | `file://` URI loader for `PrivateKey` / `PresharedKey`; env-var fallback; never on argv | `loader/config.cpp`, `loader/secmem.cpp` |
| 17 | Crash → restart loop hiding compromise | `Type=notify` + `WatchdogSec=30`; `Restart=on-failure` with `RestartSec=5`; resource limits (`MemoryMax`, `CPUQuota`, `TasksMax`) | `systemd/tachyon@.service` |
| 18 | Privilege escalation from a compromised loader | systemd hardening: `ProtectHome`, `ProtectSystem=strict`, `ProtectKernelTunables`, `ProtectClock`, `PrivateTmp`, narrow `CapabilityBoundingSet` | `systemd/tachyon@.service` |
| 19 | Kernel-module key leak via `/proc` or sysfs | RCU-protected key handles, no exposure outside kfunc API; keys never copied to userspace once installed | `kmod/mod.c` |
| 20 | Unauthenticated packet → kernel work | XDP early-drop on AEAD tag failure (no skb allocation); rate-limited error counter | `src/xdp_core.c` |

---

## Notes on Coverage

- Items 1, 2, 4, 7, 8, 10 are **cryptographic invariants**: they
  hold by construction and have no operator knob.  They cannot be
  weakened by misconfiguration.
- Items 3, 5, 6, 11, 12, 14 are **policy controls**: they have
  operator-tunable knobs (`PerIpHandshakesPerMinute`, `Padding`,
  `Obfuscation`, …).  Defaults are conservative; see
  `tun.conf.example`.
- Items 17, 18 are **process isolation** controls; they mitigate
  loader-level compromise but do not protect against kernel
  compromise (out of scope for this layer).
- Item 15: setting `EnableEncryption=false` is permitted in debug
  builds for benchmarking the data path.  Production builds reject
  the key with a fatal error at startup; verify with `tachyon
  --features` (the absence of `debug_no_crypt` is the production
  marker).

---

## Known Residual Risks

| Risk | Mitigation in place | Remaining gap |
|---|---|---|
| Kernel zero-day in XDP/eBPF verifier | DKMS module + minimal in-kernel attack surface | Patch kernel; no in-userspace mitigation |
| OpenSSL CVE in AEAD | Pinned version, distroless runtime image, monthly rebuilds | Window between disclosure and rebuild |
| Side-channel in CPU AES-NI itself | ChaCha20 fallback available (`CipherType=chacha20`) | If AES-NI is silently broken AND attacker has co-tenant code execution |
| Operator key compromise via SSH | systemd `ProtectHome`, audit log, key rotation | Out of scope; rely on host hardening |
| BGP-level traffic redirection | Endpoint authentication; AEAD tag failure on tampering; audit log | Cannot prevent path observation; only confidentiality + integrity |

A finding that is NOT in the matrix above (i.e. an attack class we
have not enumerated) should be treated as a critical security bug —
file an issue with severity `critical` and CC the security team.
