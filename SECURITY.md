# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Tachyon XDP Tunnel, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **airesearchandbusiness@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide an initial assessment within 7 days.

## Scope

The following components are in scope for security reports:

- **Cryptographic implementation** (`loader/crypto.cpp`, `kmod/mod.c`)
- **Key management** (handshake, rotation, zeroization)
- **Replay protection** (`src/xdp_core.c` replay window)
- **Control plane authentication** (cookie validation, AEAD)
- **Configuration parsing** (injection, path traversal)
- **BPF/XDP programs** (bounds checks, verifier bypass)

## Security Design

Tachyon implements several defense-in-depth measures:

- **ChaCha20-Poly1305 AEAD** for authenticated encryption
- **X25519 ECDH** with zero shared-secret rejection
- **HKDF-SHA256** key derivation with separate TX/RX keys
- **Stateless cookies** for DoS protection during handshake
- **Constant-time role comparison** to prevent timing side-channels
- **Per-packet random nonce salt** combined with monotonic sequence
- **OPENSSL_cleanse** for sensitive memory zeroization
- **RCU-protected key rotation** for zero-downtime rekeying
- **256-packet per-CPU replay window** for replay attack prevention

### Control Plane Hardening

- **No shell interpretation** -- `run_cmd()` uses `fork()/execvp()` instead of `system()`, eliminating command injection via config filenames
- **Tunnel name sanitization** -- restricted to `[a-zA-Z0-9_-]` with a 10-char IFNAMSIZ-derived cap
- **Root privilege check** -- `geteuid()` check before `up`/`down`/`show` commands
- **Monotonic clock** -- all DPD, keepalive, rekey, and cookie-rotation timers use `CLOCK_MONOTONIC`, immune to NTP step adjustments
- **Full crypto return checking** -- every `RAND_bytes()`, `cp_aead_encrypt()`, and `cp_aead_decrypt()` call site is return-value-checked
- **DPD authentication ordering** -- `last_rx_time` is updated only after a packet passes AEAD authentication, not on bare receipt
- **BPF attachment rollback** -- all-or-nothing XDP program attachment with automatic detach on partial failure
- **Peer source-port validation** -- control plane filters by both IP and UDP source port
- **Private key cleansing** -- `OPENSSL_cleanse` applied to `TunnelConfig` key strings immediately after static-key derivation
- **IP/MAC semantic validation** -- rejects loopback, broadcast, link-local, and zero addresses in config
- **Config file size guard** -- `parse_ini()` rejects files >64KB to prevent memory exhaustion
- **NonceCache deduplication** -- duplicate nonce additions do not inflate the LRU list, preserving correct capacity accounting

### Cipher Suite & Key Exchange

- **Modular CipherSuite abstraction** — ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM selectable via config; registry decouples handshake from cipher choice
- **AES-NI auto-detection** — CPUID (x86-64) / HWCAP (ARM64) probed at startup; AES-256-GCM preferred when hardware acceleration is available
- **Hardware auto-configuration** — `AutoConfig = true` automatically selects cipher, probes interface MTU; explicit config always takes precedence
- **Source port rotation** — periodic socket rebind changes ephemeral source port, defeating per-session correlation; `PortRotationInterval` is configurable
- **Post-quantum hybrid KEM skeleton** — `TACHYON_FLAG_PQ` flag and `pq_kem.h` infrastructure for X25519 + ML-KEM-768 hybrid KEM; activated when built with `-DTACHYON_PQ=ON` (requires liboqs)
- **Congestion-adaptive obfuscation** — `AdaptiveObfsController` monitors drop counters and sheds constant-size padding and decoy chaff under congestion, restoring full obfuscation when the link clears

### Traffic Analysis Resistance

- **IP header obfuscation** -- TTL jitter (63-66), IP ID randomization, probabilistic DF bit clearing defeat OS fingerprinting and cross-packet correlation
- **DSCP/ECN stripping** -- inner QoS markings zeroed in outer header to prevent application-type inference
- **Constant-size padding** -- optional mode where every packet is padded to MTU, making all tunnel traffic identical size on the wire
- **Decoy chaff traffic** -- authenticated keepalive packets injected at random intervals during idle periods, masking real traffic patterns
- **Forward secrecy key ratchet** -- control plane AEAD key advances every 5 minutes via HKDF chain; old chain material erased immediately (1-way hash chain)
- **QUIC mimicry** -- tunnel headers crafted to resemble QUIC short-header packets with randomized Connection ID and spin bit

### Build Hardening

- **`-D_FORTIFY_SOURCE=2`** -- glibc buffer-overflow detection
- **`-fstack-protector-strong`** -- stack canary on functions with arrays/pointers
- **`-fPIE` / `-pie`** -- position-independent executable for ASLR
- **`-Wformat-security`** -- reject non-literal format strings
- **`-Wl,-z,relro,-z,now`** -- full RELRO (GOT read-only after startup)
- **`-Wl,-z,noexecstack`** -- non-executable stack

### Compile-Time Verification

- **20+ `static_assert` checks** verify wire-format struct sizes and field offsets across BPF, kernel, and userspace compilation contexts
- **Cross-struct assertions** verify userspace C++ mirror types match BPF map value types byte-for-byte

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | Yes       |
