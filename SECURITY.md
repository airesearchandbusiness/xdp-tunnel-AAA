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

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | Yes       |
