---
name: Security Vulnerability
about: Report a security issue (see SECURITY.md for private disclosure)
labels: security
---

**STOP** — If this is a sensitive security vulnerability (exploitable crash, key leakage,
authentication bypass, privilege escalation), please report it **privately** per
[SECURITY.md](../../SECURITY.md) instead of opening a public issue.

Use this template only for non-sensitive security improvements (hardening suggestions,
missing validation, documentation gaps).

## Component

- [ ] Cryptographic operations (`loader/crypto.cpp`, `kmod/mod.c`)
- [ ] Key management (handshake, rotation, zeroization)
- [ ] Replay protection (`src/xdp_core.c`)
- [ ] Control plane authentication (cookie, AEAD)
- [ ] Configuration parsing (`loader/config.cpp`)
- [ ] BPF/XDP programs (bounds, verifier)
- [ ] Build/CI hardening
- [ ] Other: ___

## Description

What security property is violated or could be improved?

## Impact

What could an attacker achieve? What are the preconditions?

## Suggested Fix

If you have a proposed fix, describe it here.
