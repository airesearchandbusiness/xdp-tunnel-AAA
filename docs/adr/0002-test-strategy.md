# ADR-0002: Multi-Tier Test Strategy

## Status

Accepted

## Context

The tri-layer architecture requires different testing approaches for each
layer. Unit testing the control plane must not depend on libbpf, kernel
modules, or root privileges, since CI runners lack these.

## Decision

Adopt a four-tier test strategy:

1. **Unit tests** (tests/unit/) -- Google Test, compile with TACHYON_NO_BPF,
   link only OpenSSL. Test crypto primitives, config parsing, protocol
   structs, nonce cache, and utility functions. Run in CI without privileges.

2. **XDP tests** (tests/xdp/) -- Use BPF_PROG_TEST_RUN to exercise XDP
   programs with crafted packets. Require root and the kernel module.

3. **Integration tests** (tests/integration/) -- Shell scripts using network
   namespaces for full tunnel setup, data transfer, key rotation, and DPD.
   Require root and the kernel module.

4. **Fuzz tests** (tests/fuzz/) -- libFuzzer harnesses for config parsing
   and crypto inputs. Run in nightly CI with extended timeouts.

## Alternatives Considered

1. **Single test binary** -- Would require libbpf and root for all tests,
   making CI impractical.
2. **Mock-based BPF testing** -- Too complex to mock the BPF subsystem
   accurately; BPF_PROG_TEST_RUN is the kernel's own test facility.
3. **No fuzz testing** -- Crypto and parser code handles untrusted input;
   fuzzing has high value relative to effort.

## Consequences

- CI runs 114 unit tests without any kernel dependency
- XDP and integration tests require a privileged environment (local dev or
  dedicated CI runner)
- The TACHYON_NO_BPF compile flag decouples test builds from libbpf
- Struct layout tests catch ABI drift between common.h and tachyon.h
