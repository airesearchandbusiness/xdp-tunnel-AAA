# ADR-0001: Tri-Layer Architecture (Userspace / XDP / Kernel Module)

## Status

Accepted

## Context

Tachyon needs to process encrypted tunnel packets at wire speed while
maintaining a complex handshake protocol. The design must balance
performance (data plane throughput) with flexibility (control plane logic).

## Decision

Adopt a three-layer architecture:

1. **Userspace Control Plane** (C++17, OpenSSL, libbpf) -- handles
   handshake, key negotiation, configuration, and lifecycle management.
2. **XDP Data Plane** (eBPF) -- handles per-packet encapsulation,
   decapsulation, replay protection, and rate limiting at line rate.
3. **Kernel Crypto Module** -- provides BPF kfuncs for AEAD encryption
   and decryption, with RCU-protected twin-engine key rotation.

The layers communicate via BPF maps (config, session state, keys) and
syscall BPF programs (key injection).

## Alternatives Considered

1. **Userspace-only (DPDK/AF_XDP)** -- higher flexibility but requires
   dedicated cores, larger memory footprint, and bypasses kernel networking.
2. **Kernel module only** -- maximum performance but difficult to implement
   complex handshake logic; harder to debug and iterate.
3. **TC/cls_bpf instead of XDP** -- runs later in the stack with more
   overhead; XDP provides the earliest interception point.

## Consequences

- Data plane achieves near-wire-speed with zero-copy XDP processing
- Control plane has full C++ stdlib and OpenSSL for complex crypto
- Key rotation is atomic via RCU with zero packet loss
- Testing requires three separate strategies (unit tests, BPF_PROG_TEST_RUN, integration)
- The kernel module must be loaded before XDP programs can call kfuncs
