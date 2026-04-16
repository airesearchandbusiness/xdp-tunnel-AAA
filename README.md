# Tachyon XDP Tunnel

High-performance encrypted tunnel using eBPF/XDP for data-plane packet processing and a kernel crypto module for in-kernel AEAD encryption. Designed for wire-speed VPN connectivity with minimal CPU overhead.

## Architecture

```
Userspace Control Plane (C++17, OpenSSL, libbpf)
  main.cpp     CLI entry point (up/down/show/genkey/pubkey)
  crypto.cpp   HMAC-SHA256, X25519 ECDH, HKDF, ChaCha20-Poly1305
  config.cpp   INI-style configuration parser and validator
  network.cpp  AKE v4.0 handshake, keepalive, key rotation
  tunnel.cpp   BPF lifecycle, veth setup, statistics
        |
        | BPF map updates / syscall programs
        v
XDP Data Plane (eBPF, clang -target bpf)
  xdp_core.c   TX encapsulation, RX decryption, replay protection
        |
        | kfuncs
        v
Kernel Crypto Module (kmod/mod.c)
  Twin-engine AEAD with RCU-protected zero-downtime key rotation
  Supports ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM
```

### Key Features

- **XDP fast path** -- zero-copy, per-CPU lock-free packet processing
- **Twin-engine key rotation** -- RCU-protected atomic key swap with no packet loss
- **AKE v4.0 handshake** -- X25519 ECDH, HKDF-SHA256, stateless cookies
- **QUIC mimicry** -- bimodal padding to blend with QUIC traffic patterns
- **Replay protection** -- 256-packet sliding window per sender CPU
- **TCP MSS clamping** -- transparent overhead hiding on both TX and RX
- **Per-session rate limiting** -- token-bucket rate control in the data plane
- **Peer roaming** -- automatic endpoint migration after authenticated packets
- **Dead peer detection** -- 35s timeout with automatic re-handshake

## Requirements

- Linux 5.8+ (BPF kfuncs, XDP, RCU)
- GCC 9+ or Clang 10+
- OpenSSL 3.0+
- libbpf 0.5+, libelf, zlib
- Kernel headers for module build

## Quick Start

```bash
# Build everything (kernel module, XDP object, control plane)
make all

# Install
sudo make install
sudo make install-dkms

# Generate keys
tachyon genkey > private.key
cat private.key | tachyon pubkey > public.key

# Configure (see tun.conf.example)
sudo cp tun.conf.example /etc/tachyon/wg0.conf
sudo vi /etc/tachyon/wg0.conf

# Start tunnel
sudo tachyon up /etc/tachyon/wg0.conf

# View statistics
sudo tachyon show /etc/tachyon/wg0.conf

# Stop tunnel
sudo tachyon down /etc/tachyon/wg0.conf
```

## Build Targets

| Target | Description |
|--------|-------------|
| `make all` | Build kernel module, XDP object, and control plane |
| `make kmod` | Build kernel crypto module only |
| `make xdp` | Build XDP/eBPF object only |
| `make loader` | Build control plane binary only |
| `make test-unit` | Run unit tests (no root required) |
| `make test-xdp` | Run XDP functional tests (requires root) |
| `make test-integration` | Run end-to-end integration tests (requires root) |
| `make test-all` | Run all test tiers |
| `make lint` | Run clang-format, cppcheck, shellcheck |
| `make format` | Auto-format source files |
| `make coverage` | Generate HTML coverage report |
| `make install` | Install binary, config dir, systemd service |
| `make install-dkms` | Install kernel module via DKMS |
| `make clean` | Remove build artifacts |

## Configuration

See [`tun.conf.example`](tun.conf.example) for a complete annotated example.

### Required Fields

| Field | Description |
|-------|-------------|
| `PrivateKey` | 64-char hex X25519 private key |
| `PeerPublicKey` | 64-char hex peer's X25519 public key |
| `VirtualIP` | Tunnel interface IP with CIDR (e.g. `10.8.0.1/24`) |
| `LocalPhysicalIP` | Host's physical IP address |
| `PhysicalInterface` | Network interface name (e.g. `eth0`) |
| `Peer.EndpointIP` | Remote peer's physical IP |
| `Peer.EndpointMAC` | Remote peer's MAC address |
| `Peer.InnerIP` | Remote peer's tunnel IP |

### Optional Fields

| Field | Default | Description |
|-------|---------|-------------|
| `ListenPort` | `443` | UDP listen port |
| `PresharedKey` | none | Additional shared secret |
| `MimicryType` | `1` | `0`=standard, `1`=QUIC mimicry |
| `EnableEncryption` | `true` | Data plane encryption toggle |

## Testing

The project includes a multi-tier test suite:

- **Unit tests** (114 tests) -- crypto, config, protocol, nonce cache, utilities
- **XDP tests** -- BPF_PROG_TEST_RUN based functional tests
- **Integration tests** -- network namespace based end-to-end tests
- **Fuzz tests** -- libFuzzer harnesses for config parser and crypto

```bash
# Run unit tests (fast, no privileges needed)
make test-unit

# Run with coverage
make coverage
# Report at build/coverage/html/index.html
```

## Project Structure

```
src/
  common.h        Shared protocol definitions (wire formats, constants)
  xdp_core.c      XDP TX/RX programs and syscall helpers
loader/
  main.cpp        CLI entry point
  tachyon.h       Common header (logging, structs, declarations)
  crypto.cpp      Cryptographic primitives (OpenSSL 3.0)
  config.cpp      Configuration parser
  network.cpp     AKE v4.0 handshake and control plane
  tunnel.cpp      BPF lifecycle and tunnel management
kmod/
  mod.c           Kernel crypto module (twin-engine AEAD)
tests/
  unit/           Google Test unit tests
  xdp/            XDP functional tests
  integration/    Shell-based end-to-end tests
  fuzz/           libFuzzer harnesses
  fixtures/       Test configuration files
```

## License

Dual-licensed under GPL-2.0 and MIT. See individual file headers for details.
