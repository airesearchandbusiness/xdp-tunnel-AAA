/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Control Plane - Header-Level Deidentification
 *
 * Scrubs or randomises every host-fingerprintable field that leaves the
 * tunnel's outer encapsulation, closing passive OS-fingerprinting side
 * channels (p0f, Nmap -O, TCP-option sequencing, etc.).
 *
 * Randomised outputs are seeded from OpenSSL's CSPRNG (RAND_bytes) where a
 * per-packet value is required, or from a keyed HMAC when the value must be
 * deterministic across peers (e.g. port hopping).
 *
 * This header is pure helpers — no global state, no heap, safe for unit
 * tests with TACHYON_NO_BPF.
 */
#ifndef TACHYON_FINGERPRINT_H
#define TACHYON_FINGERPRINT_H

#include <cstdint>
#include <cstddef>

namespace tachyon::fp {

/* Tunable bounds — chosen to emulate common modern OS stacks */
constexpr uint8_t TTL_MIN = 50;
constexpr uint8_t TTL_MAX = 64;
constexpr uint16_t PORT_HOP_MIN = 20000;
constexpr uint16_t PORT_HOP_MAX = 65535;

/* ── Policy bitfield ────────────────────────────────────────────────────── */

struct Policy {
    bool ttl_random = false;   /* Scramble IP TTL per packet      */
    bool mac_random = false;   /* Locally-administered random src MAC */
    bool port_hop = false;     /* Rotate source UDP port over time */
    bool ip_id_csprng = false; /* CSPRNG-grade IP ID instead of counter */
    uint32_t port_hop_period_s = 60;
    /* Populated once at handshake; consumed by port_hop_current */
    uint8_t port_hop_psk[32] = {0};
};

/* ── TTL randomisation ──────────────────────────────────────────────────── */

/*
 * random_ttl - Draw a TTL value uniformly from [TTL_MIN, TTL_MAX]. Uses
 * RAND_bytes so the draw is cryptographically uniform, not modulo-biased for
 * reasonable ranges.
 */
uint8_t random_ttl();

/* ── MAC randomisation ──────────────────────────────────────────────────── */

/*
 * random_locally_admin_mac - Fill a 6-byte buffer with a random locally-
 * administered unicast MAC address. Preserves IEEE 802 semantics:
 *   octet0 bit 0 (multicast) = 0
 *   octet0 bit 1 (locally-administered) = 1
 * Use for outer Ethernet source address to break MAC-based host correlation.
 */
void random_locally_admin_mac(uint8_t out[6]);

/* ── Source-port hopping ────────────────────────────────────────────────── */

/*
 * port_hop_current - Given a pre-shared key and the current epoch, return the
 * UDP source port to use right now. Uses HMAC-SHA256 for deterministic output
 * across peers, mapped to [PORT_HOP_MIN, PORT_HOP_MAX] via modulo.
 *
 * The epoch is (unix_time_seconds / period_s); pass period_s = 60 for one
 * rotation per minute. Both peers compute the same value locally — no port
 * exchange is needed.
 */
uint16_t port_hop_current(const uint8_t psk[32], uint32_t period_s, uint64_t unix_time_s);

/* ── IP ID ──────────────────────────────────────────────────────────────── */

/*
 * csprng_ip_id - Draw a fresh IP ID from the CSPRNG; returns network-byte-
 * order 16-bit value. Prevents host-wide counter leaks (RFC 6864 §3).
 */
uint16_t csprng_ip_id();

/* ── Clock-skew obfuscation ─────────────────────────────────────────────── */

/*
 * obfuscate_timestamp - Add a small random jitter to an outgoing monotonic
 * timestamp so that p0f-style clock-skew fingerprinting cannot pin the exact
 * host clock. Returns ts + U[-jitter_ns, +jitter_ns].
 */
uint64_t obfuscate_timestamp(uint64_t ts_ns, uint64_t jitter_ns);

} /* namespace tachyon::fp */

#endif /* TACHYON_FINGERPRINT_H */
