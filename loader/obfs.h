/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Control Plane - DPI Evasion via TLS 1.3 Mimicry
 *
 * Builds a byte-for-byte TLS 1.3 ClientHello record whose outer structure is
 * indistinguishable from a real browser handshake (uTLS/Chrome fingerprint).
 * The ghost header and session ciphertext ride inside the record as opaque
 * payload bytes, protected by the tunnel AEAD.
 *
 * Used in REALITY-style deployments: probes that try to speak TLS back to us
 * see a legitimate-looking ClientHello structure, while real peers know the
 * shared secret needed to decode the embedded ghost header.
 *
 * References:
 *   - RFC 8446 §4.1.2 (ClientHello)
 *   - draft-ietf-tls-grease-01 (RFC 8701)
 *   - REALITY protocol (Xray-core, 2023+)
 *
 * The module is stateless and allocation-free: callers pass a stack-allocated
 * buffer and receive a written byte count.
 */
#ifndef TACHYON_OBFS_H
#define TACHYON_OBFS_H

#include <cstdint>
#include <cstddef>

namespace tachyon::obfs {

enum class Mode : uint8_t {
    NONE = 0,     /* No outer mimicry */
    QUIC = 1,     /* QUIC-Initial long-header prefix (legacy behaviour) */
    REALITY = 2,  /* Full TLS 1.3 ClientHello mimicry */
};

Mode mode_from_string(const char *s);
const char *mode_to_string(Mode m);

/* The assembled record never exceeds this — a typical browser ClientHello is
 * 500-600 bytes. Callers should supply a buffer of at least this size. */
constexpr size_t MAX_RECORD_LEN = 1400;

struct Options {
    const char *sni;          /* e.g. "www.cloudflare.com"; passed verbatim to SNI extension */
    const uint8_t *client_random; /* 32 bytes; usually caller-provided randomness */
    const uint8_t *session_id;    /* 32 bytes (TLS 1.3 compat session ID) */
    const uint8_t *alpn_list;     /* packed: len1, bytes1, len2, bytes2, ... 0 */
    size_t alpn_list_len;
};

/*
 * build_client_hello - Encode a TLS 1.3 record-layer frame containing a
 * ClientHello handshake message to `out`.
 *
 * Record layout (out[0..]):
 *   05 bytes  TLSCiphertext header  { type=0x16, version=0x0303, length }
 *   04 bytes  Handshake header      { type=0x01, length=24-bit }
 *   ...       ClientHello body
 *
 * Returns the total bytes written (>= 5) or 0 on failure. Fails only if
 * out_cap < MAX_RECORD_LEN or required options are missing.
 *
 * Deterministic given the same inputs — use random client_random/session_id
 * to avoid trivial correlation across handshakes.
 */
size_t build_client_hello(uint8_t *out, size_t out_cap, const Options &opts);

/*
 * parse_client_hello_sni - Extract the SNI host-name from a TLS 1.3
 * ClientHello record in `record_bytes` and copy it into `out` (NUL-terminated).
 *
 * Returns 0 on success and a negative errno-style code on failure:
 *   -1  malformed record
 *   -2  no SNI extension
 *   -3  out_cap too small for SNI hostname + NUL
 *
 * Used in round-trip unit tests and to validate peer-origin in REALITY mode.
 */
int parse_client_hello_sni(const uint8_t *record_bytes, size_t len, char *out, size_t out_cap);

/* ── GREASE utilities (RFC 8701) ────────────────────────────────────────── */

/* The 16 GREASE code points that browsers/servers must ignore */
bool is_grease_codepoint(uint16_t v);

/*
 * pick_grease - Return a random GREASE value [0x0A0A..0xFAFA] in step 0x1010.
 * Used to populate cipher-suite, extension, and named-group lists with
 * "reserved" IANA codepoints that real TLS stacks skip silently but DPIs
 * frequently parse incorrectly. Seeded from OpenSSL CSPRNG.
 */
uint16_t pick_grease();

/* Register REALITY as a pluggable transport engine (wraps in TLS records). */
void register_reality_transport();

} /* namespace tachyon::obfs */

#endif /* TACHYON_OBFS_H */
