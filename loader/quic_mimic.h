/* SPDX-License-Identifier: MIT */
/*
 * QUIC v1 Initial long-header mimicry (RFC 9000 §17.2).
 *
 * Builds wire-accurate QUIC Initial packets that survive deep-packet
 * inspection. The tunnel payload rides in the position of the CRYPTO
 * frame. Real QUIC Initial packets are unencrypted (client-side, before
 * keys are derived) so DPI can parse the header; ours look byte-for-byte
 * identical to a legitimate handshake initiation.
 *
 * Wire layout (RFC 9000 Figure 15):
 *   ┌─1 bit Header Form = 1 (long)─────────────┐
 *   │ 1 bit Fixed = 1                           │
 *   │ 2 bit Long Type = 00 (Initial)            │
 *   │ 2 bit Reserved = 00                       │
 *   │ 2 bit Pkt Num Len = NN (0..3 → 1..4 oct) │
 *   ├───────────────────────────────────────────┤
 *   │ 4 bytes  Version = 0x00000001 (QUICv1)    │
 *   │ 1 byte   DCID Length                       │
 *   │ 0..20    DCID bytes                        │
 *   │ 1 byte   SCID Length                       │
 *   │ 0..20    SCID bytes                        │
 *   │ VarInt   Token Length (usually 0)           │
 *   │ VarInt   Payload Length                     │
 *   │ 1..4     Packet Number                     │
 *   │ N        Payload (our tunnel frame)         │
 *   │ 0..N     AEAD tag / padding to ≥1200 bytes │
 *   └───────────────────────────────────────────┘
 *
 * Minimum QUIC Initial is 1200 bytes (MUST, §14.1). We pad short
 * payloads to reach this floor.
 */
#ifndef TACHYON_QUIC_MIMIC_H
#define TACHYON_QUIC_MIMIC_H

#include "transport.h"

namespace tachyon::quic_mimic {

constexpr uint32_t QUIC_V1           = 0x00000001;
constexpr size_t   QUIC_MIN_INITIAL  = 1200;
constexpr size_t   QUIC_HEADER_MAX   = 54;  /* worst-case header before payload */
constexpr size_t   QUIC_MAX_PAYLOAD  = 1350; /* safe for most MTUs */

/* Register with the transport framework. Called once at startup. */
void register_transport();

/* Low-level — build a QUIC Initial long header into `out`.
 * Returns bytes written (header only, before payload). */
size_t build_initial_header(uint8_t *out, size_t cap,
                            const uint8_t *dcid, uint8_t dcid_len,
                            const uint8_t *scid, uint8_t scid_len,
                            uint32_t pkt_num, size_t payload_len);

/* Parse just the DCID/SCID and payload offset from a received frame. */
struct ParseResult {
    bool     ok;
    uint8_t  dcid[20];
    uint8_t  dcid_len;
    uint8_t  scid[20];
    uint8_t  scid_len;
    uint32_t pkt_num;
    size_t   payload_offset;
    size_t   payload_len;
};
ParseResult parse_initial_header(const uint8_t *buf, size_t len);

} /* namespace tachyon::quic_mimic */

#endif /* TACHYON_QUIC_MIMIC_H */
