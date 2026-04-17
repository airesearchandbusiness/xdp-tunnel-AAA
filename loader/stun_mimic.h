/* SPDX-License-Identifier: MIT */
/*
 * STUN/TURN message mimicry (RFC 8489 / RFC 8656).
 *
 * Wraps tunnel payloads inside STUN messages that look like WebRTC
 * connectivity checks or TURN data relaying. STUN traffic is ubiquitous
 * (every WebRTC call, Google Meet, Teams, Zoom), making it extremely
 * hard to block without collateral damage. Even the GFW allows STUN on
 * ports 3478 and 19302.
 *
 * STUN message format (RFC 8489 §6):
 *   ┌──────────────────────────────────────┐
 *   │  Type (16)                            │ 0x0001 = Binding Request
 *   │  Length (16)                           │ payload + attrs length
 *   │  Magic Cookie (32) = 0x2112A442       │
 *   │  Transaction ID (96)                   │
 *   ├──────────────────────────────────────┤
 *   │  Attribute: DATA (type 0x0013)        │ carries tunnel payload
 *   │    Type (16) Length (16) Value (N)     │ padded to 4-byte boundary
 *   │  [Attribute: FINGERPRINT (0x8028)]    │ CRC32 integrity check
 *   └──────────────────────────────────────┘
 *
 * The DATA attribute (§14.7 of RFC 8656) is the TURN relay payload
 * carrier. We use it to smuggle tunnel frames in what looks like a
 * legitimate TURN data indication or ChannelData.
 *
 * The FINGERPRINT attribute provides a CRC32-based integrity check that
 * DPI middleboxes use to confirm "this is real STUN" — so we include it.
 */
#ifndef TACHYON_STUN_MIMIC_H
#define TACHYON_STUN_MIMIC_H

#include "transport.h"

namespace tachyon::stun_mimic {

constexpr size_t   STUN_HEADER_LEN    = 20;
constexpr size_t   STUN_ATTR_HEADER   = 4;
constexpr uint32_t STUN_MAGIC_COOKIE  = 0x2112A442;
constexpr uint16_t STUN_BINDING_REQ   = 0x0001;
constexpr uint16_t STUN_DATA_IND      = 0x0017; /* Data Indication */
constexpr uint16_t ATTR_DATA          = 0x0013;
constexpr uint16_t ATTR_FINGERPRINT   = 0x8028;
constexpr size_t   STUN_OVERHEAD      = STUN_HEADER_LEN + STUN_ATTR_HEADER + 8; /* +fingerprint */
constexpr size_t   STUN_MAX_PAYLOAD   = 1400;

void register_transport();

/* Build a STUN message wrapping `payload` in a DATA attribute.
 * `txn_id` must be 12 bytes. Returns total message length. */
size_t build_stun_message(uint8_t *out, size_t cap, uint16_t msg_type,
                          const uint8_t txn_id[12],
                          const uint8_t *payload, size_t payload_len);

/* Parse a STUN message and extract the DATA attribute payload. */
struct StunParseResult {
    bool     ok;
    uint16_t msg_type;
    uint8_t  txn_id[12];
    size_t   data_offset;
    size_t   data_len;
};
StunParseResult parse_stun_message(const uint8_t *buf, size_t len);

/* CRC32 for STUN FINGERPRINT (XORed with 0x5354554E per RFC 8489). */
uint32_t stun_fingerprint(const uint8_t *msg, size_t len);

} /* namespace tachyon::stun_mimic */

#endif /* TACHYON_STUN_MIMIC_H */
