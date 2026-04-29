/* SPDX-License-Identifier: MIT */
/*
 * HTTP/2 frame-level mimicry (RFC 9113).
 *
 * Wraps tunnel payloads in valid HTTP/2 DATA frames so DPI sees what
 * appears to be an HTTPS session carrying normal web traffic. A Chrome-
 * realistic SETTINGS frame + pseudo HEADERS frame are emitted as the
 * "connection preface" on first wrap — subsequent payloads are pure
 * DATA frames on stream ID 1.
 *
 * Frame format (§4.1):
 *   ┌─────────────────────────────────┐
 *   │ Length (24)                       │
 *   │ Type (8)     Flags (8)           │
 *   │ Reserved (1) Stream Identifier (31) │
 *   ├─────────────────────────────────┤
 *   │ Frame Payload (Length bytes)      │
 *   └─────────────────────────────────┘
 *
 * Frame types used:
 *   0x00 = DATA    — carries tunnel payload
 *   0x01 = HEADERS — pseudo request (GET /)
 *   0x04 = SETTINGS — connection params
 *
 * The HEADERS frame contains pre-encoded HPACK-static entries for
 *   :method=GET, :path=/, :scheme=https, :authority=<sni>
 * This is static-table-only (no Huffman, no dynamic table) to keep the
 * implementation small and deterministic.
 */
#ifndef TACHYON_HTTP2_MIMIC_H
#define TACHYON_HTTP2_MIMIC_H

#include "transport.h"

namespace tachyon::http2_mimic {

constexpr size_t H2_FRAME_HEADER    = 9;
constexpr size_t H2_MAX_PAYLOAD     = 16384; /* default MAX_FRAME_SIZE */
constexpr size_t H2_PREFACE_LEN     = 24;    /* PRI * HTTP/2.0... */

/* HTTP/2 frame types */
constexpr uint8_t H2_DATA     = 0x00;
constexpr uint8_t H2_HEADERS  = 0x01;
constexpr uint8_t H2_SETTINGS = 0x04;

/* Flags */
constexpr uint8_t H2_FLAG_END_STREAM  = 0x01;
constexpr uint8_t H2_FLAG_END_HEADERS = 0x04;

void register_transport();

/* Build a 9-byte HTTP/2 frame header. Returns 9 always. */
size_t build_frame_header(uint8_t out[H2_FRAME_HEADER], uint32_t length,
                          uint8_t type, uint8_t flags, uint32_t stream_id);

/* Parse a 9-byte frame header from `buf`. */
struct FrameHeader {
    uint32_t length;
    uint8_t  type;
    uint8_t  flags;
    uint32_t stream_id;
    bool     ok;
};
FrameHeader parse_frame_header(const uint8_t *buf, size_t len);

/* Build the connection preface (PRI + SETTINGS). Returns bytes written. */
size_t build_connection_preface(uint8_t *out, size_t cap);

/* Build a minimal HEADERS frame for GET / with given authority. */
size_t build_headers_frame(uint8_t *out, size_t cap, const char *authority,
                           uint32_t stream_id);

/* Build a DATA frame wrapping `payload`. Returns total frame bytes. */
size_t build_data_frame(uint8_t *out, size_t cap, const uint8_t *payload,
                        size_t payload_len, uint32_t stream_id);

} /* namespace tachyon::http2_mimic */

#endif /* TACHYON_HTTP2_MIMIC_H */
