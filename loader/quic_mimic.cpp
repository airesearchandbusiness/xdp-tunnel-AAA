/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Transport — QUIC Initial Mimicry
 *
 * Wraps control-plane frames in a QUIC-v1-like Initial packet envelope
 * so that passive observers classify the flow as ordinary QUIC.
 *
 * Wire layout (RFC 9000 §17.2.2):
 *
 *   Byte 0        : long-header form + type (0xC0 | pn_len)
 *   Bytes 1–4     : Version  (0x00000001 = QUIC v1)
 *   Byte 5        : DCID length  (0–20)
 *   Bytes 6..     : DCID
 *   Next byte     : SCID length  (0–20)
 *   Next bytes    : SCID
 *   Varint        : Token length (always 0 for client Initial)
 *   Varint        : Payload Length
 *   1–4 bytes     : Packet Number
 *   Remaining     : Payload (the real control-plane message)
 *
 * On the receive side we strip this envelope to recover the original frame.
 */

#include "transport.h"
#include <cstring>
#include <openssl/rand.h>

namespace tachyon::transport {

/* ── Varint encoding (RFC 9000 §16) ────────────────────────────────── */

static size_t encode_varint(uint64_t v, uint8_t *out) {
    if (v < 0x40) {
        out[0] = static_cast<uint8_t>(v);
        return 1;
    }
    if (v < 0x4000) {
        out[0] = static_cast<uint8_t>(0x40 | (v >> 8));
        out[1] = static_cast<uint8_t>(v & 0xFF);
        return 2;
    }
    if (v < 0x40000000ULL) {
        out[0] = static_cast<uint8_t>(0x80 | (v >> 24));
        out[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
        out[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
        out[3] = static_cast<uint8_t>(v & 0xFF);
        return 4;
    }
    out[0] = static_cast<uint8_t>(0xC0 | (v >> 56));
    out[1] = static_cast<uint8_t>((v >> 48) & 0xFF);
    out[2] = static_cast<uint8_t>((v >> 40) & 0xFF);
    out[3] = static_cast<uint8_t>((v >> 32) & 0xFF);
    out[4] = static_cast<uint8_t>((v >> 24) & 0xFF);
    out[5] = static_cast<uint8_t>((v >> 16) & 0xFF);
    out[6] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[7] = static_cast<uint8_t>(v & 0xFF);
    return 8;
}

static size_t decode_varint(const uint8_t *buf, size_t avail, uint64_t *out) {
    if (avail == 0)
        return 0;
    uint8_t prefix = buf[0] >> 6;
    size_t need = static_cast<size_t>(1) << prefix;
    if (avail < need)
        return 0;
    uint64_t val = buf[0] & 0x3F;
    for (size_t i = 1; i < need; ++i)
        val = (val << 8) | buf[i];
    *out = val;
    return need;
}

/* ── Build a QUIC Initial envelope ───────────────────────────────── */

size_t build_initial_header(uint8_t *out, size_t out_cap, const uint8_t *dcid, uint8_t dcid_len,
                            const uint8_t *scid, uint8_t scid_len, uint64_t pkt_num,
                            size_t payload_len) {
    size_t pn_bytes = (pkt_num < 0x100) ? 1 : (pkt_num < 0x10000) ? 2 : 4;

    uint8_t token_vi[8], pl_vi[8];
    size_t token_vi_len = encode_varint(0, token_vi);
    size_t pl_vi_len = encode_varint(payload_len + pn_bytes, pl_vi);

    size_t hdr_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + token_vi_len + pl_vi_len + pn_bytes;
    if (hdr_len + payload_len > out_cap)
        return 0;

    size_t off = 0;
    out[off++] = static_cast<uint8_t>(0xC0 | (pn_bytes - 1));

    /* Version: QUIC v1 */
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x01;

    /* DCID */
    out[off++] = dcid_len;
    std::memcpy(out + off, dcid, dcid_len);
    off += dcid_len;

    /* SCID */
    out[off++] = scid_len;
    std::memcpy(out + off, scid, scid_len);
    off += scid_len;

    /* Token Length (0 for client Initial) */
    std::memcpy(out + off, token_vi, token_vi_len);
    off += token_vi_len;

    /* Payload Length */
    std::memcpy(out + off, pl_vi, pl_vi_len);
    off += pl_vi_len;

    /* Packet Number */
    for (size_t i = 0; i < pn_bytes; ++i)
        out[off++] = static_cast<uint8_t>((pkt_num >> (8 * (pn_bytes - 1 - i))) & 0xFF);

    return off;
}

/* ── Header parser ────────────────────────────────────────────────── */

ParseResult parse_initial_header(const uint8_t *buf, size_t len) {
    ParseResult r{};
    if (len < 7)
        return r;

    /* First byte checks */
    const uint8_t fb = buf[0];
    if ((fb & 0xC0) != 0xC0)
        return r; /* not a long-header Initial */
    const uint8_t pn_len_field = fb & 0x03;
    const size_t pn_bytes = static_cast<size_t>(pn_len_field) + 1;

    /* Version must be QUIC v1 */
    if (buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0x00 || buf[4] != 0x01)
        return r;

    size_t off = 5; /* len >= 7 guaranteed by the guard above */

    /* DCID */
    r.dcid_len = buf[off++];
    if (r.dcid_len > 20 || off + r.dcid_len > len)
        return r;
    std::memcpy(r.dcid, buf + off, r.dcid_len);
    off += r.dcid_len;

    /* SCID */
    if (off >= len)
        return r;
    r.scid_len = buf[off++];
    if (r.scid_len > 20 || off + r.scid_len > len)
        return r;
    std::memcpy(r.scid, buf + off, r.scid_len);
    off += r.scid_len;

    /* Token Length */
    uint64_t tok_len = 0;
    size_t vi = decode_varint(buf + off, len - off, &tok_len);
    if (vi == 0)
        return r;
    off += vi;
    if (tok_len > 0) {
        if (off + tok_len > len)
            return r;
        off += static_cast<size_t>(tok_len);
    }

    /* Payload Length */
    uint64_t pay_len = 0;
    vi = decode_varint(buf + off, len - off, &pay_len);
    if (vi == 0)
        return r;
    off += vi;

    /* Packet Number */
    if (off + pn_bytes > len)
        return r;
    r.pkt_num = 0;
    for (size_t i = 0; i < pn_bytes; ++i)
        r.pkt_num = (r.pkt_num << 8) | buf[off++];

    r.header_len = off;
    r.payload_offset = off;
    if (pay_len >= pn_bytes)
        r.payload_len = static_cast<size_t>(pay_len) - pn_bytes;
    else
        r.payload_len = 0;
    r.valid = true;
    return r;
}

} /* namespace tachyon::transport */
