/* SPDX-License-Identifier: MIT */
#include "stun_mimic.h"

#include <cstring>

namespace tachyon::stun_mimic {

/* ── CRC32 (ISO 3309 polynomial, same as Ethernet) ────────────────── */

static uint32_t crc32_table[256];
static bool crc32_inited = false;

static void crc32_init() {
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_inited = true;
}

static uint32_t crc32_compute(const uint8_t *data, size_t len) {
    if (!crc32_inited)
        crc32_init();
    uint32_t c = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i)
        c = crc32_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFF;
}

uint32_t stun_fingerprint(const uint8_t *msg, size_t len) {
    return crc32_compute(msg, len) ^ 0x5354554Eu;
}

/* ── Helpers ──────────────────────────────────────────────────────── */

static inline void put_u16(uint8_t *p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v & 0xFF);
}

static inline void put_u32(uint8_t *p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
}

static inline uint16_t get_u16(const uint8_t *p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

static inline uint32_t get_u32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

/* Attribute padding to 4-byte boundary */
static inline size_t pad4(size_t n) { return (n + 3) & ~static_cast<size_t>(3); }

/* ── Builder ──────────────────────────────────────────────────────── */

size_t build_stun_message(uint8_t *out, size_t cap, uint16_t msg_type,
                          const uint8_t txn_id[12],
                          const uint8_t *payload, size_t payload_len) {
    if (payload_len > STUN_MAX_PAYLOAD)
        return 0;

    const size_t data_attr_len   = STUN_ATTR_HEADER + pad4(payload_len);
    const size_t fp_attr_len     = STUN_ATTR_HEADER + 4; /* FINGERPRINT = 4 bytes */
    const size_t body_len        = data_attr_len + fp_attr_len;
    const size_t total           = STUN_HEADER_LEN + body_len;
    if (total > cap)
        return 0;

    size_t off = 0;

    /* STUN header */
    put_u16(out + off, msg_type); off += 2;
    put_u16(out + off, static_cast<uint16_t>(body_len)); off += 2;
    put_u32(out + off, STUN_MAGIC_COOKIE); off += 4;
    std::memcpy(out + off, txn_id, 12); off += 12;

    /* DATA attribute */
    put_u16(out + off, ATTR_DATA); off += 2;
    put_u16(out + off, static_cast<uint16_t>(payload_len)); off += 2;
    std::memcpy(out + off, payload, payload_len); off += payload_len;
    /* Padding to 4-byte boundary */
    const size_t pad = pad4(payload_len) - payload_len;
    if (pad > 0) {
        std::memset(out + off, 0, pad);
        off += pad;
    }

    /* FINGERPRINT attribute — computed over everything before it.
     * Per RFC 8489 §14.7, the message length in the header for CRC
     * computation includes the FINGERPRINT attribute itself (8 bytes). */
    put_u16(out + off, ATTR_FINGERPRINT);
    put_u16(out + off + 2, 4);
    const uint32_t fp = stun_fingerprint(out, off);
    put_u32(out + off + 4, fp);
    off += 8;

    return off;
}

/* ── Parser ───────────────────────────────────────────────────────── */

StunParseResult parse_stun_message(const uint8_t *buf, size_t len) {
    StunParseResult r{};
    if (len < STUN_HEADER_LEN)
        return r;

    /* STUN messages have the top two bits = 00 */
    if ((buf[0] & 0xC0) != 0x00)
        return r;

    r.msg_type = get_u16(buf);
    const uint16_t body_len = get_u16(buf + 2);
    if (get_u32(buf + 4) != STUN_MAGIC_COOKIE)
        return r;
    std::memcpy(r.txn_id, buf + 8, 12);

    if (STUN_HEADER_LEN + body_len > len)
        return r;

    /* Scan attributes for DATA */
    size_t off = STUN_HEADER_LEN;
    const size_t end = STUN_HEADER_LEN + body_len;
    while (off + STUN_ATTR_HEADER <= end) {
        const uint16_t atype = get_u16(buf + off);
        const uint16_t alen  = get_u16(buf + off + 2);
        if (off + STUN_ATTR_HEADER + alen > end)
            break;
        if (atype == ATTR_DATA) {
            r.data_offset = off + STUN_ATTR_HEADER;
            r.data_len    = alen;
            r.ok          = true;
            return r;
        }
        off += STUN_ATTR_HEADER + pad4(alen);
    }
    return r; /* no DATA attribute found */
}

/* ── Transport engine ─────────────────────────────────────────────── */

static tachyon::transport::FrameResult
stun_wrap(const uint8_t *payload, size_t payload_len, uint8_t *out, size_t out_cap,
          const tachyon::transport::FrameContext *ctx) {
    using tachyon::transport::FrameResult;
    if (!payload || !out || !ctx)
        return {0, false};
    /* Use conn_id as transaction ID (first 12 bytes, or zero-pad) */
    uint8_t txn_id[12] = {};
    const size_t copy = ctx->conn_id_len < 12 ? ctx->conn_id_len : 12;
    std::memcpy(txn_id, ctx->conn_id, copy);

    const uint16_t type = (ctx->seq == 0) ? STUN_BINDING_REQ : STUN_DATA_IND;
    const size_t n = build_stun_message(out, out_cap, type, txn_id, payload, payload_len);
    return {n, n > 0};
}

static tachyon::transport::FrameResult
stun_unwrap(const uint8_t *frame, size_t frame_len, uint8_t *out, size_t out_cap) {
    using tachyon::transport::FrameResult;
    const auto r = parse_stun_message(frame, frame_len);
    if (!r.ok || r.data_len > out_cap || r.data_offset + r.data_len > frame_len)
        return {0, false};
    std::memcpy(out, frame + r.data_offset, r.data_len);
    return {r.data_len, true};
}

static int stun_score(const tachyon::transport::EnvProfile &env) {
    int s = 40;
    if (env.udp) s += 20;
    if (env.port == 3478 || env.port == 19302) s += 30;
    if (env.port == 443) s += 5;
    if (env.region == tachyon::transport::RegionHint::RESTRICTIVE) s += 15;
    if (env.bandwidth == tachyon::transport::BandwidthTier::LOW) s += 5;
    return s;
}

static const tachyon::transport::TransportOps stun_ops = {
    tachyon::transport::TransportId::STUN,
    "stun",
    STUN_OVERHEAD,
    STUN_MAX_PAYLOAD,
    stun_wrap,
    stun_unwrap,
    stun_score,
};

void register_transport() { tachyon::transport::transport_register(&stun_ops); }

} /* namespace tachyon::stun_mimic */
