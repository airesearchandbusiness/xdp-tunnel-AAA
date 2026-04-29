/* SPDX-License-Identifier: MIT */
#include "quic_mimic.h"

#include <cstring>
#include <openssl/rand.h>

namespace tachyon::quic_mimic {

/* ── Variable-length integer (RFC 9000 §16) ───────────────────────── */

static size_t varint_encode(uint8_t *out, uint64_t val) {
    if (val <= 63) {
        out[0] = static_cast<uint8_t>(val);
        return 1;
    }
    if (val <= 16383) {
        out[0] = static_cast<uint8_t>(0x40 | (val >> 8));
        out[1] = static_cast<uint8_t>(val & 0xFF);
        return 2;
    }
    if (val <= 1073741823ULL) {
        out[0] = static_cast<uint8_t>(0x80 | (val >> 24));
        out[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
        out[2] = static_cast<uint8_t>((val >> 8) & 0xFF);
        out[3] = static_cast<uint8_t>(val & 0xFF);
        return 4;
    }
    out[0] = static_cast<uint8_t>(0xC0 | (val >> 56));
    for (int i = 1; i < 8; ++i)
        out[i] = static_cast<uint8_t>((val >> (56 - 8 * i)) & 0xFF);
    return 8;
}

static size_t varint_decode(const uint8_t *buf, size_t len, uint64_t *out) {
    if (len == 0)
        return 0;
    const uint8_t prefix = buf[0] >> 6;
    const size_t  width  = 1u << prefix;
    if (len < width)
        return 0;
    uint64_t val = buf[0] & 0x3F;
    for (size_t i = 1; i < width; ++i)
        val = (val << 8) | buf[i];
    *out = val;
    return width;
}

/* ── Header builder ───────────────────────────────────────────────── */

size_t build_initial_header(uint8_t *out, size_t cap,
                            const uint8_t *dcid, uint8_t dcid_len,
                            const uint8_t *scid, uint8_t scid_len,
                            uint32_t pkt_num, size_t payload_len) {
    if (dcid_len > 20 || scid_len > 20)
        return 0;

    /* Determine packet-number length (1–4 bytes) */
    uint8_t pn_len_field;
    size_t  pn_bytes;
    if (pkt_num <= 0xFF)           { pn_len_field = 0; pn_bytes = 1; }
    else if (pkt_num <= 0xFFFF)    { pn_len_field = 1; pn_bytes = 2; }
    else if (pkt_num <= 0xFFFFFF)  { pn_len_field = 2; pn_bytes = 3; }
    else                           { pn_len_field = 3; pn_bytes = 4; }

    /* Token Length = 0 for client Initial */
    uint8_t token_vi[1] = {0};
    const size_t token_vi_len = 1;

    /* Payload Length = pn_bytes + payload_len (varint-encoded) */
    uint8_t pl_vi[8];
    const size_t pl_vi_len = varint_encode(pl_vi, pn_bytes + payload_len);

    const size_t hdr_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + token_vi_len +
                           pl_vi_len + pn_bytes;
    if (hdr_len > cap)
        return 0;

    size_t off = 0;

    /* First byte: form=1, fixed=1, type=00 (Initial), reserved=00, pn_len */
    out[off++] = static_cast<uint8_t>(0xC0 | pn_len_field);

    /* Version */
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x01;

    /* DCID */
    out[off++] = dcid_len;
    if (dcid && dcid_len > 0)
        std::memcpy(out + off, dcid, dcid_len);
    off += dcid_len;

    /* SCID */
    out[off++] = scid_len;
    if (scid && scid_len > 0)
        std::memcpy(out + off, scid, scid_len);
    off += scid_len;

    /* Token Length (0) */
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

    size_t off = 5;

    /* DCID */
    if (off >= len) return r;
    r.dcid_len = buf[off++];
    if (r.dcid_len > 20 || off + r.dcid_len > len) return r;
    std::memcpy(r.dcid, buf + off, r.dcid_len);
    off += r.dcid_len;

    /* SCID */
    if (off >= len) return r;
    r.scid_len = buf[off++];
    if (r.scid_len > 20 || off + r.scid_len > len) return r;
    std::memcpy(r.scid, buf + off, r.scid_len);
    off += r.scid_len;

    /* Token Length */
    uint64_t token_len;
    const size_t tl = varint_decode(buf + off, len - off, &token_len);
    if (tl == 0) return r;
    off += tl;
    if (off + token_len > len) return r;
    off += static_cast<size_t>(token_len);

    /* Payload Length */
    uint64_t payload_with_pn;
    const size_t pl = varint_decode(buf + off, len - off, &payload_with_pn);
    if (pl == 0) return r;
    off += pl;

    /* Packet Number */
    if (off + pn_bytes > len) return r;
    r.pkt_num = 0;
    for (size_t i = 0; i < pn_bytes; ++i)
        r.pkt_num = (r.pkt_num << 8) | buf[off + i];
    off += pn_bytes;

    r.payload_offset = off;
    if (payload_with_pn >= pn_bytes)
        r.payload_len = static_cast<size_t>(payload_with_pn) - pn_bytes;
    else
        r.payload_len = 0;
    if (r.payload_offset + r.payload_len > len)
        r.payload_len = len - r.payload_offset;

    r.ok = true;
    return r;
}

/* ── Transport engine ─────────────────────────────────────────────── */

static tachyon::transport::FrameResult
quic_wrap(const uint8_t *payload, size_t payload_len,
          uint8_t *out, size_t out_cap,
          const tachyon::transport::FrameContext *ctx) {
    using tachyon::transport::FrameResult;
    if (!payload || !out || !ctx)
        return {0, false};

    const size_t hdr = build_initial_header(out, out_cap, ctx->conn_id, ctx->conn_id_len,
                                            nullptr, 0, ctx->seq, payload_len);
    if (hdr == 0)
        return {0, false};

    const size_t total_before_pad = hdr + payload_len;
    if (total_before_pad > out_cap)
        return {0, false};

    std::memcpy(out + hdr, payload, payload_len);

    /* Pad to QUIC_MIN_INITIAL (1200) per RFC 9000 §14.1 */
    size_t total = total_before_pad;
    if (total < QUIC_MIN_INITIAL && out_cap >= QUIC_MIN_INITIAL) {
        std::memset(out + total, 0, QUIC_MIN_INITIAL - total);
        total = QUIC_MIN_INITIAL;
    }
    return {total, true};
}

static tachyon::transport::FrameResult
quic_unwrap(const uint8_t *frame, size_t frame_len, uint8_t *out, size_t out_cap) {
    using tachyon::transport::FrameResult;
    const auto r = parse_initial_header(frame, frame_len);
    if (!r.ok)
        return {0, false};
    if (r.payload_len > out_cap || r.payload_offset + r.payload_len > frame_len)
        return {0, false};
    std::memcpy(out, frame + r.payload_offset, r.payload_len);
    return {r.payload_len, true};
}

static int quic_score(const tachyon::transport::EnvProfile &env) {
    if (!env.udp) return 0; /* QUIC is UDP only */
    int s = 60;
    if (env.port == 443) s += 20;
    if (env.region == tachyon::transport::RegionHint::RESTRICTIVE) s -= 15;
    if (env.bandwidth == tachyon::transport::BandwidthTier::LOW) s -= 10;
    return s > 0 ? s : 1;
}

static const tachyon::transport::TransportOps quic_ops = {
    tachyon::transport::TransportId::QUIC,
    "quic",
    QUIC_HEADER_MAX,
    QUIC_MAX_PAYLOAD,
    quic_wrap,
    quic_unwrap,
    quic_score,
};

void register_transport() { tachyon::transport::transport_register(&quic_ops); }

} /* namespace tachyon::quic_mimic */
