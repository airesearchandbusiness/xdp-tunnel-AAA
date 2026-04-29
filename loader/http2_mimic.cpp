/* SPDX-License-Identifier: MIT */
#include "http2_mimic.h"

#include <cstring>

namespace tachyon::http2_mimic {

/* ── Frame header ─────────────────────────────────────────────────── */

size_t build_frame_header(uint8_t out[H2_FRAME_HEADER], uint32_t length,
                          uint8_t type, uint8_t flags, uint32_t stream_id) {
    out[0] = static_cast<uint8_t>((length >> 16) & 0xFF);
    out[1] = static_cast<uint8_t>((length >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>(length & 0xFF);
    out[3] = type;
    out[4] = flags;
    out[5] = static_cast<uint8_t>((stream_id >> 24) & 0x7F); /* R=0 */
    out[6] = static_cast<uint8_t>((stream_id >> 16) & 0xFF);
    out[7] = static_cast<uint8_t>((stream_id >> 8) & 0xFF);
    out[8] = static_cast<uint8_t>(stream_id & 0xFF);
    return H2_FRAME_HEADER;
}

FrameHeader parse_frame_header(const uint8_t *buf, size_t len) {
    FrameHeader h{};
    if (len < H2_FRAME_HEADER)
        return h;
    h.length    = (static_cast<uint32_t>(buf[0]) << 16) |
                  (static_cast<uint32_t>(buf[1]) << 8) | buf[2];
    h.type      = buf[3];
    h.flags     = buf[4];
    h.stream_id = (static_cast<uint32_t>(buf[5] & 0x7F) << 24) |
                  (static_cast<uint32_t>(buf[6]) << 16) |
                  (static_cast<uint32_t>(buf[7]) << 8) | buf[8];
    h.ok = true;
    return h;
}

/* ── Connection preface ───────────────────────────────────────────── */

/* PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n */
static constexpr uint8_t CLIENT_PREFACE[H2_PREFACE_LEN] = {
    0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54,
    0x54, 0x50, 0x2F, 0x32, 0x2E, 0x30, 0x0D, 0x0A,
    0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A,
};

/* Chrome-like SETTINGS (6 bytes per param × 4 params = 24 bytes payload):
 *   HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0,
 *   INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144 */
static constexpr uint8_t SETTINGS_PAYLOAD[] = {
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, /* HEADER_TABLE_SIZE=65536 */
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, /* ENABLE_PUSH=0 */
    0x00, 0x04, 0x00, 0x60, 0x00, 0x00, /* INITIAL_WINDOW_SIZE=6291456 */
    0x00, 0x06, 0x00, 0x04, 0x00, 0x00, /* MAX_HEADER_LIST_SIZE=262144 */
};

size_t build_connection_preface(uint8_t *out, size_t cap) {
    const size_t need = H2_PREFACE_LEN + H2_FRAME_HEADER + sizeof(SETTINGS_PAYLOAD);
    if (cap < need)
        return 0;
    std::memcpy(out, CLIENT_PREFACE, H2_PREFACE_LEN);
    build_frame_header(out + H2_PREFACE_LEN, sizeof(SETTINGS_PAYLOAD), H2_SETTINGS, 0, 0);
    std::memcpy(out + H2_PREFACE_LEN + H2_FRAME_HEADER, SETTINGS_PAYLOAD,
                sizeof(SETTINGS_PAYLOAD));
    return need;
}

/* ── HEADERS frame ────────────────────────────────────────────────── */

/* HPACK static-table-only pseudo headers for GET / https. Entries:
 *   :method: GET     → static index 2  (0x82)
 *   :path: /         → static index 4  (0x84)
 *   :scheme: https   → static index 7  (0x87)
 *   :authority: <authority> → indexed name 1 (0x41) + literal value
 * We intentionally avoid Huffman encoding and dynamic-table updates
 * to keep the implementation deterministic and tiny. */

size_t build_headers_frame(uint8_t *out, size_t cap, const char *authority,
                           uint32_t stream_id) {
    if (!authority)
        authority = "www.example.com";
    const size_t auth_len = std::strlen(authority);
    if (auth_len > 253)
        return 0;

    /* HPACK field block: 3 indexed + 1 literal-with-indexed-name */
    const size_t block_len = 3 + 2 + auth_len; /* 0x82,0x84,0x87 + 0x41,len + value */
    const size_t total = H2_FRAME_HEADER + block_len;
    if (total > cap)
        return 0;

    size_t off = build_frame_header(out, static_cast<uint32_t>(block_len), H2_HEADERS,
                                    H2_FLAG_END_HEADERS, stream_id);
    out[off++] = 0x82; /* :method GET */
    out[off++] = 0x84; /* :path / */
    out[off++] = 0x87; /* :scheme https */
    out[off++] = 0x41; /* :authority (indexed name 1) */
    out[off++] = static_cast<uint8_t>(auth_len); /* value length */
    std::memcpy(out + off, authority, auth_len);
    off += auth_len;
    return off;
}

/* ── DATA frame ───────────────────────────────────────────────────── */

size_t build_data_frame(uint8_t *out, size_t cap, const uint8_t *payload,
                        size_t payload_len, uint32_t stream_id) {
    if (payload_len > H2_MAX_PAYLOAD)
        return 0;
    const size_t total = H2_FRAME_HEADER + payload_len;
    if (total > cap)
        return 0;
    build_frame_header(out, static_cast<uint32_t>(payload_len), H2_DATA, 0, stream_id);
    std::memcpy(out + H2_FRAME_HEADER, payload, payload_len);
    return total;
}

/* ── Transport engine ─────────────────────────────────────────────── */

static tachyon::transport::FrameResult
http2_wrap(const uint8_t *payload, size_t payload_len, uint8_t *out, size_t out_cap,
           const tachyon::transport::FrameContext *ctx) {
    using tachyon::transport::FrameResult;
    if (!payload || !out || !ctx || payload_len > H2_MAX_PAYLOAD)
        return {0, false};

    const uint32_t sid = ctx->stream_id ? ctx->stream_id : 1;

    if (ctx->seq == 0) {
        /* First frame of session: emit preface + HEADERS + DATA */
        const size_t preface_len = build_connection_preface(out, out_cap);
        if (preface_len == 0)
            return {0, false};
        const size_t hdr_len = build_headers_frame(out + preface_len,
                                                   out_cap - preface_len, ctx->sni, sid);
        if (hdr_len == 0)
            return {0, false};
        const size_t data_len = build_data_frame(out + preface_len + hdr_len,
                                                 out_cap - preface_len - hdr_len,
                                                 payload, payload_len, sid);
        if (data_len == 0)
            return {0, false};
        return {preface_len + hdr_len + data_len, true};
    }

    /* Subsequent frames: DATA only */
    const size_t n = build_data_frame(out, out_cap, payload, payload_len, sid);
    return {n, n > 0};
}

static tachyon::transport::FrameResult
http2_unwrap(const uint8_t *frame, size_t frame_len, uint8_t *out, size_t out_cap) {
    using tachyon::transport::FrameResult;
    /* Scan forward past any non-DATA frames until we find the first DATA. */
    size_t off = 0;

    /* Skip connection preface if present */
    if (frame_len >= H2_PREFACE_LEN &&
        std::memcmp(frame, CLIENT_PREFACE, H2_PREFACE_LEN) == 0)
        off += H2_PREFACE_LEN;

    while (off + H2_FRAME_HEADER <= frame_len) {
        const auto h = parse_frame_header(frame + off, frame_len - off);
        if (!h.ok)
            return {0, false};
        if (h.type == H2_DATA) {
            if (off + H2_FRAME_HEADER + h.length > frame_len)
                return {0, false};
            if (h.length > out_cap)
                return {0, false};
            std::memcpy(out, frame + off + H2_FRAME_HEADER, h.length);
            return {h.length, true};
        }
        off += H2_FRAME_HEADER + h.length;
    }
    return {0, false};
}

static int http2_score(const tachyon::transport::EnvProfile &env) {
    int s = 50;
    if (env.port == 443 || env.port == 8443) s += 25;
    if (env.region == tachyon::transport::RegionHint::RESTRICTIVE) s += 10;
    if (env.bandwidth == tachyon::transport::BandwidthTier::HIGH) s += 10;
    if (!env.udp) s += 15; /* HTTP/2 is TCP-native */
    return s;
}

static const tachyon::transport::TransportOps http2_ops = {
    tachyon::transport::TransportId::HTTP2,
    "http2",
    H2_FRAME_HEADER,
    H2_MAX_PAYLOAD,
    http2_wrap,
    http2_unwrap,
    http2_score,
};

void register_transport() { tachyon::transport::transport_register(&http2_ops); }

} /* namespace tachyon::http2_mimic */
