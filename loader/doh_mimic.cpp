/* SPDX-License-Identifier: MIT */
#include "doh_mimic.h"

#include <cstring>

namespace tachyon::doh_mimic {

/* ── DNS label encoding ───────────────────────────────────────────── */

size_t encode_qname(uint8_t *out, size_t cap, const char *domain) {
    if (!domain || !*domain)
        return 0;
    const size_t dlen = std::strlen(domain);
    if (dlen + 2 > cap) /* worst case: one label + trailing null */
        return 0;

    size_t off = 0;
    const char *p = domain;
    while (*p) {
        const char *dot = std::strchr(p, '.');
        size_t label_len = dot ? static_cast<size_t>(dot - p) : std::strlen(p);
        if (label_len == 0 || label_len > 63 || off + 1 + label_len + 1 > cap)
            return 0;
        out[off++] = static_cast<uint8_t>(label_len);
        std::memcpy(out + off, p, label_len);
        off += label_len;
        p += label_len;
        if (*p == '.')
            ++p;
    }
    out[off++] = 0x00; /* root label */
    return off;
}

/* ── TXT RDATA encoding ───────────────────────────────────────────── */

/* TXT records use character-string encoding: each ≤255 byte chunk is
 * preceded by a 1-byte length. */
static size_t txt_rdata_len(size_t payload_len) {
    const size_t full_chunks = payload_len / 255;
    const size_t remainder   = payload_len % 255;
    return full_chunks * 256 + (remainder ? 1 + remainder : 0);
}

static size_t encode_txt_rdata(uint8_t *out, size_t cap, const uint8_t *data, size_t len) {
    const size_t need = txt_rdata_len(len);
    if (need > cap)
        return 0;
    size_t off = 0, src = 0;
    while (src < len) {
        const size_t chunk = (len - src > 255) ? 255 : (len - src);
        out[off++] = static_cast<uint8_t>(chunk);
        std::memcpy(out + off, data + src, chunk);
        off += chunk;
        src += chunk;
    }
    return off;
}

/* ── DNS message builder ──────────────────────────────────────────── */

size_t build_dns_message(uint8_t *out, size_t cap, uint16_t txn_id,
                         const char *qname, const uint8_t *payload, size_t payload_len) {
    if (payload_len > DOH_MAX_PAYLOAD)
        return 0;
    if (!qname)
        qname = "dns.google";

    /* Encode QNAME first to know its length */
    uint8_t qname_buf[256];
    const size_t qname_len = encode_qname(qname_buf, sizeof(qname_buf), qname);
    if (qname_len == 0)
        return 0;

    const size_t rdata_len = txt_rdata_len(payload_len);
    /* answer name (2 bytes, pointer to question QNAME) + TYPE(2) + CLASS(2) +
     * TTL(4) + RDLENGTH(2) + RDATA */
    const size_t answer_len = 2 + 2 + 2 + 4 + 2 + rdata_len;
    /* question = QNAME + QTYPE(2) + QCLASS(2) */
    const size_t question_len = qname_len + 4;
    const size_t total = DNS_HEADER_LEN + question_len + answer_len;
    if (total > cap)
        return 0;

    size_t off = 0;

    /* Header: response with one question and one answer */
    out[off++] = static_cast<uint8_t>(txn_id >> 8);
    out[off++] = static_cast<uint8_t>(txn_id & 0xFF);
    out[off++] = 0x81; /* QR=1 (response), Opcode=0, AA=0, TC=0, RD=1 */
    out[off++] = 0x80; /* RA=1, Z=0, RCODE=0 (no error) */
    out[off++] = 0x00; out[off++] = 0x01; /* QDCOUNT=1 */
    out[off++] = 0x00; out[off++] = 0x01; /* ANCOUNT=1 */
    out[off++] = 0x00; out[off++] = 0x00; /* NSCOUNT=0 */
    out[off++] = 0x00; out[off++] = 0x00; /* ARCOUNT=0 */

    /* Question section */
    std::memcpy(out + off, qname_buf, qname_len);
    off += qname_len;
    out[off++] = 0x00; out[off++] = 0x10; /* QTYPE=TXT */
    out[off++] = 0x00; out[off++] = 0x01; /* QCLASS=IN */

    /* Answer section: name pointer + TYPE/CLASS/TTL/RDLENGTH + RDATA */
    out[off++] = 0xC0; /* pointer to offset 12 (start of QNAME) */
    out[off++] = 0x0C;
    out[off++] = 0x00; out[off++] = 0x10; /* TYPE=TXT */
    out[off++] = 0x00; out[off++] = 0x01; /* CLASS=IN */
    out[off++] = 0x00; out[off++] = 0x00; /* TTL=300 */
    out[off++] = 0x01; out[off++] = 0x2C;
    out[off++] = static_cast<uint8_t>(rdata_len >> 8);
    out[off++] = static_cast<uint8_t>(rdata_len & 0xFF);

    const size_t rw = encode_txt_rdata(out + off, cap - off, payload, payload_len);
    if (rw == 0 && payload_len > 0)
        return 0;
    off += rw;

    return off;
}

/* ── DNS message parser ───────────────────────────────────────────── */

/* Skip a DNS name (labels or pointer). */
static size_t skip_name(const uint8_t *buf, size_t len, size_t off) {
    while (off < len) {
        const uint8_t label = buf[off];
        if (label == 0) { return off + 1; }
        if ((label & 0xC0) == 0xC0) { return off + 2; } /* pointer */
        off += 1 + label;
    }
    return 0; /* truncated */
}

DnsParseResult parse_dns_message(const uint8_t *buf, size_t len) {
    DnsParseResult r{};
    if (len < DNS_HEADER_LEN)
        return r;

    const uint16_t qdcount = (static_cast<uint16_t>(buf[4]) << 8) | buf[5];
    const uint16_t ancount = (static_cast<uint16_t>(buf[6]) << 8) | buf[7];
    if (ancount == 0)
        return r;

    /* Skip question section */
    size_t off = DNS_HEADER_LEN;
    for (uint16_t i = 0; i < qdcount; ++i) {
        off = skip_name(buf, len, off);
        if (off == 0 || off + 4 > len) return r;
        off += 4; /* QTYPE + QCLASS */
    }

    /* Scan answers for TXT record */
    for (uint16_t i = 0; i < ancount; ++i) {
        off = skip_name(buf, len, off);
        if (off == 0 || off + 10 > len) return r;
        const uint16_t rtype = (static_cast<uint16_t>(buf[off]) << 8) | buf[off + 1];
        off += 8; /* TYPE(2) + CLASS(2) + TTL(4) */
        const uint16_t rdlength = (static_cast<uint16_t>(buf[off]) << 8) | buf[off + 1];
        off += 2;
        if (off + rdlength > len) return r;

        if (rtype == 0x0010) { /* TXT */
            /* Decode character strings into payload */
            r.payload_offset = off;
            r.payload_len    = 0;
            size_t roff      = off;
            const size_t rend = off + rdlength;
            while (roff < rend) {
                const uint8_t slen = buf[roff++];
                if (roff + slen > rend) return r;
                r.payload_len += slen;
                roff += slen;
            }
            r.ok = true;
            return r;
        }
        off += rdlength;
    }
    return r;
}

/* ── Transport engine ─────────────────────────────────────────────── */

static tachyon::transport::FrameResult
doh_wrap(const uint8_t *payload, size_t payload_len, uint8_t *out, size_t out_cap,
         const tachyon::transport::FrameContext *ctx) {
    using tachyon::transport::FrameResult;
    if (!payload || !out || !ctx)
        return {0, false};
    const uint16_t txn_id = static_cast<uint16_t>(ctx->seq & 0xFFFF);
    const char *qname = ctx->sni ? ctx->sni : "dns.google";
    const size_t n = build_dns_message(out, out_cap, txn_id, qname, payload, payload_len);
    return {n, n > 0};
}

static tachyon::transport::FrameResult
doh_unwrap(const uint8_t *frame, size_t frame_len, uint8_t *out, size_t out_cap) {
    using tachyon::transport::FrameResult;
    const auto r = parse_dns_message(frame, frame_len);
    if (!r.ok || r.payload_len > out_cap)
        return {0, false};

    /* Re-decode character strings, stripping length prefixes */
    size_t roff = r.payload_offset;
    size_t woff = 0;
    while (woff < r.payload_len && roff < frame_len) {
        const uint8_t slen = frame[roff++];
        if (roff + slen > frame_len || woff + slen > out_cap)
            return {0, false};
        std::memcpy(out + woff, frame + roff, slen);
        woff += slen;
        roff += slen;
    }
    return {woff, true};
}

static int doh_score(const tachyon::transport::EnvProfile &env) {
    int s = 45;
    if (env.port == 443) s += 20;
    if (env.port == 853) s += 15;
    if (env.region == tachyon::transport::RegionHint::RESTRICTIVE) s += 20;
    if (env.bandwidth == tachyon::transport::BandwidthTier::LOW) s += 10;
    return s;
}

static const tachyon::transport::TransportOps doh_ops = {
    tachyon::transport::TransportId::DOH,
    "doh",
    DOH_OVERHEAD,
    DOH_MAX_PAYLOAD,
    doh_wrap,
    doh_unwrap,
    doh_score,
};

void register_transport() { tachyon::transport::transport_register(&doh_ops); }

} /* namespace tachyon::doh_mimic */
