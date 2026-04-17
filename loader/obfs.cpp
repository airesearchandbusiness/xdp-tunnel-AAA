/* SPDX-License-Identifier: MIT */
#include "obfs.h"

#include <cstring>
#include <openssl/rand.h>

namespace tachyon::obfs {

Mode mode_from_string(const char *s) {
    if (!s || !*s)
        return Mode::NONE;
    if (!strcasecmp(s, "none") || !strcasecmp(s, "off") || !strcasecmp(s, "false"))
        return Mode::NONE;
    if (!strcasecmp(s, "quic"))
        return Mode::QUIC;
    if (!strcasecmp(s, "reality") || !strcasecmp(s, "tls"))
        return Mode::REALITY;
    return Mode::NONE;
}

const char *mode_to_string(Mode m) {
    switch (m) {
    case Mode::NONE:
        return "none";
    case Mode::QUIC:
        return "quic";
    case Mode::REALITY:
        return "reality";
    }
    return "none";
}

/* ── Byte writer helper ─────────────────────────────────────────────────── */

namespace {

struct Writer {
    uint8_t *buf;
    size_t cap;
    size_t pos;

    bool put_u8(uint8_t v) {
        if (pos + 1 > cap)
            return false;
        buf[pos++] = v;
        return true;
    }
    bool put_u16(uint16_t v) {
        if (pos + 2 > cap)
            return false;
        buf[pos++] = static_cast<uint8_t>(v >> 8);
        buf[pos++] = static_cast<uint8_t>(v);
        return true;
    }
    bool put_u24(uint32_t v) {
        if (pos + 3 > cap)
            return false;
        buf[pos++] = static_cast<uint8_t>(v >> 16);
        buf[pos++] = static_cast<uint8_t>(v >> 8);
        buf[pos++] = static_cast<uint8_t>(v);
        return true;
    }
    bool put_bytes(const uint8_t *src, size_t len) {
        if (pos + len > cap)
            return false;
        memcpy(buf + pos, src, len);
        pos += len;
        return true;
    }
    /* Fix up a previously-written big-endian u16 length field */
    void patch_u16(size_t at, uint16_t v) {
        buf[at] = static_cast<uint8_t>(v >> 8);
        buf[at + 1] = static_cast<uint8_t>(v);
    }
    void patch_u24(size_t at, uint32_t v) {
        buf[at] = static_cast<uint8_t>(v >> 16);
        buf[at + 1] = static_cast<uint8_t>(v >> 8);
        buf[at + 2] = static_cast<uint8_t>(v);
    }
};

/* Modern Chrome-like cipher suite list (5 real + 1 GREASE) */
constexpr uint16_t CIPHER_SUITES[] = {
    0x1301, /* TLS_AES_128_GCM_SHA256 */
    0x1302, /* TLS_AES_256_GCM_SHA384 */
    0x1303, /* TLS_CHACHA20_POLY1305_SHA256 */
    0xc02b, /* ECDHE-ECDSA-AES128-GCM-SHA256 */
    0xc02f, /* ECDHE-RSA-AES128-GCM-SHA256 */
};

constexpr uint16_t NAMED_GROUPS[] = {
    0x001d, /* x25519 */
    0x0017, /* secp256r1 */
    0x0018, /* secp384r1 */
};

/* Extension IDs we emit (order matches Chrome fingerprint) */
constexpr uint16_t EXT_SERVER_NAME = 0x0000;
constexpr uint16_t EXT_SUPPORTED_VERSIONS = 0x002b;
constexpr uint16_t EXT_SUPPORTED_GROUPS = 0x000a;
constexpr uint16_t EXT_SIGNATURE_ALGORITHMS = 0x000d;
constexpr uint16_t EXT_ALPN = 0x0010;
constexpr uint16_t EXT_KEY_SHARE = 0x0033;

} /* namespace */

/* ── GREASE helpers ─────────────────────────────────────────────────────── */

bool is_grease_codepoint(uint16_t v) {
    /* GREASE values are 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA (16 values) */
    if ((v & 0x0F0F) != 0x0A0A)
        return false;
    if ((v >> 8) != (v & 0xFF))
        return false;
    return true;
}

uint16_t pick_grease() {
    uint8_t r;
    RAND_bytes(&r, 1);
    const uint8_t nib = r & 0x0F;
    const uint8_t byte = static_cast<uint8_t>((nib << 4) | 0x0A);
    return static_cast<uint16_t>((static_cast<uint16_t>(byte) << 8) | byte);
}

/* ── ClientHello builder ────────────────────────────────────────────────── */

size_t build_client_hello(uint8_t *out, size_t out_cap, const Options &opts) {
    if (!out || out_cap < MAX_RECORD_LEN || !opts.sni || !opts.client_random ||
        !opts.session_id)
        return 0;

    Writer w{out, out_cap, 0};

    /* TLS record header (will patch length after body is written) */
    if (!w.put_u8(0x16))         /* ContentType = handshake */
        return 0;
    if (!w.put_u16(0x0303))       /* legacy_record_version = TLS 1.2 */
        return 0;
    const size_t record_len_at = w.pos;
    if (!w.put_u16(0))            /* placeholder for record length */
        return 0;

    /* Handshake header */
    if (!w.put_u8(0x01))         /* HandshakeType = ClientHello */
        return 0;
    const size_t hs_len_at = w.pos;
    if (!w.put_u24(0))            /* placeholder for handshake length */
        return 0;

    /* ClientHello body */
    if (!w.put_u16(0x0303))       /* legacy_version = TLS 1.2 */
        return 0;
    if (!w.put_bytes(opts.client_random, 32))
        return 0;

    /* legacy_session_id: TLS 1.3 uses 32-byte echo to look like session-resumption */
    if (!w.put_u8(32))
        return 0;
    if (!w.put_bytes(opts.session_id, 32))
        return 0;

    /* cipher_suites: GREASE + real suites */
    const uint16_t grease_cipher = pick_grease();
    const size_t cipher_list_len = 2 * (1 + sizeof(CIPHER_SUITES) / sizeof(CIPHER_SUITES[0]));
    if (!w.put_u16(static_cast<uint16_t>(cipher_list_len)))
        return 0;
    if (!w.put_u16(grease_cipher))
        return 0;
    for (auto cs : CIPHER_SUITES)
        if (!w.put_u16(cs))
            return 0;

    /* legacy_compression_methods: [0x01, 0x00] — "null" only */
    if (!w.put_u8(0x01))
        return 0;
    if (!w.put_u8(0x00))
        return 0;

    /* Extensions block — placeholder for length */
    const size_t ext_len_at = w.pos;
    if (!w.put_u16(0))
        return 0;
    const size_t ext_start = w.pos;

    /* GREASE first extension (RFC 8701 recommended placement) */
    if (!w.put_u16(pick_grease()))
        return 0;
    if (!w.put_u16(0))
        return 0;

    /* server_name extension */
    {
        const size_t sni_len = strlen(opts.sni);
        if (sni_len > 255)
            return 0;
        if (!w.put_u16(EXT_SERVER_NAME))
            return 0;
        const uint16_t body_len = static_cast<uint16_t>(2 + 1 + 2 + sni_len);
        if (!w.put_u16(body_len))
            return 0;
        if (!w.put_u16(static_cast<uint16_t>(1 + 2 + sni_len))) /* list length */
            return 0;
        if (!w.put_u8(0x00)) /* name_type = host_name */
            return 0;
        if (!w.put_u16(static_cast<uint16_t>(sni_len)))
            return 0;
        if (!w.put_bytes(reinterpret_cast<const uint8_t *>(opts.sni), sni_len))
            return 0;
    }

    /* supported_versions: TLS 1.3 only (plus GREASE) */
    if (!w.put_u16(EXT_SUPPORTED_VERSIONS))
        return 0;
    if (!w.put_u16(5))            /* ext body length */
        return 0;
    if (!w.put_u8(4))             /* list length */
        return 0;
    if (!w.put_u16(pick_grease()))
        return 0;
    if (!w.put_u16(0x0304))       /* TLS 1.3 */
        return 0;

    /* supported_groups */
    if (!w.put_u16(EXT_SUPPORTED_GROUPS))
        return 0;
    {
        const size_t count = sizeof(NAMED_GROUPS) / sizeof(NAMED_GROUPS[0]);
        const uint16_t body_len = static_cast<uint16_t>(2 + 2 + 2 * count);
        if (!w.put_u16(body_len))
            return 0;
        if (!w.put_u16(static_cast<uint16_t>(2 + 2 * count))) /* list length inc. GREASE */
            return 0;
        if (!w.put_u16(pick_grease()))
            return 0;
        for (auto g : NAMED_GROUPS)
            if (!w.put_u16(g))
                return 0;
    }

    /* signature_algorithms — Chrome's default set */
    {
        static const uint16_t sigalgs[] = {
            0x0403, /* ecdsa_secp256r1_sha256 */
            0x0804, /* rsa_pss_rsae_sha256 */
            0x0401, /* rsa_pkcs1_sha256 */
            0x0503, /* ecdsa_secp384r1_sha384 */
        };
        if (!w.put_u16(EXT_SIGNATURE_ALGORITHMS))
            return 0;
        const uint16_t body_len = static_cast<uint16_t>(2 + sizeof(sigalgs));
        if (!w.put_u16(body_len))
            return 0;
        if (!w.put_u16(static_cast<uint16_t>(sizeof(sigalgs))))
            return 0;
        for (auto s : sigalgs)
            if (!w.put_u16(s))
                return 0;
    }

    /* ALPN */
    if (opts.alpn_list && opts.alpn_list_len > 0) {
        if (!w.put_u16(EXT_ALPN))
            return 0;
        if (!w.put_u16(static_cast<uint16_t>(2 + opts.alpn_list_len)))
            return 0;
        if (!w.put_u16(static_cast<uint16_t>(opts.alpn_list_len)))
            return 0;
        if (!w.put_bytes(opts.alpn_list, opts.alpn_list_len))
            return 0;
    }

    /* key_share: x25519 only, with random 32-byte pubkey placeholder */
    {
        if (!w.put_u16(EXT_KEY_SHARE))
            return 0;
        const uint16_t body_len = 2 + 2 + 2 + 32;
        if (!w.put_u16(body_len))
            return 0;
        if (!w.put_u16(2 + 2 + 32))     /* shares list length */
            return 0;
        if (!w.put_u16(0x001d))          /* x25519 */
            return 0;
        if (!w.put_u16(32))
            return 0;
        uint8_t scratch[32];
        RAND_bytes(scratch, 32);
        if (!w.put_bytes(scratch, 32))
            return 0;
    }

    /* Patch ext length, handshake length, record length */
    const uint16_t ext_block = static_cast<uint16_t>(w.pos - ext_start);
    w.patch_u16(ext_len_at, ext_block);

    const uint32_t hs_len = static_cast<uint32_t>(w.pos - hs_len_at - 3);
    w.patch_u24(hs_len_at, hs_len);

    const uint16_t rec_len = static_cast<uint16_t>(w.pos - record_len_at - 2);
    w.patch_u16(record_len_at, rec_len);

    return w.pos;
}

/* ── Minimal SNI extraction (for tests/REALITY validator) ──────────────── */

int parse_client_hello_sni(const uint8_t *p, size_t len, char *out, size_t out_cap) {
    if (!p || len < 5 + 4 + 2 + 32 + 1)
        return -1;
    /* TLS record */
    if (p[0] != 0x16)
        return -1;
    const size_t rec_len = (static_cast<size_t>(p[3]) << 8) | p[4];
    if (5 + rec_len > len)
        return -1;

    const uint8_t *q = p + 5;
    const uint8_t *end = p + 5 + rec_len;
    if (q + 4 > end || q[0] != 0x01)
        return -1;
    const size_t hs_len = (static_cast<size_t>(q[1]) << 16) | (static_cast<size_t>(q[2]) << 8) | q[3];
    q += 4;
    if (q + hs_len > end)
        return -1;
    end = q + hs_len;

    /* legacy_version + random */
    if (q + 2 + 32 > end)
        return -1;
    q += 2 + 32;

    /* session_id */
    if (q >= end)
        return -1;
    const size_t sid_len = *q++;
    if (q + sid_len > end)
        return -1;
    q += sid_len;

    /* cipher_suites */
    if (q + 2 > end)
        return -1;
    const size_t cs_len = (static_cast<size_t>(q[0]) << 8) | q[1];
    q += 2;
    if (q + cs_len > end)
        return -1;
    q += cs_len;

    /* compression_methods */
    if (q >= end)
        return -1;
    const size_t comp_len = *q++;
    if (q + comp_len > end)
        return -1;
    q += comp_len;

    /* extensions */
    if (q + 2 > end)
        return -1;
    const size_t ext_len = (static_cast<size_t>(q[0]) << 8) | q[1];
    q += 2;
    if (q + ext_len > end)
        return -1;
    const uint8_t *ext_end = q + ext_len;

    while (q + 4 <= ext_end) {
        const uint16_t ext_type = static_cast<uint16_t>((q[0] << 8) | q[1]);
        const uint16_t ext_body = static_cast<uint16_t>((q[2] << 8) | q[3]);
        q += 4;
        if (q + ext_body > ext_end)
            return -1;
        if (ext_type == 0x0000) { /* server_name */
            if (ext_body < 5)
                return -1;
            /* server_name_list[] length prefix + first entry */
            const uint8_t *sq = q;
            sq += 2; /* list length */
            if (sq >= q + ext_body)
                return -1;
            const uint8_t name_type = *sq++;
            if (name_type != 0x00)
                return -1;
            if (sq + 2 > q + ext_body)
                return -1;
            const size_t name_len = (static_cast<size_t>(sq[0]) << 8) | sq[1];
            sq += 2;
            if (sq + name_len > q + ext_body)
                return -1;
            if (name_len + 1 > out_cap)
                return -3;
            memcpy(out, sq, name_len);
            out[name_len] = '\0';
            return 0;
        }
        q += ext_body;
    }
    return -2;
}

} /* namespace tachyon::obfs */
