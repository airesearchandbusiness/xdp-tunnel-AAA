/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the REALITY-style ClientHello builder (obfs.cpp).
 *
 * Coverage:
 *   - build_client_hello produces a valid TLS 1.3 record header
 *   - Embedded SNI round-trips through parse_client_hello_sni
 *   - Handshake length field is consistent with record length
 *   - GREASE detection (RFC 8701)
 *   - Mode string round-trip
 *   - Rejects invalid options (missing SNI, too-small buffer)
 */

#include <gtest/gtest.h>
#include "obfs.h"

#include <cstring>
#include <openssl/rand.h>

using namespace tachyon::obfs;

namespace {

void make_rand(uint8_t *buf, size_t n) { RAND_bytes(buf, n); }

Options make_opts(const char *sni, uint8_t *cr, uint8_t *sid) {
    Options o{};
    o.sni = sni;
    make_rand(cr, 32);
    make_rand(sid, 32);
    o.client_random = cr;
    o.session_id = sid;
    o.alpn_list = reinterpret_cast<const uint8_t *>("\x02h2\x08http/1.1");
    o.alpn_list_len = 3 + 9;
    return o;
}

} /* namespace */

TEST(Obfs, ModeRoundTrip) {
    EXPECT_EQ(mode_from_string("reality"), Mode::REALITY);
    EXPECT_EQ(mode_from_string("TLS"), Mode::REALITY);
    EXPECT_EQ(mode_from_string("quic"), Mode::QUIC);
    EXPECT_EQ(mode_from_string("none"), Mode::NONE);
    EXPECT_EQ(mode_from_string(nullptr), Mode::NONE);
    EXPECT_STREQ(mode_to_string(Mode::REALITY), "reality");
    EXPECT_STREQ(mode_to_string(Mode::QUIC), "quic");
    EXPECT_STREQ(mode_to_string(Mode::NONE), "none");
}

TEST(Obfs, GreaseCodepointsAreRecognized) {
    EXPECT_TRUE(is_grease_codepoint(0x0A0A));
    EXPECT_TRUE(is_grease_codepoint(0x1A1A));
    EXPECT_TRUE(is_grease_codepoint(0xFAFA));
    EXPECT_FALSE(is_grease_codepoint(0x1301));   /* TLS_AES_128_GCM_SHA256 */
    EXPECT_FALSE(is_grease_codepoint(0x0000));
    EXPECT_FALSE(is_grease_codepoint(0x0A0B));
}

TEST(Obfs, PickGreaseReturnsValidCodepoint) {
    for (int i = 0; i < 200; ++i) {
        const uint16_t g = pick_grease();
        EXPECT_TRUE(is_grease_codepoint(g)) << "pick_grease returned " << std::hex << g;
    }
}

TEST(Obfs, BuildClientHelloProducesValidRecord) {
    uint8_t buf[MAX_RECORD_LEN] = {0};
    uint8_t cr[32], sid[32];
    const auto opts = make_opts("www.example.com", cr, sid);
    const size_t n = build_client_hello(buf, sizeof(buf), opts);
    ASSERT_GT(n, 0u);
    ASSERT_GE(n, 5u);

    /* Record header sanity */
    EXPECT_EQ(buf[0], 0x16);                             /* handshake */
    EXPECT_EQ(buf[1], 0x03);
    EXPECT_EQ(buf[2], 0x03);                             /* TLS 1.2 legacy */
    const size_t rec_len = (static_cast<size_t>(buf[3]) << 8) | buf[4];
    EXPECT_EQ(rec_len, n - 5);

    /* Handshake type = ClientHello */
    EXPECT_EQ(buf[5], 0x01);
    const size_t hs_len =
        (static_cast<size_t>(buf[6]) << 16) | (static_cast<size_t>(buf[7]) << 8) | buf[8];
    EXPECT_EQ(hs_len, n - 9);
}

TEST(Obfs, SniRoundTrip) {
    const char *sni = "cdn.cloudflare.com";
    uint8_t buf[MAX_RECORD_LEN] = {0};
    uint8_t cr[32], sid[32];
    const auto opts = make_opts(sni, cr, sid);
    const size_t n = build_client_hello(buf, sizeof(buf), opts);
    ASSERT_GT(n, 0u);

    char got[256] = {0};
    const int rc = parse_client_hello_sni(buf, n, got, sizeof(got));
    EXPECT_EQ(rc, 0);
    EXPECT_STREQ(got, sni);
}

TEST(Obfs, BufferTooSmallFails) {
    uint8_t tiny[64];
    uint8_t cr[32], sid[32];
    const auto opts = make_opts("a.b", cr, sid);
    EXPECT_EQ(build_client_hello(tiny, sizeof(tiny), opts), 0u);
}

TEST(Obfs, MissingSniFails) {
    uint8_t buf[MAX_RECORD_LEN] = {0};
    uint8_t cr[32], sid[32];
    make_rand(cr, 32);
    make_rand(sid, 32);
    Options opts{};
    opts.sni = nullptr;
    opts.client_random = cr;
    opts.session_id = sid;
    EXPECT_EQ(build_client_hello(buf, sizeof(buf), opts), 0u);
}

TEST(Obfs, ParseRejectsGarbage) {
    uint8_t garbage[32];
    memset(garbage, 0x00, sizeof(garbage));
    char out[64];
    EXPECT_LT(parse_client_hello_sni(garbage, sizeof(garbage), out, sizeof(out)), 0);
}

TEST(Obfs, DifferentRandomnessProducesDifferentOutput) {
    uint8_t b1[MAX_RECORD_LEN] = {0};
    uint8_t b2[MAX_RECORD_LEN] = {0};
    uint8_t cr1[32], sid1[32], cr2[32], sid2[32];
    const auto o1 = make_opts("x.y", cr1, sid1);
    const auto o2 = make_opts("x.y", cr2, sid2);
    const size_t n1 = build_client_hello(b1, sizeof(b1), o1);
    const size_t n2 = build_client_hello(b2, sizeof(b2), o2);
    ASSERT_GT(n1, 0u);
    ASSERT_GT(n2, 0u);
    /* Almost certainly differ because client_random/session_id differ */
    EXPECT_NE(memcmp(b1, b2, std::min(n1, n2)), 0);
}
