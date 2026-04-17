/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the pluggable transport framework + all four engines.
 *
 * Coverage:
 *   Registry: register, lookup, string round-trip, auto-select
 *   QUIC:     Initial header structure, version field, DCID/SCID round-trip,
 *             1200-byte minimum padding, wrap→unwrap payload integrity
 *   HTTP/2:   Connection preface, SETTINGS frame, HEADERS pseudo-headers,
 *             DATA frame round-trip, seq==0 preface emission
 *   DoH:      DNS header flags, QNAME encoding, TXT RDATA segmentation,
 *             wrap→unwrap round-trip, character-string reassembly
 *   STUN:     Magic cookie, FINGERPRINT CRC, DATA attribute, Binding
 *             Request vs Data Indication, message parsing
 */

#include <gtest/gtest.h>
#include "transport.h"
#include "quic_mimic.h"
#include "http2_mimic.h"
#include "doh_mimic.h"
#include "stun_mimic.h"

#include <cstring>
#include <set>

using namespace tachyon::transport;

/* Register all engines before the first test. */
struct TransportSetup : public ::testing::Test {
    static void SetUpTestSuite() {
        tachyon::quic_mimic::register_transport();
        tachyon::http2_mimic::register_transport();
        tachyon::doh_mimic::register_transport();
        tachyon::stun_mimic::register_transport();
    }
};

/* ── Registry ─────────────────────────────────────────────────────── */

TEST_F(TransportSetup, AllEnginesRegistered) {
    EXPECT_NE(transport_get(TransportId::QUIC), nullptr);
    EXPECT_NE(transport_get(TransportId::HTTP2), nullptr);
    EXPECT_NE(transport_get(TransportId::DOH), nullptr);
    EXPECT_NE(transport_get(TransportId::STUN), nullptr);
    EXPECT_EQ(transport_get(TransportId::NONE), nullptr);
}

TEST_F(TransportSetup, StringRoundTrip) {
    EXPECT_EQ(transport_id_from_string("quic"), TransportId::QUIC);
    EXPECT_EQ(transport_id_from_string("http2"), TransportId::HTTP2);
    EXPECT_EQ(transport_id_from_string("h2"), TransportId::HTTP2);
    EXPECT_EQ(transport_id_from_string("doh"), TransportId::DOH);
    EXPECT_EQ(transport_id_from_string("dns"), TransportId::DOH);
    EXPECT_EQ(transport_id_from_string("stun"), TransportId::STUN);
    EXPECT_EQ(transport_id_from_string("webrtc"), TransportId::STUN);
    EXPECT_EQ(transport_id_from_string("auto"), TransportId::AUTO);
    EXPECT_EQ(transport_id_from_string(nullptr), TransportId::NONE);
    EXPECT_EQ(transport_id_from_string(""), TransportId::NONE);
    EXPECT_STREQ(transport_id_to_string(TransportId::QUIC), "quic");
    EXPECT_STREQ(transport_id_to_string(TransportId::HTTP2), "http2");
}

TEST_F(TransportSetup, ListReturnsAll) {
    const TransportOps *ops[8] = {};
    const int n = transport_list(ops, 8);
    EXPECT_GE(n, 4);
    std::set<TransportId> ids;
    for (int i = 0; i < n; ++i)
        ids.insert(ops[i]->id);
    EXPECT_TRUE(ids.count(TransportId::QUIC));
    EXPECT_TRUE(ids.count(TransportId::HTTP2));
    EXPECT_TRUE(ids.count(TransportId::DOH));
    EXPECT_TRUE(ids.count(TransportId::STUN));
}

TEST_F(TransportSetup, AutoSelectPicksSomething) {
    EnvProfile env;
    env.port      = 443;
    env.udp       = true;
    env.bandwidth = BandwidthTier::MEDIUM;
    env.region    = RegionHint::OPEN;
    const TransportId id = transport_auto_select(env);
    EXPECT_NE(id, TransportId::NONE);
    EXPECT_NE(id, TransportId::AUTO);
}

TEST_F(TransportSetup, AutoSelectPrefersHttp2ForTcpRestrictive) {
    EnvProfile env;
    env.port      = 443;
    env.udp       = false; /* TCP-only */
    env.bandwidth = BandwidthTier::HIGH;
    env.region    = RegionHint::RESTRICTIVE;
    const TransportId id = transport_auto_select(env);
    EXPECT_EQ(id, TransportId::HTTP2);
}

TEST_F(TransportSetup, AutoSelectPrefersStunOnStunPort) {
    EnvProfile env;
    env.port      = 3478;
    env.udp       = true;
    env.bandwidth = BandwidthTier::MEDIUM;
    env.region    = RegionHint::MODERATE;
    const TransportId id = transport_auto_select(env);
    EXPECT_EQ(id, TransportId::STUN);
}

/* ── QUIC Initial ─────────────────────────────────────────────────── */

TEST_F(TransportSetup, QuicHeaderVersionIsV1) {
    uint8_t buf[128];
    const uint8_t dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const size_t n =
        tachyon::quic_mimic::build_initial_header(buf, sizeof(buf), dcid, 8, nullptr, 0, 0, 100);
    ASSERT_GT(n, 5u);
    /* Version at bytes 1..4 = 0x00000001 */
    EXPECT_EQ(buf[1], 0x00);
    EXPECT_EQ(buf[2], 0x00);
    EXPECT_EQ(buf[3], 0x00);
    EXPECT_EQ(buf[4], 0x01);
}

TEST_F(TransportSetup, QuicHeaderFormIsLong) {
    uint8_t buf[128];
    const size_t n =
        tachyon::quic_mimic::build_initial_header(buf, sizeof(buf), nullptr, 0, nullptr, 0, 1, 50);
    ASSERT_GT(n, 0u);
    EXPECT_EQ(buf[0] & 0xC0, 0xC0u); /* form=1, fixed=1 → 0b11xxxxxx */
}

TEST_F(TransportSetup, QuicDcidScidRoundTrip) {
    uint8_t buf[256];
    const uint8_t dcid[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44};
    const uint8_t scid[4] = {0x55, 0x66, 0x77, 0x88};
    const size_t n = tachyon::quic_mimic::build_initial_header(buf, sizeof(buf), dcid, 8, scid, 4,
                                                               42, 200);
    ASSERT_GT(n, 0u);
    const auto r = tachyon::quic_mimic::parse_initial_header(buf, n + 200);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.dcid_len, 8u);
    EXPECT_EQ(std::memcmp(r.dcid, dcid, 8), 0);
    EXPECT_EQ(r.scid_len, 4u);
    EXPECT_EQ(std::memcmp(r.scid, scid, 4), 0);
    EXPECT_EQ(r.pkt_num, 42u);
}

TEST_F(TransportSetup, QuicWrapUnwrapRoundTrip) {
    uint8_t payload[128];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i ^ 0xAB);

    uint8_t frame[2048] = {};
    FrameContext ctx{};
    ctx.conn_id[0]  = 0xDE;
    ctx.conn_id_len = 1;
    ctx.seq         = 7;

    const auto wr = transport_wrap(TransportId::QUIC, payload, sizeof(payload),
                                   frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr.ok);
    EXPECT_GE(wr.bytes, tachyon::quic_mimic::QUIC_MIN_INITIAL);

    uint8_t recovered[2048] = {};
    const auto ur = transport_unwrap(TransportId::QUIC, frame, wr.bytes,
                                     recovered, sizeof(recovered));
    ASSERT_TRUE(ur.ok);
    EXPECT_EQ(ur.bytes, sizeof(payload));
    EXPECT_EQ(std::memcmp(recovered, payload, sizeof(payload)), 0);
}

TEST_F(TransportSetup, QuicMinimum1200Bytes) {
    uint8_t small[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t frame[2048] = {};
    FrameContext ctx{};
    ctx.conn_id_len = 0;
    ctx.seq = 0;
    const auto wr = transport_wrap(TransportId::QUIC, small, sizeof(small),
                                   frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr.ok);
    EXPECT_GE(wr.bytes, tachyon::quic_mimic::QUIC_MIN_INITIAL);
}

/* ── HTTP/2 ───────────────────────────────────────────────────────── */

TEST_F(TransportSetup, Http2ConnectionPreface) {
    uint8_t buf[256];
    const size_t n = tachyon::http2_mimic::build_connection_preface(buf, sizeof(buf));
    ASSERT_GT(n, 0u);
    EXPECT_GE(n, tachyon::http2_mimic::H2_PREFACE_LEN + tachyon::http2_mimic::H2_FRAME_HEADER);
    /* Starts with PRI * HTTP/2.0 */
    EXPECT_EQ(buf[0], 'P');
    EXPECT_EQ(buf[1], 'R');
    EXPECT_EQ(buf[2], 'I');
}

TEST_F(TransportSetup, Http2FrameHeaderRoundTrip) {
    uint8_t hdr[9];
    tachyon::http2_mimic::build_frame_header(hdr, 0x1234, 0x00, 0x01, 7);
    const auto h = tachyon::http2_mimic::parse_frame_header(hdr, sizeof(hdr));
    ASSERT_TRUE(h.ok);
    EXPECT_EQ(h.length, 0x1234u);
    EXPECT_EQ(h.type, 0x00u);
    EXPECT_EQ(h.flags, 0x01u);
    EXPECT_EQ(h.stream_id, 7u);
}

TEST_F(TransportSetup, Http2DataFrameRoundTrip) {
    uint8_t payload[64];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i);
    uint8_t frame[128];
    const size_t n = tachyon::http2_mimic::build_data_frame(frame, sizeof(frame), payload,
                                                            sizeof(payload), 1);
    ASSERT_EQ(n, tachyon::http2_mimic::H2_FRAME_HEADER + sizeof(payload));

    const auto h = tachyon::http2_mimic::parse_frame_header(frame, n);
    ASSERT_TRUE(h.ok);
    EXPECT_EQ(h.type, tachyon::http2_mimic::H2_DATA);
    EXPECT_EQ(h.length, sizeof(payload));
    EXPECT_EQ(std::memcmp(frame + tachyon::http2_mimic::H2_FRAME_HEADER, payload,
                          sizeof(payload)),
              0);
}

TEST_F(TransportSetup, Http2WrapUnwrapRoundTrip) {
    uint8_t payload[200];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i ^ 0x55);

    uint8_t frame[2048] = {};
    FrameContext ctx{};
    ctx.stream_id = 1;
    ctx.seq       = 0; /* first frame: preface + headers + data */
    ctx.sni       = "cdn.example.com";

    const auto wr = transport_wrap(TransportId::HTTP2, payload, sizeof(payload),
                                   frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr.ok);
    EXPECT_GT(wr.bytes, sizeof(payload) + 50u); /* preface + headers + frame header */

    uint8_t recovered[2048] = {};
    const auto ur = transport_unwrap(TransportId::HTTP2, frame, wr.bytes,
                                     recovered, sizeof(recovered));
    ASSERT_TRUE(ur.ok);
    EXPECT_EQ(ur.bytes, sizeof(payload));
    EXPECT_EQ(std::memcmp(recovered, payload, sizeof(payload)), 0);
}

TEST_F(TransportSetup, Http2SubsequentFrameIsDataOnly) {
    uint8_t payload[32] = {};
    uint8_t frame[256] = {};
    FrameContext ctx{};
    ctx.stream_id = 1;
    ctx.seq       = 5; /* not first frame */

    const auto wr = transport_wrap(TransportId::HTTP2, payload, sizeof(payload),
                                   frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr.ok);
    /* Subsequent frame = exactly 9-byte header + payload */
    EXPECT_EQ(wr.bytes, tachyon::http2_mimic::H2_FRAME_HEADER + sizeof(payload));
}

/* ── DNS-over-HTTPS ───────────────────────────────────────────────── */

TEST_F(TransportSetup, DohQnameEncoding) {
    uint8_t buf[64];
    const size_t n = tachyon::doh_mimic::encode_qname(buf, sizeof(buf), "dns.google");
    ASSERT_GT(n, 0u);
    /* Expected: \x03dns\x06google\x00 */
    EXPECT_EQ(buf[0], 3u);
    EXPECT_EQ(buf[1], 'd');
    EXPECT_EQ(buf[4], 6u);
    EXPECT_EQ(buf[n - 1], 0u);
}

TEST_F(TransportSetup, DohMessageHasDnsHeader) {
    uint8_t payload[16] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t buf[512];
    const size_t n =
        tachyon::doh_mimic::build_dns_message(buf, sizeof(buf), 0x1234, "example.com", payload, 4);
    ASSERT_GT(n, tachyon::doh_mimic::DNS_HEADER_LEN);
    /* Transaction ID */
    EXPECT_EQ(buf[0], 0x12u);
    EXPECT_EQ(buf[1], 0x34u);
    /* QR=1 (response), RD=1 */
    EXPECT_EQ(buf[2] & 0x80, 0x80u);
    /* QDCOUNT=1, ANCOUNT=1 */
    EXPECT_EQ(buf[5], 1u);
    EXPECT_EQ(buf[7], 1u);
}

TEST_F(TransportSetup, DohWrapUnwrapRoundTrip) {
    uint8_t payload[300];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i ^ 0xCC);

    uint8_t frame[2048] = {};
    FrameContext ctx{};
    ctx.seq = 42;
    ctx.sni = "cloudflare-dns.com";

    const auto wr = transport_wrap(TransportId::DOH, payload, sizeof(payload),
                                   frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr.ok);
    EXPECT_GT(wr.bytes, sizeof(payload));

    uint8_t recovered[2048] = {};
    const auto ur = transport_unwrap(TransportId::DOH, frame, wr.bytes,
                                     recovered, sizeof(recovered));
    ASSERT_TRUE(ur.ok);
    EXPECT_EQ(ur.bytes, sizeof(payload));
    EXPECT_EQ(std::memcmp(recovered, payload, sizeof(payload)), 0);
}

TEST_F(TransportSetup, DohLargePayloadSegmentation) {
    /* TXT RDATA segments payload into ≤255-byte character strings. A
     * 600-byte payload spans 3 segments (255 + 255 + 90). Round-trip
     * must reassemble them. */
    uint8_t payload[600];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i);

    uint8_t frame[2048] = {};
    FrameContext ctx{};
    ctx.seq = 1;
    ctx.sni = "dns.google";

    const auto wr = transport_wrap(TransportId::DOH, payload, sizeof(payload),
                                   frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr.ok);

    uint8_t recovered[2048] = {};
    const auto ur = transport_unwrap(TransportId::DOH, frame, wr.bytes,
                                     recovered, sizeof(recovered));
    ASSERT_TRUE(ur.ok);
    EXPECT_EQ(ur.bytes, sizeof(payload));
    EXPECT_EQ(std::memcmp(recovered, payload, sizeof(payload)), 0);
}

/* ── STUN/TURN ────────────────────────────────────────────────────── */

TEST_F(TransportSetup, StunMagicCookiePresent) {
    uint8_t txn[12] = {};
    uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t buf[256];
    const size_t n = tachyon::stun_mimic::build_stun_message(
        buf, sizeof(buf), tachyon::stun_mimic::STUN_BINDING_REQ, txn, payload, sizeof(payload));
    ASSERT_GT(n, tachyon::stun_mimic::STUN_HEADER_LEN);
    /* Magic cookie at bytes 4..7 */
    const uint32_t cookie = (static_cast<uint32_t>(buf[4]) << 24) |
                            (static_cast<uint32_t>(buf[5]) << 16) |
                            (static_cast<uint32_t>(buf[6]) << 8) | buf[7];
    EXPECT_EQ(cookie, tachyon::stun_mimic::STUN_MAGIC_COOKIE);
}

TEST_F(TransportSetup, StunFingerprintPresent) {
    uint8_t txn[12] = {};
    uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t buf[256];
    const size_t n = tachyon::stun_mimic::build_stun_message(
        buf, sizeof(buf), tachyon::stun_mimic::STUN_BINDING_REQ, txn, payload, sizeof(payload));
    ASSERT_GT(n, 8u);
    /* FINGERPRINT is the last 8 bytes */
    const uint16_t fp_type = (static_cast<uint16_t>(buf[n - 8]) << 8) | buf[n - 7];
    EXPECT_EQ(fp_type, tachyon::stun_mimic::ATTR_FINGERPRINT);
    /* Verify CRC matches */
    const uint32_t fp_val = (static_cast<uint32_t>(buf[n - 4]) << 24) |
                            (static_cast<uint32_t>(buf[n - 3]) << 16) |
                            (static_cast<uint32_t>(buf[n - 2]) << 8) | buf[n - 1];
    const uint32_t expected = tachyon::stun_mimic::stun_fingerprint(buf, n - 8);
    EXPECT_EQ(fp_val, expected);
}

TEST_F(TransportSetup, StunWrapUnwrapRoundTrip) {
    uint8_t payload[100];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i ^ 0x37);

    uint8_t frame[2048] = {};
    FrameContext ctx{};
    ctx.conn_id[0]  = 0x01;
    ctx.conn_id_len = 1;
    ctx.seq         = 0;

    const auto wr = transport_wrap(TransportId::STUN, payload, sizeof(payload),
                                   frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr.ok);

    uint8_t recovered[2048] = {};
    const auto ur = transport_unwrap(TransportId::STUN, frame, wr.bytes,
                                     recovered, sizeof(recovered));
    ASSERT_TRUE(ur.ok);
    EXPECT_EQ(ur.bytes, sizeof(payload));
    EXPECT_EQ(std::memcmp(recovered, payload, sizeof(payload)), 0);
}

TEST_F(TransportSetup, StunBindingReqVsDataIndication) {
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t frame[256];
    FrameContext ctx{};
    ctx.conn_id_len = 0;

    ctx.seq = 0; /* first → Binding Request */
    const auto wr0 = transport_wrap(TransportId::STUN, payload, sizeof(payload),
                                    frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr0.ok);
    auto r0 = tachyon::stun_mimic::parse_stun_message(frame, wr0.bytes);
    ASSERT_TRUE(r0.ok);
    EXPECT_EQ(r0.msg_type, tachyon::stun_mimic::STUN_BINDING_REQ);

    ctx.seq = 5; /* subsequent → Data Indication */
    const auto wr5 = transport_wrap(TransportId::STUN, payload, sizeof(payload),
                                    frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr5.ok);
    auto r5 = tachyon::stun_mimic::parse_stun_message(frame, wr5.bytes);
    ASSERT_TRUE(r5.ok);
    EXPECT_EQ(r5.msg_type, tachyon::stun_mimic::STUN_DATA_IND);
}

TEST_F(TransportSetup, StunAttributePadding) {
    /* Payload of 5 bytes must be padded to 8 in the attribute. The
     * unwrapped output must still be exactly 5 bytes. */
    uint8_t payload[5] = {10, 20, 30, 40, 50};
    uint8_t frame[256] = {};
    FrameContext ctx{};
    ctx.conn_id_len = 0;
    ctx.seq         = 1;

    const auto wr = transport_wrap(TransportId::STUN, payload, sizeof(payload),
                                   frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr.ok);

    uint8_t recovered[256] = {};
    const auto ur = transport_unwrap(TransportId::STUN, frame, wr.bytes,
                                     recovered, sizeof(recovered));
    ASSERT_TRUE(ur.ok);
    EXPECT_EQ(ur.bytes, 5u);
    EXPECT_EQ(std::memcmp(recovered, payload, 5), 0);
}

/* ── Cross-engine: wrap with unregistered ID fails ────────────────── */

TEST_F(TransportSetup, WrapUnregisteredIdFails) {
    uint8_t payload[8] = {};
    uint8_t frame[64]  = {};
    FrameContext ctx{};
    const auto r = transport_wrap(TransportId::NONE, payload, sizeof(payload),
                                  frame, sizeof(frame), &ctx);
    EXPECT_FALSE(r.ok);
}
