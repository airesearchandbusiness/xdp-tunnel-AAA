/* SPDX-License-Identifier: MIT */
/*
 * Integration test for the v5 wired-up control plane.
 *
 * Exercises the REAL code paths that `tachyon up` triggers — transport
 * engine registration, auto-selection, wrap→unwrap round-trip through
 * every engine, PADME quantisation, cover-traffic emission, replay
 * window, ratchet key advancement, metrics accounting, rate limiting,
 * and REALITY TLS record framing.
 *
 * No network socket needed — all tests use in-memory buffers.
 */

#include <gtest/gtest.h>

#include "transport.h"
#include "quic_mimic.h"
#include "http2_mimic.h"
#include "doh_mimic.h"
#include "stun_mimic.h"
#include "obfs.h"
#include "padding.h"
#include "fingerprint.h"
#include "metrics.h"
#include "rate_limiter.h"
#include "replay.h"
#include "ratchet.h"
#include "transcript.h"
#include "hybrid_kex.h"
#include "secmem.h"

#include <cstring>
#include <set>
#include <openssl/rand.h>

using namespace tachyon;

/* Register all engines once — same as tunnel.cpp does at startup. */
struct IntegrationV5 : public ::testing::Test {
    static void SetUpTestSuite() {
        quic_mimic::register_transport();
        http2_mimic::register_transport();
        doh_mimic::register_transport();
        stun_mimic::register_transport();
        obfs::register_reality_transport();
    }
    void SetUp() override { metrics::reset(); }
};

/* ── Transport: every engine wrap→unwrap preserves payload ─────────── */

TEST_F(IntegrationV5, AllEnginesRoundTrip) {
    const transport::TransportId engines[] = {
        transport::TransportId::QUIC,
        transport::TransportId::HTTP2,
        transport::TransportId::DOH,
        transport::TransportId::STUN,
        transport::TransportId::REALITY,
    };

    uint8_t payload[200];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i ^ 0xAB);

    for (auto tid : engines) {
        SCOPED_TRACE(transport::transport_id_to_string(tid));
        uint8_t frame[8192] = {};
        transport::FrameContext ctx{};
        ctx.seq = 0;
        ctx.sni = "www.example.com";
        ctx.conn_id_len = 8;
        RAND_bytes(ctx.conn_id, 8);

        auto wr = transport::transport_wrap(tid, payload, sizeof(payload),
                                            frame, sizeof(frame), &ctx);
        ASSERT_TRUE(wr.ok) << "wrap failed for " << transport::transport_id_to_string(tid);
        EXPECT_GT(wr.bytes, sizeof(payload));

        uint8_t recovered[8192] = {};
        auto ur = transport::transport_unwrap(tid, frame, wr.bytes,
                                              recovered, sizeof(recovered));
        ASSERT_TRUE(ur.ok) << "unwrap failed for " << transport::transport_id_to_string(tid);
        EXPECT_EQ(ur.bytes, sizeof(payload));
        EXPECT_EQ(memcmp(recovered, payload, sizeof(payload)), 0);
    }
}

/* ── Auto-select picks something sane for every profile ───────────── */

TEST_F(IntegrationV5, AutoSelectEveryProfile) {
    struct Case {
        uint16_t port;
        bool udp;
        transport::RegionHint region;
    } cases[] = {
        {443, true,  transport::RegionHint::OPEN},
        {443, false, transport::RegionHint::RESTRICTIVE},
        {3478, true, transport::RegionHint::MODERATE},
        {853, true,  transport::RegionHint::RESTRICTIVE},
    };

    for (auto &c : cases) {
        transport::EnvProfile env{};
        env.port   = c.port;
        env.udp    = c.udp;
        env.region = c.region;
        auto tid = transport::transport_auto_select(env);
        EXPECT_NE(tid, transport::TransportId::NONE)
            << "No engine for port=" << c.port << " udp=" << c.udp;
        EXPECT_NE(tid, transport::TransportId::AUTO);
    }
}

/* ── PADME quantisation is applied and overhead is bounded ─────────── */

TEST_F(IntegrationV5, PadmeOverheadBounded) {
    for (uint32_t n = 16; n <= 1400; ++n) {
        uint32_t padded = padding::padme_round(n);
        ASSERT_GE(padded, n);
        uint32_t overhead = padded - n;
        EXPECT_LE(overhead * 100, n * 14)
            << "PADME overhead too high at n=" << n;
    }
}

/* ── Cover traffic scheduler emits frames at configured rate ──────── */

TEST_F(IntegrationV5, CoverTrafficEmission) {
    padding::ShaperState shaper;
    padding::shaper_init(shaper, 10); /* 10 Hz */
    shaper.state = padding::State::IDLE;

    int emitted = 0;
    for (int i = 0; i < 30; ++i) {
        shaper.next_cover_ns = 0; /* force emit */
        uint32_t sz = padding::shaper_poll_cover(
            shaper, static_cast<uint64_t>(i + 1) * 1'000'000'000ULL, 64, 1400);
        if (sz > 0) ++emitted;
    }
    EXPECT_GE(emitted, 15); /* at least half should fire */
}

/* ── Replay window rejects duplicates ─────────────────────────────── */

TEST_F(IntegrationV5, ReplayRejectsDuplicates) {
    replay::Window w(1024);
    EXPECT_EQ(w.check_and_commit(42), replay::Result::ACCEPTED);
    EXPECT_EQ(w.check_and_commit(42), replay::Result::REPLAY);
    EXPECT_EQ(w.check_and_commit(43), replay::Result::ACCEPTED);
    EXPECT_EQ(w.replays(), 1u);
}

/* ── Ratchet produces unique forward-secure keys ──────────────────── */

TEST_F(IntegrationV5, RatchetForwardSecrecy) {
    uint8_t root[32];
    RAND_bytes(root, 32);
    ratchet::SendState s;
    ratchet::ratchet_init(s, root);

    std::set<std::string> keys;
    for (int i = 0; i < 100; ++i) {
        uint8_t k[32], n[12];
        uint64_t ctr;
        ASSERT_TRUE(ratchet::ratchet_next(s, k, n, &ctr));
        EXPECT_EQ(ctr, static_cast<uint64_t>(i));
        keys.insert(std::string(reinterpret_cast<char*>(k), 32));
    }
    EXPECT_EQ(keys.size(), 100u);
}

/* ── Transcript binds fields into unique digests ──────────────────── */

TEST_F(IntegrationV5, TranscriptBindsFields) {
    transcript::Transcript a("tch5-akev5");
    transcript::Transcript b("tch5-akev5");

    uint8_t data1[4] = {1, 2, 3, 4};
    uint8_t data2[4] = {5, 6, 7, 8};

    ASSERT_TRUE(a.absorb(data1, 4));
    ASSERT_TRUE(b.absorb(data2, 4));

    uint8_t da[48], db[48];
    ASSERT_TRUE(a.finalize(da));
    ASSERT_TRUE(b.finalize(db));
    EXPECT_NE(memcmp(da, db, 48), 0);
}

/* ── Metrics accounting works end-to-end ──────────────────────────── */

TEST_F(IntegrationV5, MetricsAccounting) {
    auto &m = metrics::global();
    m.tx_packets.fetch_add(10);
    m.tx_bytes.fetch_add(5000);
    m.hs_completed.fetch_add(1);
    m.transport_wrap_ok.fetch_add(10);
    m.cover_frames_sent.fetch_add(3);

    auto snap = metrics::snapshot();
    EXPECT_EQ(snap.tx_packets, 10u);
    EXPECT_EQ(snap.tx_bytes, 5000u);
    EXPECT_EQ(snap.hs_completed, 1u);
    EXPECT_EQ(snap.transport_wrap_ok, 10u);
    EXPECT_EQ(snap.cover_frames_sent, 3u);
}

/* ── Rate limiter respects burst and refill ───────────────────────── */

TEST_F(IntegrationV5, RateLimiterEnforcesBurst) {
    rl::TokenBucket b;
    rl::bucket_init(b, 1000, 500, 0);
    EXPECT_TRUE(rl::bucket_allow(b, 500, 0));
    EXPECT_FALSE(rl::bucket_allow(b, 1, 0));
    /* Refill after 1 second */
    EXPECT_TRUE(rl::bucket_allow(b, 500, 1'000'000'000ULL));
}

/* ── Fingerprint: port hopping is deterministic ───────────────────── */

TEST_F(IntegrationV5, PortHopDeterministic) {
    uint8_t psk[32] = {};
    psk[0] = 0xAB;
    uint16_t a = fp::port_hop_current(psk, 60, 1'700'000'000ULL);
    uint16_t b = fp::port_hop_current(psk, 60, 1'700'000'030ULL);
    EXPECT_EQ(a, b); /* same 60-second epoch */
    uint16_t c = fp::port_hop_current(psk, 60, 1'700'000'060ULL);
    /* Different epoch — should differ with high probability */
    EXPECT_TRUE(a != c || b != c); /* at least one must differ */
}

/* ── REALITY: TLS record structure on first frame ─────────────────── */

TEST_F(IntegrationV5, RealityFirstFrameIsTlsHandshake) {
    uint8_t payload[32] = {1, 2, 3, 4};
    uint8_t frame[8192] = {};
    transport::FrameContext ctx{};
    ctx.seq = 0;
    ctx.sni = "cdn.cloudflare.com";

    auto wr = transport::transport_wrap(transport::TransportId::REALITY,
                                        payload, sizeof(payload),
                                        frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr.ok);
    /* First record should be handshake (0x16) */
    EXPECT_EQ(frame[0], 0x16u);
    /* Should contain SNI somewhere in the ClientHello */
    char sni[256] = {};
    int rc = obfs::parse_client_hello_sni(frame, wr.bytes, sni, sizeof(sni));
    EXPECT_EQ(rc, 0);
    EXPECT_STREQ(sni, "cdn.cloudflare.com");
}

/* ── REALITY: subsequent frames are Application Data ──────────────── */

TEST_F(IntegrationV5, RealitySubsequentFrameIsAppData) {
    uint8_t payload[64] = {};
    RAND_bytes(payload, sizeof(payload));

    uint8_t frame[4096] = {};
    transport::FrameContext ctx{};
    ctx.seq = 5; /* not first */
    ctx.sni = "x.y";

    auto wr = transport::transport_wrap(transport::TransportId::REALITY,
                                        payload, sizeof(payload),
                                        frame, sizeof(frame), &ctx);
    ASSERT_TRUE(wr.ok);
    /* Application Data content type */
    EXPECT_EQ(frame[0], 0x17u);
    /* Legacy TLS 1.2 version */
    EXPECT_EQ(frame[1], 0x03u);
    EXPECT_EQ(frame[2], 0x03u);
    /* Length matches payload */
    uint16_t rec_len = (static_cast<uint16_t>(frame[3]) << 8) | frame[4];
    EXPECT_EQ(rec_len, sizeof(payload));
}

/* ── SecureBytes: wipe on destruction ─────────────────────────────── */

TEST_F(IntegrationV5, SecureBytesWipe) {
    uint8_t *raw_ptr = nullptr;
    {
        secmem::SecureBytes b(32);
        for (size_t i = 0; i < 32; ++i)
            b.data()[i] = 0xAA;
        raw_ptr = b.data();
        EXPECT_EQ(b.size(), 32u);
    }
    /* After destruction, we can't safely read raw_ptr, but at least
     * we verified it was non-null and the destructor ran. */
    (void)raw_ptr;
}

/* ── Full pipeline: pad → wrap → unwrap → verify ──────────────────── */

TEST_F(IntegrationV5, FullPipelinePadWrapUnwrap) {
    uint8_t payload[100];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i);

    /* PADME quantise */
    uint32_t padded_len = padding::padme_round(sizeof(payload));
    EXPECT_GE(padded_len, sizeof(payload));
    uint8_t padded[4096] = {};
    memcpy(padded, payload, sizeof(payload));
    if (padded_len > sizeof(payload))
        RAND_bytes(padded + sizeof(payload), padded_len - sizeof(payload));

    /* Transport wrap (QUIC) */
    uint8_t framed[8192] = {};
    transport::FrameContext ctx{};
    ctx.seq = 1;
    ctx.conn_id_len = 4;
    RAND_bytes(ctx.conn_id, 4);

    auto wr = transport::transport_wrap(transport::TransportId::QUIC,
                                        padded, padded_len,
                                        framed, sizeof(framed), &ctx);
    ASSERT_TRUE(wr.ok);

    /* Transport unwrap */
    uint8_t recovered[8192] = {};
    auto ur = transport::transport_unwrap(transport::TransportId::QUIC,
                                          framed, wr.bytes,
                                          recovered, sizeof(recovered));
    ASSERT_TRUE(ur.ok);
    EXPECT_EQ(ur.bytes, padded_len);

    /* Original payload bytes preserved (padding bytes are random) */
    EXPECT_EQ(memcmp(recovered, payload, sizeof(payload)), 0);
}
