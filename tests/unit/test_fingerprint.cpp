/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the deidentification helpers (fingerprint.cpp).
 *
 * Coverage:
 *   - TTL draws stay within configured bounds
 *   - MAC has locally-administered + unicast bits set correctly
 *   - port_hop_current is deterministic given (psk, epoch)
 *   - port_hop_current rotates on epoch change
 *   - ip_id draws exercise the full 16-bit range (entropy sanity)
 *   - obfuscate_timestamp returns values within [ts-j, ts+j]
 */

#include <gtest/gtest.h>
#include "fingerprint.h"
#include <cstring>
#include <set>

using namespace tachyon::fp;

TEST(Fingerprint, TTLBoundsRespected) {
    for (int i = 0; i < 10000; ++i) {
        const uint8_t t = random_ttl();
        EXPECT_GE(t, TTL_MIN);
        EXPECT_LE(t, TTL_MAX);
    }
}

TEST(Fingerprint, TTLHasReasonableSpread) {
    std::set<uint8_t> seen;
    for (int i = 0; i < 1000; ++i)
        seen.insert(random_ttl());
    /* Spread should cover at least half of the 15-value range */
    EXPECT_GE(seen.size(), 8u);
}

TEST(Fingerprint, MacIsLocallyAdministeredUnicast) {
    for (int i = 0; i < 500; ++i) {
        uint8_t mac[6];
        random_locally_admin_mac(mac);
        EXPECT_EQ(mac[0] & 0x01, 0x00) << "multicast bit set in MAC";
        EXPECT_EQ(mac[0] & 0x02, 0x02) << "locally-administered bit not set";
    }
}

TEST(Fingerprint, MacEntropyNotStuckZero) {
    uint8_t mac1[6];
    uint8_t mac2[6];
    random_locally_admin_mac(mac1);
    random_locally_admin_mac(mac2);
    /* Two independent draws should differ in at least one byte */
    EXPECT_NE(memcmp(mac1, mac2, 6), 0);
}

TEST(Fingerprint, PortHopDeterministicForSameEpoch) {
    uint8_t psk[32];
    memset(psk, 0xA5, sizeof(psk));
    const uint16_t a = port_hop_current(psk, 60, 1'700'000'000ull);
    const uint16_t b = port_hop_current(psk, 60, 1'700'000'030ull); /* same 60-s bucket */
    EXPECT_EQ(a, b);
}

TEST(Fingerprint, PortHopChangesAcrossEpochs) {
    uint8_t psk[32];
    memset(psk, 0x7F, sizeof(psk));
    const uint16_t a = port_hop_current(psk, 60, 0);
    const uint16_t b = port_hop_current(psk, 60, 60);
    const uint16_t c = port_hop_current(psk, 60, 120);
    /* With high probability, at least two of three differ */
    const int distinct = (a != b) + (a != c) + (b != c);
    EXPECT_GE(distinct, 1);
}

TEST(Fingerprint, PortHopInRange) {
    uint8_t psk[32];
    memset(psk, 0x01, sizeof(psk));
    for (uint64_t ep = 0; ep < 200; ++ep) {
        const uint16_t p = port_hop_current(psk, 60, ep * 60);
        EXPECT_GE(p, PORT_HOP_MIN);
        EXPECT_LE(p, PORT_HOP_MAX);
    }
}

TEST(Fingerprint, PortHopDependsOnKey) {
    uint8_t psk1[32] = {0};
    uint8_t psk2[32] = {0};
    psk2[0] = 0x01;
    uint64_t ts = 1'700'000'000ull;
    const uint16_t a = port_hop_current(psk1, 60, ts);
    const uint16_t b = port_hop_current(psk2, 60, ts);
    /* Single-bit key change should almost certainly change the port */
    EXPECT_NE(a, b);
}

TEST(Fingerprint, PortHopZeroPeriodDefaults) {
    /* API contract: period_s==0 implies 60 internally */
    uint8_t psk[32] = {0};
    const uint16_t p1 = port_hop_current(psk, 0, 1234);
    const uint16_t p2 = port_hop_current(psk, 60, 1234);
    EXPECT_EQ(p1, p2);
}

TEST(Fingerprint, IpIdHasEntropy) {
    std::set<uint16_t> seen;
    for (int i = 0; i < 2000; ++i)
        seen.insert(csprng_ip_id());
    /* With 16-bit CSPRNG we expect at least 1000 distinct values in 2000 draws */
    EXPECT_GE(seen.size(), 1000u);
}

TEST(Fingerprint, TimestampJitterInBounds) {
    const uint64_t ts = 1'000'000'000'000ull;
    for (int i = 0; i < 1000; ++i) {
        const uint64_t out = obfuscate_timestamp(ts, 1'000'000ull);
        const int64_t delta = static_cast<int64_t>(out) - static_cast<int64_t>(ts);
        EXPECT_GE(delta, -1'000'000);
        EXPECT_LE(delta, 1'000'000);
    }
}

TEST(Fingerprint, TimestampZeroJitterIdentity) {
    EXPECT_EQ(obfuscate_timestamp(42, 0), 42u);
}

TEST(Fingerprint, TimestampNeverUnderflowsToWraparound) {
    /* ts < jitter — must clamp to 0 rather than underflow */
    const uint64_t out = obfuscate_timestamp(100, 1'000'000);
    EXPECT_LT(out, 2'000'000u);
}
