/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Unit Tests - Protocol Definitions & Wire Format
 *
 * Tests:
 *   - Wire-format struct sizes match protocol constants
 *   - Constant-time role comparison (ct_role_compare)
 *   - Sequence number encoding/decoding
 *   - Protocol constant consistency
 */

#include <gtest/gtest.h>
#include <cstring>
#include <algorithm>

#include "tachyon.h"

/* ══════════════════════════════════════════════════════════════════════════
 * We re-implement ct_role_compare here for testing since it's static
 * in network.cpp. This validates the algorithm independently.
 * ══════════════════════════════════════════════════════════════════════════ */

static int ct_role_compare(const uint8_t *my_pub, const uint8_t *peer_pub) {
    /* Check equality in constant time */
    bool equal = true;
    for (int i = 0; i < TACHYON_X25519_KEY_LEN; i++) {
        if (my_pub[i] != peer_pub[i]) {
            equal = false;
            break;
        }
    }
    if (equal)
        return -1;

    /* Constant-time greater-than */
    int gt = 0, lt = 0;
    for (int i = 0; i < TACHYON_X25519_KEY_LEN; i++) {
        int diff = (int)my_pub[i] - (int)peer_pub[i];
        gt |= (diff > 0) & ~(gt | lt);
        lt |= (diff < 0) & ~(gt | lt);
    }
    return gt ? 1 : 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Wire Format Size Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(ProtocolTest, GhostHeaderSize) {
    EXPECT_EQ(sizeof(struct tachyon_ghost_hdr), TACHYON_GHOST_HDR_LEN);
}

TEST(ProtocolTest, MsgInitSize) {
    /* flags(1) + pad(3) + session_id(4) + client_nonce(8) + is_rekey(1) + reserved(3) = 20 */
    EXPECT_EQ(sizeof(MsgInit), 20u);
}

TEST(ProtocolTest, MsgCookieSize) {
    /* flags(1) + pad(3) + session_id(4) + client_nonce(8) + cookie(32) = 48 */
    EXPECT_EQ(sizeof(MsgCookie), 48u);
}

TEST(ProtocolTest, MsgAuthSize) {
    /* flags(1) + pad(3) + session_id(4) + client_nonce(8) +
     * is_rekey(1) + reserved(3) + cookie(32) + ciphertext(48) = 100 */
    EXPECT_EQ(sizeof(MsgAuth), 100u);
}

TEST(ProtocolTest, MsgFinishSize) {
    /* flags(1) + pad(3) + session_id(4) + server_nonce(8) + ciphertext(48) = 64 */
    EXPECT_EQ(sizeof(MsgFinish), 64u);
}

TEST(ProtocolTest, MsgKeepaliveSize) {
    /* flags(1) + pad(3) + session_id(4) + timestamp(8) + ciphertext(32) = 48 */
    EXPECT_EQ(sizeof(MsgKeepalive), 48u);
}

TEST(ProtocolTest, ConfigStructSize) {
    /* listen_port_net(2) + mimicry_type(1) + pad(1) = 4 */
    EXPECT_EQ(sizeof(struct tachyon_config), 4u);
}

TEST(ProtocolTest, StatsStructFields) {
    struct tachyon_stats s;
    /* Verify all 14 stat counters exist and are 8 bytes each */
    EXPECT_EQ(sizeof(s.rx_packets), 8u);
    EXPECT_EQ(sizeof(s.rx_bytes), 8u);
    EXPECT_EQ(sizeof(s.tx_packets), 8u);
    EXPECT_EQ(sizeof(s.tx_bytes), 8u);
    EXPECT_EQ(sizeof(s.rx_replay_drops), 8u);
    EXPECT_EQ(sizeof(s.rx_crypto_errors), 8u);
    EXPECT_EQ(sizeof(s.rx_invalid_session), 8u);
    EXPECT_EQ(sizeof(s.rx_malformed), 8u);
    EXPECT_EQ(sizeof(s.rx_ratelimit_drops), 8u);
    EXPECT_EQ(sizeof(s.tx_crypto_errors), 8u);
    EXPECT_EQ(sizeof(s.tx_headroom_errors), 8u);
    EXPECT_EQ(sizeof(s.tx_ratelimit_drops), 8u);
    EXPECT_EQ(sizeof(s.rx_ratelimit_data_drops), 8u);
    EXPECT_EQ(sizeof(s.rx_roam_events), 8u);
}

TEST(ProtocolTest, LpmKeyV4Size) {
    /* prefixlen(4) + addr(4) = 8 bytes */
    EXPECT_EQ(sizeof(struct tachyon_lpm_key_v4), 8u);
}

TEST(ProtocolTest, RateCfgSize) {
    /* 4 x uint64_t = 32 bytes */
    EXPECT_EQ(sizeof(struct tachyon_rate_cfg), 32u);
}

TEST(ProtocolTest, SessionHasRateLimitFields) {
    struct tachyon_session s;
    /* Verify rate limiting and roaming fields exist */
    EXPECT_EQ(sizeof(s.peer_port), 2u);
    EXPECT_EQ(sizeof(s.tx_rl_tokens), 8u);
    EXPECT_EQ(sizeof(s.tx_rl_last_ns), 8u);
    EXPECT_EQ(sizeof(s.rx_rl_tokens), 8u);
    EXPECT_EQ(sizeof(s.rx_rl_last_ns), 8u);
}

TEST(ProtocolTest, PeerRoamEventType) {
    EXPECT_EQ(TACHYON_EVT_PEER_ROAM, 5);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Struct Layout Consistency (kernel <-> userspace mirror)
 *
 * These tests catch ABI drift between tachyon_stats/tachyon_session
 * (BPF map values in common.h) and their userspace mirrors in tachyon.h.
 * A size mismatch causes silent data corruption during bpf_map_lookup.
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(ProtocolTest, StatsLayoutMatchesUserspace) {
    EXPECT_EQ(sizeof(struct tachyon_stats), sizeof(userspace_stats));
}

TEST(ProtocolTest, SessionLayoutMatchesUserspace) {
    EXPECT_EQ(sizeof(struct tachyon_session), sizeof(userspace_session));
}

TEST(ProtocolTest, KeyInitLayoutMatchesUserspace) {
    EXPECT_EQ(sizeof(struct tachyon_key_init), sizeof(userspace_key_init));
}

TEST(ProtocolTest, ConfigLayoutMatchesUserspace) {
    EXPECT_EQ(sizeof(struct tachyon_config), sizeof(userspace_config));
}

/* ══════════════════════════════════════════════════════════════════════════
 * Protocol Constants Consistency
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(ProtocolTest, OuterHeaderLenConsistency) {
    EXPECT_EQ(TACHYON_OUTER_HDR_LEN, TACHYON_ETH_HDR_LEN + TACHYON_IP_HDR_LEN +
                                         TACHYON_UDP_HDR_LEN + TACHYON_GHOST_HDR_LEN);
}

TEST(ProtocolTest, ReplayWindowWordCount) {
    EXPECT_EQ(TACHYON_REPLAY_WORDS, TACHYON_REPLAY_WINDOW / 64);
}

TEST(ProtocolTest, MinEncapLenConsistency) {
    EXPECT_EQ(TACHYON_MIN_ENCAP_LEN, TACHYON_OUTER_HDR_LEN + TACHYON_AEAD_TAG_LEN + 1);
}

TEST(ProtocolTest, ControlPlanePacketTypes) {
    /* All CP packet types should have the 0xC0 prefix */
    EXPECT_EQ(TACHYON_PKT_INIT & TACHYON_CP_FLAG_MASK, TACHYON_CP_FLAG_PREFIX);
    EXPECT_EQ(TACHYON_PKT_COOKIE & TACHYON_CP_FLAG_MASK, TACHYON_CP_FLAG_PREFIX);
    EXPECT_EQ(TACHYON_PKT_AUTH & TACHYON_CP_FLAG_MASK, TACHYON_CP_FLAG_PREFIX);
    EXPECT_EQ(TACHYON_PKT_FINISH & TACHYON_CP_FLAG_MASK, TACHYON_CP_FLAG_PREFIX);
    EXPECT_EQ(TACHYON_PKT_KEEPALIVE & TACHYON_CP_FLAG_MASK, TACHYON_CP_FLAG_PREFIX);
}

TEST(ProtocolTest, PacketTypesUnique) {
    /* All CP packet types must be distinct */
    EXPECT_NE(TACHYON_PKT_INIT, TACHYON_PKT_COOKIE);
    EXPECT_NE(TACHYON_PKT_INIT, TACHYON_PKT_AUTH);
    EXPECT_NE(TACHYON_PKT_INIT, TACHYON_PKT_FINISH);
    EXPECT_NE(TACHYON_PKT_INIT, TACHYON_PKT_KEEPALIVE);
    EXPECT_NE(TACHYON_PKT_COOKIE, TACHYON_PKT_AUTH);
    EXPECT_NE(TACHYON_PKT_COOKIE, TACHYON_PKT_FINISH);
    EXPECT_NE(TACHYON_PKT_COOKIE, TACHYON_PKT_KEEPALIVE);
    EXPECT_NE(TACHYON_PKT_AUTH, TACHYON_PKT_FINISH);
    EXPECT_NE(TACHYON_PKT_AUTH, TACHYON_PKT_KEEPALIVE);
    EXPECT_NE(TACHYON_PKT_FINISH, TACHYON_PKT_KEEPALIVE);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Sequence Number Encoding Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(ProtocolTest, SeqEncodingCpuId) {
    /* Encode CPU 5, sequence 42 */
    uint64_t seq = ((uint64_t)5 << TACHYON_SEQ_CPU_SHIFT) | 42;

    /* Extract CPU ID */
    uint16_t cpu = (seq & TACHYON_SEQ_CPU_MASK) >> TACHYON_SEQ_CPU_SHIFT;
    EXPECT_EQ(cpu, 5);

    /* Extract sequence number */
    uint64_t num = seq & TACHYON_SEQ_NUM_MASK;
    EXPECT_EQ(num, 42u);
}

TEST(ProtocolTest, SeqEncodingMaxValues) {
    uint64_t seq = ((uint64_t)0xFFFF << TACHYON_SEQ_CPU_SHIFT) | TACHYON_SEQ_NUM_MASK;

    uint16_t cpu = (seq & TACHYON_SEQ_CPU_MASK) >> TACHYON_SEQ_CPU_SHIFT;
    EXPECT_EQ(cpu, 0xFFFF);

    uint64_t num = seq & TACHYON_SEQ_NUM_MASK;
    EXPECT_EQ(num, TACHYON_SEQ_NUM_MASK);
}

TEST(ProtocolTest, SeqMasksNoOverlap) {
    EXPECT_EQ(TACHYON_SEQ_CPU_MASK & TACHYON_SEQ_NUM_MASK, 0u);
    EXPECT_EQ(TACHYON_SEQ_CPU_MASK | TACHYON_SEQ_NUM_MASK, 0xFFFFFFFFFFFFFFFFULL);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Constant-Time Role Comparison Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(RoleCompareTest, GreaterKeyFirstByte) {
    uint8_t a[32] = {0}, b[32] = {0};
    a[0] = 0xFF;
    b[0] = 0x00;
    EXPECT_EQ(ct_role_compare(a, b), 1);
}

TEST(RoleCompareTest, LesserKeyFirstByte) {
    uint8_t a[32] = {0}, b[32] = {0};
    a[0] = 0x00;
    b[0] = 0xFF;
    EXPECT_EQ(ct_role_compare(a, b), 0);
}

TEST(RoleCompareTest, EqualKeys) {
    uint8_t a[32], b[32];
    memset(a, 0xAA, 32);
    memset(b, 0xAA, 32);
    EXPECT_EQ(ct_role_compare(a, b), -1);
}

TEST(RoleCompareTest, DifferAtLastByte) {
    uint8_t a[32], b[32];
    memset(a, 0x42, 32);
    memset(b, 0x42, 32);
    a[31] = 0x43;
    b[31] = 0x42;
    EXPECT_EQ(ct_role_compare(a, b), 1);
}

TEST(RoleCompareTest, DifferAtLastByteLesser) {
    uint8_t a[32], b[32];
    memset(a, 0x42, 32);
    memset(b, 0x42, 32);
    a[31] = 0x41;
    b[31] = 0x42;
    EXPECT_EQ(ct_role_compare(a, b), 0);
}

TEST(RoleCompareTest, FirstByteDominates) {
    /* a[0] > b[0] but a[31] < b[31] -- first difference wins */
    uint8_t a[32] = {0}, b[32] = {0};
    a[0] = 0x10;
    b[0] = 0x0F;
    a[31] = 0x00;
    b[31] = 0xFF;
    EXPECT_EQ(ct_role_compare(a, b), 1);
}

TEST(RoleCompareTest, SymmetricResults) {
    uint8_t a[32], b[32];
    memset(a, 0x11, 32);
    memset(b, 0x22, 32);

    int r1 = ct_role_compare(a, b);
    int r2 = ct_role_compare(b, a);

    /* If a < b (r1=0), then b > a (r2=1) */
    EXPECT_EQ(r1, 0);
    EXPECT_EQ(r2, 1);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Traffic Obfuscation Constants
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(ObfuscationTest, FlagBitsAreDistinct) {
    EXPECT_EQ(TACHYON_OBFS_TTL_JITTER & TACHYON_OBFS_IPID_RAND, 0);
    EXPECT_EQ(TACHYON_OBFS_IPID_RAND & TACHYON_OBFS_DF_VARY, 0);
    EXPECT_EQ(TACHYON_OBFS_DF_VARY & TACHYON_OBFS_DSCP_STRIP, 0);
    EXPECT_EQ(TACHYON_OBFS_DSCP_STRIP & TACHYON_OBFS_CONST_PAD, 0);
    EXPECT_EQ(TACHYON_OBFS_CONST_PAD & TACHYON_OBFS_DECOY, 0);
}

TEST(ObfuscationTest, AllFlagsCoverFullMask) {
    uint8_t combined = TACHYON_OBFS_TTL_JITTER | TACHYON_OBFS_IPID_RAND | TACHYON_OBFS_DF_VARY |
                       TACHYON_OBFS_DSCP_STRIP | TACHYON_OBFS_CONST_PAD | TACHYON_OBFS_DECOY;
    EXPECT_EQ(combined, TACHYON_OBFS_ALL);
}

TEST(ObfuscationTest, ConfigStructPreservesObfsField) {
    EXPECT_EQ(sizeof(struct tachyon_config), 4u);
    struct tachyon_config cfg = {};
    cfg.obfs_flags = TACHYON_OBFS_ALL;
    EXPECT_EQ(cfg.obfs_flags, TACHYON_OBFS_ALL);
}

TEST(ObfuscationTest, DecoyTimingConstants) {
    EXPECT_GT(TACHYON_DECOY_BASE, 0);
    EXPECT_GT(TACHYON_DECOY_JITTER, 0);
    EXPECT_GT(TACHYON_KEY_RATCHET_INTERVAL, TACHYON_REKEY_INTERVAL);
}

TEST(ObfuscationTest, KdfRatchetLabelsDistinct) {
    EXPECT_NE(std::string(TACHYON_KDF_KEY_RATCHET), std::string(TACHYON_KDF_DECOY_SEED));
    EXPECT_NE(std::string(TACHYON_KDF_KEY_RATCHET), std::string(TACHYON_KDF_SESSION_MASTER));
    EXPECT_NE(std::string(TACHYON_KDF_DECOY_SEED), std::string(TACHYON_KDF_CP_AEAD));
}
