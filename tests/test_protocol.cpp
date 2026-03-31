/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Test Suite - Wire Protocol Struct Verification
 *
 * Validates that all packed structures match their expected wire-format
 * sizes. A size mismatch here means the protocol is broken on the wire.
 */

#include "test_harness.h"
#include "../loader/tachyon.h"

/* ── Ghost Header (must be exactly 20 bytes) ── */

TEST(ghost_hdr_size) {
    ASSERT_EQ(sizeof(tachyon_ghost_hdr), 20);
}

/* ── BPF Map Value Structures ── */

TEST(config_size) {
    ASSERT_EQ(sizeof(tachyon_config), 4);
}

TEST(key_init_size) {
    ASSERT_EQ(sizeof(tachyon_key_init), 4 + 32 + 32);  /* session_id + tx + rx */
}

/* ── Control Plane Messages ── */

TEST(msg_init_size) {
    ASSERT_EQ(sizeof(MsgInit), 20);
}

TEST(msg_cookie_size) {
    ASSERT_EQ(sizeof(MsgCookie), 48);  /* 4+4+8+32 */
}

TEST(msg_auth_size) {
    ASSERT_EQ(sizeof(MsgAuth), 100);  /* 1+3+4+8+1+3+32+48 = 100 */
}

TEST(msg_finish_size) {
    ASSERT_EQ(sizeof(MsgFinish), 64);  /* 1+3+4+8+48 = 64 */
}

TEST(msg_keepalive_size) {
    ASSERT_EQ(sizeof(MsgKeepalive), 48);  /* 4+4+8+32 */
}

/* ── Constants Consistency ── */

TEST(tx_head_adjust_consistency) {
    /* TX_HEAD_ADJUST = ETH(14) + IP(20) + UDP(8) + (Ghost reuses inner ETH = -14) */
    ASSERT_EQ(TACHYON_TX_HEAD_ADJUST, 48);
}

TEST(outer_hdr_len_consistency) {
    int expected = TACHYON_ETH_HDR_LEN + TACHYON_IP_HDR_LEN +
                   TACHYON_UDP_HDR_LEN + TACHYON_GHOST_HDR_LEN;
    ASSERT_EQ(TACHYON_OUTER_HDR_LEN, expected);
}

TEST(aead_tag_len) {
    ASSERT_EQ(TACHYON_AEAD_TAG_LEN, 16);
}

TEST(aead_key_len) {
    ASSERT_EQ(TACHYON_AEAD_KEY_LEN, 32);
}

TEST(aead_iv_len) {
    ASSERT_EQ(TACHYON_AEAD_IV_LEN, 12);
}

TEST(replay_window_words) {
    ASSERT_EQ(TACHYON_REPLAY_WINDOW / 64, TACHYON_REPLAY_WORDS);
}

TEST(max_sessions) {
    ASSERT_EQ(TACHYON_MAX_SESSIONS, 256);
}

/* ── Rate Limit Config Size ── */

TEST(rate_cfg_size) {
    ASSERT_EQ(sizeof(tachyon_rate_cfg), 32);  /* 4 x uint64_t */
}

/* ── Runner ── */

int main() {
    printf("\n  Tachyon Protocol Tests\n");
    printf("  ─────────────────────────────────\n");

    RUN_TEST(ghost_hdr_size);
    RUN_TEST(config_size);
    RUN_TEST(key_init_size);
    RUN_TEST(msg_init_size);
    RUN_TEST(msg_cookie_size);
    RUN_TEST(msg_auth_size);
    RUN_TEST(msg_finish_size);
    RUN_TEST(msg_keepalive_size);
    RUN_TEST(tx_head_adjust_consistency);
    RUN_TEST(outer_hdr_len_consistency);
    RUN_TEST(aead_tag_len);
    RUN_TEST(aead_key_len);
    RUN_TEST(aead_iv_len);
    RUN_TEST(replay_window_words);
    RUN_TEST(max_sessions);
    RUN_TEST(rate_cfg_size);

    return test_summary();
}
