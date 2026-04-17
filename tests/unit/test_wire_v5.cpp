/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for v5 wire-format structures and constants.
 *
 * These verify compile-time sizes and field offsets to catch layout drift
 * between the eBPF, kernel-module, and userspace compilation paths.
 */

#include <gtest/gtest.h>

#define TACHYON_NO_BPF
#include "../src/common.h"

#include <cstddef>
#include <cstring>

TEST(WireV5, MsgInitV5Size) {
    EXPECT_EQ(sizeof(tachyon_msg_init_v5), 1264u);
}

TEST(WireV5, MsgCookieV5Size) {
    EXPECT_EQ(sizeof(tachyon_msg_cookie_v5), 1176u);
}

TEST(WireV5, DataHdrV5Size) {
    EXPECT_EQ(sizeof(tachyon_data_hdr_v5), 28u);
}

TEST(WireV5, MagicConstants) {
    EXPECT_EQ(TACHYON_V5_MAGIC, 0x54434835u);
    EXPECT_EQ(TACHYON_V4_MAGIC, 0x54434834u);
    EXPECT_NE(TACHYON_V5_MAGIC, TACHYON_V4_MAGIC);
}

TEST(WireV5, MlkemConstantsMatchFips) {
    EXPECT_EQ(TACHYON_MLKEM768_PK_LEN, 1184u);
    EXPECT_EQ(TACHYON_MLKEM768_SK_LEN, 2400u);
    EXPECT_EQ(TACHYON_MLKEM768_CT_LEN, 1088u);
    EXPECT_EQ(TACHYON_MLKEM768_SS_LEN, 32u);
}

TEST(WireV5, ProtoVersion) {
    EXPECT_EQ(TACHYON_PROTO_VERSION, 5);
    EXPECT_EQ(TACHYON_PROTO_VERSION_V4, 4);
}

TEST(WireV5, InitV5FieldLayout) {
    tachyon_msg_init_v5 m{};
    m.magic = TACHYON_V5_MAGIC;
    m.version = 5;
    m.flags = TACHYON_V5_FLAG_PQ_HYBRID;
    m.transport_id = 2; /* QUIC */

    const uint8_t *raw = reinterpret_cast<const uint8_t *>(&m);

    /* Magic at offset 0: big-endian "TCH5" = 0x54434835 on LE means
     * raw bytes are 0x35, 0x48, 0x43, 0x54. Just check field offset. */
    EXPECT_EQ(offsetof(tachyon_msg_init_v5, magic), 0u);
    EXPECT_EQ(offsetof(tachyon_msg_init_v5, version), 4u);
    EXPECT_EQ(offsetof(tachyon_msg_init_v5, flags), 5u);
    EXPECT_EQ(offsetof(tachyon_msg_init_v5, transport_id), 6u);
    EXPECT_EQ(offsetof(tachyon_msg_init_v5, client_x25519_pk), 8u);
    EXPECT_EQ(offsetof(tachyon_msg_init_v5, client_mlkem768_pk), 40u);
    EXPECT_EQ(offsetof(tachyon_msg_init_v5, nonce), 1224u);
    EXPECT_EQ(offsetof(tachyon_msg_init_v5, timestamp_be), 1240u);
    EXPECT_EQ(offsetof(tachyon_msg_init_v5, cookie), 1248u);
    (void)raw;
}

TEST(WireV5, CookieV5FieldLayout) {
    EXPECT_EQ(offsetof(tachyon_msg_cookie_v5, magic), 0u);
    EXPECT_EQ(offsetof(tachyon_msg_cookie_v5, server_x25519_pk), 4u);
    EXPECT_EQ(offsetof(tachyon_msg_cookie_v5, mlkem768_ct), 36u);
    EXPECT_EQ(offsetof(tachyon_msg_cookie_v5, transport_id), 1124u);
    EXPECT_EQ(offsetof(tachyon_msg_cookie_v5, cookie), 1128u);
    EXPECT_EQ(offsetof(tachyon_msg_cookie_v5, hmac), 1144u);
}

TEST(WireV5, DataHdrV5FieldLayout) {
    EXPECT_EQ(offsetof(tachyon_data_hdr_v5, flags), 0u);
    EXPECT_EQ(offsetof(tachyon_data_hdr_v5, transport_id), 1u);
    EXPECT_EQ(offsetof(tachyon_data_hdr_v5, session_id), 4u);
    EXPECT_EQ(offsetof(tachyon_data_hdr_v5, seq), 8u);
    EXPECT_EQ(offsetof(tachyon_data_hdr_v5, nonce_salt), 16u);
    EXPECT_EQ(offsetof(tachyon_data_hdr_v5, ratchet_ctr), 20u);
}

TEST(WireV5, V4LegacyStructsUnchanged) {
    EXPECT_EQ(sizeof(tachyon_ghost_hdr), 20u);
    EXPECT_EQ(sizeof(tachyon_msg_init), 20u);
    EXPECT_EQ(sizeof(tachyon_msg_cookie), 48u);
    EXPECT_EQ(sizeof(tachyon_msg_auth), 100u);
    EXPECT_EQ(sizeof(tachyon_msg_finish), 64u);
}

TEST(WireV5, FlagBitsOrthogonal) {
    EXPECT_EQ(TACHYON_V5_FLAG_PQ_HYBRID & TACHYON_V5_FLAG_CLASSICAL, 0);
    EXPECT_EQ(TACHYON_V5_FLAG_PQ_HYBRID & TACHYON_V5_FLAG_REKEY, 0);
    EXPECT_EQ(TACHYON_V5_FLAG_CLASSICAL & TACHYON_V5_FLAG_TRANSPORT, 0);
}
