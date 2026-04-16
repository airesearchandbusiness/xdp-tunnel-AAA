/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Unit Tests - Utility Helpers
 *
 * Tests hex2bin(), parse_mac(), and trim() from loader/tachyon.h.
 */

#include <gtest/gtest.h>
#include <cstring>
#include "tachyon.h"

/* ══════════════════════════════════════════════════════════════════════════
 * hex2bin Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(Hex2BinTest, ValidConversion) {
    uint8_t out[4];
    ASSERT_TRUE(hex2bin("deadbeef", out, 4));
    EXPECT_EQ(out[0], 0xde);
    EXPECT_EQ(out[1], 0xad);
    EXPECT_EQ(out[2], 0xbe);
    EXPECT_EQ(out[3], 0xef);
}

TEST(Hex2BinTest, ValidUpperCase) {
    uint8_t out[4];
    ASSERT_TRUE(hex2bin("DEADBEEF", out, 4));
    EXPECT_EQ(out[0], 0xde);
    EXPECT_EQ(out[1], 0xad);
    EXPECT_EQ(out[2], 0xbe);
    EXPECT_EQ(out[3], 0xef);
}

TEST(Hex2BinTest, ValidMixedCase) {
    uint8_t out[2];
    ASSERT_TRUE(hex2bin("aB12", out, 2));
    EXPECT_EQ(out[0], 0xab);
    EXPECT_EQ(out[1], 0x12);
}

TEST(Hex2BinTest, ValidAllZeros) {
    uint8_t out[4];
    ASSERT_TRUE(hex2bin("00000000", out, 4));
    EXPECT_EQ(out[0], 0x00);
    EXPECT_EQ(out[1], 0x00);
    EXPECT_EQ(out[2], 0x00);
    EXPECT_EQ(out[3], 0x00);
}

TEST(Hex2BinTest, ValidAllOnes) {
    uint8_t out[4];
    ASSERT_TRUE(hex2bin("ffffffff", out, 4));
    EXPECT_EQ(out[0], 0xff);
    EXPECT_EQ(out[1], 0xff);
    EXPECT_EQ(out[2], 0xff);
    EXPECT_EQ(out[3], 0xff);
}

TEST(Hex2BinTest, Valid32ByteKey) {
    uint8_t out[32];
    std::string hex(64, 'a');
    ASSERT_TRUE(hex2bin(hex, out, 32));
    for (int i = 0; i < 32; i++)
        EXPECT_EQ(out[i], 0xaa);
}

TEST(Hex2BinTest, InvalidOddLength) {
    uint8_t out[4];
    EXPECT_FALSE(hex2bin("deadbee", out, 4)); /* 7 hex chars for 4 bytes */
}

TEST(Hex2BinTest, InvalidTooShort) {
    uint8_t out[4];
    EXPECT_FALSE(hex2bin("dead", out, 4)); /* 4 hex chars for 4 bytes */
}

TEST(Hex2BinTest, InvalidTooLong) {
    uint8_t out[2];
    EXPECT_FALSE(hex2bin("deadbeef", out, 2)); /* 8 hex chars for 2 bytes */
}

TEST(Hex2BinTest, EmptyStringZeroLen) {
    uint8_t out[1] = {0xff};
    ASSERT_TRUE(hex2bin("", out, 0));
    EXPECT_EQ(out[0], 0xff); /* Unchanged */
}

TEST(Hex2BinTest, InvalidNonHexChars) {
    uint8_t out[4];
    EXPECT_FALSE(hex2bin("deadgxyz", out, 4));
}

/* ══════════════════════════════════════════════════════════════════════════
 * parse_mac Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(ParseMacTest, ValidMAC) {
    uint8_t mac[6];
    ASSERT_TRUE(parse_mac("aa:bb:cc:dd:ee:ff", mac));
    EXPECT_EQ(mac[0], 0xaa);
    EXPECT_EQ(mac[1], 0xbb);
    EXPECT_EQ(mac[2], 0xcc);
    EXPECT_EQ(mac[3], 0xdd);
    EXPECT_EQ(mac[4], 0xee);
    EXPECT_EQ(mac[5], 0xff);
}

TEST(ParseMacTest, ValidMACAllZeros) {
    uint8_t mac[6];
    ASSERT_TRUE(parse_mac("00:00:00:00:00:00", mac));
    for (int i = 0; i < 6; i++)
        EXPECT_EQ(mac[i], 0x00);
}

TEST(ParseMacTest, ValidMACBroadcast) {
    uint8_t mac[6];
    ASSERT_TRUE(parse_mac("ff:ff:ff:ff:ff:ff", mac));
    for (int i = 0; i < 6; i++)
        EXPECT_EQ(mac[i], 0xff);
}

TEST(ParseMacTest, InvalidMissingColons) {
    uint8_t mac[6];
    EXPECT_FALSE(parse_mac("aabbccddeeff", mac));
}

TEST(ParseMacTest, InvalidTooFewOctets) {
    uint8_t mac[6];
    EXPECT_FALSE(parse_mac("aa:bb:cc:dd:ee", mac));
}

TEST(ParseMacTest, InvalidEmpty) {
    uint8_t mac[6];
    EXPECT_FALSE(parse_mac("", mac));
}

TEST(ParseMacTest, InvalidGarbage) {
    uint8_t mac[6];
    EXPECT_FALSE(parse_mac("not_a_mac", mac));
}

/* ══════════════════════════════════════════════════════════════════════════
 * trim Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(TrimTest, LeadingSpaces) {
    EXPECT_EQ(trim("   hello"), "hello");
}

TEST(TrimTest, TrailingSpaces) {
    EXPECT_EQ(trim("hello   "), "hello");
}

TEST(TrimTest, BothSides) {
    EXPECT_EQ(trim("  hello  "), "hello");
}

TEST(TrimTest, Tabs) {
    EXPECT_EQ(trim("\thello\t"), "hello");
}

TEST(TrimTest, Newlines) {
    EXPECT_EQ(trim("\nhello\n"), "hello");
}

TEST(TrimTest, CarriageReturn) {
    EXPECT_EQ(trim("\r\nhello\r\n"), "hello");
}

TEST(TrimTest, MixedWhitespace) {
    EXPECT_EQ(trim(" \t\n\r hello world \r\n\t "), "hello world");
}

TEST(TrimTest, EmptyString) {
    EXPECT_EQ(trim(""), "");
}

TEST(TrimTest, AllWhitespace) {
    EXPECT_EQ(trim("   \t\n\r  "), "");
}

TEST(TrimTest, NoWhitespace) {
    EXPECT_EQ(trim("hello"), "hello");
}

TEST(TrimTest, InternalSpacesPreserved) {
    EXPECT_EQ(trim("  hello   world  "), "hello   world");
}
