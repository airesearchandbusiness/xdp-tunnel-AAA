/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Test Suite - Utility Functions & NonceCache
 */

#include "test_harness.h"
#include "../loader/tachyon.h"

/* ── hex2bin Tests ── */

TEST(hex2bin_valid)
{
    uint8_t out[4];
    ASSERT_TRUE(hex2bin("deadbeef", out, 4));
    ASSERT_EQ(out[0], 0xDE);
    ASSERT_EQ(out[1], 0xAD);
    ASSERT_EQ(out[2], 0xBE);
    ASSERT_EQ(out[3], 0xEF);
}

TEST(hex2bin_zeros)
{
    uint8_t out[2];
    ASSERT_TRUE(hex2bin("0000", out, 2));
    ASSERT_EQ(out[0], 0x00);
    ASSERT_EQ(out[1], 0x00);
}

TEST(hex2bin_full_key)
{
    uint8_t out[32];
    std::string hex = "aabbccdd00112233445566778899aabbccddeeff0011223344556677889900aa";
    ASSERT_TRUE(hex2bin(hex, out, 32));
    ASSERT_EQ(out[0], 0xAA);
    ASSERT_EQ(out[31], 0xAA);
}

TEST(hex2bin_wrong_length)
{
    uint8_t out[4];
    ASSERT_FALSE(hex2bin("dead", out, 4));       /* Too short */
    ASSERT_FALSE(hex2bin("deadbeef00", out, 4)); /* Too long */
}

TEST(hex2bin_empty)
{
    uint8_t out[1];
    ASSERT_FALSE(hex2bin("", out, 1));
    ASSERT_TRUE(hex2bin("", out, 0)); /* Zero-length is valid */
}

/* ── parse_mac Tests ── */

TEST(parse_mac_valid)
{
    uint8_t mac[6];
    ASSERT_TRUE(parse_mac("aa:bb:cc:dd:ee:ff", mac));
    ASSERT_EQ(mac[0], 0xAA);
    ASSERT_EQ(mac[5], 0xFF);
}

TEST(parse_mac_zeros)
{
    uint8_t mac[6];
    ASSERT_TRUE(parse_mac("00:00:00:00:00:00", mac));
    ASSERT_EQ(mac[0], 0x00);
    ASSERT_EQ(mac[5], 0x00);
}

TEST(parse_mac_invalid_format)
{
    uint8_t mac[6];
    ASSERT_FALSE(parse_mac("not-a-mac", mac));
    ASSERT_FALSE(parse_mac("aa:bb:cc:dd:ee", mac)); /* Too few */
    ASSERT_FALSE(parse_mac("", mac));
}

/* ── trim Tests ── */

TEST(trim_leading)
{
    ASSERT_TRUE(trim("  hello") == "hello");
}

TEST(trim_trailing)
{
    ASSERT_TRUE(trim("hello  ") == "hello");
}

TEST(trim_both)
{
    ASSERT_TRUE(trim("  hello  ") == "hello");
}

TEST(trim_tabs_and_newlines)
{
    ASSERT_TRUE(trim("\t\n  data \r\n") == "data");
}

TEST(trim_empty)
{
    ASSERT_TRUE(trim("") == "");
}

TEST(trim_only_whitespace)
{
    ASSERT_TRUE(trim("   \t\n  ") == "");
}

TEST(trim_no_whitespace)
{
    ASSERT_TRUE(trim("clean") == "clean");
}

/* ── NonceCache Tests ── */

TEST(nonce_cache_add_and_exists)
{
    NonceCache cache;
    cache.add(12345, 100);
    ASSERT_TRUE(cache.exists(12345));
    ASSERT_FALSE(cache.exists(99999));
}

TEST(nonce_cache_expiry)
{
    NonceCache cache;
    cache.add(100, 1000); /* Added at time 1000 */
    ASSERT_TRUE(cache.exists(100));

    /* Add another entry far in the future - should evict expired ones */
    cache.add(200, 1000 + TACHYON_NONCE_EXPIRY + 1);
    ASSERT_FALSE(cache.exists(100)); /* Expired */
    ASSERT_TRUE(cache.exists(200));  /* Fresh */
}

TEST(nonce_cache_multiple_entries)
{
    NonceCache cache;
    for (uint64_t i = 0; i < 100; i++) {
        cache.add(i, i);
    }
    ASSERT_TRUE(cache.exists(0));
    ASSERT_TRUE(cache.exists(50));
    ASSERT_TRUE(cache.exists(99));
    ASSERT_FALSE(cache.exists(100));
}

TEST(nonce_cache_overwrite)
{
    NonceCache cache;
    cache.add(42, 100);
    cache.add(42, 200); /* Update timestamp */
    ASSERT_TRUE(cache.exists(42));
}

/* ── Runner ── */

int main()
{
    printf("\n  Tachyon Utility Tests\n");
    printf("  ─────────────────────────────────\n");

    RUN_TEST(hex2bin_valid);
    RUN_TEST(hex2bin_zeros);
    RUN_TEST(hex2bin_full_key);
    RUN_TEST(hex2bin_wrong_length);
    RUN_TEST(hex2bin_empty);
    RUN_TEST(parse_mac_valid);
    RUN_TEST(parse_mac_zeros);
    RUN_TEST(parse_mac_invalid_format);
    RUN_TEST(trim_leading);
    RUN_TEST(trim_trailing);
    RUN_TEST(trim_both);
    RUN_TEST(trim_tabs_and_newlines);
    RUN_TEST(trim_empty);
    RUN_TEST(trim_only_whitespace);
    RUN_TEST(trim_no_whitespace);
    RUN_TEST(nonce_cache_add_and_exists);
    RUN_TEST(nonce_cache_expiry);
    RUN_TEST(nonce_cache_multiple_entries);
    RUN_TEST(nonce_cache_overwrite);

    return test_summary();
}
