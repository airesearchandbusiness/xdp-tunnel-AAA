/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for loader/secmem — constant-time primitives and the
 * SecureBytes RAII buffer.
 *
 * Coverage:
 *   - secure_zero actually clears (sanity check; LTO elide-resistance is
 *     a property of OPENSSL_cleanse)
 *   - const_time_eq matches memcmp semantics but is side-channel-safe
 *   - const_time_select_u8 / _u32 return the correct side under both
 *     boolean selectors
 *   - const_time_copy copies iff cond==1
 *   - SecureBytes: construct / move / resize / wipe semantics
 *   - Buffer is zero-initialised
 */

#include <gtest/gtest.h>
#include "secmem.h"

#include <cstring>
#include <vector>
#include <utility>

using namespace tachyon::secmem;

TEST(Secmem, SecureZeroActuallyZeroes) {
    uint8_t buf[64];
    for (size_t i = 0; i < sizeof(buf); ++i)
        buf[i] = static_cast<uint8_t>(i + 1);
    secure_zero(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); ++i)
        EXPECT_EQ(buf[i], 0u) << "byte " << i << " not zero";
}

TEST(Secmem, SecureZeroHandlesNullAndZero) {
    secure_zero(nullptr, 16); /* must not crash */
    uint8_t b = 0xAB;
    secure_zero(&b, 0); /* must not touch */
    EXPECT_EQ(b, 0xABu);
}

TEST(Secmem, ConstTimeEqMatchesMemcmp) {
    uint8_t a[32], b[32];
    for (size_t i = 0; i < 32; ++i) {
        a[i] = static_cast<uint8_t>(i);
        b[i] = static_cast<uint8_t>(i);
    }
    EXPECT_EQ(const_time_eq(a, b, 32), 1);
    b[17] ^= 0x01;
    EXPECT_EQ(const_time_eq(a, b, 32), 0);
    /* Zero-length is vacuously equal */
    EXPECT_EQ(const_time_eq(a, b, 0), 1);
}

TEST(Secmem, ConstTimeSelectU8) {
    EXPECT_EQ(const_time_select_u8(0, 0xAA, 0xBB), 0xAAu);
    EXPECT_EQ(const_time_select_u8(1, 0xAA, 0xBB), 0xBBu);
}

TEST(Secmem, ConstTimeSelectU32) {
    EXPECT_EQ(const_time_select_u32(0, 0xDEADBEEF, 0xCAFEBABE), 0xDEADBEEFu);
    EXPECT_EQ(const_time_select_u32(1, 0xDEADBEEF, 0xCAFEBABE), 0xCAFEBABEu);
}

TEST(Secmem, ConstTimeCopy) {
    uint8_t dst[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t src[8] = {9, 9, 9, 9, 9, 9, 9, 9};
    const_time_copy(0, dst, src, 8);
    EXPECT_EQ(dst[0], 1u); /* unchanged */
    const_time_copy(1, dst, src, 8);
    for (int i = 0; i < 8; ++i)
        EXPECT_EQ(dst[i], 9u);
}

/* ── SecureBytes ────────────────────────────────────────────────────── */

TEST(Secmem, SecureBytesZeroInitialised) {
    SecureBytes b(64);
    for (size_t i = 0; i < 64; ++i)
        EXPECT_EQ(b.data()[i], 0u);
    EXPECT_EQ(b.size(), 64u);
    EXPECT_FALSE(b.empty());
}

TEST(Secmem, SecureBytesDefaultConstructor) {
    SecureBytes b;
    EXPECT_TRUE(b.empty());
    EXPECT_EQ(b.size(), 0u);
    EXPECT_EQ(b.data(), nullptr);
}

TEST(Secmem, SecureBytesCopyFromSource) {
    const uint8_t src[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    SecureBytes b(src, sizeof(src));
    ASSERT_EQ(b.size(), 4u);
    EXPECT_EQ(std::memcmp(b.data(), src, 4), 0);
}

TEST(Secmem, SecureBytesMove) {
    SecureBytes a(32);
    a.data()[0] = 0xAA;
    uint8_t *raw = a.data();
    SecureBytes b = std::move(a);
    EXPECT_EQ(b.size(), 32u);
    EXPECT_EQ(b.data(), raw); /* pointer ownership transferred */
    EXPECT_EQ(a.size(), 0u);
    EXPECT_EQ(a.data(), nullptr);
    EXPECT_EQ(b.data()[0], 0xAAu);
}

TEST(Secmem, SecureBytesMoveAssign) {
    SecureBytes a(16), b(8);
    a.data()[0] = 0x42;
    b = std::move(a);
    EXPECT_EQ(b.size(), 16u);
    EXPECT_EQ(b.data()[0], 0x42u);
}

TEST(Secmem, SecureBytesWipeIsIdempotent) {
    SecureBytes b(8);
    b.wipe();
    EXPECT_TRUE(b.empty());
    b.wipe(); /* must not crash */
    EXPECT_TRUE(b.empty());
}

TEST(Secmem, SecureBytesResizeGrow) {
    SecureBytes b(4);
    for (size_t i = 0; i < 4; ++i)
        b.data()[i] = static_cast<uint8_t>(i + 1);
    b.resize(8);
    ASSERT_EQ(b.size(), 8u);
    EXPECT_EQ(b.data()[0], 1u);
    EXPECT_EQ(b.data()[3], 4u);
    EXPECT_EQ(b.data()[4], 0u); /* zero-initialised tail */
    EXPECT_EQ(b.data()[7], 0u);
}

TEST(Secmem, SecureBytesResizeShrink) {
    SecureBytes b(16);
    for (size_t i = 0; i < 16; ++i)
        b.data()[i] = static_cast<uint8_t>(i + 1);
    b.resize(4);
    ASSERT_EQ(b.size(), 4u);
    for (size_t i = 0; i < 4; ++i)
        EXPECT_EQ(b.data()[i], i + 1);
}

/* ── KeyBuf<N> ──────────────────────────────────────────────────────── */

TEST(Secmem, KeyBufIsZeroInitialised) {
    KeyBuf<32> k;
    EXPECT_EQ(k.size(), 32u);
    for (size_t i = 0; i < 32; ++i)
        EXPECT_EQ(k.data()[i], 0u);
}

TEST(Secmem, KeyBufAllowsMutation) {
    KeyBuf<16> k;
    for (size_t i = 0; i < 16; ++i)
        k.data()[i] = static_cast<uint8_t>(i + 1);
    EXPECT_EQ(k.data()[0], 1u);
    EXPECT_EQ(k.data()[15], 16u);
}

TEST(Secmem, KeyBufImplicitlyConvertsToPointer) {
    KeyBuf<32> k;
    /* This test verifies that KeyBuf can be passed to functions taking
     * uint8_t* — the same way raw uint8_t arrays are passed to OpenSSL. */
    auto fill = [](uint8_t *buf, size_t n) {
        for (size_t i = 0; i < n; ++i)
            buf[i] = 0xCC;
    };
    fill(k, 32);
    EXPECT_EQ(k.data()[0], 0xCCu);
    EXPECT_EQ(k.data()[31], 0xCCu);
}

TEST(Secmem, KeyBufDestructorCleansesContents) {
    /* Verify destructor runs secure_zero. We can't observe the cleansed
     * memory after destruction (UB), so we verify by placement-new into
     * a heap buffer, observe contents, destroy explicitly, then check
     * the underlying storage was zeroed. */
    alignas(KeyBuf<16>) uint8_t storage[sizeof(KeyBuf<16>)];
    auto *k = new (storage) KeyBuf<16>();
    for (size_t i = 0; i < 16; ++i)
        k->data()[i] = 0xAB;
    EXPECT_EQ(k->data()[0], 0xABu);
    k->~KeyBuf<16>();
    /* Read raw storage — must be zero after destructor cleanse */
    for (size_t i = 0; i < 16; ++i)
        EXPECT_EQ(storage[i], 0u) << "byte " << i << " not cleansed";
}

TEST(Secmem, KeyBufVariousSizes) {
    KeyBuf<1> k1;
    KeyBuf<8> k8;
    KeyBuf<48> k48;
    KeyBuf<256> k256;
    EXPECT_EQ(k1.size(), 1u);
    EXPECT_EQ(k8.size(), 8u);
    EXPECT_EQ(k48.size(), 48u);
    EXPECT_EQ(k256.size(), 256u);
    /* All zero-initialised */
    EXPECT_EQ(k1.data()[0], 0u);
    EXPECT_EQ(k48.data()[47], 0u);
    EXPECT_EQ(k256.data()[255], 0u);
}
