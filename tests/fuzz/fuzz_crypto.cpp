/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Fuzz Test - Cryptographic Operations
 *
 * libFuzzer harness for crypto primitives. Tests that no combination
 * of inputs causes crashes, memory errors, or undefined behavior.
 *
 * Build:
 *   cmake -B build -S tests -DBUILD_FUZZ_TESTS=ON \
 *         -DCMAKE_CXX_COMPILER=clang++
 *   cmake --build build --target fuzz_crypto
 *
 * Run:
 *   ./build/fuzz_crypto -max_total_time=300
 */

#include <cstdint>
#include <cstring>
#include "tachyon.h"

static bool g_initialized = false;

/* Initialize OpenSSL globals once */
static void ensure_init()
{
    if (!g_initialized) {
        init_crypto_globals();
        g_initialized = true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ensure_init();

    /* Need at least: 1 byte selector + 32 byte key + 12 byte nonce + 1 byte data */
    if (size < 46)
        return 0;

    uint8_t selector = data[0];
    data++;
    size--;

    switch (selector % 4) {
    case 0: {
        /* Fuzz HMAC-SHA256 */
        if (size < 32)
            break;
        uint8_t mac[TACHYON_HMAC_LEN];
        calc_hmac(data, 32, data + 32, size - 32, mac);
        break;
    }

    case 1: {
        /* Fuzz ChaCha20-Poly1305 encrypt + decrypt roundtrip */
        if (size < 44)
            break; /* 32 key + 12 nonce */
        const uint8_t *key = data;
        const uint8_t *nonce = data + 32;
        const uint8_t *pt = data + 44;
        size_t pt_len = size - 44;

        if (pt_len > 4096)
            pt_len = 4096; /* Cap to avoid huge allocations */

        uint8_t ct[4096], tag[TACHYON_AEAD_TAG_LEN], dec[4096];

        if (cp_aead_encrypt(key, pt, pt_len, nullptr, 0, nonce, ct, tag)) {
            cp_aead_decrypt(key, ct, pt_len, nullptr, 0, nonce, tag, dec);
        }
        break;
    }

    case 2: {
        /* Fuzz ChaCha20-Poly1305 decrypt with random inputs (should fail gracefully) */
        if (size < 60)
            break; /* 32 key + 12 nonce + 16 tag */
        const uint8_t *key = data;
        const uint8_t *nonce = data + 32;
        const uint8_t *tag = data + 44;
        const uint8_t *ct = data + 60;
        size_t ct_len = size - 60;

        if (ct_len > 4096)
            ct_len = 4096;
        if (ct_len == 0)
            break;

        uint8_t dec[4096];
        /* This should return false for random input, never crash */
        cp_aead_decrypt(key, ct, ct_len, nullptr, 0, nonce, tag, dec);
        break;
    }

    case 3: {
        /* Fuzz HKDF derivation */
        if (size < 64)
            break; /* 32 salt + 32 ikm */
        uint8_t out[TACHYON_AEAD_KEY_LEN];

        /* Use remaining bytes as info label, null-terminated */
        size_t info_len = size - 64;
        if (info_len > 255)
            info_len = 255;

        char info[256];
        memcpy(info, data + 64, info_len);
        info[info_len] = '\0';

        derive_kdf(data, 32, data + 32, 32, info, out);
        break;
    }
    }

    return 0;
}
