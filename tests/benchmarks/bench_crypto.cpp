/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Crypto Benchmarks
 *
 * Measures throughput and latency of the crypto primitives that are in
 * the hot path of the XDP tunnel:
 *
 *   BM_AeadEncrypt   — ChaCha20-Poly1305 encrypt (various payload sizes)
 *   BM_AeadDecrypt   — ChaCha20-Poly1305 decrypt (various payload sizes)
 *   BM_HmacSha256    — HMAC-SHA256 (cookie generation, N-byte payloads)
 *   BM_Hkdf          — HKDF-SHA256 (key derivation, one call per session)
 *   BM_EcdhKeypair   — X25519 keypair generation
 *   BM_EcdhExchange  — X25519 shared-secret derivation
 *
 * Build:
 *   cmake -B build/bench -S tests -DBUILD_BENCHMARKS=ON
 *   cmake --build build/bench --target bench_crypto
 *   build/bench/bench_crypto --benchmark_format=json
 *
 * Run requirements: no root, no kernel module, no libbpf.
 */

#include <benchmark/benchmark.h>
#include <cstring>
#include <vector>

#include "tachyon.h"

/* ── Fixture: initialise/free OpenSSL globals once per benchmark ─────────── */

class CryptoBenchmark : public benchmark::Fixture {
  public:
    void SetUp(::benchmark::State &) override { init_crypto_globals(); }
    void TearDown(::benchmark::State &) override { free_crypto_globals(); }
};

/* ══════════════════════════════════════════════════════════════════════════
 * ChaCha20-Poly1305 AEAD — Encrypt
 *
 * Packet sizes modelled after real XDP workloads:
 *   64 B  — minimum Ethernet frame payload
 *   512 B — typical DNS/NTP
 *   1400 B — near-MTU (post-tunnel overhead)
 *   9000 B — jumbo frame
 * ══════════════════════════════════════════════════════════════════════════ */

BENCHMARK_DEFINE_F(CryptoBenchmark, AeadEncrypt)(benchmark::State &state) {
    const size_t pt_size = static_cast<size_t>(state.range(0));

    uint8_t key[TACHYON_AEAD_KEY_LEN], nonce[TACHYON_AEAD_NONCE_LEN];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x00, sizeof(nonce));

    std::vector<uint8_t> plaintext(pt_size, 0xAB);
    std::vector<uint8_t> ciphertext(pt_size);
    uint8_t tag[TACHYON_AEAD_TAG_LEN];

    for (auto _ : state) {
        benchmark::DoNotOptimize(cp_aead_encrypt(key, plaintext.data(), pt_size, nullptr, 0, nonce,
                                                 ciphertext.data(), tag));
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(pt_size));
    state.SetLabel(std::to_string(pt_size) + " B/op");
}
BENCHMARK_REGISTER_F(CryptoBenchmark, AeadEncrypt)
    ->Arg(64)
    ->Arg(512)
    ->Arg(1400)
    ->Arg(9000)
    ->Unit(benchmark::kMicrosecond);

/* ── Decrypt ─────────────────────────────────────────────────────────────── */

BENCHMARK_DEFINE_F(CryptoBenchmark, AeadDecrypt)(benchmark::State &state) {
    const size_t pt_size = static_cast<size_t>(state.range(0));

    uint8_t key[TACHYON_AEAD_KEY_LEN], nonce[TACHYON_AEAD_NONCE_LEN];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x00, sizeof(nonce));

    std::vector<uint8_t> plaintext(pt_size, 0xAB);
    std::vector<uint8_t> ciphertext(pt_size);
    std::vector<uint8_t> decrypted(pt_size);
    uint8_t tag[TACHYON_AEAD_TAG_LEN];

    /* Pre-encrypt once so we have a valid (ct, tag) pair to decrypt */
    cp_aead_encrypt(key, plaintext.data(), pt_size, nullptr, 0, nonce, ciphertext.data(), tag);

    for (auto _ : state) {
        benchmark::DoNotOptimize(cp_aead_decrypt(key, ciphertext.data(), pt_size, nullptr, 0, nonce,
                                                 tag, decrypted.data()));
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(pt_size));
    state.SetLabel(std::to_string(pt_size) + " B/op");
}
BENCHMARK_REGISTER_F(CryptoBenchmark, AeadDecrypt)
    ->Arg(64)
    ->Arg(512)
    ->Arg(1400)
    ->Arg(9000)
    ->Unit(benchmark::kMicrosecond);

/* ══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256 — Cookie / MAC generation
 * ══════════════════════════════════════════════════════════════════════════ */

BENCHMARK_DEFINE_F(CryptoBenchmark, HmacSha256)(benchmark::State &state) {
    const size_t data_size = static_cast<size_t>(state.range(0));

    uint8_t key[32];
    memset(key, 0x0b, sizeof(key));

    std::vector<uint8_t> data(data_size, 0xAA);
    uint8_t mac[TACHYON_HMAC_LEN];

    for (auto _ : state) {
        benchmark::DoNotOptimize(calc_hmac(key, sizeof(key), data.data(), data_size, mac));
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(data_size));
}
BENCHMARK_REGISTER_F(CryptoBenchmark, HmacSha256)
    ->Arg(32)
    ->Arg(64)
    ->Arg(256)
    ->Unit(benchmark::kMicrosecond);

/* ══════════════════════════════════════════════════════════════════════════
 * HKDF-SHA256 — Key Derivation
 *
 * Called once per session during handshake; latency matters more than
 * throughput here.
 * ══════════════════════════════════════════════════════════════════════════ */

BENCHMARK_DEFINE_F(CryptoBenchmark, HkdfDerive)(benchmark::State &state) {
    uint8_t salt[32], ikm[32], out[TACHYON_AEAD_KEY_LEN];
    memset(salt, 0xaa, sizeof(salt));
    memset(ikm, 0xbb, sizeof(ikm));

    for (auto _ : state) {
        benchmark::DoNotOptimize(
            derive_kdf(salt, sizeof(salt), ikm, sizeof(ikm), TACHYON_KDF_SESSION_MASTER, out));
        benchmark::ClobberMemory();
    }
}
BENCHMARK_REGISTER_F(CryptoBenchmark, HkdfDerive)->Unit(benchmark::kMicrosecond);

/* ══════════════════════════════════════════════════════════════════════════
 * X25519 — Keypair Generation & ECDH Exchange
 *
 * Both ops happen once per AKE handshake per peer.
 * ══════════════════════════════════════════════════════════════════════════ */

BENCHMARK_DEFINE_F(CryptoBenchmark, EcdhKeypairGen)(benchmark::State &state) {
    uint8_t priv_key[32], pub_key[32];

    for (auto _ : state) {
        benchmark::DoNotOptimize(generate_x25519_keypair(priv_key, pub_key));
        benchmark::ClobberMemory();
    }
}
BENCHMARK_REGISTER_F(CryptoBenchmark, EcdhKeypairGen)->Unit(benchmark::kMicrosecond);

BENCHMARK_DEFINE_F(CryptoBenchmark, EcdhExchange)(benchmark::State &state) {
    uint8_t priv_a[32], pub_a[32], priv_b[32], pub_b[32], shared[32];
    generate_x25519_keypair(priv_a, pub_a);
    generate_x25519_keypair(priv_b, pub_b);

    for (auto _ : state) {
        benchmark::DoNotOptimize(do_ecdh(priv_a, pub_b, shared));
        benchmark::ClobberMemory();
    }
}
BENCHMARK_REGISTER_F(CryptoBenchmark, EcdhExchange)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();
