/* SPDX-License-Identifier: MIT */
#include "fingerprint.h"

#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cstring>

namespace tachyon::fp {

static uint32_t rand_u32() {
    uint32_t r = 0;
    RAND_bytes(reinterpret_cast<unsigned char *>(&r), sizeof(r));
    return r;
}

uint8_t random_ttl() {
    const uint32_t range = static_cast<uint32_t>(TTL_MAX - TTL_MIN + 1);
    return static_cast<uint8_t>(TTL_MIN + (rand_u32() % range));
}

void random_locally_admin_mac(uint8_t out[6]) {
    RAND_bytes(out, 6);
    /* Enforce locally-administered (bit 1 of first octet) and unicast (bit 0 = 0). */
    out[0] = (out[0] & 0xFCu) | 0x02u;
}

uint16_t port_hop_current(const uint8_t psk[32], uint32_t period_s, uint64_t unix_time_s) {
    if (period_s == 0)
        period_s = 60;

    const uint64_t epoch = unix_time_s / period_s;

    uint8_t mac[SHA256_DIGEST_LENGTH];
    unsigned int mac_len = 0;

    /* HMAC-SHA256(psk, big-endian epoch bytes) */
    uint8_t msg[8];
    for (int i = 0; i < 8; i++)
        msg[7 - i] = static_cast<uint8_t>((epoch >> (i * 8)) & 0xFFu);

    if (!HMAC(EVP_sha256(), psk, 32, msg, sizeof(msg), mac, &mac_len) ||
        mac_len < 2) {
        /* Deterministic fallback on HMAC failure — never happens with valid inputs */
        return PORT_HOP_MIN;
    }

    const uint32_t range = static_cast<uint32_t>(PORT_HOP_MAX - PORT_HOP_MIN + 1);
    const uint32_t raw = (static_cast<uint32_t>(mac[0]) << 8) | mac[1];
    return static_cast<uint16_t>(PORT_HOP_MIN + (raw % range));
}

uint16_t csprng_ip_id() {
    uint16_t r = 0;
    RAND_bytes(reinterpret_cast<unsigned char *>(&r), sizeof(r));
    return r;
}

uint64_t obfuscate_timestamp(uint64_t ts_ns, uint64_t jitter_ns) {
    if (jitter_ns == 0)
        return ts_ns;
    uint64_t r;
    RAND_bytes(reinterpret_cast<unsigned char *>(&r), sizeof(r));
    /* signed jitter: map r into [-jitter_ns, +jitter_ns] */
    const int64_t j = static_cast<int64_t>(r % (2 * jitter_ns + 1)) - static_cast<int64_t>(jitter_ns);
    const int64_t signed_ts = static_cast<int64_t>(ts_ns);
    const int64_t combined = signed_ts + j;
    return combined < 0 ? 0 : static_cast<uint64_t>(combined);
}

} /* namespace tachyon::fp */
