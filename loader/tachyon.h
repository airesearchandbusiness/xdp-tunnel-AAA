/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Control Plane - Shared Header
 *
 * Common includes, type definitions, logging macros, and function
 * declarations shared across all control plane translation units.
 */
#ifndef TACHYON_CTRL_H
#define TACHYON_CTRL_H

/* ── Standard Library ── */
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_map>
#include <list>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

/* ── System ── */
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/stat.h>
#include <linux/limits.h>

/* ── BPF ── */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* ── OpenSSL ── */
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>

/* ── Protocol Constants (from shared header) ── */
#include "../src/common.h"

/* ══════════════════════════════════════════════════════════════════════════
 * Logging
 * ══════════════════════════════════════════════════════════════════════════ */

#define LOG_INFO(fmt, ...)  fprintf(stderr, "[INFO]  " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  fprintf(stderr, "[WARN]  " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_CRYPTO(fmt, ...) fprintf(stderr, "[CRYPTO] " fmt "\n", ##__VA_ARGS__)

/* ══════════════════════════════════════════════════════════════════════════
 * Userspace Mirror Structures
 *
 * These mirror the BPF map value types from common.h but use standard
 * C types (no bpf_spin_lock). Layout MUST match tachyon_session etc.
 * ══════════════════════════════════════════════════════════════════════════ */

struct userspace_config {
    uint16_t listen_port_net;
    uint8_t  mimicry_type;
    uint8_t  pad;
};

struct userspace_session {
    uint32_t lock_pad;
    uint32_t peer_ip;
    uint32_t local_ip;
    uint8_t  peer_mac[6];
    uint8_t  _pad1[2];
    uint32_t _pad2;
    uint64_t rx_highest_seq[TACHYON_MAX_TX_CPUS];
    uint64_t rx_bitmap[TACHYON_MAX_TX_CPUS][TACHYON_REPLAY_WORDS];
};

struct userspace_key_init {
    uint32_t session_id;
    uint8_t  tx_key[TACHYON_AEAD_KEY_LEN];
    uint8_t  rx_key[TACHYON_AEAD_KEY_LEN];
};

struct userspace_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_replay_drops;
    uint64_t rx_crypto_errors;
    uint64_t rx_invalid_session;
    uint64_t rx_malformed;
    uint64_t rx_ratelimit_drops;
    uint64_t tx_crypto_errors;
    uint64_t tx_headroom_errors;
};

/* ══════════════════════════════════════════════════════════════════════════
 * Control Plane Message Structures (packed, wire format)
 * ══════════════════════════════════════════════════════════════════════════ */

#pragma pack(push, 1)

struct MsgInit {
    uint8_t  flags;
    uint8_t  pad[3];
    uint32_t session_id;
    uint64_t client_nonce;
    uint8_t  is_rekey;
    uint8_t  _reserved[3];
};

struct MsgCookie {
    uint8_t  flags;
    uint8_t  pad[3];
    uint32_t session_id;
    uint64_t client_nonce;
    uint8_t  cookie[TACHYON_HMAC_LEN];
};

struct MsgAuth {
    uint8_t  flags;
    uint8_t  pad[3];
    uint32_t session_id;
    uint64_t client_nonce;
    uint8_t  is_rekey;
    uint8_t  _reserved[3];
    uint8_t  cookie[TACHYON_HMAC_LEN];
    uint8_t  ciphertext[TACHYON_X25519_KEY_LEN + TACHYON_AEAD_TAG_LEN];
};

struct MsgFinish {
    uint8_t  flags;
    uint8_t  pad[3];
    uint32_t session_id;
    uint64_t server_nonce;
    uint8_t  ciphertext[TACHYON_X25519_KEY_LEN + TACHYON_AEAD_TAG_LEN];
};

struct MsgKeepalive {
    uint8_t  flags;
    uint8_t  pad[3];
    uint32_t session_id;
    uint64_t timestamp;
    uint8_t  ciphertext[TACHYON_AEAD_TAG_LEN + TACHYON_AEAD_TAG_LEN];
};

#pragma pack(pop)

/* ══════════════════════════════════════════════════════════════════════════
 * Parsed Tunnel Configuration
 * ══════════════════════════════════════════════════════════════════════════ */

struct TunnelConfig {
    std::string name;
    std::string private_key;
    std::string peer_public_key;
    std::string psk;
    std::string virtual_ip;
    std::string local_physical_ip;
    std::string physical_interface;
    std::string peer_endpoint_ip;
    std::string peer_endpoint_mac;
    std::string peer_inner_ip;
    int         listen_port   = TACHYON_DEFAULT_PORT;
    int         mimicry_type  = TACHYON_MIMICRY_QUIC;
    bool        encryption    = true;
};

/* ══════════════════════════════════════════════════════════════════════════
 * Nonce Deduplication Cache
 *
 * Uses an LRU list + hash map for O(1) insert and O(1) eviction.
 * Replaces the old linear-scan approach that had O(n) cleanup.
 * ══════════════════════════════════════════════════════════════════════════ */

class NonceCache {
public:
    void add(uint64_t nonce, uint64_t now_sec) {
        /* Evict expired entries from the front (oldest first) */
        while (!order_.empty()) {
            auto &front = order_.front();
            if (now_sec - front.second > TACHYON_NONCE_EXPIRY)  {
                map_.erase(front.first);
                order_.pop_front();
            } else {
                break;
            }
        }
        /* Cap total size */
        while (map_.size() >= TACHYON_NONCE_CACHE_MAX && !order_.empty()) {
            map_.erase(order_.front().first);
            order_.pop_front();
        }
        map_[nonce] = now_sec;
        order_.push_back({nonce, now_sec});
    }

    bool exists(uint64_t nonce) const {
        return map_.count(nonce) > 0;
    }

private:
    std::unordered_map<uint64_t, uint64_t> map_;
    std::list<std::pair<uint64_t, uint64_t>> order_;  /* front=oldest */
};

/* ══════════════════════════════════════════════════════════════════════════
 * Global State
 * ══════════════════════════════════════════════════════════════════════════ */

extern volatile sig_atomic_t g_exiting;
extern EVP_MAC *g_mac;
extern EVP_KDF *g_kdf;

/* ══════════════════════════════════════════════════════════════════════════
 * Function Declarations - crypto.cpp
 * ══════════════════════════════════════════════════════════════════════════ */

void  init_crypto_globals();
void  free_crypto_globals();

bool  calc_hmac(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *out_mac);

void  generate_cookie(const uint8_t *secret, uint32_t client_ip,
                      uint64_t nonce, uint64_t window,
                      uint8_t *out_cookie);

bool  do_ecdh(const uint8_t *my_priv, const uint8_t *peer_pub,
              uint8_t *out_shared_secret);

bool  derive_kdf(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const char *info, uint8_t *out_key);

bool  cp_aead_encrypt(const uint8_t *key, const uint8_t *pt, size_t pt_len,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *nonce,
                      uint8_t *ct, uint8_t *tag);

bool  cp_aead_decrypt(const uint8_t *key, const uint8_t *ct, size_t ct_len,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *nonce, const uint8_t *tag,
                      uint8_t *pt);

bool  generate_x25519_keypair(uint8_t *priv_out, uint8_t *pub_out);
bool  get_public_key(const uint8_t *priv, uint8_t *pub_out);

/* ══════════════════════════════════════════════════════════════════════════
 * Function Declarations - tunnel.cpp
 * ══════════════════════════════════════════════════════════════════════════ */

TunnelConfig parse_config(const std::string &filename);
bool         validate_config(const TunnelConfig &cfg);
std::string  tunnel_name_from_conf(const std::string &conf_path);

void  command_up(const std::string &conf_file);
void  command_down(const std::string &conf_file);
void  command_show(const std::string &conf_file);

/* ══════════════════════════════════════════════════════════════════════════
 * Utility Helpers
 * ══════════════════════════════════════════════════════════════════════════ */

inline bool hex2bin(const std::string &hex, uint8_t *bin, size_t bin_len) {
    if (hex.size() != bin_len * 2) return false;
    for (size_t i = 0; i < bin_len; i++) {
        if (sscanf(&hex[i * 2], "%2hhx", &bin[i]) != 1)
            return false;
    }
    return true;
}

inline bool parse_mac(const std::string &str, uint8_t mac[6]) {
    return sscanf(str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

inline std::string trim(std::string s) {
    s.erase(0, s.find_first_not_of(" \t\r\n"));
    s.erase(s.find_last_not_of(" \t\r\n") + 1);
    return s;
}

inline bool run_cmd(const std::string &cmd) {
    int ret = system(cmd.c_str());
    if (ret != 0)
        LOG_WARN("Command failed (exit %d): %s", ret, cmd.c_str());
    return ret == 0;
}

#endif /* TACHYON_CTRL_H */
