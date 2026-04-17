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
#include <cassert>
#include <cctype>
#include <cinttypes>
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
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/limits.h>

/* ── BPF (optional - define TACHYON_NO_BPF to exclude for unit tests) ── */
#ifndef TACHYON_NO_BPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#endif

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

#define LOG_INFO(fmt, ...) fprintf(stderr, "[INFO]  " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) fprintf(stderr, "[WARN]  " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_CRYPTO(fmt, ...) fprintf(stderr, "[CRYPTO] " fmt "\n", ##__VA_ARGS__)

/* ══════════════════════════════════════════════════════════════════════════
 * Userspace Mirror Structures
 *
 * These mirror the BPF map value types from common.h but use standard
 * C types (no bpf_spin_lock). Layout MUST match tachyon_session etc.
 * ══════════════════════════════════════════════════════════════════════════ */

struct userspace_config {
    uint16_t listen_port_net;
    uint8_t mimicry_type;
    uint8_t pad;
};

struct userspace_session {
    uint32_t lock_pad;
    uint32_t peer_ip;
    uint32_t local_ip;
    uint8_t peer_mac[6];
    uint16_t peer_port;
    uint32_t _pad2;
    /* Rate limiting state */
    uint64_t tx_rl_tokens;
    uint64_t tx_rl_last_ns;
    uint64_t rx_rl_tokens;
    uint64_t rx_rl_last_ns;
    /* Replay protection */
    uint64_t rx_highest_seq[TACHYON_MAX_TX_CPUS];
    uint64_t rx_bitmap[TACHYON_MAX_TX_CPUS][TACHYON_REPLAY_WORDS];
};

struct userspace_key_init {
    uint32_t session_id;
    uint8_t tx_key[TACHYON_AEAD_KEY_LEN];
    uint8_t rx_key[TACHYON_AEAD_KEY_LEN];
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
    uint64_t tx_ratelimit_drops;
    uint64_t rx_ratelimit_data_drops;
    uint64_t rx_roam_events;
};

/* ══════════════════════════════════════════════════════════════════════════
 * Control Plane Message Structures (packed, wire format)
 * ══════════════════════════════════════════════════════════════════════════ */

#pragma pack(push, 1)

struct MsgInit {
    uint8_t flags;
    uint8_t pad[3];
    uint32_t session_id;
    uint64_t client_nonce;
    uint8_t is_rekey;
    uint8_t _reserved[3];
};

struct MsgCookie {
    uint8_t flags;
    uint8_t pad[3];
    uint32_t session_id;
    uint64_t client_nonce;
    uint8_t cookie[TACHYON_HMAC_LEN];
};

struct MsgAuth {
    uint8_t flags;
    uint8_t pad[3];
    uint32_t session_id;
    uint64_t client_nonce;
    uint8_t is_rekey;
    uint8_t _reserved[3];
    uint8_t cookie[TACHYON_HMAC_LEN];
    uint8_t ciphertext[TACHYON_X25519_KEY_LEN + TACHYON_AEAD_TAG_LEN];
};

struct MsgFinish {
    uint8_t flags;
    uint8_t pad[3];
    uint32_t session_id;
    uint64_t server_nonce;
    uint8_t ciphertext[TACHYON_X25519_KEY_LEN + TACHYON_AEAD_TAG_LEN];
};

struct MsgKeepalive {
    uint8_t flags;
    uint8_t pad[3];
    uint32_t session_id;
    uint64_t timestamp;
    uint8_t ciphertext[TACHYON_AEAD_TAG_LEN + TACHYON_AEAD_TAG_LEN];
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
    int listen_port = TACHYON_DEFAULT_PORT;
    int mimicry_type = TACHYON_MIMICRY_QUIC;
    bool encryption = true;

    /* ── v5 "Ghost-PQ" policy ───────────────────────────────────────────────
     * These are off by default so v4 configs keep working unchanged. They are
     * parsed from the INI by config.cpp and consumed by network.cpp. Strings
     * are stored raw; network.cpp maps them to the typed enums in
     * padding.h / obfs.h via the *_from_string helpers. */
    std::string pqc_mode   = "classical"; /* classical | hybrid */
    std::string obfuscation = "none";     /* none | reality | quic */
    std::string obfuscation_sni = "www.microsoft.com";
    std::string padding    = "none";      /* none | padme | constant_rate | random */
    uint32_t cover_rate_hz = 0;           /* 0 disables cover traffic */
    uint32_t port_hop_seconds = 0;        /* 0 disables port hopping */
    bool ttl_random = false;
    bool mac_random = false;
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
            if (now_sec - front.second > TACHYON_NONCE_EXPIRY) {
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
        if (map_.count(nonce) == 0)
            order_.push_back({nonce, now_sec});
        map_[nonce] = now_sec;
    }

    bool exists(uint64_t nonce) const { return map_.count(nonce) > 0; }

  private:
    std::unordered_map<uint64_t, uint64_t> map_;
    std::list<std::pair<uint64_t, uint64_t>> order_; /* front=oldest */
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

void init_crypto_globals();
void free_crypto_globals();

bool calc_hmac(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
               uint8_t *out_mac);

void generate_cookie(const uint8_t *secret, uint32_t client_ip, uint64_t nonce, uint64_t window,
                     uint8_t *out_cookie);

bool do_ecdh(const uint8_t *my_priv, const uint8_t *peer_pub, uint8_t *out_shared_secret);

bool derive_kdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                const char *info, uint8_t *out_key);

bool cp_aead_encrypt(const uint8_t *key, const uint8_t *pt, size_t pt_len, const uint8_t *ad,
                     size_t ad_len, const uint8_t *nonce, uint8_t *ct, uint8_t *tag);

bool cp_aead_decrypt(const uint8_t *key, const uint8_t *ct, size_t ct_len, const uint8_t *ad,
                     size_t ad_len, const uint8_t *nonce, const uint8_t *tag, uint8_t *pt);

bool generate_x25519_keypair(uint8_t *priv_out, uint8_t *pub_out);
bool get_public_key(const uint8_t *priv, uint8_t *pub_out);

/* ══════════════════════════════════════════════════════════════════════════
 * Function Declarations - tunnel.cpp
 * ══════════════════════════════════════════════════════════════════════════ */

TunnelConfig parse_config(const std::string &filename);
bool validate_config(const TunnelConfig &cfg);
std::string tunnel_name_from_conf(const std::string &conf_path);

void command_up(const std::string &conf_file);
void command_down(const std::string &conf_file);
void command_show(const std::string &conf_file);

/* ══════════════════════════════════════════════════════════════════════════
 * Function Declarations - network.cpp
 * ══════════════════════════════════════════════════════════════════════════ */

void run_control_plane(struct bpf_object *obj, TunnelConfig &cfg, uint32_t session_id,
                       uint32_t peer_ip_net, uint32_t local_ip_net, const uint8_t *peer_mac);

/* ══════════════════════════════════════════════════════════════════════════
 * Utility Helpers
 * ══════════════════════════════════════════════════════════════════════════ */

inline bool hex2bin(const std::string &hex, uint8_t *bin, size_t bin_len) {
    if (hex.size() != bin_len * 2)
        return false;
    for (size_t i = 0; i < bin_len; i++) {
        const auto hi = static_cast<unsigned char>(hex[i * 2]);
        const auto lo = static_cast<unsigned char>(hex[i * 2 + 1]);
        if (!isxdigit(hi) || !isxdigit(lo))
            return false; /* reject non-hex characters early */
        if (sscanf(&hex[i * 2], "%2hhx", &bin[i]) != 1)
            return false;
    }
    return true;
}

inline bool parse_mac(const std::string &str, uint8_t mac[6]) {
    return sscanf(str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3],
                  &mac[4], &mac[5]) == 6;
}

inline std::string trim(std::string s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {}; /* all whitespace */
    s.erase(0, first);
    /* find_last_not_of cannot return npos here: s now starts with non-whitespace */
    s.erase(s.find_last_not_of(" \t\r\n") + 1);
    return s;
}

/*
 * run_cmd - Execute a shell-style command via fork/execvp.
 *
 * Security: uses fork+execvp instead of system() to prevent shell injection.
 * The command string is whitespace-tokenised into an argv array; no shell
 * interprets the result, so metacharacters ($(), ;, `, |, &&, >, etc.) pass
 * through as literal argv entries rather than being interpreted.
 *
 * Limitations: callers must not use shell redirection (2>/dev/null), pipes,
 * or quoted arguments containing spaces. All in-tree callers comply.
 *
 * Set quiet=true to silence child stdout/stderr and suppress the failure
 * LOG_WARN — useful for best-effort teardown paths.
 */
inline bool run_cmd(const std::string &cmd, bool quiet = false) {
    std::vector<std::string> tokens;
    std::istringstream iss(cmd);
    for (std::string tok; iss >> tok;)
        tokens.push_back(std::move(tok));
    if (tokens.empty())
        return false;

    std::vector<char *> argv;
    argv.reserve(tokens.size() + 1);
    for (auto &t : tokens)
        argv.push_back(t.data());
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0) {
        LOG_ERR("fork() failed: %s", strerror(errno));
        return false;
    }
    if (pid == 0) {
        if (quiet) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        execvp(argv[0], argv.data());
        _exit(127); /* execvp only returns on failure */
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        LOG_ERR("waitpid() failed: %s", strerror(errno));
        return false;
    }
    bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!ok && !quiet)
        LOG_WARN("Command failed (status %d): %s", status, cmd.c_str());
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Compile-Time Cross-Structure Verification
 *
 * Ensure userspace mirror structs remain identical in size to their
 * common.h counterparts so BPF map reads/writes never silently corrupt.
 * ══════════════════════════════════════════════════════════════════════════ */

static_assert(sizeof(userspace_config) == sizeof(struct tachyon_config),
              "userspace_config layout must match tachyon_config");
static_assert(sizeof(userspace_key_init) == sizeof(struct tachyon_key_init),
              "userspace_key_init layout must match tachyon_key_init");
static_assert(sizeof(userspace_stats) == sizeof(struct tachyon_stats),
              "userspace_stats layout must match tachyon_stats");

/* Control-plane message structs: userspace #pragma pack(1) vs common.h __attribute__((packed)) */
static_assert(sizeof(MsgInit) == sizeof(struct tachyon_msg_init),
              "MsgInit must match tachyon_msg_init wire size");
static_assert(sizeof(MsgCookie) == sizeof(struct tachyon_msg_cookie),
              "MsgCookie must match tachyon_msg_cookie wire size");
static_assert(sizeof(MsgAuth) == sizeof(struct tachyon_msg_auth),
              "MsgAuth must match tachyon_msg_auth wire size");
static_assert(sizeof(MsgFinish) == sizeof(struct tachyon_msg_finish),
              "MsgFinish must match tachyon_msg_finish wire size");
static_assert(sizeof(MsgKeepalive) == sizeof(struct tachyon_msg_keepalive),
              "MsgKeepalive must match tachyon_msg_keepalive wire size");

#endif /* TACHYON_CTRL_H */
