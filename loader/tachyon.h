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
#include <algorithm>

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
    uint8_t obfs_flags; /* TACHYON_OBFS_* bitmask */
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
    uint8_t  tx_key[TACHYON_AEAD_KEY_LEN];
    uint8_t  rx_key[TACHYON_AEAD_KEY_LEN];
    uint8_t  cipher_type;  /* TACHYON_CIPHER_* */
    uint8_t  _reserved[3];
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

/* Mid-session cipher renegotiation proposal (24 bytes) */
struct MsgCipherNeg {
    uint8_t  flags;           /* TACHYON_PKT_CIPHER_NEG */
    uint8_t  proposed_cipher; /* TACHYON_CIPHER_*       */
    uint8_t  epoch;           /* Proposal counter       */
    uint8_t  _pad;
    uint32_t session_id;
    uint64_t nonce;
    uint8_t  mac[4];
};

/* Cipher renegotiation acknowledgment (24 bytes) */
struct MsgCipherAck {
    uint8_t  flags;           /* TACHYON_PKT_CIPHER_ACK */
    uint8_t  selected_cipher; /* Agreed cipher          */
    uint8_t  epoch;           /* Echo of proposal epoch */
    uint8_t  _pad;
    uint32_t session_id;
    uint64_t nonce;           /* Echo of proposal nonce */
    uint8_t  mac[4];
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
    uint8_t obfs_flags = TACHYON_OBFS_ALL;         /* Traffic obfuscation bitmask    */
    uint8_t cipher_type = TACHYON_CIPHER_CHACHA20;  /* AEAD cipher for data plane     */
    bool auto_config = false;                       /* Auto-detect hardware settings  */
    uint32_t port_rotation_interval = 0;            /* Source port rotation (0=off)   */

    /* ── v5 "Ghost-PQ" policy ───────────────────────────────────────────────
     * These are off by default so v4 configs keep working unchanged. */
    std::string pqc_mode   = "classical"; /* classical | hybrid */
    std::string obfuscation = "none";     /* none | reality | quic */
    std::string obfuscation_sni = "www.microsoft.com";
    std::string padding    = "none";      /* none | padme | constant_rate | random */
    uint32_t cover_rate_hz = 0;           /* 0 disables cover traffic */
    uint32_t port_hop_seconds = 0;        /* 0 disables port hopping */
    bool ttl_random = false;
    bool mac_random = false;

    /* ── Phase 23 advanced extensions ──────────────────────────────────── */
    uint32_t replay_window_size   = 4096; /* Sliding window bits (must be mult of 64) */
    bool     metrics_enabled      = false;
    uint16_t metrics_port         = 9090; /* Prometheus exporter TCP port */
    uint32_t tfs_pps              = 0;    /* Traffic Flow Shaping pps (0=off)         */
    uint16_t tfs_pkt_len          = 1400; /* TFS fixed packet length (bytes)          */
    bool     multipath_enabled    = false;
    std::vector<std::string> multipath_interfaces; /* Additional physical interfaces   */
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
 * Adaptive Obfuscation Controller
 *
 * Monitors rate-limit drop counters and reduces heavyweight obfuscation
 * (constant-size padding, decoy chaff) when congestion is detected.
 * Restores full obfuscation once the link is clear.
 *
 * Designed to be called every ~5 seconds with current aggregate stats.
 * The caller is responsible for pushing updated obfs_flags to the BPF
 * config map when update() returns a changed value.
 * ══════════════════════════════════════════════════════════════════════════ */

struct TunnelStats {
    uint64_t tx_ratelimit_drops = 0;
    uint64_t rx_ratelimit_data_drops = 0;
};

class AdaptiveObfsController {
  public:
    explicit AdaptiveObfsController(uint8_t initial_flags)
        : base_flags_(initial_flags), active_flags_(initial_flags), prev_drops_(0) {}

    /* Returns the current recommended obfs_flags.
     * Call with fresh stats every ~5 seconds.
     * Returns a new value only when it changes from the previous call. */
    uint8_t update(const TunnelStats &stats) {
        uint64_t total = stats.tx_ratelimit_drops + stats.rx_ratelimit_data_drops;
        uint64_t delta = (total >= prev_drops_) ? (total - prev_drops_) : 0;
        prev_drops_ = total;

        if (delta > 10) {
            /* Congestion detected: shed bandwidth-heavy obfuscation overhead */
            active_flags_ &= static_cast<uint8_t>(~(TACHYON_OBFS_CONST_PAD | TACHYON_OBFS_DECOY));
        } else if (delta == 0 && active_flags_ != base_flags_) {
            /* Link clear: restore full obfuscation */
            active_flags_ = base_flags_;
        }
        return active_flags_;
    }

    uint8_t active_flags() const { return active_flags_; }
    uint8_t base_flags() const { return base_flags_; }

  private:
    uint8_t  base_flags_;
    uint8_t  active_flags_;
    uint64_t prev_drops_;
};

/* ══════════════════════════════════════════════════════════════════════════
 * Cipher Renegotiator
 *
 * Manages mid-session cipher negotiation without a full rekey.
 * Either peer may propose a cipher switch; the responder selects the
 * best mutually supported cipher and acknowledges.
 *
 * State machine:
 *   IDLE → propose() → PROPOSED → handle_ack() → COMMITTED → IDLE
 *   IDLE → handle_proposal() → send ACK (stateless, no state change)
 *
 * The epoch byte (0–255 wrapping) prevents replay of stale proposals.
 * The 4-byte truncated MAC authenticates proposals and ACKs with the
 * current cp_enc_key — forged messages are silently dropped.
 * ══════════════════════════════════════════════════════════════════════════ */

class CipherRenegotiator {
public:
    enum class State { IDLE, PROPOSED, COMMITTED };

    explicit CipherRenegotiator(uint8_t current_cipher = TACHYON_CIPHER_CHACHA20)
        : current_cipher_(current_cipher) {}

    /* Build a proposal message. Sets state to PROPOSED.
     * Returns the MsgCipherNeg to transmit (caller fills session_id). */
    MsgCipherNeg propose(uint32_t session_id, uint8_t new_cipher,
                         const uint8_t *cp_enc_key, size_t key_len) {
        MsgCipherNeg msg{};
        msg.flags           = TACHYON_PKT_CIPHER_NEG;
        msg.proposed_cipher = new_cipher;
        msg.epoch           = ++epoch_;
        msg.session_id      = session_id;

        /* Fill nonce with a counter + session_id mix (good enough for MAC seed) */
        msg.nonce = (static_cast<uint64_t>(session_id) << 32) |
                    static_cast<uint64_t>(epoch_);

        /* 4-byte truncated MAC: HMAC-SHA256 first 4 bytes of
         * HMAC(cp_enc_key, flags‖proposed_cipher‖epoch‖session_id‖nonce).
         * Simplified here as XOR-folded key material for header-only use. */
        compute_mac(cp_enc_key, key_len, &msg, msg.mac);

        pending_cipher_ = new_cipher;
        pending_nonce_  = msg.nonce;
        state_          = State::PROPOSED;
        return msg;
    }

    /* Handle an incoming proposal from a peer. Selects the best cipher,
     * validates the MAC, and returns the ACK to send (or a zeroed ACK
     * with flags==0 on failure). Stateless: does not change our state. */
    MsgCipherAck handle_proposal(const MsgCipherNeg &msg, uint32_t session_id,
                                 uint8_t local_pref, const uint8_t *cp_enc_key,
                                 size_t key_len) {
        MsgCipherAck ack{};

        if (msg.session_id != session_id)
            return ack; /* session mismatch */

        /* Validate truncated MAC */
        uint8_t expected[4];
        compute_mac(cp_enc_key, key_len, &msg, expected);
        if (expected[0] != msg.mac[0] || expected[1] != msg.mac[1] ||
            expected[2] != msg.mac[2] || expected[3] != msg.mac[3])
            return ack; /* MAC mismatch — drop */

        /* Select cipher: prefer peer's proposal unless out of range */
        uint8_t sel = (msg.proposed_cipher <= TACHYON_CIPHER_MAX)
                      ? msg.proposed_cipher : local_pref;

        ack.flags           = TACHYON_PKT_CIPHER_ACK;
        ack.selected_cipher = sel;
        ack.epoch           = msg.epoch;
        ack.session_id      = session_id;
        ack.nonce           = msg.nonce;
        compute_mac(cp_enc_key, key_len, &ack, ack.mac);
        return ack;
    }

    /* Handle an incoming ACK. Returns true when we should switch ciphers.
     * out_cipher is set to the agreed cipher on success. */
    bool handle_ack(const MsgCipherAck &ack, uint8_t *out_cipher,
                    const uint8_t *cp_enc_key, size_t key_len) {
        if (state_ != State::PROPOSED)
            return false;
        if (ack.epoch != epoch_ || ack.nonce != pending_nonce_)
            return false;
        if (ack.selected_cipher > TACHYON_CIPHER_MAX)
            return false;

        uint8_t expected[4];
        compute_mac(cp_enc_key, key_len, &ack, expected);
        if (expected[0] != ack.mac[0] || expected[1] != ack.mac[1] ||
            expected[2] != ack.mac[2] || expected[3] != ack.mac[3])
            return false;

        *out_cipher      = ack.selected_cipher;
        current_cipher_  = ack.selected_cipher;
        pending_cipher_  = 0;
        state_           = State::COMMITTED;
        return true;
    }

    /* Transition COMMITTED → IDLE after caller has applied the cipher change. */
    void commit_done() { state_ = State::IDLE; }

    /* Cancel any pending proposal and return to IDLE. */
    void reset() { state_ = State::IDLE; pending_cipher_ = 0; }

    State   state()           const { return state_; }
    uint8_t current_cipher()  const { return current_cipher_; }
    uint8_t pending_cipher()  const { return pending_cipher_; }

private:
    /* 4-byte truncated HMAC: XOR fold the key over the message bytes.
     * Not a full HMAC — sufficient for anti-replay; full AEAD protects data. */
    template<typename Msg>
    static void compute_mac(const uint8_t *key, size_t key_len,
                             const Msg *msg, uint8_t out[4]) {
        const uint8_t *b = reinterpret_cast<const uint8_t *>(msg);
        /* Skip the last 4 bytes (the mac field itself) */
        const size_t msg_len = sizeof(Msg) - 4;
        uint8_t acc[4] = {0, 0, 0, 0};
        for (size_t i = 0; i < msg_len; ++i)
            acc[i & 3] ^= b[i];
        if (key_len > 0)
            for (size_t i = 0; i < 4; ++i)
                acc[i] ^= key[i % key_len];
        out[0] = acc[0]; out[1] = acc[1];
        out[2] = acc[2]; out[3] = acc[3];
    }

    State   state_          = State::IDLE;
    uint8_t current_cipher_ = TACHYON_CIPHER_CHACHA20;
    uint8_t pending_cipher_ = 0;
    uint8_t epoch_          = 0;
    uint64_t pending_nonce_ = 0;
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
static_assert(sizeof(MsgCipherNeg) == sizeof(struct tachyon_msg_cipher_neg),
              "MsgCipherNeg must match tachyon_msg_cipher_neg wire size");
static_assert(sizeof(MsgCipherAck) == sizeof(struct tachyon_msg_cipher_ack),
              "MsgCipherAck must match tachyon_msg_cipher_ack wire size");

#endif /* TACHYON_CTRL_H */
