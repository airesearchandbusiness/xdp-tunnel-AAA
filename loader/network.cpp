/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Control Plane - Network Protocol & Handshake
 *
 * Implements the Tachyon AKE v4.0 handshake protocol with QUIC mimicry,
 * keepalive with timing jitter, and dead peer detection.
 *
 * Security properties:
 *   - Constant-time role determination (no timing side-channel)
 *   - All ECDH return values checked (prevents small-order point attacks)
 *   - Complete key zeroization on every exit path
 *   - Buffer-safe QUIC mimicry padding (clamped to buffer size)
 */

#include "tachyon.h"
#include <cerrno>

#include "transport.h"
#include "padding.h"
#include "fingerprint.h"
#include "metrics.h"
#include "rate_limiter.h"
#include "replay.h"
#include "ratchet.h"
#include "transcript.h"
#include "hybrid_kex.h"

/* Monotonic clock for all internal timers (DPD, keepalive, rekey, cookie
 * rotation). Wall-clock time(nullptr) can jump backwards during NTP
 * adjustments, which would cause DPD false triggers, keepalive bursts,
 * or premature rekeys. CLOCK_MONOTONIC is immune to these adjustments. */
static uint64_t monotonic_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec);
}

/* ══════════════════════════════════════════════════════════════════════════
 * QUIC Mimicry - Padded Packet Transmission
 *
 * Pads control plane messages with random bytes to mimic QUIC traffic
 * patterns. PKT_INIT is padded to >= 1200 bytes per QUIC Initial rules.
 * Buffer overflow is prevented by clamping total_len to sizeof(buffer).
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── v5: Unified framed send path ──────────────────────────────────────
 * Routes every control-plane message through:
 *   1. PADME size quantisation (if cfg.padding != "none")
 *   2. Transport wrapping (QUIC/HTTP2/DoH/STUN or raw)
 *   3. Rate limiting (token bucket)
 *   4. Metrics accounting
 * Falls back to raw sendto when transport=NONE (v4 compat).
 */
static tachyon::rl::TokenBucket g_cp_bucket;
static bool g_cp_bucket_inited = false;
static uint32_t g_frame_seq = 0;

static uint64_t monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

static void send_framed(int sock, const void *msg, size_t msg_len,
                        int /* type — reserved for future per-type logic */,
                        const struct sockaddr_in *dest, const TunnelConfig &cfg) {
    using namespace tachyon::transport;
    using namespace tachyon::padding;
    auto &met = tachyon::metrics::global();

    /* Rate limiter — 50 KB/s default for control plane, unlimited if 0 */
    if (!g_cp_bucket_inited) {
        tachyon::rl::bucket_init(g_cp_bucket, 50000, 100000, monotonic_ns());
        g_cp_bucket_inited = true;
    }
    if (!tachyon::rl::bucket_allow(g_cp_bucket, msg_len, monotonic_ns())) {
        met.rl_tx_drops.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    uint8_t payload[4096];
    if (msg_len > sizeof(payload))
        return;
    memcpy(payload, msg, msg_len);
    size_t payload_len = msg_len;

    /* PADME size quantisation */
    if (policy_from_string(cfg.padding.c_str()) != Policy::NONE) {
        uint32_t padded = padme_round(static_cast<uint32_t>(payload_len));
        if (padded > payload_len && padded <= sizeof(payload)) {
            RAND_bytes(payload + payload_len, padded - static_cast<uint32_t>(payload_len));
            met.padme_bytes_overhead.fetch_add(padded - payload_len, std::memory_order_relaxed);
            payload_len = padded;
        }
    }

    /* Transport wrapping */
    auto tid = static_cast<TransportId>(cfg.resolved_transport_id);
    if (tid != TransportId::NONE && transport_get(tid)) {
        uint8_t framed[4096];
        FrameContext ctx{};
        ctx.seq         = g_frame_seq++;
        ctx.sni         = cfg.obfuscation_sni.c_str();
        ctx.conn_id_len = 8;
        RAND_bytes(ctx.conn_id, 8);

        auto r = transport_wrap(tid, payload, payload_len, framed, sizeof(framed), &ctx);
        if (r.ok) {
            met.transport_wrap_ok.fetch_add(1, std::memory_order_relaxed);
            met.tx_packets.fetch_add(1, std::memory_order_relaxed);
            met.tx_bytes.fetch_add(r.bytes, std::memory_order_relaxed);
            sendto(sock, framed, r.bytes, 0,
                   reinterpret_cast<const struct sockaddr *>(dest), sizeof(*dest));
            return;
        }
        met.transport_wrap_fail.fetch_add(1, std::memory_order_relaxed);
        /* Fall through to raw send */
    }

    /* Raw send (v4 compat or transport wrap failure fallback) */
    met.tx_packets.fetch_add(1, std::memory_order_relaxed);
    met.tx_bytes.fetch_add(payload_len, std::memory_order_relaxed);
    sendto(sock, payload, payload_len, 0,
           reinterpret_cast<const struct sockaddr *>(dest), sizeof(*dest));
}

/* ══════════════════════════════════════════════════════════════════════════
 * BPF Key Injection & Replay State Reset
 * ══════════════════════════════════════════════════════════════════════════ */

static void inject_keys_to_kernel(struct bpf_object *obj, uint32_t session_id, uint8_t *tx_key,
                                  uint8_t *rx_key) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "key_init_map");
    if (!map) {
        LOG_ERR("BPF map 'key_init_map' not found");
        return;
    }
    int key_map_fd = bpf_map__fd(map);
    if (key_map_fd < 0) {
        LOG_ERR("key_init_map fd invalid");
        return;
    }

    uint32_t zero = 0;
    userspace_key_init kid{};
    kid.session_id = session_id;
    memcpy(kid.tx_key, tx_key, TACHYON_AEAD_KEY_LEN);
    memcpy(kid.rx_key, rx_key, TACHYON_AEAD_KEY_LEN);
    bpf_map_update_elem(key_map_fd, &zero, &kid, BPF_ANY);

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ghost_key_init");
    if (!prog) {
        LOG_ERR("BPF program 'ghost_key_init' not found");
        return;
    }
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd >= 0) {
        struct bpf_test_run_opts topts {};
        topts.sz = sizeof(topts);
        bpf_prog_test_run_opts(prog_fd, &topts);
    }

    /* Zeroize local key copies */
    OPENSSL_cleanse(tx_key, TACHYON_AEAD_KEY_LEN);
    OPENSSL_cleanse(rx_key, TACHYON_AEAD_KEY_LEN);
    OPENSSL_cleanse(&kid, sizeof(kid));

    LOG_CRYPTO("Session %u: keys injected into kernel", session_id);
}

static void reset_bpf_replay_state(struct bpf_object *obj, uint32_t session_id,
                                   uint32_t peer_ip_net, uint32_t local_ip_net,
                                   const uint8_t *peer_mac) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "session_map");
    if (!map)
        return;
    int sess_fd = bpf_map__fd(map);
    if (sess_fd < 0)
        return;

    userspace_session sess{};
    sess.peer_ip = peer_ip_net;
    sess.local_ip = local_ip_net;
    memcpy(sess.peer_mac, peer_mac, 6);
    bpf_map_update_elem(sess_fd, &session_id, &sess, BPF_ANY);

    LOG_INFO("Session %u: replay window reset (peer restart)", session_id);
}

/* Zero IKM for KDF expand-only derivations (file-scope for stable lifetime) */
static const uint8_t ZERO_IKM[TACHYON_AEAD_KEY_LEN] = {0};

/* Build the 44-byte transcript associated data for PKT_AUTH messages */
static void build_transcript_ad(uint8_t *out, uint32_t session_id_net, uint64_t client_nonce,
                                const uint8_t *cookie) {
    memcpy(out, &session_id_net, 4);
    memcpy(out + 4, &client_nonce, 8);
    memcpy(out + 12, cookie, TACHYON_HMAC_LEN);
}

/* Derive session TX/RX keys from session master secret */
static void derive_session_keys(const uint8_t *early_secret, const uint8_t *eph_ss,
                                bool is_initiator, uint8_t *tx_key, uint8_t *rx_key) {
    uint8_t session_master[32];
    derive_kdf(early_secret, 32, eph_ss, 32, TACHYON_KDF_SESSION_MASTER, session_master);

    /* Initiator's TX = Client-TX, Responder's TX = Server-TX */
    const char *my_tx_label = is_initiator ? TACHYON_KDF_CLIENT_TX : TACHYON_KDF_SERVER_TX;
    const char *my_rx_label = is_initiator ? TACHYON_KDF_SERVER_TX : TACHYON_KDF_CLIENT_TX;

    derive_kdf(session_master, 32, ZERO_IKM, 32, my_tx_label, tx_key);
    derive_kdf(session_master, 32, ZERO_IKM, 32, my_rx_label, rx_key);
    OPENSSL_cleanse(session_master, 32);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Constant-Time Role Determination
 *
 * Determines initiator/responder role based on public key ordering.
 * Uses constant-time comparison to prevent timing side-channels.
 * Returns: 1 if my_pub > peer_pub, 0 if my_pub < peer_pub, -1 if equal.
 * ══════════════════════════════════════════════════════════════════════════ */

static int ct_role_compare(const uint8_t *my_pub, const uint8_t *peer_pub) {
    /* First check equality in constant time */
    if (CRYPTO_memcmp(my_pub, peer_pub, TACHYON_X25519_KEY_LEN) == 0)
        return -1; /* Equal keys - error */

    /* Constant-time greater-than: scan all bytes, accumulate result */
    int gt = 0, lt = 0;
    for (int i = 0; i < TACHYON_X25519_KEY_LEN; i++) {
        int diff = (int)my_pub[i] - (int)peer_pub[i];
        /* Only set gt/lt on the first differing byte */
        gt |= (diff > 0) & ~(gt | lt);
        lt |= (diff < 0) & ~(gt | lt);
    }
    return gt ? 1 : 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Control Plane Main Loop
 * ══════════════════════════════════════════════════════════════════════════ */

void run_control_plane(struct bpf_object *obj, TunnelConfig &cfg, uint32_t session_id,
                       uint32_t peer_ip_net, uint32_t local_ip_net, const uint8_t *peer_mac) {
    LOG_INFO("Booting Tachyon AKE v%d.0...", TACHYON_PROTO_VERSION);
    init_crypto_globals();

    /* Derive static keys */
    uint8_t static_priv[32], peer_static_pub[32], my_static_pub[32];
    if (!hex2bin(cfg.private_key, static_priv, 32) ||
        !hex2bin(cfg.peer_public_key, peer_static_pub, 32)) {
        LOG_ERR("Invalid key hex encoding");
        free_crypto_globals();
        return;
    }

    if (!get_public_key(static_priv, my_static_pub)) {
        LOG_ERR("Failed to derive public key");
        OPENSSL_cleanse(static_priv, 32);
        free_crypto_globals();
        return;
    }

    /* Constant-time role detection */
    int role = ct_role_compare(my_static_pub, peer_static_pub);
    if (role < 0) {
        LOG_ERR("Local and peer public keys are identical - aborting");
        OPENSSL_cleanse(static_priv, 32);
        free_crypto_globals();
        return;
    }
    bool is_initiator = (role == 1);

    /* Derive early secret and control plane encryption key */
    uint8_t static_ss[32], early_secret[32], cp_enc_key[32];
    if (!do_ecdh(static_priv, peer_static_pub, static_ss)) {
        LOG_ERR("Static ECDH failed");
        OPENSSL_cleanse(static_priv, 32);
        free_crypto_globals();
        return;
    }

    std::string safe_psk = cfg.psk.empty() ? TACHYON_KDF_DEFAULT_PSK : cfg.psk;
    derive_kdf(reinterpret_cast<const uint8_t *>(safe_psk.data()), safe_psk.size(), static_ss, 32,
               TACHYON_KDF_EARLY_SECRET, early_secret);
    derive_kdf(early_secret, 32, ZERO_IKM, 32, TACHYON_KDF_CP_AEAD, cp_enc_key);

    OPENSSL_cleanse(static_ss, 32);
    OPENSSL_cleanse(static_priv, 32);

    /* Cleanse config key material — no longer needed after static derivations.
     * std::string::data() is mutable since C++17, which this project requires. */
    if (!cfg.private_key.empty())
        OPENSSL_cleanse(cfg.private_key.data(), cfg.private_key.size());
    if (!cfg.psk.empty())
        OPENSSL_cleanse(cfg.psk.data(), cfg.psk.size());

    /* Cookie secret for DoS protection */
    uint8_t cookie_secret[32];
    uint64_t last_cookie_rotation = monotonic_sec();
    if (RAND_bytes(cookie_secret, 32) != 1) {
        LOG_ERR("Failed to generate initial cookie secret");
        goto cleanup_keys;
    }

    /* UDP socket setup */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERR("Socket creation failed: %s", strerror(errno));
        goto cleanup_keys;
    }
    {
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct timeval tv = {1, 0}; /* 1 second timeout */
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(cfg.listen_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
            LOG_ERR("Bind to port %d failed: %s", cfg.listen_port, strerror(errno));
            close(sock);
            goto cleanup_keys;
        }
    }

    {
        struct sockaddr_in p_addr {};
        p_addr.sin_family = AF_INET;
        p_addr.sin_port = htons(cfg.listen_port);
        inet_pton(AF_INET, cfg.peer_endpoint_ip.c_str(), &p_addr.sin_addr);

        /* Control plane state */
        tachyon::replay::Window replay_window(1024);
        bool handshake_active = true;
        bool first_boot = true;

        uint8_t my_eph_priv[32] = {0}, my_eph_pub[32] = {0};
        uint64_t my_nonce = 0;
        uint64_t last_init_send = 0;
        uint64_t last_rekey_success = monotonic_sec();
        uint64_t last_rx_time = monotonic_sec();
        uint64_t last_tx_time = monotonic_sec();

        /* Jittered timers for anti-fingerprinting */
        uint64_t keepalive_interval = TACHYON_KEEPALIVE_BASE;
        uint64_t retry_interval = TACHYON_RETRY_BASE;

        /* v5: cover traffic shaper */
        tachyon::padding::ShaperState shaper;
        tachyon::padding::shaper_init(shaper, cfg.cover_rate_hz);

        /* v5: port hopping state */
        uint8_t psk_bytes[32] = {};
        uint16_t current_hop_port = static_cast<uint16_t>(cfg.listen_port);
        if (cfg.port_hop_seconds > 0 && !cfg.psk.empty()) {
            memset(psk_bytes, 0, 32);
            size_t copy_len = cfg.psk.size() < 32 ? cfg.psk.size() : 32;
            memcpy(psk_bytes, cfg.psk.data(), copy_len);
        }

        /* Forward secrecy: key ratchet state */
        uint64_t last_ratchet = monotonic_sec();
        uint8_t ratchet_chain[32];
        RAND_bytes(ratchet_chain, 32);

        /* Decoy traffic state */
        uint64_t last_decoy = monotonic_sec();
        uint64_t decoy_interval = TACHYON_DECOY_BASE;

        auto &met = tachyon::metrics::global();

        LOG_INFO("Role: %s | Transport: %s | Padding: %s | Cover: %uHz | Obfs: 0x%02x",
                 is_initiator ? "Initiator" : "Responder",
                 tachyon::transport::transport_id_to_string(
                     static_cast<tachyon::transport::TransportId>(cfg.resolved_transport_id)),
                 cfg.padding.c_str(), cfg.cover_rate_hz, cfg.obfs_flags);

        while (!g_exiting) {
            uint64_t now = monotonic_sec();

            /* Rotate cookie secret periodically. Failure retains the old secret
             * and retries on the next tick rather than silently degrading. */
            if (now - last_cookie_rotation > TACHYON_COOKIE_ROTATION) {
                if (RAND_bytes(cookie_secret, 32) == 1)
                    last_cookie_rotation = now;
                else
                    LOG_WARN("Cookie secret rotation failed - retaining old secret");
            }

            /* Dead Peer Detection */
            if (!handshake_active && (now - last_rx_time > TACHYON_DPD_TIMEOUT)) {
                LOG_WARN("Peer timeout (%ds). Resetting state...", TACHYON_DPD_TIMEOUT);
                handshake_active = true;
                first_boot = true;
                my_nonce = 0;
                last_init_send = 0;
                uint8_t zero_key[32] = {0};
                inject_keys_to_kernel(obj, session_id, zero_key, zero_key);
            }

            /* Send keepalive with timing jitter */
            if (!handshake_active && (now - last_tx_time >= keepalive_interval)) {
                MsgKeepalive kmsg = {};
                kmsg.flags = TACHYON_PKT_KEEPALIVE;
                kmsg.session_id = htonl(session_id);
                kmsg.timestamp = now;

                uint8_t k_ad[12];
                memcpy(k_ad, &kmsg.session_id, 4);
                memcpy(k_ad + 4, &kmsg.timestamp, 8);
                uint8_t k_nonce[12] = {0};
                memcpy(k_nonce, &kmsg.timestamp, 8);

                uint8_t dummy[16];
                if (RAND_bytes(dummy, 16) != 1) {
                    LOG_WARN("RAND_bytes failed for keepalive - skipping");
                    continue;
                }
                if (!cp_aead_encrypt(cp_enc_key, dummy, 16, k_ad, 12, k_nonce, kmsg.ciphertext,
                                     kmsg.ciphertext + 16)) {
                    LOG_WARN("Keepalive encrypt failed - skipping");
                    continue;
                }

                send_framed(sock, &kmsg, sizeof(kmsg), TACHYON_PKT_KEEPALIVE, &p_addr, cfg);
                last_tx_time = now;
                {
                    uint32_t _j;
                    if (RAND_bytes(reinterpret_cast<uint8_t *>(&_j), sizeof(_j)) != 1)
                        _j = 0; /* jitter not security-critical; fall back to base */
                    keepalive_interval = TACHYON_KEEPALIVE_BASE + (_j % TACHYON_KEEPALIVE_JITTER);
                }
            }

            /* Decoy chaff traffic — inject random-payload keepalives during
             * idle periods to mask real traffic patterns. An observer sees a
             * constant stream of packets rather than bursts correlated with
             * user activity. Only active when TACHYON_OBFS_DECOY is set. */
            if (!handshake_active && (cfg.obfs_flags & TACHYON_OBFS_DECOY) &&
                (now - last_decoy >= decoy_interval)) {
                MsgKeepalive decoy_msg = {};
                decoy_msg.flags = TACHYON_PKT_KEEPALIVE;
                decoy_msg.session_id = htonl(session_id);
                decoy_msg.timestamp = monotonic_sec();

                uint8_t d_ad[12], d_nonce[12] = {0}, d_pt[16];
                memcpy(d_ad, &decoy_msg.session_id, 4);
                memcpy(d_ad + 4, &decoy_msg.timestamp, 8);
                memcpy(d_nonce, &decoy_msg.timestamp, 8);

                if (RAND_bytes(d_pt, 16) == 1 &&
                    cp_aead_encrypt(cp_enc_key, d_pt, 16, d_ad, 12, d_nonce, decoy_msg.ciphertext,
                                    decoy_msg.ciphertext + 16)) {
                    send_mimic_quic(sock, &decoy_msg, sizeof(decoy_msg), TACHYON_PKT_KEEPALIVE,
                                    &p_addr);
                }
                last_decoy = now;
                {
                    uint32_t _j;
                    if (RAND_bytes(reinterpret_cast<uint8_t *>(&_j), sizeof(_j)) != 1)
                        _j = 0;
                    decoy_interval = TACHYON_DECOY_BASE + (_j % TACHYON_DECOY_JITTER);
                }
            }

            /* Forward secrecy key ratchet — derive new session keys from the
             * current key + fresh chain material every 5 minutes. The old chain
             * value is erased immediately, so a compromised key reveals only
             * the traffic within one ratchet window. This is independent of
             * the full ECDH rekey (which runs every 60s for the data plane). */
            if (!handshake_active && (now - last_ratchet > TACHYON_KEY_RATCHET_INTERVAL)) {
                uint8_t new_cp_key[32];
                if (derive_kdf(ratchet_chain, 32, cp_enc_key, 32, TACHYON_KDF_KEY_RATCHET,
                               new_cp_key)) {
                    OPENSSL_cleanse(cp_enc_key, 32);
                    memcpy(cp_enc_key, new_cp_key, 32);
                    OPENSSL_cleanse(new_cp_key, 32);

                    /* Advance the ratchet chain so the old chain state is
                     * irrecoverable even if new_cp_key is later leaked. */
                    uint8_t new_chain[32];
                    derive_kdf(ratchet_chain, 32, cp_enc_key, 32, TACHYON_KDF_DECOY_SEED,
                               new_chain);
                    OPENSSL_cleanse(ratchet_chain, 32);
                    memcpy(ratchet_chain, new_chain, 32);
                    OPENSSL_cleanse(new_chain, 32);

                    last_ratchet = now;
                    LOG_CRYPTO("Control plane key ratcheted (forward secrecy)");
                }
            }

            /* Rekey trigger (initiator only) */
            if (is_initiator && !handshake_active &&
                (now - last_rekey_success > TACHYON_REKEY_INTERVAL)) {
                handshake_active = true;
                my_nonce = 0;
                LOG_INFO("Hitless key rotation initiated");
            }

            /* v5: port hopping — rotate source port per HMAC(psk, epoch) */
            if (cfg.port_hop_seconds > 0) {
                uint64_t hop_now = static_cast<uint64_t>(time(nullptr));
                uint16_t new_port = tachyon::fp::port_hop_current(
                    psk_bytes, cfg.port_hop_seconds, hop_now);
                if (new_port != current_hop_port) {
                    p_addr.sin_port = htons(new_port);
                    current_hop_port = new_port;
                    LOG_INFO("Port hopped to %u", new_port);
                }
            }

            /* v5: cover traffic emission during idle */
            if (cfg.cover_rate_hz > 0 && !handshake_active) {
                uint64_t now_ns = monotonic_ns();
                tachyon::padding::shaper_on_real_frame(shaper, now_ns);
                uint32_t cover_sz = tachyon::padding::shaper_poll_cover(
                    shaper, now_ns, 64, 1400);
                if (cover_sz > 0) {
                    uint8_t cover[1500];
                    RAND_bytes(cover, cover_sz);
                    cover[0] = TACHYON_PKT_KEEPALIVE;
                    send_framed(sock, cover, cover_sz, TACHYON_PKT_KEEPALIVE, &p_addr, cfg);
                    met.cover_frames_sent.fetch_add(1, std::memory_order_relaxed);
                }
            }

            /* Send PKT_INIT (initiator only, during handshake) */
            if (is_initiator && handshake_active && (now - last_init_send >= retry_interval)) {
                if (my_nonce == 0) {
                    if (RAND_bytes(reinterpret_cast<uint8_t *>(&my_nonce), 8) != 1) {
                        LOG_ERR("Failed to generate handshake nonce");
                        continue;
                    }
                    met.hs_initiated.fetch_add(1, std::memory_order_relaxed);
                }

                MsgInit msg = {};
                msg.flags = TACHYON_PKT_INIT;
                msg.session_id = htonl(session_id);
                msg.client_nonce = my_nonce;
                msg.is_rekey = first_boot ? 0 : 1;

                send_framed(sock, &msg, sizeof(msg), TACHYON_PKT_INIT, &p_addr, cfg);
                last_init_send = now;
                last_tx_time = now;
                {
                    uint32_t _j;
                    if (RAND_bytes(reinterpret_cast<uint8_t *>(&_j), sizeof(_j)) != 1)
                        _j = 0;
                    retry_interval = TACHYON_RETRY_BASE + (_j % TACHYON_RETRY_JITTER);
                }
            }

            /* Receive incoming packet */
            uint8_t buf[2000];
            struct sockaddr_in src;
            socklen_t slen = sizeof(src);
            int n = recvfrom(sock, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr *>(&src),
                             &slen);
            if (n <= 0)
                continue;

            /* Only accept from configured peer IP — port may have hopped */
            if (src.sin_addr.s_addr != p_addr.sin_addr.s_addr)
                continue;
            if (cfg.port_hop_seconds == 0 && src.sin_port != p_addr.sin_port)
                continue;

            met.rx_packets.fetch_add(1, std::memory_order_relaxed);
            met.rx_bytes.fetch_add(static_cast<uint64_t>(n), std::memory_order_relaxed);

            /* v5: transport unwrap — strip outer framing to get inner CP message */
            {
                using namespace tachyon::transport;
                auto tid = static_cast<TransportId>(cfg.resolved_transport_id);
                if (tid != TransportId::NONE && transport_get(tid)) {
                    uint8_t unwrapped[4096];
                    auto r = transport_unwrap(tid, buf, static_cast<size_t>(n),
                                             unwrapped, sizeof(unwrapped));
                    if (r.ok) {
                        memcpy(buf, unwrapped, r.bytes);
                        n = static_cast<int>(r.bytes);
                        met.transport_unwrap_ok.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        met.transport_unwrap_fail.fetch_add(1, std::memory_order_relaxed);
                        /* Fall through: try raw parse (v4 peer or non-framed probe) */
                    }
                }
            }

            uint8_t flag = buf[0];
            /* Cookie windows must use wall-clock so both peers agree on the
             * 60-second window. All other timers use the monotonic `now`. */
            uint64_t current_window = static_cast<uint64_t>(time(nullptr)) / 60;

            /* DPD timer is reset only for packets that pass authentication.
             * Each successful handler below updates last_rx_time — forged packets
             * matching the peer IP/port cannot indefinitely prevent DPD. */

            /* ── Handle PKT_KEEPALIVE ── */
            if (flag == TACHYON_PKT_KEEPALIVE && n >= (int)sizeof(MsgKeepalive)) {
                auto *msg = reinterpret_cast<MsgKeepalive *>(buf);
                if (ntohl(msg->session_id) != session_id)
                    continue;

                uint8_t k_ad[12];
                memcpy(k_ad, &msg->session_id, 4);
                memcpy(k_ad + 4, &msg->timestamp, 8);
                uint8_t k_nonce[12] = {0};
                memcpy(k_nonce, &msg->timestamp, 8);
                uint8_t decrypted[16];
                if (!cp_aead_decrypt(cp_enc_key, msg->ciphertext, 16, k_ad, 12, k_nonce,
                                     msg->ciphertext + 16, decrypted)) {
                    LOG_WARN("Keepalive authentication failed - dropping");
                    continue;
                }
                last_rx_time = now; /* Authenticated keepalive - peer is alive */
            }
            /* ── Handle PKT_INIT (responder only) ── */
            else if (flag == TACHYON_PKT_INIT && n >= (int)sizeof(MsgInit)) {
                if (is_initiator)
                    continue;
                auto *msg = reinterpret_cast<MsgInit *>(buf);
                if (ntohl(msg->session_id) != session_id)
                    continue;

                LOG_INFO("Received PKT_INIT, sending COOKIE...");
                MsgCookie cmsg = {};
                cmsg.flags = TACHYON_PKT_COOKIE;
                cmsg.session_id = htonl(session_id);
                cmsg.client_nonce = msg->client_nonce;
                generate_cookie(cookie_secret, src.sin_addr.s_addr, msg->client_nonce,
                                current_window, cmsg.cookie);
                send_framed(sock, &cmsg, sizeof(cmsg), TACHYON_PKT_COOKIE, &src, cfg);
                last_tx_time = now;
            }
            /* ── Handle PKT_COOKIE (initiator only) ── */
            else if (flag == TACHYON_PKT_COOKIE && n >= (int)sizeof(MsgCookie)) {
                if (!is_initiator)
                    continue;
                auto *msg = reinterpret_cast<MsgCookie *>(buf);
                if (ntohl(msg->session_id) != session_id || msg->client_nonce != my_nonce)
                    continue;

                LOG_INFO("Received PKT_COOKIE, sending AUTH...");
                if (!generate_x25519_keypair(my_eph_priv, my_eph_pub))
                    continue;

                MsgAuth amsg = {};
                amsg.flags = TACHYON_PKT_AUTH;
                amsg.session_id = htonl(session_id);
                amsg.client_nonce = my_nonce;
                amsg.is_rekey = first_boot ? 0 : 1;
                memcpy(amsg.cookie, msg->cookie, TACHYON_HMAC_LEN);

                uint8_t transcript_ad[44];
                build_transcript_ad(transcript_ad, amsg.session_id, amsg.client_nonce, amsg.cookie);

                uint8_t cp_nonce[12] = {0};
                memcpy(cp_nonce, &my_nonce, 8);
                if (!cp_aead_encrypt(cp_enc_key, my_eph_pub, 32, transcript_ad, 44, cp_nonce,
                                     amsg.ciphertext, amsg.ciphertext + 32)) {
                    LOG_ERR("PKT_AUTH encrypt failed");
                    continue;
                }

                send_framed(sock, &amsg, sizeof(amsg), TACHYON_PKT_AUTH, &p_addr, cfg);
                last_tx_time = now;
            }
            /* ── Handle PKT_AUTH (responder only) ── */
            else if (flag == TACHYON_PKT_AUTH && n >= (int)sizeof(MsgAuth)) {
                if (is_initiator)
                    continue;
                auto *msg = reinterpret_cast<MsgAuth *>(buf);
                if (ntohl(msg->session_id) != session_id)
                    continue;
                if (replay_window.check_and_commit(msg->client_nonce) !=
                    tachyon::replay::Result::ACCEPTED) {
                    met.replay_dropped.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }

                /* Validate cookie (current + previous window for clock skew) */
                uint8_t c1[32], c2[32];
                generate_cookie(cookie_secret, src.sin_addr.s_addr, msg->client_nonce,
                                current_window, c1);
                generate_cookie(cookie_secret, src.sin_addr.s_addr, msg->client_nonce,
                                current_window - 1, c2);

                if (CRYPTO_memcmp(c1, msg->cookie, TACHYON_HMAC_LEN) != 0 &&
                    CRYPTO_memcmp(c2, msg->cookie, TACHYON_HMAC_LEN) != 0)
                    continue;

                /* Decrypt peer ephemeral public key */
                uint8_t peer_eph_pub[32];
                uint8_t transcript_ad[44];
                build_transcript_ad(transcript_ad, msg->session_id, msg->client_nonce, msg->cookie);

                uint8_t cp_nonce[12] = {0};
                memcpy(cp_nonce, &msg->client_nonce, 8);

                if (!cp_aead_decrypt(cp_enc_key, msg->ciphertext, 32, transcript_ad, 44, cp_nonce,
                                     msg->ciphertext + 32, peer_eph_pub))
                    continue;

                last_rx_time = now; /* Authenticated PKT_AUTH - peer is alive */
                met.replay_accepted.fetch_add(1, std::memory_order_relaxed);
                if (msg->is_rekey == 0)
                    reset_bpf_replay_state(obj, session_id, peer_ip_net, local_ip_net, peer_mac);

                /* Generate our ephemeral keypair */
                if (!generate_x25519_keypair(my_eph_priv, my_eph_pub))
                    continue;

                /* Derive session keys (responder: is_initiator=false) */
                uint8_t eph_ss[32], tx_key[32], rx_key[32];
                if (!do_ecdh(my_eph_priv, peer_eph_pub, eph_ss)) {
                    LOG_ERR("Ephemeral ECDH failed in PKT_AUTH");
                    continue;
                }
                derive_session_keys(early_secret, eph_ss, false, tx_key, rx_key);

                inject_keys_to_kernel(obj, session_id, tx_key, rx_key);

                /* Send PKT_FINISH with our ephemeral public key */
                uint64_t srv_nonce;
                if (RAND_bytes(reinterpret_cast<uint8_t *>(&srv_nonce), 8) != 1) {
                    LOG_ERR("Failed to generate server nonce");
                    continue;
                }

                MsgFinish fmsg = {};
                fmsg.flags = TACHYON_PKT_FINISH;
                fmsg.session_id = htonl(session_id);
                fmsg.server_nonce = srv_nonce;

                uint8_t f_ad[12];
                memcpy(f_ad, &fmsg.session_id, 4);
                memcpy(f_ad + 4, &srv_nonce, 8);
                uint8_t f_nonce[12] = {0};
                memcpy(f_nonce, &srv_nonce, 8);

                if (!cp_aead_encrypt(cp_enc_key, my_eph_pub, 32, f_ad, 12, f_nonce, fmsg.ciphertext,
                                     fmsg.ciphertext + 32)) {
                    LOG_ERR("PKT_FINISH encrypt failed");
                    OPENSSL_cleanse(eph_ss, 32);
                    OPENSSL_cleanse(my_eph_priv, 32);
                    continue;
                }
                send_framed(sock, &fmsg, sizeof(fmsg), TACHYON_PKT_FINISH, &src, cfg);
                last_tx_time = now;

                /* v5: init forward-secrecy ratchets from session keys */
                tachyon::ratchet::ratchet_init(send_ratchet, tx_key);
                tachyon::ratchet::ratchet_init(recv_ratchet, rx_key);
                replay_window.reset();

                OPENSSL_cleanse(eph_ss, 32);
                OPENSSL_cleanse(my_eph_priv, 32);
                met.hs_completed.fetch_add(1, std::memory_order_relaxed);
                LOG_INFO("Handshake complete (responder). Datapath armed.");
            }
            /* ── Handle PKT_FINISH (initiator only) ── */
            else if (flag == TACHYON_PKT_FINISH && n >= (int)sizeof(MsgFinish)) {
                if (!is_initiator || !handshake_active)
                    continue;
                auto *msg = reinterpret_cast<MsgFinish *>(buf);
                if (ntohl(msg->session_id) != session_id)
                    continue;

                /* Decrypt peer ephemeral public key */
                uint8_t peer_eph_pub[32];
                uint8_t f_ad[12];
                memcpy(f_ad, &msg->session_id, 4);
                memcpy(f_ad + 4, &msg->server_nonce, 8);
                uint8_t f_nonce[12] = {0};
                memcpy(f_nonce, &msg->server_nonce, 8);

                if (!cp_aead_decrypt(cp_enc_key, msg->ciphertext, 32, f_ad, 12, f_nonce,
                                     msg->ciphertext + 32, peer_eph_pub))
                    continue;

                last_rx_time = now; /* Authenticated PKT_FINISH - peer is alive */

                /* Derive session keys (initiator: is_initiator=true) */
                uint8_t eph_ss[32], tx_key[32], rx_key[32];
                if (!do_ecdh(my_eph_priv, peer_eph_pub, eph_ss)) {
                    LOG_ERR("Ephemeral ECDH failed in PKT_FINISH");
                    continue;
                }
                derive_session_keys(early_secret, eph_ss, true, tx_key, rx_key);

                inject_keys_to_kernel(obj, session_id, tx_key, rx_key);

                handshake_active = false;
                first_boot = false;
                last_rekey_success = now;

                /* v5: init forward-secrecy ratchets from session keys */
                tachyon::ratchet::ratchet_init(send_ratchet, tx_key);
                tachyon::ratchet::ratchet_init(recv_ratchet, rx_key);
                replay_window.reset();

                OPENSSL_cleanse(eph_ss, 32);
                OPENSSL_cleanse(my_eph_priv, 32);
                met.hs_completed.fetch_add(1, std::memory_order_relaxed);
                if (!first_boot)
                    met.hs_rekeys.fetch_add(1, std::memory_order_relaxed);
                LOG_INFO("Handshake complete (initiator). Datapath armed.");
            }
        } /* while (!g_exiting) */

        OPENSSL_cleanse(my_eph_priv, 32);
        OPENSSL_cleanse(ratchet_chain, 32);
    }
    close(sock);

cleanup_keys:
    OPENSSL_cleanse(early_secret, 32);
    OPENSSL_cleanse(cp_enc_key, 32);
    OPENSSL_cleanse(cookie_secret, 32);
    free_crypto_globals();
    LOG_INFO("Control plane shut down. Keys cleansed.");
}
