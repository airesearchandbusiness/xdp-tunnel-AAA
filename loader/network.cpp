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
 *   - Per-message AEAD nonce counters (CWE-323)
 *   - Branch-free constant-time public key comparison (CWE-208)
 *   - Cookie rotation failure escalation after 5 RAND_bytes errors (CWE-755)
 *   - Optional post-quantum hybrid handshake (pqc_mode=hybrid): the classical
 *     ephemeral X25519 AUTH/FINISH exchange is replaced by the cookie-gated
 *     PQ-AKE (tachyon::pqsession) — ephemeral X25519+ML-KEM-768 for forward
 *     secrecy against a quantum adversary, static-static X25519 for mutual
 *     authentication. The classical path is unchanged when hybrid is off.
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
#include "secmem.h"
#include "mgmt.h"
#include "ip_rate_limiter.h"
#include "circuit_breaker.h"
#include "audit.h"
#include "shutdown.h"
#include "pq_session.h"

#include <memory>

template <size_t N> using KeyBuf = tachyon::secmem::KeyBuf<N>;

static uint64_t monotonic_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec);
}

static tachyon::rl::TokenBucket g_cp_bucket;
static bool g_cp_bucket_inited = false;
static uint32_t g_frame_seq = 0;

static uint64_t monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

static void send_framed(int sock, const void *msg, size_t msg_len, const struct sockaddr_in *dest,
                        const TunnelConfig &cfg) {
    using namespace tachyon::transport;
    using namespace tachyon::padding;
    auto &met = tachyon::metrics::global();

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

    if (policy_from_string(cfg.padding.c_str()) != Policy::NONE) {
        uint32_t padded = padme_round(static_cast<uint32_t>(payload_len));
        /* Only extend the frame if the padding was actually randomized; on RNG
         * failure, send unpadded rather than leak uninitialized stack bytes. */
        if (padded > payload_len && padded <= sizeof(payload) &&
            RAND_bytes(payload + payload_len, padded - static_cast<uint32_t>(payload_len)) == 1) {
            met.padme_bytes_overhead.fetch_add(padded - payload_len, std::memory_order_relaxed);
            payload_len = padded;
        }
    }

    auto tid = static_cast<TransportId>(cfg.resolved_transport_id);
    if (tid != TransportId::NONE && transport_get(tid)) {
        uint8_t framed[4096];
        FrameContext ctx{};
        ctx.seq = g_frame_seq++;
        ctx.sni = cfg.obfuscation_sni.c_str();
        ctx.conn_id_len = 8;
        if (RAND_bytes(ctx.conn_id, 8) != 1)
            memset(ctx.conn_id, 0, 8);

        auto r = transport_wrap(tid, payload, payload_len, framed, sizeof(framed), &ctx);
        if (r.ok) {
            met.transport_wrap_ok.fetch_add(1, std::memory_order_relaxed);
            met.tx_packets.fetch_add(1, std::memory_order_relaxed);
            met.tx_bytes.fetch_add(r.bytes, std::memory_order_relaxed);
            sendto(sock, framed, r.bytes, 0, reinterpret_cast<const struct sockaddr *>(dest),
                   sizeof(*dest));
            return;
        }
        met.transport_wrap_fail.fetch_add(1, std::memory_order_relaxed);
    }

    met.tx_packets.fetch_add(1, std::memory_order_relaxed);
    met.tx_bytes.fetch_add(payload_len, std::memory_order_relaxed);
    sendto(sock, payload, payload_len, 0, reinterpret_cast<const struct sockaddr *>(dest),
           sizeof(*dest));
}

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

static const uint8_t ZERO_IKM[TACHYON_AEAD_KEY_LEN] = {0};

static void build_transcript_ad(uint8_t *out, uint32_t session_id_net, uint64_t client_nonce,
                                const uint8_t *cookie) {
    memcpy(out, &session_id_net, 4);
    memcpy(out + 4, &client_nonce, 8);
    memcpy(out + 12, cookie, TACHYON_HMAC_LEN);
}

static void derive_session_keys(const uint8_t *early_secret, const uint8_t *eph_ss,
                                bool is_initiator, uint8_t *tx_key, uint8_t *rx_key) {
    KeyBuf<32> session_master;
    derive_kdf(early_secret, 32, eph_ss, 32, TACHYON_KDF_SESSION_MASTER, session_master);

    const char *my_tx_label = is_initiator ? TACHYON_KDF_CLIENT_TX : TACHYON_KDF_SERVER_TX;
    const char *my_rx_label = is_initiator ? TACHYON_KDF_SERVER_TX : TACHYON_KDF_CLIENT_TX;

    derive_kdf(session_master, 32, ZERO_IKM, 32, my_tx_label, tx_key);
    derive_kdf(session_master, 32, ZERO_IKM, 32, my_rx_label, rx_key);
}

/* Constant-Time Role Determination (CWE-208 fix: branch-free arithmetic) */
static int ct_role_compare(const uint8_t *my_pub, const uint8_t *peer_pub) {
    if (CRYPTO_memcmp(my_pub, peer_pub, TACHYON_X25519_KEY_LEN) == 0)
        return -1;

    uint32_t gt = 0, lt = 0;
    for (int i = 0; i < TACHYON_X25519_KEY_LEN; i++) {
        int32_t diff = static_cast<int32_t>(my_pub[i]) - static_cast<int32_t>(peer_pub[i]);
        uint32_t neg = static_cast<uint32_t>(diff) >> 31;
        uint32_t pos = static_cast<uint32_t>(-diff) >> 31;
        gt |= pos & ~(gt | lt);
        lt |= neg & ~(gt | lt);
    }
    return gt ? 1 : 0;
}

/* Reload request flag, shared with the SIGHUP handler (tunnel.cpp) and the mgmt
 * "reload" RPC. The control-plane loop hot-reloads the safe config subset when
 * it is set, then clears it. */
volatile sig_atomic_t g_reload_requested = 0;

/* Re-parse the source config file and apply the runtime-safe subset to the
 * live config. Keys, ports, transport, and sockets need a restart and are
 * intentionally NOT touched; an invalid new config is rejected and the running
 * one is kept. Invoked on SIGHUP or the mgmt "reload" RPC. */
static void hot_reload_config(TunnelConfig &cfg) {
    if (cfg.config_path.empty())
        return;
    TunnelConfig fresh = parse_config(cfg.config_path);
    if (!validate_config(fresh)) {
        LOG_WARN("Reload: new config failed validation; keeping current config");
        return;
    }
    cfg.cover_rate_hz = fresh.cover_rate_hz;
    cfg.padding = fresh.padding;
    cfg.obfuscation_sni = fresh.obfuscation_sni;
    cfg.port_hop_seconds = fresh.port_hop_seconds;
    cfg.ttl_random = fresh.ttl_random;
    cfg.mac_random = fresh.mac_random;
    cfg.key_rotation_seconds = fresh.key_rotation_seconds;
    cfg.drain_seconds = fresh.drain_seconds;
    LOG_INFO("Configuration hot-reloaded (runtime-safe subset applied)");
    tachyon::audit::EventInfo ev{};
    ev.event = tachyon::audit::Event::CONFIG_RELOAD;
    ev.outcome = "applied";
    tachyon::audit::emit(ev);
}

/* Read the per-CPU kernel datapath stats map through `obj` and aggregate it
 * into a single userspace_stats. Used to feed the Prometheus exporter from the
 * control-plane loop without re-opening pinned paths. Returns false if the map
 * is unavailable. */
static bool read_stats_total(struct bpf_object *obj, userspace_stats &total) {
    struct bpf_map *m = bpf_object__find_map_by_name(obj, "stats_map");
    if (!m)
        return false;
    int fd = bpf_map__fd(m);
    if (fd < 0)
        return false;
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return false;
    std::vector<userspace_stats> per_cpu(static_cast<size_t>(ncpus));
    uint32_t zero = 0;
    if (bpf_map_lookup_elem(fd, &zero, per_cpu.data()) != 0)
        return false;
    total = userspace_stats{};
    for (int i = 0; i < ncpus; i++) {
        total.rx_packets += per_cpu[i].rx_packets;
        total.rx_bytes += per_cpu[i].rx_bytes;
        total.tx_packets += per_cpu[i].tx_packets;
        total.tx_bytes += per_cpu[i].tx_bytes;
        total.rx_replay_drops += per_cpu[i].rx_replay_drops;
        total.rx_crypto_errors += per_cpu[i].rx_crypto_errors;
        total.rx_invalid_session += per_cpu[i].rx_invalid_session;
        total.rx_malformed += per_cpu[i].rx_malformed;
        total.rx_ratelimit_drops += per_cpu[i].rx_ratelimit_drops;
        total.tx_crypto_errors += per_cpu[i].tx_crypto_errors;
        total.tx_headroom_errors += per_cpu[i].tx_headroom_errors;
        total.tx_ratelimit_drops += per_cpu[i].tx_ratelimit_drops;
        total.rx_ratelimit_data_drops += per_cpu[i].rx_ratelimit_data_drops;
        total.rx_roam_events += per_cpu[i].rx_roam_events;
    }
    return true;
}

void run_control_plane(struct bpf_object *obj, TunnelConfig &cfg, uint32_t session_id,
                       uint32_t peer_ip_net, uint32_t local_ip_net, const uint8_t *peer_mac) {
    LOG_INFO("Booting Tachyon AKE v%d.0...", TACHYON_PROTO_VERSION);
    init_crypto_globals();

    /* Post-quantum hybrid mode (pqc_mode=hybrid). The long-term identity and PSK
     * are captured here, before the classical path wipes static_priv/cfg.psk,
     * because the PQ-AKE needs the raw static key on every (re)handshake. Both
     * are zeroized at cleanup. When classical (default), none of this is used. */
    const bool pq_hybrid = (cfg.pqc_mode == "hybrid");
    std::vector<uint8_t> pq_psk;
    tachyon::pqhs::StaticIdentity pq_id;
    memset(&pq_id, 0, sizeof(pq_id));
    if (pq_hybrid && !tachyon::pqsession::available())
        LOG_WARN("pqc_mode=hybrid requested but no ML-KEM backend is linked; "
                 "the handshake will not complete until a PQ build is deployed");

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

    int role = ct_role_compare(my_static_pub, peer_static_pub);
    if (role < 0) {
        LOG_ERR("Local and peer public keys are identical - aborting");
        OPENSSL_cleanse(static_priv, 32);
        free_crypto_globals();
        return;
    }
    bool is_initiator = (role == 1);

    uint8_t static_ss[32], early_secret[32], cp_tx_key[32], cp_rx_key[32];
    if (!do_ecdh(static_priv, peer_static_pub, static_ss)) {
        LOG_ERR("Static ECDH failed");
        OPENSSL_cleanse(static_priv, 32);
        free_crypto_globals();
        return;
    }

    std::string safe_psk = cfg.psk.empty() ? TACHYON_KDF_DEFAULT_PSK : cfg.psk;
    if (!derive_kdf(reinterpret_cast<const uint8_t *>(safe_psk.data()), safe_psk.size(), static_ss,
                    32, TACHYON_KDF_EARLY_SECRET, early_secret) ||
        !derive_kdf(early_secret, 32, ZERO_IKM, 32,
                    is_initiator ? TACHYON_KDF_CP_I2R : TACHYON_KDF_CP_R2I, cp_tx_key) ||
        !derive_kdf(early_secret, 32, ZERO_IKM, 32,
                    is_initiator ? TACHYON_KDF_CP_R2I : TACHYON_KDF_CP_I2R, cp_rx_key)) {
        /* Fail closed: never key the control plane with uninitialized/stale bytes. */
        LOG_ERR("Control-plane key derivation failed");
        OPENSSL_cleanse(static_ss, 32);
        OPENSSL_cleanse(early_secret, 32);
        OPENSSL_cleanse(cp_tx_key, 32);
        OPENSSL_cleanse(cp_rx_key, 32);
        OPENSSL_cleanse(static_priv, 32);
        free_crypto_globals();
        return;
    }

    /* Capture the long-term identity (and PSK) for the PQ-AKE before they are
     * wiped. pqhs performs the static-static authentication DH internally. */
    if (pq_hybrid) {
        memcpy(pq_id.priv, static_priv, 32);
        memcpy(pq_id.my_pub, my_static_pub, 32);
        memcpy(pq_id.peer_pub, peer_static_pub, 32);
        if (!cfg.psk.empty())
            pq_psk.assign(cfg.psk.begin(), cfg.psk.end());
    }

    OPENSSL_cleanse(static_ss, 32);
    OPENSSL_cleanse(static_priv, 32);

    if (!cfg.private_key.empty())
        OPENSSL_cleanse(cfg.private_key.data(), cfg.private_key.size());
    if (!cfg.psk.empty())
        OPENSSL_cleanse(cfg.psk.data(), cfg.psk.size());

    uint8_t cookie_secret[32];
    uint64_t last_cookie_rotation = monotonic_sec();
    int sock = -1;

    if (RAND_bytes(cookie_secret, 32) != 1) {
        LOG_ERR("Failed to generate initial cookie secret");
        goto cleanup_keys;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERR("Socket creation failed: %s", strerror(errno));
        goto cleanup_keys;
    }
    {
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct timeval tv = {1, 0};
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

        /* Control-plane replay window. Width is operator-tunable via
         * ReplayWindowSize; Window clamps to a multiple of 64 in [64,65536]. */
        tachyon::replay::Window replay_window(cfg.replay_window_size);
        bool handshake_active = true;
        bool first_boot = true;

        uint8_t my_eph_priv[32] = {0}, my_eph_pub[32] = {0};
        uint64_t my_nonce = 0;
        uint64_t last_init_send = 0;

        /* Hybrid-mode handshake drivers. One in-flight handshake at a time
         * (point-to-point tunnel); rebuilt fresh on each attempt so the ephemera
         * always match the latest exchange. Null in classical mode. */
        std::unique_ptr<tachyon::pqsession::Client> pq_client;
        std::unique_ptr<tachyon::pqsession::Server> pq_server;
        bool pq_responder_armed = false;
        uint64_t last_rekey_success = monotonic_sec();
        uint64_t last_rx_time = monotonic_sec();
        uint64_t last_tx_time = monotonic_sec();

        uint64_t keepalive_interval = TACHYON_KEEPALIVE_BASE;
        uint64_t retry_interval = TACHYON_RETRY_BASE;

        tachyon::padding::ShaperState shaper;
        tachyon::padding::shaper_init(shaper, cfg.cover_rate_hz);

        uint8_t psk_bytes[32] = {};
        uint16_t current_hop_port = static_cast<uint16_t>(cfg.listen_port);
        if (cfg.port_hop_seconds > 0 && !cfg.psk.empty()) {
            memset(psk_bytes, 0, 32);
            size_t copy_len = cfg.psk.size() < 32 ? cfg.psk.size() : 32;
            memcpy(psk_bytes, cfg.psk.data(), copy_len);
        }

        uint64_t last_ratchet = monotonic_sec();
        uint8_t ratchet_chain[32];
        RAND_bytes(ratchet_chain, 32);

        tachyon::ratchet::SendState send_ratchet{};
        tachyon::ratchet::SendState recv_ratchet{};

        uint64_t last_decoy = monotonic_sec();
        uint64_t decoy_interval = TACHYON_DECOY_BASE;

        /* Unified control-plane AEAD nonce counter: shared across keepalives AND
         * decoys so no two control packets under the same per-direction CP key
         * can produce the same (key, nonce) pair. The lower 3 bytes are carried
         * in MsgKeepalive.pad[3] so the receiver can reconstruct the nonce. The
         * counter is monotonic for a CP key's lifetime (it resets only on an
         * actual key ratchet, where the key changes too), so reuse is
         * impossible even across a re-handshake. CWE-323. */
        uint32_t ctrl_nonce_ctr = 0;

        /* Cookie rotation failure tracking — escalate after persistent RNG failure (CWE-755) */
        int cookie_failure_streak = 0;

        auto &met = tachyon::metrics::global();

        LOG_INFO("Role: %s | Transport: %s | Padding: %s | Cover: %uHz | Obfs: 0x%02x",
                 is_initiator ? "Initiator" : "Responder",
                 tachyon::transport::transport_id_to_string(
                     static_cast<tachyon::transport::TransportId>(cfg.resolved_transport_id)),
                 cfg.padding.c_str(), cfg.cover_rate_hz, cfg.obfs_flags);

        /* Prometheus/OpenMetrics exporter (/metrics, /health, /ready). Bound to
         * the configured port only when enabled; serviced once per second from
         * this loop so it never blocks the data path. Destroyed (socket closed)
         * when run_control_plane returns. */
        tachyon::MetricsExporter exporter;
        if (cfg.metrics_enabled) {
            if (exporter.start(cfg.metrics_port))
                LOG_INFO("Metrics exporter listening on :%u (/metrics /health /ready)",
                         cfg.metrics_port);
            else
                LOG_WARN("Metrics exporter failed to bind port %u (continuing without it)",
                         cfg.metrics_port);
        }
        /* Anti-abuse: a per-source-IP handshake rate limiter (responder side)
         * blocks flood/brute-force sources, and a circuit breaker backs off
         * INIT retries to a peer that is not answering (initiator side). */
        tachyon::rl::IpRateLimiter ip_limiter;
        tachyon::CircuitBreaker breaker;

        /* JSON-RPC control socket (status / stats / reload) over a 0600 Unix
         * socket. Handlers close over this loop's state and run synchronously
         * inside mgmt::poll(), so the captured references are always valid. */
        const bool mgmt_enabled = !cfg.mgmt_socket.empty();
        if (mgmt_enabled) {
            tachyon::mgmt::Handlers h;
            h.status = [&]() {
                return std::string("{\"tunnel\":\"") + cfg.name + "\",\"role\":\"" +
                       (is_initiator ? "initiator" : "responder") +
                       "\",\"session_id\":" + std::to_string(session_id) +
                       ",\"handshake_active\":" + (handshake_active ? "true" : "false") +
                       ",\"transport\":\"" +
                       tachyon::transport::transport_id_to_string(
                           static_cast<tachyon::transport::TransportId>(
                               cfg.resolved_transport_id)) +
                       "\"}";
            };
            h.stats = [&]() {
                auto s = tachyon::metrics::snapshot();
                return std::string("{\"tx_packets\":") + std::to_string(s.tx_packets) +
                       ",\"rx_packets\":" + std::to_string(s.rx_packets) +
                       ",\"tx_bytes\":" + std::to_string(s.tx_bytes) +
                       ",\"rx_bytes\":" + std::to_string(s.rx_bytes) +
                       ",\"hs_completed\":" + std::to_string(s.hs_completed) +
                       ",\"hs_failed\":" + std::to_string(s.hs_failed) +
                       ",\"replay_dropped\":" + std::to_string(s.replay_dropped) +
                       ",\"cover_frames_sent\":" + std::to_string(s.cover_frames_sent) + "}";
            };
            h.reload = [&]() {
                g_reload_requested = 1;
                return true;
            };
            if (tachyon::mgmt::init(cfg.mgmt_socket, h))
                LOG_INFO("Management socket on %s (JSON-RPC: status/stats/reload)",
                         cfg.mgmt_socket.c_str());
        }

        uint64_t last_services_sec = 0;
        tachyon::shutdown::DrainState drain;

        while (true) {
            uint64_t now = monotonic_sec();

            /* Graceful drain: on SIGTERM keep servicing the session (keepalives,
             * metrics, in-flight control traffic) for DrainSeconds before
             * exiting, so peers and scrapers settle. 0 = exit immediately. */
            if (g_exiting) {
                if (cfg.drain_seconds == 0)
                    break;
                if (!drain.active) {
                    tachyon::shutdown::enter_drain(drain, cfg.drain_seconds, now);
                    LOG_INFO("Draining for %us before shutdown...", cfg.drain_seconds);
                }
                if (tachyon::shutdown::drain_expired(drain, now))
                    break;
            }

            /* Hot config reload (SIGHUP or mgmt "reload"): apply the safe subset. */
            if (g_reload_requested) {
                g_reload_requested = 0;
                hot_reload_config(cfg);
                tachyon::padding::shaper_init(shaper, cfg.cover_rate_hz);
            }

            /* Service the metrics and management endpoints ~1Hz: refresh the
             * Prometheus snapshot, publish readiness, and accept any pending
             * scrape / health / control connections (all non-blocking). */
            if (now != last_services_sec) {
                if (exporter.is_running()) {
                    userspace_stats st{};
                    if (read_stats_total(obj, st))
                        exporter.update(st, cfg.name);
                    exporter.set_ready(!handshake_active);
                    exporter.poll();
                }
                if (mgmt_enabled)
                    tachyon::mgmt::poll();
                last_services_sec = now;
            }

            /* Rotate cookie secret periodically. Failure retains the old secret.
             * After 5 consecutive failures, treat the entropy source as
             * compromised and exit gracefully (CWE-755). */
            if (now - last_cookie_rotation > TACHYON_COOKIE_ROTATION) {
                if (RAND_bytes(cookie_secret, 32) == 1) {
                    last_cookie_rotation = now;
                    cookie_failure_streak = 0;
                } else if (++cookie_failure_streak >= 5) {
                    LOG_ERR("Cookie rotation failed %d consecutive times - "
                            "entropy source compromised, exiting",
                            cookie_failure_streak);
                    g_exiting = 1;
                } else {
                    LOG_WARN("Cookie secret rotation failed (streak=%d) - "
                             "retaining old secret",
                             cookie_failure_streak);
                }
            }

            if (!handshake_active && (now - last_rx_time > TACHYON_DPD_TIMEOUT)) {
                LOG_WARN("Peer timeout (%ds). Resetting state...", TACHYON_DPD_TIMEOUT);
                handshake_active = true;
                first_boot = true;
                my_nonce = 0;
                last_init_send = 0;
                uint8_t zero_key[32] = {0};
                inject_keys_to_kernel(obj, session_id, zero_key, zero_key);
            }

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
                uint32_t ctr_le = ctrl_nonce_ctr++;
                memcpy(k_nonce + 8, &ctr_le, 4);
                memcpy(kmsg.pad, &ctr_le, 3);

                uint8_t dummy[16];
                if (RAND_bytes(dummy, 16) != 1) {
                    LOG_WARN("RAND_bytes failed for keepalive - skipping");
                    continue;
                }
                if (!cp_aead_encrypt(cp_tx_key, dummy, 16, k_ad, 12, k_nonce, kmsg.ciphertext,
                                     kmsg.ciphertext + 16)) {
                    LOG_WARN("Keepalive encrypt failed - skipping");
                    continue;
                }

                send_framed(sock, &kmsg, sizeof(kmsg), &p_addr, cfg);
                tachyon::padding::shaper_on_real_frame(shaper, monotonic_ns());
                last_tx_time = now;
                {
                    uint32_t _j;
                    if (RAND_bytes(reinterpret_cast<uint8_t *>(&_j), sizeof(_j)) != 1)
                        _j = 0;
                    keepalive_interval = TACHYON_KEEPALIVE_BASE + (_j % TACHYON_KEEPALIVE_JITTER);
                }
            }

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
                uint32_t ctr_le = ctrl_nonce_ctr++;
                memcpy(d_nonce + 8, &ctr_le, 4);
                memcpy(decoy_msg.pad, &ctr_le, 3);

                if (RAND_bytes(d_pt, 16) == 1 &&
                    cp_aead_encrypt(cp_tx_key, d_pt, 16, d_ad, 12, d_nonce, decoy_msg.ciphertext,
                                    decoy_msg.ciphertext + 16)) {
                    send_framed(sock, &decoy_msg, sizeof(decoy_msg), &p_addr, cfg);
                }
                last_decoy = now;
                {
                    uint32_t _j;
                    if (RAND_bytes(reinterpret_cast<uint8_t *>(&_j), sizeof(_j)) != 1)
                        _j = 0;
                    decoy_interval = TACHYON_DECOY_BASE + (_j % TACHYON_DECOY_JITTER);
                }
            }

            uint64_t ratchet_interval = cfg.key_rotation_seconds > 0 ? cfg.key_rotation_seconds
                                                                     : TACHYON_KEY_RATCHET_INTERVAL;
            if (!handshake_active && (now - last_ratchet > ratchet_interval)) {
                KeyBuf<32> new_tx, new_rx;
                if (derive_kdf(ratchet_chain, 32, cp_tx_key, 32, TACHYON_KDF_KEY_RATCHET, new_tx) &&
                    derive_kdf(ratchet_chain, 32, cp_rx_key, 32, TACHYON_KDF_KEY_RATCHET, new_rx)) {
                    OPENSSL_cleanse(cp_tx_key, 32);
                    memcpy(cp_tx_key, new_tx, 32);
                    OPENSSL_cleanse(cp_rx_key, 32);
                    memcpy(cp_rx_key, new_rx, 32);
                    ctrl_nonce_ctr = 0;

                    KeyBuf<32> new_chain;
                    derive_kdf(ratchet_chain, 32, cp_tx_key, 32, TACHYON_KDF_DECOY_SEED, new_chain);
                    OPENSSL_cleanse(ratchet_chain, 32);
                    memcpy(ratchet_chain, new_chain, 32);

                    last_ratchet = now;
                    LOG_CRYPTO("Control plane keys ratcheted (forward secrecy)");
                }
            }

            if (is_initiator && !handshake_active &&
                (now - last_rekey_success > TACHYON_REKEY_INTERVAL)) {
                handshake_active = true;
                my_nonce = 0;
                LOG_INFO("Hitless key rotation initiated");
            }

            /* Port hopping — wall-clock time() is intentional here (not
             * monotonic_sec): both peers must derive the same hop port
             * from the same epoch number, which only works if both use
             * the same wall-clock reference. NTP drift tolerance is
             * implicit in the period quantization. */
            if (cfg.port_hop_seconds > 0) {
                uint64_t hop_now = static_cast<uint64_t>(time(nullptr));
                uint16_t new_port =
                    tachyon::fp::port_hop_current(psk_bytes, cfg.port_hop_seconds, hop_now);
                if (new_port != current_hop_port) {
                    struct sockaddr_in rebind {};
                    rebind.sin_family = AF_INET;
                    rebind.sin_port = htons(new_port);
                    rebind.sin_addr.s_addr = INADDR_ANY;
                    int new_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if (new_sock >= 0) {
                        int opt = 1;
                        setsockopt(new_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
                        struct timeval tv = {1, 0};
                        setsockopt(new_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                        if (bind(new_sock, reinterpret_cast<struct sockaddr *>(&rebind),
                                 sizeof(rebind)) == 0) {
                            close(sock);
                            sock = new_sock;
                            p_addr.sin_port = htons(new_port);
                            current_hop_port = new_port;
                            LOG_INFO("Port hopped to %u (socket rebound)", new_port);
                        } else {
                            close(new_sock);
                            LOG_WARN("Port hop bind to %u failed: %s", new_port, strerror(errno));
                        }
                    }
                }
            }

            if (cfg.cover_rate_hz > 0 && !handshake_active) {
                uint64_t now_ns = monotonic_ns();
                uint32_t cover_sz = tachyon::padding::shaper_poll_cover(shaper, now_ns, 64, 1400);
                if (cover_sz > 0) {
                    uint8_t cover[1500];
                    /* Skip the cover frame on RNG failure rather than transmit
                     * uninitialized stack contents as the cover body. */
                    if (RAND_bytes(cover, cover_sz) == 1) {
                        cover[0] = TACHYON_PKT_KEEPALIVE;
                        send_framed(sock, cover, cover_sz, &p_addr, cfg);
                        met.cover_frames_sent.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            if (is_initiator && handshake_active && (now - last_init_send >= retry_interval)) {
                /* Each retry firing while still handshaking means the previous
                 * INIT went unanswered; feed that to the breaker so a dead peer
                 * trips it OPEN and we stop hammering until its cooldown. */
                if (last_init_send != 0)
                    breaker.record_failure(now);
                bool may_send = breaker.allow_request(now);

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

                if (may_send) {
                    send_framed(sock, &msg, sizeof(msg), &p_addr, cfg);
                    tachyon::padding::shaper_on_real_frame(shaper, monotonic_ns());
                    last_tx_time = now;
                }
                last_init_send = now;
                {
                    uint32_t _j;
                    if (RAND_bytes(reinterpret_cast<uint8_t *>(&_j), sizeof(_j)) != 1)
                        _j = 0;
                    retry_interval = TACHYON_RETRY_BASE + (_j % TACHYON_RETRY_JITTER);
                }
            }

            /* 4 KiB holds the largest framed control packet — the hybrid PQ-AKE
             * INIT/RESPONSE are ~1.3 KiB before transport wrapping and padding;
             * classical messages are far smaller. Sized to match the unwrap
             * scratch buffer so a decoded payload can never overflow it. */
            uint8_t buf[4096];
            struct sockaddr_in src;
            socklen_t slen = sizeof(src);
            int n = recvfrom(sock, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr *>(&src),
                             &slen);
            if (n <= 0)
                continue;

            if (src.sin_addr.s_addr != p_addr.sin_addr.s_addr)
                continue;
            if (cfg.port_hop_seconds == 0 && src.sin_port != p_addr.sin_port)
                continue;

            met.rx_packets.fetch_add(1, std::memory_order_relaxed);
            met.rx_bytes.fetch_add(static_cast<uint64_t>(n), std::memory_order_relaxed);

            {
                using namespace tachyon::transport;
                auto tid = static_cast<TransportId>(cfg.resolved_transport_id);
                if (tid != TransportId::NONE && transport_get(tid)) {
                    uint8_t unwrapped[4096];
                    auto r = transport_unwrap(tid, buf, static_cast<size_t>(n), unwrapped,
                                              sizeof(unwrapped));
                    if (r.ok) {
                        memcpy(buf, unwrapped, r.bytes);
                        n = static_cast<int>(r.bytes);
                        met.transport_unwrap_ok.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        met.transport_unwrap_fail.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            uint8_t flag = buf[0];
            uint64_t current_window = static_cast<uint64_t>(time(nullptr)) / 60;

            /* Downgrade protection: refuse a handshake message that belongs to
             * the other pqc_mode. A hybrid node must never complete a classical
             * (non-quantum-resistant) exchange, and a classical node must not be
             * dragged into a PQ one — fail closed and record the attempt rather
             * than silently degrade. The shared cookie round and keepalives are
             * always permitted. */
            if (!tachyon::pqsession::handshake_flag_allowed(flag, pq_hybrid)) {
                LOG_WARN("Dropped handshake packet 0x%02x disallowed under pqc_mode=%s "
                         "(possible downgrade attempt)",
                         flag, cfg.pqc_mode.c_str());
                tachyon::audit::EventInfo ev{};
                ev.event = tachyon::audit::Event::AUTH_FAIL;
                ev.peer_ip = src.sin_addr.s_addr;
                ev.session_id = session_id;
                ev.outcome = pq_hybrid ? "downgrade-classical-rejected" : "unexpected-pq-rejected";
                tachyon::audit::emit(ev);
                continue;
            }

            if (flag == TACHYON_PKT_KEEPALIVE && n >= (int)sizeof(MsgKeepalive)) {
                auto *msg = reinterpret_cast<MsgKeepalive *>(buf);
                if (ntohl(msg->session_id) != session_id)
                    continue;

                uint8_t k_ad[12];
                memcpy(k_ad, &msg->session_id, 4);
                memcpy(k_ad + 4, &msg->timestamp, 8);
                uint8_t k_nonce[12] = {0};
                memcpy(k_nonce, &msg->timestamp, 8);
                uint32_t rx_ctr = 0;
                memcpy(&rx_ctr, msg->pad, 3);
                memcpy(k_nonce + 8, &rx_ctr, 4);
                uint8_t decrypted[16];
                if (!cp_aead_decrypt(cp_rx_key, msg->ciphertext, 16, k_ad, 12, k_nonce,
                                     msg->ciphertext + 16, decrypted)) {
                    LOG_WARN("Keepalive authentication failed - dropping");
                    continue;
                }
                last_rx_time = now;
            } else if (flag == TACHYON_PKT_INIT && n >= (int)sizeof(MsgInit)) {
                if (is_initiator)
                    continue;
                auto *msg = reinterpret_cast<MsgInit *>(buf);
                if (ntohl(msg->session_id) != session_id)
                    continue;

                /* Anti-flood: drop handshake attempts from a source that has
                 * been backed off or blocked for repeated bad handshakes. */
                if (ip_limiter.check(src.sin_addr.s_addr, now) !=
                    tachyon::rl::IpRateLimiter::Verdict::ALLOW) {
                    met.rl_rx_drops.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }

                LOG_INFO("Received PKT_INIT, sending COOKIE...");
                MsgCookie cmsg = {};
                cmsg.flags = TACHYON_PKT_COOKIE;
                cmsg.session_id = htonl(session_id);
                cmsg.client_nonce = msg->client_nonce;
                if (!generate_cookie(cookie_secret, src.sin_addr.s_addr, msg->client_nonce,
                                     current_window, cmsg.cookie))
                    continue;
                send_framed(sock, &cmsg, sizeof(cmsg), &src, cfg);
                last_tx_time = now;
            } else if (flag == TACHYON_PKT_COOKIE && n >= (int)sizeof(MsgCookie)) {
                if (!is_initiator)
                    continue;
                auto *msg = reinterpret_cast<MsgCookie *>(buf);
                if (ntohl(msg->session_id) != session_id || msg->client_nonce != my_nonce)
                    continue;

                if (pq_hybrid) {
                    /* Hybrid PQ-AKE: the stateless cookie round is unchanged; the
                     * COOKIE now triggers a PQ_INIT (ephemeral hybrid KEM pubkey)
                     * instead of the classical AUTH. A fresh Client is minted per
                     * attempt so retries always carry fresh ephemera. */
                    pq_client = std::make_unique<tachyon::pqsession::Client>(
                        pq_id, session_id, pq_psk.empty() ? nullptr : pq_psk.data(), pq_psk.size());
                    std::vector<uint8_t> pkt;
                    if (!pq_client->make_init(msg->cookie, my_nonce, pkt)) {
                        LOG_ERR("PQ_INIT construction failed (no ML-KEM backend?)");
                        pq_client.reset();
                        continue;
                    }
                    LOG_INFO("Received PKT_COOKIE, sending PQ_INIT...");
                    send_framed(sock, pkt.data(), pkt.size(), &p_addr, cfg);
                    last_tx_time = now;
                    continue;
                }

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
                if (!cp_aead_encrypt(cp_tx_key, my_eph_pub, 32, transcript_ad, 44, cp_nonce,
                                     amsg.ciphertext, amsg.ciphertext + 32)) {
                    LOG_ERR("PKT_AUTH encrypt failed");
                    continue;
                }

                send_framed(sock, &amsg, sizeof(amsg), &p_addr, cfg);
                last_tx_time = now;
            } else if (flag == TACHYON_PKT_AUTH && n >= (int)sizeof(MsgAuth)) {
                if (is_initiator)
                    continue;
                auto *msg = reinterpret_cast<MsgAuth *>(buf);
                if (ntohl(msg->session_id) != session_id)
                    continue;
                if (replay_window.peek(msg->client_nonce) != tachyon::replay::Result::ACCEPTED) {
                    met.replay_dropped.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }

                uint8_t c1[32], c2[32];
                if (!generate_cookie(cookie_secret, src.sin_addr.s_addr, msg->client_nonce,
                                     current_window, c1) ||
                    !generate_cookie(cookie_secret, src.sin_addr.s_addr, msg->client_nonce,
                                     current_window - 1, c2))
                    continue;

                if (CRYPTO_memcmp(c1, msg->cookie, TACHYON_HMAC_LEN) != 0 &&
                    CRYPTO_memcmp(c2, msg->cookie, TACHYON_HMAC_LEN) != 0) {
                    ip_limiter.record_failure(src.sin_addr.s_addr, now);
                    tachyon::audit::EventInfo ev{};
                    ev.event = tachyon::audit::Event::COOKIE_INVALID;
                    ev.peer_ip = src.sin_addr.s_addr;
                    ev.session_id = session_id;
                    ev.outcome = "cookie-mismatch";
                    tachyon::audit::emit(ev);
                    continue;
                }

                uint8_t peer_eph_pub[32];
                uint8_t transcript_ad[44];
                build_transcript_ad(transcript_ad, msg->session_id, msg->client_nonce, msg->cookie);

                uint8_t cp_nonce[12] = {0};
                memcpy(cp_nonce, &msg->client_nonce, 8);

                if (!cp_aead_decrypt(cp_rx_key, msg->ciphertext, 32, transcript_ad, 44, cp_nonce,
                                     msg->ciphertext + 32, peer_eph_pub)) {
                    ip_limiter.record_failure(src.sin_addr.s_addr, now);
                    tachyon::audit::EventInfo ev{};
                    ev.event = tachyon::audit::Event::AUTH_FAIL;
                    ev.peer_ip = src.sin_addr.s_addr;
                    ev.session_id = session_id;
                    ev.outcome = "auth-decrypt-failed";
                    tachyon::audit::emit(ev);
                    continue;
                }

                replay_window.check_and_commit(msg->client_nonce);
                last_rx_time = now;
                met.replay_accepted.fetch_add(1, std::memory_order_relaxed);
                if (msg->is_rekey == 0)
                    reset_bpf_replay_state(obj, session_id, peer_ip_net, local_ip_net, peer_mac);

                if (!generate_x25519_keypair(my_eph_priv, my_eph_pub))
                    continue;

                KeyBuf<32> eph_ss, tx_key, rx_key;
                if (!do_ecdh(my_eph_priv, peer_eph_pub, eph_ss)) {
                    LOG_ERR("Ephemeral ECDH failed in PKT_AUTH");
                    continue;
                }
                derive_session_keys(early_secret, eph_ss, false, tx_key, rx_key);

                inject_keys_to_kernel(obj, session_id, tx_key, rx_key);

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

                if (!cp_aead_encrypt(cp_tx_key, my_eph_pub, 32, f_ad, 12, f_nonce, fmsg.ciphertext,
                                     fmsg.ciphertext + 32)) {
                    LOG_ERR("PKT_FINISH encrypt failed");
                    OPENSSL_cleanse(my_eph_priv, 32);
                    continue;
                }
                send_framed(sock, &fmsg, sizeof(fmsg), &src, cfg);
                last_tx_time = now;

                tachyon::ratchet::ratchet_init(send_ratchet, tx_key);
                tachyon::ratchet::ratchet_init(recv_ratchet, rx_key);
                replay_window.reset();

                OPENSSL_cleanse(my_eph_priv, 32);
                met.hs_completed.fetch_add(1, std::memory_order_relaxed);
                ip_limiter.record_success(src.sin_addr.s_addr);
                LOG_INFO("Handshake complete (responder). Datapath armed.");
            } else if (flag == TACHYON_PKT_FINISH && n >= (int)sizeof(MsgFinish)) {
                if (!is_initiator || !handshake_active)
                    continue;
                auto *msg = reinterpret_cast<MsgFinish *>(buf);
                if (ntohl(msg->session_id) != session_id)
                    continue;

                uint8_t peer_eph_pub[32];
                uint8_t f_ad[12];
                memcpy(f_ad, &msg->session_id, 4);
                memcpy(f_ad + 4, &msg->server_nonce, 8);
                uint8_t f_nonce[12] = {0};
                memcpy(f_nonce, &msg->server_nonce, 8);

                if (!cp_aead_decrypt(cp_rx_key, msg->ciphertext, 32, f_ad, 12, f_nonce,
                                     msg->ciphertext + 32, peer_eph_pub))
                    continue;

                last_rx_time = now;

                KeyBuf<32> eph_ss, tx_key, rx_key;
                if (!do_ecdh(my_eph_priv, peer_eph_pub, eph_ss)) {
                    LOG_ERR("Ephemeral ECDH failed in PKT_FINISH");
                    continue;
                }
                derive_session_keys(early_secret, eph_ss, true, tx_key, rx_key);

                inject_keys_to_kernel(obj, session_id, tx_key, rx_key);

                handshake_active = false;
                first_boot = false;
                last_rekey_success = now;
                /* Do NOT reset ctrl_nonce_ctr here: the per-direction CP keys are
                 * unchanged across a re-handshake (they derive from the static
                 * ECDH), so resetting the counter could repeat a (key, nonce).
                 * The counter resets only on an actual key ratchet. CWE-323. */

                tachyon::ratchet::ratchet_init(send_ratchet, tx_key);
                tachyon::ratchet::ratchet_init(recv_ratchet, rx_key);
                replay_window.reset();

                OPENSSL_cleanse(my_eph_priv, 32);
                met.hs_completed.fetch_add(1, std::memory_order_relaxed);
                breaker.record_success(now);
                ip_limiter.record_success(src.sin_addr.s_addr);
                if (!first_boot)
                    met.hs_rekeys.fetch_add(1, std::memory_order_relaxed);
                LOG_INFO("Handshake complete (initiator). Datapath armed.");
            } else if (flag == TACHYON_PKT_PQ_INIT && pq_hybrid &&
                       n >= (int)tachyon::pqsession::PQ_INIT_LEN) {
                /* ── Hybrid PQ-AKE, responder step 1 ───────────────────────────
                 * Cookie-gated (inside Server::on_init) exactly like classical
                 * AUTH, so no KEM work happens for an unauthenticated source. */
                if (is_initiator)
                    continue;
                if (ip_limiter.check(src.sin_addr.s_addr, now) !=
                    tachyon::rl::IpRateLimiter::Verdict::ALLOW) {
                    met.rl_rx_drops.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
                /* No userspace replay window here (unlike classical AUTH): the
                 * PQ responder is stateful across two messages and cannot reset
                 * the window until PQ_CONFIRM, so a committed nonce would block
                 * the initiator's legitimate PQ_INIT retransmit (same nonce) and
                 * deadlock a lost-RESPONSE recovery. Anti-DoS is already covered
                 * by the source-IP filter, the per-IP rate limiter, and the
                 * stateless cookie validated inside on_init; the handshake still
                 * cannot complete without the initiator's authenticated CONFIRM. */

                pq_server = std::make_unique<tachyon::pqsession::Server>(
                    pq_id, session_id, pq_psk.empty() ? nullptr : pq_psk.data(), pq_psk.size());
                std::vector<uint8_t> resp;
                auto st = pq_server->on_init(buf, static_cast<size_t>(n), cookie_secret,
                                             src.sin_addr.s_addr, current_window, resp);
                if (st == tachyon::pqsession::Step::IGNORE) {
                    pq_server.reset();
                    continue;
                }
                if (st != tachyon::pqsession::Step::OK) {
                    ip_limiter.record_failure(src.sin_addr.s_addr, now);
                    tachyon::audit::EventInfo ev{};
                    ev.event = tachyon::audit::Event::AUTH_FAIL;
                    ev.peer_ip = src.sin_addr.s_addr;
                    ev.session_id = session_id;
                    ev.outcome = (st == tachyon::pqsession::Step::DOS_REJECT) ? "pq-cookie-mismatch"
                                                                              : "pq-init-rejected";
                    tachyon::audit::emit(ev);
                    pq_server.reset();
                    continue;
                }
                last_rx_time = now;
                send_framed(sock, resp.data(), resp.size(), &src, cfg);
                last_tx_time = now;
                LOG_INFO("Received PQ_INIT, sent PQ_RESPONSE (awaiting confirm)...");
            } else if (flag == TACHYON_PKT_PQ_RESPONSE && pq_hybrid &&
                       n >= (int)tachyon::pqsession::PQ_RESPONSE_LEN) {
                /* ── Hybrid PQ-AKE, initiator step 2 ───────────────────────────
                 * Authenticate the responder, emit our confirmation, and arm. */
                if (!is_initiator || !handshake_active || !pq_client)
                    continue;
                std::vector<uint8_t> confirm;
                auto st = pq_client->on_response(buf, static_cast<size_t>(n), confirm);
                if (st == tachyon::pqsession::Step::IGNORE)
                    continue;
                if (st != tachyon::pqsession::Step::COMPLETE) {
                    tachyon::audit::EventInfo ev{};
                    ev.event = tachyon::audit::Event::AUTH_FAIL;
                    ev.peer_ip = src.sin_addr.s_addr;
                    ev.session_id = session_id;
                    ev.outcome = "pq-response-auth-failed";
                    tachyon::audit::emit(ev);
                    pq_client.reset();
                    continue;
                }
                last_rx_time = now;
                send_framed(sock, confirm.data(), confirm.size(), &p_addr, cfg);
                last_tx_time = now;

                KeyBuf<32> tx_key, rx_key;
                if (!pq_client->export_keys(tx_key, rx_key)) {
                    LOG_ERR("PQ key export failed (initiator)");
                    pq_client.reset();
                    continue;
                }
                tachyon::ratchet::ratchet_init(send_ratchet, tx_key);
                tachyon::ratchet::ratchet_init(recv_ratchet, rx_key);
                inject_keys_to_kernel(obj, session_id, tx_key, rx_key);

                handshake_active = false;
                first_boot = false;
                last_rekey_success = now;
                replay_window.reset();
                met.hs_completed.fetch_add(1, std::memory_order_relaxed);
                breaker.record_success(now);
                ip_limiter.record_success(src.sin_addr.s_addr);
                pq_client.reset();
                LOG_INFO("Handshake complete (initiator, hybrid PQ). Datapath armed.");
            } else if (flag == TACHYON_PKT_PQ_CONFIRM && pq_hybrid &&
                       n >= (int)tachyon::pqsession::PQ_CONFIRM_LEN) {
                /* ── Hybrid PQ-AKE, responder step 2 ───────────────────────────
                 * Authenticate the initiator's confirmation, then arm. Mutual
                 * authentication completes before any datapath key is injected. */
                if (is_initiator || !pq_server)
                    continue;
                auto st = pq_server->on_confirm(buf, static_cast<size_t>(n));
                if (st == tachyon::pqsession::Step::IGNORE)
                    continue;
                if (st != tachyon::pqsession::Step::COMPLETE) {
                    ip_limiter.record_failure(src.sin_addr.s_addr, now);
                    tachyon::audit::EventInfo ev{};
                    ev.event = tachyon::audit::Event::AUTH_FAIL;
                    ev.peer_ip = src.sin_addr.s_addr;
                    ev.session_id = session_id;
                    ev.outcome = "pq-confirm-auth-failed";
                    tachyon::audit::emit(ev);
                    pq_server.reset();
                    continue;
                }
                last_rx_time = now;

                KeyBuf<32> tx_key, rx_key;
                if (!pq_server->export_keys(tx_key, rx_key)) {
                    LOG_ERR("PQ key export failed (responder)");
                    pq_server.reset();
                    continue;
                }
                /* First hybrid handshake resets the kernel replay window (fresh
                 * peer); subsequent rekeys keep it to avoid dropping in-flight
                 * datapath packets — mirrors the classical is_rekey behaviour. */
                if (!pq_responder_armed) {
                    reset_bpf_replay_state(obj, session_id, peer_ip_net, local_ip_net, peer_mac);
                    pq_responder_armed = true;
                }
                tachyon::ratchet::ratchet_init(send_ratchet, tx_key);
                tachyon::ratchet::ratchet_init(recv_ratchet, rx_key);
                inject_keys_to_kernel(obj, session_id, tx_key, rx_key);

                replay_window.reset();
                met.hs_completed.fetch_add(1, std::memory_order_relaxed);
                ip_limiter.record_success(src.sin_addr.s_addr);
                pq_server.reset();
                LOG_INFO("Handshake complete (responder, hybrid PQ). Datapath armed.");
            }
        }

        OPENSSL_cleanse(my_eph_priv, 32);
        OPENSSL_cleanse(ratchet_chain, 32);
        OPENSSL_cleanse(psk_bytes, 32);
    }
    close(sock);

cleanup_keys:
    tachyon::mgmt::shutdown();
    OPENSSL_cleanse(early_secret, 32);
    OPENSSL_cleanse(cp_tx_key, 32);
    OPENSSL_cleanse(cp_rx_key, 32);
    OPENSSL_cleanse(cookie_secret, 32);
    OPENSSL_cleanse(&pq_id, sizeof(pq_id));
    if (!pq_psk.empty())
        OPENSSL_cleanse(pq_psk.data(), pq_psk.size());
    free_crypto_globals();
    LOG_INFO("Control plane shut down. Keys cleansed.");
}
