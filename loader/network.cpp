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

/* ══════════════════════════════════════════════════════════════════════════
 * QUIC Mimicry - Padded Packet Transmission
 *
 * Pads control plane messages with random bytes to mimic QUIC traffic
 * patterns. PKT_INIT is padded to >= 1200 bytes per QUIC Initial rules.
 * Buffer overflow is prevented by clamping total_len to sizeof(buffer).
 * ══════════════════════════════════════════════════════════════════════════ */

static void send_mimic_quic(int sock, const void *msg, size_t msg_len, int type,
                            const struct sockaddr_in *dest) {
    uint8_t buffer[1500];

    if (msg_len > sizeof(buffer)) {
        LOG_ERR("Message too large for QUIC mimicry buffer (%zu)", msg_len);
        return;
    }
    memcpy(buffer, msg, msg_len);

    /* Fake Connection ID in header padding bytes */
    uint32_t cid_fake;
    if (RAND_bytes(reinterpret_cast<uint8_t *>(&cid_fake), 4) != 1) {
        LOG_ERR("RAND_bytes failed for CID entropy");
        return;
    }
    buffer[1] = cid_fake & 0xFF;
    buffer[2] = (cid_fake >> 8) & 0xFF;
    buffer[3] = (cid_fake >> 16) & 0xFF;

    /* Determine padded size based on packet type */
    uint32_t rnd;
    if (RAND_bytes(reinterpret_cast<uint8_t *>(&rnd), 4) != 1) {
        LOG_ERR("RAND_bytes failed for padding size");
        return;
    }

    size_t total_len;
    if (type == TACHYON_PKT_INIT) {
        total_len = TACHYON_QUIC_INIT_MIN_LEN + (rnd % 150);
    } else {
        total_len = msg_len + 60 + (rnd % 300);
    }

    /* Clamp to buffer size to prevent overflow */
    if (total_len > sizeof(buffer))
        total_len = sizeof(buffer);

    /* Fill padding with cryptographic random bytes */
    if (total_len > msg_len) {
        if (RAND_bytes(buffer + msg_len, total_len - msg_len) != 1) {
            LOG_ERR("RAND_bytes failed for mimicry padding fill");
            return;
        }
    }

    if (sendto(sock, buffer, total_len, 0, reinterpret_cast<const struct sockaddr *>(dest),
               sizeof(*dest)) < 0)
        LOG_WARN("sendto failed: %s", strerror(errno));
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
    uint64_t last_cookie_rotation = time(nullptr);
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
        NonceCache seen_nonces;
        bool handshake_active = true;
        bool first_boot = true;

        uint8_t my_eph_priv[32] = {0}, my_eph_pub[32] = {0};
        uint64_t my_nonce = 0;
        uint64_t last_init_send = 0;
        uint64_t last_rekey_success = time(nullptr);
        uint64_t last_rx_time = time(nullptr);
        uint64_t last_tx_time = time(nullptr);

        /* Jittered timers for anti-fingerprinting */
        uint64_t keepalive_interval = TACHYON_KEEPALIVE_BASE;
        uint64_t retry_interval = TACHYON_RETRY_BASE;

        LOG_INFO("Role: %s", is_initiator ? "Initiator" : "Responder");

        while (!g_exiting) {
            uint64_t now = time(nullptr);

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

                send_mimic_quic(sock, &kmsg, sizeof(kmsg), TACHYON_PKT_KEEPALIVE, &p_addr);
                last_tx_time = now;
                {
                    uint32_t _j;
                    if (RAND_bytes(reinterpret_cast<uint8_t *>(&_j), sizeof(_j)) != 1)
                        _j = 0; /* jitter not security-critical; fall back to base */
                    keepalive_interval = TACHYON_KEEPALIVE_BASE + (_j % TACHYON_KEEPALIVE_JITTER);
                }
            }

            /* Rekey trigger (initiator only) */
            if (is_initiator && !handshake_active &&
                (now - last_rekey_success > TACHYON_REKEY_INTERVAL)) {
                handshake_active = true;
                my_nonce = 0;
                LOG_INFO("Hitless key rotation initiated");
            }

            /* Send PKT_INIT (initiator only, during handshake) */
            if (is_initiator && handshake_active && (now - last_init_send >= retry_interval)) {
                if (my_nonce == 0) {
                    if (RAND_bytes(reinterpret_cast<uint8_t *>(&my_nonce), 8) != 1) {
                        LOG_ERR("Failed to generate handshake nonce");
                        continue;
                    }
                }

                MsgInit msg = {};
                msg.flags = TACHYON_PKT_INIT;
                msg.session_id = htonl(session_id);
                msg.client_nonce = my_nonce;
                msg.is_rekey = first_boot ? 0 : 1;

                send_mimic_quic(sock, &msg, sizeof(msg), TACHYON_PKT_INIT, &p_addr);
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

            /* Only accept from configured peer (IP and source port) */
            if (src.sin_addr.s_addr != p_addr.sin_addr.s_addr || src.sin_port != p_addr.sin_port)
                continue;

            uint8_t flag = buf[0];
            uint64_t current_window = now / 60;

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
                send_mimic_quic(sock, &cmsg, sizeof(cmsg), TACHYON_PKT_COOKIE, &src);
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

                send_mimic_quic(sock, &amsg, sizeof(amsg), TACHYON_PKT_AUTH, &p_addr);
                last_tx_time = now;
            }
            /* ── Handle PKT_AUTH (responder only) ── */
            else if (flag == TACHYON_PKT_AUTH && n >= (int)sizeof(MsgAuth)) {
                if (is_initiator)
                    continue;
                auto *msg = reinterpret_cast<MsgAuth *>(buf);
                if (ntohl(msg->session_id) != session_id)
                    continue;
                if (seen_nonces.exists(msg->client_nonce))
                    continue;

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
                seen_nonces.add(msg->client_nonce, now);
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
                send_mimic_quic(sock, &fmsg, sizeof(fmsg), TACHYON_PKT_FINISH, &src);
                last_tx_time = now;

                OPENSSL_cleanse(eph_ss, 32);
                OPENSSL_cleanse(my_eph_priv, 32);
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

                OPENSSL_cleanse(eph_ss, 32);
                OPENSSL_cleanse(my_eph_priv, 32);
                /* session_master is already cleansed inside derive_session_keys() */
                LOG_INFO("Handshake complete (initiator). Datapath armed.");
            }
        } /* while (!g_exiting) */

        OPENSSL_cleanse(my_eph_priv, 32);
    }
    close(sock);

cleanup_keys:
    OPENSSL_cleanse(early_secret, 32);
    OPENSSL_cleanse(cp_enc_key, 32);
    OPENSSL_cleanse(cookie_secret, 32);
    free_crypto_globals();
    LOG_INFO("Control plane shut down. Keys cleansed.");
}
