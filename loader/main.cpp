// Compile: g++ -O2 -Wall -std=c++23 ghostctl.cpp -o ghostctl -lbpf -lcrypto

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <chrono>
#include <time.h>
#include <cstdlib>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <signal.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>     
#include <openssl/crypto.h>   
#include <openssl/core_names.h>

const std::string BASE_BPF_DIR = "/sys/fs/bpf/tachyon";
static volatile bool exiting = false;
void sig_handler(int sig) { exiting = true; }

struct global_config { uint16_t listen_port_net; uint8_t mimicry_type; uint8_t pad; };
struct session_ctx {
    uint32_t lock_pad; uint32_t peer_ip; uint32_t local_ip;
    uint8_t peer_mac[6]; uint8_t pad[2]; uint32_t pad_align;
    uint64_t rx_highest_seq[64]; uint64_t rx_bitmap[64][4];
};

struct key_init_data { 
    uint32_t session_id; 
    uint8_t tx_key[32]; 
    uint8_t rx_key[32]; 
};

#define PKT_INIT       0xC0
#define PKT_COOKIE     0xC1
#define PKT_AUTH       0xC2
#define PKT_FINISH     0xC3
#define PKT_KEEPALIVE  0xC4

#pragma pack(push, 1)
struct MsgInit { 
    uint8_t flags; uint8_t pad[3]; uint32_t session_id; uint64_t client_nonce; 
    uint8_t is_rekey; uint8_t dummy_pad[3]; 
};
struct MsgCookie { 
    uint8_t flags; uint8_t pad[3]; uint32_t session_id; uint64_t client_nonce; 
    uint8_t cookie[32]; 
};
struct MsgAuth {
    uint8_t flags; uint8_t pad[3]; uint32_t session_id; uint64_t client_nonce;
    uint8_t is_rekey; uint8_t dummy_pad[3]; 
    uint8_t cookie[32]; 
    uint8_t ciphertext[48]; 
};
struct MsgFinish {
    uint8_t flags; uint8_t pad[3]; uint32_t session_id; uint64_t server_nonce;
    uint8_t ciphertext[48]; 
};
struct MsgKeepalive {
    uint8_t flags; uint8_t pad[3]; uint32_t session_id; uint64_t timestamp;
    uint8_t ciphertext[32];
};
#pragma pack(pop)

EVP_MAC *g_mac = nullptr;
EVP_KDF *g_kdf = nullptr;

void init_crypto_globals() {
    g_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    g_kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!g_mac || !g_kdf) { std::cerr << "Fatal: Failed to fetch crypto engines!\n"; exit(1); }
    srand(time(NULL));
}
void free_crypto_globals() { if (g_mac) EVP_MAC_free(g_mac); if (g_kdf) EVP_KDF_free(g_kdf); }

struct NonceCache {
    std::unordered_map<uint64_t, uint64_t> cache;
    void add(uint64_t nonce, uint64_t now) {
        if (cache.size() > 50000) { 
            for (auto it = cache.begin(); it != cache.end(); ) {
                if (now - it->second > 180) it = cache.erase(it);
                else ++it;
            }
        }
        cache[nonce] = now;
    }
    bool exists(uint64_t nonce) { return cache.count(nonce) > 0; }
};

void calc_hmac(const uint8_t* key, const uint8_t* data, size_t len, uint8_t* out_mac) {
    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(g_mac);
    OSSL_PARAM params[2] = { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0), OSSL_PARAM_END };
    EVP_MAC_init(mctx, key, 32, params);
    EVP_MAC_update(mctx, data, len);
    size_t out_len = 0; EVP_MAC_final(mctx, out_mac, &out_len, 32);
    EVP_MAC_CTX_free(mctx);
}

void generate_cookie(const uint8_t* cookie_secret, uint32_t client_ip, uint64_t nonce, uint64_t window, uint8_t* out_cookie) {
    uint8_t buf[20];
    memcpy(buf, &client_ip, 4); memcpy(buf + 4, &nonce, 8); memcpy(buf + 12, &window, 8);
    calc_hmac(cookie_secret, buf, sizeof(buf), out_cookie);
}

bool do_ecdh(const uint8_t* my_priv, const uint8_t* peer_pub, uint8_t* out_ss) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, my_priv, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_derive_init(ctx); EVP_PKEY_derive_set_peer(ctx, peer);
    size_t slen = 32; int ret = EVP_PKEY_derive(ctx, out_ss, &slen);
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer); EVP_PKEY_free(pkey);
    return ret > 0;
}

void derive_kdf(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, const char* info, uint8_t* out_key) {
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(g_kdf);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA256", 0),
        OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len),
        OSSL_PARAM_construct_octet_string("key", (void*)ikm, 32),
        OSSL_PARAM_construct_octet_string("info", (void*)info, strlen(info)),
        OSSL_PARAM_END
    };
    EVP_KDF_derive(kctx, out_key, 32, params);
    EVP_KDF_CTX_free(kctx);
}

bool cp_aead_encrypt(const uint8_t* key, const uint8_t* plaintext, size_t pt_len, 
                     const uint8_t* ad, size_t ad_len, uint8_t* nonce, 
                     uint8_t* ciphertext, uint8_t* tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);
    if (ad && ad_len > 0) EVP_EncryptUpdate(ctx, NULL, &len, ad, ad_len); 
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool cp_aead_decrypt(const uint8_t* key, const uint8_t* ciphertext, size_t ct_len, 
                     const uint8_t* ad, size_t ad_len, uint8_t* nonce, 
                     const uint8_t* tag, uint8_t* plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret;
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);
    if (ad && ad_len > 0) EVP_DecryptUpdate(ctx, NULL, &len, ad, ad_len); 
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ret > 0; 
}

// 🔥 تابع حیاتی: استتار کامل ترافیک (QUIC Mimicry)
void send_mimic_quic(int sock, const void* msg, size_t msg_len, int type, const struct sockaddr_in* dest) {
    uint8_t buffer[1500];
    memcpy(buffer, msg, msg_len);
    
    // شبیه‌سازی CID (Connection ID) فیک روی هدر Control Plane
    uint32_t cid_fake; RAND_bytes((uint8_t*)&cid_fake, 4);
    buffer[1] = cid_fake & 0xFF; buffer[2] = (cid_fake >> 8) & 0xFF; buffer[3] = (cid_fake >> 16) & 0xFF;

    size_t total_len = msg_len;
    uint32_t rnd; RAND_bytes((uint8_t*)&rnd, 4);

    if (type == PKT_INIT) {
        // قانون QUIC: پکت Initial باید حداقل 1200 بایت باشد!
        total_len = 1200 + (rnd % 150); 
    } else {
        // بقیه پکت‌ها توزیع سایز رندوم می‌گیرند
        total_len = msg_len + 60 + (rnd % 300);
    }
    
    // پر کردن فضای خالی با آشغال‌های کریپتوگرافیک
    if (total_len > msg_len) {
        RAND_bytes(buffer + msg_len, total_len - msg_len);
    }
    
    sendto(sock, buffer, total_len, 0, (struct sockaddr*)dest, sizeof(*dest));
}

bool run_cmd_check(const std::string& cmd) { return system(cmd.c_str()) == 0; }
void run_cmd(const std::string& cmd) { run_cmd_check(cmd); }
bool parse_mac(const std::string& str, uint8_t mac[6]) {
    return sscanf(str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}
void hex2bin(const std::string& hex, uint8_t* bin) {
    for(int i = 0; i < 32; i++) sscanf(&hex[i*2], "%2hhx", &bin[i]);
}
std::string trim(std::string s) {
    s.erase(0, s.find_first_not_of(" \t\r\n")); s.erase(s.find_last_not_of(" \t\r\n") + 1); return s;
}

std::unordered_map<std::string, std::string> parse_config(const std::string& filename) {
    std::unordered_map<std::string, std::string> config; std::ifstream file(filename); if (!file.is_open()) exit(1);
    std::string line, section;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line.front() == '[' && line.back() == ']') { section = line.substr(1, line.size() - 2) + "."; continue; }
        auto pos = line.find('='); if (pos == std::string::npos) continue;
        std::string key = line.substr(0, pos); key.erase(key.find_last_not_of(" \t") + 1);
        std::string val = line.substr(pos + 1); val.erase(0, val.find_first_not_of(" \t"));
        config[section + key] = val; config[key] = val;
    }
    return config;
}

std::string tunnel_name_from_conf(const std::string& conf) {
    std::string name = conf; size_t p = name.find_last_of('/');
    if (p != std::string::npos) name = name.substr(p + 1);
    p = name.find('.'); if (p != std::string::npos) name = name.substr(0, p);
    return name;
}

void inject_keys_to_kernel(struct bpf_object *obj, uint32_t session_id, uint8_t* tx_key, uint8_t* rx_key) {
    int key_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "key_init_map"));
    if (key_map_fd < 0) return;
    uint32_t zero = 0; key_init_data kid{}; 
    kid.session_id = session_id; 
    memcpy(kid.tx_key, tx_key, 32); memcpy(kid.rx_key, rx_key, 32);
    bpf_map_update_elem(key_map_fd, &zero, &kid, BPF_ANY);

    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "ghost_key_init"));
    if (prog_fd >= 0) {
        DECLARE_LIBBPF_OPTS(bpf_test_run_opts, topts, .ctx_in = NULL, .ctx_size_in = 0);
        bpf_prog_test_run_opts(prog_fd, &topts);
    }
    OPENSSL_cleanse(tx_key, 32); OPENSSL_cleanse(rx_key, 32);
}

void reset_bpf_replay_state(struct bpf_object *obj, uint32_t session_id, uint32_t peer_ip_net, uint32_t local_ip_net, const uint8_t* peer_mac) {
    int sess_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "session_map"));
    if (sess_fd < 0) return;
    session_ctx sess{};
    sess.peer_ip = peer_ip_net;
    sess.local_ip = local_ip_net;
    memcpy(sess.peer_mac, peer_mac, 6);
    bpf_map_update_elem(sess_fd, &session_id, &sess, BPF_ANY);
    std::cout << "    [Kernel] Replay Window explicitly reset for peer restart.\n";
}

void run_control_plane(struct bpf_object *obj, const std::string& psk, 
                       const std::string& my_priv_hex, const std::string& peer_pub_hex,
                       int port, uint32_t session_id, const std::string& peer_ip_str,
                       const std::string& local_ip_str, const std::string& peer_mac_str) {
    
    std::cout << "\n Booting Tachyon AKE v4.0 (Full Obfuscation & Jitter Timing)...\n";
    init_crypto_globals();

    uint8_t static_priv[32], peer_static_pub[32], my_static_pub[32];
    hex2bin(my_priv_hex, static_priv); hex2bin(peer_pub_hex, peer_static_pub);
    
    EVP_PKEY *spk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, static_priv, 32);
    size_t slen = 32; EVP_PKEY_get_raw_public_key(spk, my_static_pub, &slen); EVP_PKEY_free(spk);

    if (CRYPTO_memcmp(my_static_pub, peer_static_pub, 32) == 0) exit(1);
    bool is_initiator = memcmp(my_static_pub, peer_static_pub, 32) > 0;

    uint8_t static_ss[32], early_secret[32], cp_enc_key[32];
    if (!do_ecdh(static_priv, peer_static_pub, static_ss)) exit(1);
    
    std::string safe_psk = psk.empty() ? "Tachyon-Default-PSK" : psk;
    derive_kdf((uint8_t*)safe_psk.data(), safe_psk.size(), static_ss, "Tachyon-EarlySecret", early_secret);
    derive_kdf(early_secret, 32, (uint8_t*)"", "Tachyon-CP-AEAD", cp_enc_key);
    
    OPENSSL_cleanse(static_ss, 32); OPENSSL_cleanse(static_priv, 32);

    uint8_t cookie_secret[32]; RAND_bytes(cookie_secret, 32);
    uint64_t last_cookie_rotation = time(NULL);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    int opt = 1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct timeval tv = {0, 500000}; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); 
    struct sockaddr_in addr{}; 
    addr.sin_family = AF_INET; 
    addr.sin_port = htons(port); 
    addr.sin_addr.s_addr = INADDR_ANY; 
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    struct sockaddr_in p_addr{}; p_addr.sin_family = AF_INET; p_addr.sin_port = htons(port);
    inet_pton(AF_INET, peer_ip_str.c_str(), &p_addr.sin_addr);

    uint32_t peer_ip_net = p_addr.sin_addr.s_addr;
    uint32_t local_ip_net; inet_pton(AF_INET, local_ip_str.c_str(), &local_ip_net);
    uint8_t p_mac[6]; parse_mac(peer_mac_str, p_mac);

    NonceCache seen_nonces;
    bool handshake_active = true; 
    bool first_boot = true; 

    uint8_t my_eph_priv[32], my_eph_pub[32];
    uint64_t my_nonce = 0;
    uint64_t last_init_send = 0;
    uint64_t last_rekey_success = time(NULL);

    uint64_t last_rx_time = time(NULL);
    uint64_t last_tx_time = time(NULL);
    
    // 🔥 تایمرهای متغیر (Jitter) برای فرار از تحلیل زمانی
    uint64_t current_keepalive_interval = 10;
    uint64_t current_retry_interval = 2;

    std::cout << "  Role: " << (is_initiator ? "Initiator" : "Responder") << "\n";

    while (!exiting) {
        uint64_t now_sec = time(NULL);
        
        if (now_sec - last_cookie_rotation > 120) {
            RAND_bytes(cookie_secret, 32);
            last_cookie_rotation = now_sec;
        }

        if (!handshake_active && (now_sec - last_rx_time > 35)) {
            std::cout << "  [DPD] Peer timeout! Connection lost. Resetting state...\n";
            handshake_active = true; first_boot = true; my_nonce = 0; last_init_send = 0;
            uint8_t zero_key[32] = {0}; inject_keys_to_kernel(obj, session_id, zero_key, zero_key);
        }

        // 🔥 ارسال Keepalive با زمان‌بندی رندوم (بین 8 تا 15 ثانیه)
        if (!handshake_active && (now_sec - last_tx_time >= current_keepalive_interval)) {
            MsgKeepalive kmsg = {PKT_KEEPALIVE, {0}, htonl(session_id), now_sec, {0}};
            uint8_t k_ad[12]; memcpy(k_ad, &kmsg.session_id, 4); memcpy(k_ad + 4, &kmsg.timestamp, 8);
            uint8_t k_nonce[12] = {0}; memcpy(k_nonce, &kmsg.timestamp, 8);
            uint8_t dummy_data[16]; RAND_bytes(dummy_data, 16); 
            
            cp_aead_encrypt(cp_enc_key, dummy_data, 16, k_ad, 12, k_nonce, kmsg.ciphertext, kmsg.ciphertext + 16);
            send_mimic_quic(sock, &kmsg, sizeof(kmsg), PKT_KEEPALIVE, &p_addr);
            
            last_tx_time = now_sec;
            current_keepalive_interval = 8 + (rand() % 8); // Timing Jitter
        }

        if (is_initiator && !handshake_active && (now_sec - last_rekey_success > 60)) {
            handshake_active = true; my_nonce = 0;
            std::cout << "  [Rekey] Hitless Key Rotation Initiated...\n";
        }

        if (is_initiator && handshake_active) {
            if (now_sec - last_init_send >= current_retry_interval) {
                if (my_nonce == 0) RAND_bytes((unsigned char*)&my_nonce, 8);
                uint8_t is_rk = first_boot ? 0 : 1;
                MsgInit msg = {PKT_INIT, {0}, htonl(session_id), my_nonce, is_rk, {0}};
                send_mimic_quic(sock, &msg, sizeof(msg), PKT_INIT, &p_addr);
                last_init_send = now_sec;
                last_tx_time = now_sec;
                current_retry_interval = 2 + (rand() % 3); // Jitter (2 to 4s)
            }
        }

        uint8_t buf[2000]; struct sockaddr_in src; socklen_t len = sizeof(src);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&src, &len);
        if (n <= 0) continue;
        if (src.sin_addr.s_addr != p_addr.sin_addr.s_addr) continue; 

        uint8_t flag = buf[0];
        uint64_t current_window = now_sec / 60;
        last_rx_time = now_sec;

        // 🔥 تمام شرط‌ها حالا به n >= sizeof() تغییر کرده‌اند تا پدینگ‌ها قبول شوند
        if (flag == PKT_KEEPALIVE && n >= (int)sizeof(MsgKeepalive)) {
            MsgKeepalive* msg = (MsgKeepalive*)buf;
            if (ntohl(msg->session_id) != session_id) continue;
            uint8_t k_ad[12]; memcpy(k_ad, &msg->session_id, 4); memcpy(k_ad + 4, &msg->timestamp, 8);
            uint8_t k_nonce[12] = {0}; memcpy(k_nonce, &msg->timestamp, 8);
            uint8_t decrypted_dummy[16];
            if (cp_aead_decrypt(cp_enc_key, msg->ciphertext, 16, k_ad, 12, k_nonce, msg->ciphertext + 16, decrypted_dummy)) continue; 
        }
        else if (flag == PKT_INIT && n >= (int)sizeof(MsgInit)) {
            if (is_initiator) continue;
            MsgInit* msg = (MsgInit*)buf;
            if (ntohl(msg->session_id) != session_id) continue;
            
            std::cout << "  [CP] Received PKT_INIT. Sending COOKIE...\n";
            MsgCookie cmsg = {PKT_COOKIE, {0}, htonl(session_id), msg->client_nonce, {0}};
            generate_cookie(cookie_secret, src.sin_addr.s_addr, msg->client_nonce, current_window, cmsg.cookie);
            send_mimic_quic(sock, &cmsg, sizeof(cmsg), PKT_COOKIE, &src);
            last_tx_time = now_sec;
        }
        else if (flag == PKT_COOKIE && n >= (int)sizeof(MsgCookie)) {
            if (!is_initiator) continue;
            MsgCookie* msg = (MsgCookie*)buf;
            if (ntohl(msg->session_id) != session_id || msg->client_nonce != my_nonce) continue;

            std::cout << "  [CP] Received PKT_COOKIE. Sending AUTH...\n";
            EVP_PKEY *pk = EVP_PKEY_Q_keygen(NULL, NULL, "X25519"); size_t pk_len = 32; 
            EVP_PKEY_get_raw_private_key(pk, my_eph_priv, &pk_len); EVP_PKEY_get_raw_public_key(pk, my_eph_pub, &pk_len); EVP_PKEY_free(pk);

            uint8_t is_rk = first_boot ? 0 : 1;
            MsgAuth amsg = {PKT_AUTH, {0}, htonl(session_id), my_nonce, is_rk, {0}};
            memcpy(amsg.cookie, msg->cookie, 32);
            
            uint8_t transcript_ad[44];
            memcpy(transcript_ad, &amsg.session_id, 4); memcpy(transcript_ad + 4, &amsg.client_nonce, 8); memcpy(transcript_ad + 12, amsg.cookie, 32);
            uint8_t cp_nonce[12] = {0}; memcpy(cp_nonce, &my_nonce, 8);
            cp_aead_encrypt(cp_enc_key, my_eph_pub, 32, transcript_ad, 44, cp_nonce, amsg.ciphertext, amsg.ciphertext + 32);

            send_mimic_quic(sock, &amsg, sizeof(amsg), PKT_AUTH, &p_addr);
            last_tx_time = now_sec;
        }
        else if (flag == PKT_AUTH && n >= (int)sizeof(MsgAuth)) {
            if (is_initiator) continue;
            MsgAuth* msg = (MsgAuth*)buf;
            if (ntohl(msg->session_id) != session_id || seen_nonces.exists(msg->client_nonce)) continue;

            uint8_t c1[32], c2[32];
            generate_cookie(cookie_secret, src.sin_addr.s_addr, msg->client_nonce, current_window, c1);
            generate_cookie(cookie_secret, src.sin_addr.s_addr, msg->client_nonce, current_window - 1, c2);
            if (CRYPTO_memcmp(c1, msg->cookie, 32) != 0 && CRYPTO_memcmp(c2, msg->cookie, 32) != 0) continue;

            uint8_t peer_eph_pub[32];
            uint8_t transcript_ad[44];
            memcpy(transcript_ad, &msg->session_id, 4); memcpy(transcript_ad + 4, &msg->client_nonce, 8); memcpy(transcript_ad + 12, msg->cookie, 32);
            uint8_t cp_nonce[12] = {0}; memcpy(cp_nonce, &msg->client_nonce, 8);

            if (!cp_aead_decrypt(cp_enc_key, msg->ciphertext, 32, transcript_ad, 44, cp_nonce, msg->ciphertext + 32, peer_eph_pub)) continue; 

            seen_nonces.add(msg->client_nonce, now_sec);
            if (msg->is_rekey == 0) reset_bpf_replay_state(obj, session_id, peer_ip_net, local_ip_net, p_mac);

            EVP_PKEY *pk = EVP_PKEY_Q_keygen(NULL, NULL, "X25519"); size_t pk_len = 32; 
            EVP_PKEY_get_raw_private_key(pk, my_eph_priv, &pk_len); EVP_PKEY_get_raw_public_key(pk, my_eph_pub, &pk_len); EVP_PKEY_free(pk);

            uint8_t eph_ss[32], session_master[32], tx_key[32], rx_key[32];
            do_ecdh(my_eph_priv, peer_eph_pub, eph_ss);
            derive_kdf(early_secret, 32, eph_ss, "Tachyon-Session-Master", session_master);
            derive_kdf(session_master, 32, (uint8_t*)"", "Tachyon-Srv-TX", tx_key);
            derive_kdf(session_master, 32, (uint8_t*)"", "Tachyon-Cli-TX", rx_key);
            
            inject_keys_to_kernel(obj, session_id, tx_key, rx_key);
            
            uint64_t srv_nonce; RAND_bytes((unsigned char*)&srv_nonce, 8);
            MsgFinish fmsg = {PKT_FINISH, {0}, htonl(session_id), srv_nonce, {0}};
            uint8_t f_ad[12]; memcpy(f_ad, &fmsg.session_id, 4); memcpy(f_ad + 4, &srv_nonce, 8);
            uint8_t f_nonce[12] = {0}; memcpy(f_nonce, &srv_nonce, 8);
            
            cp_aead_encrypt(cp_enc_key, my_eph_pub, 32, f_ad, 12, f_nonce, fmsg.ciphertext, fmsg.ciphertext + 32);
            
            send_mimic_quic(sock, &fmsg, sizeof(fmsg), PKT_FINISH, &src);
            last_tx_time = now_sec;

            OPENSSL_cleanse(eph_ss, 32); OPENSSL_cleanse(my_eph_priv, 32); OPENSSL_cleanse(session_master, 32);
            std::cout << " [CP] Handshake/Rekey Complete. Datapath is armed!\n";
        }
        else if (flag == PKT_FINISH && n >= (int)sizeof(MsgFinish)) {
            if (!is_initiator || !handshake_active) continue;
            MsgFinish* msg = (MsgFinish*)buf;
            if (ntohl(msg->session_id) != session_id) continue;
            
            uint8_t peer_eph_pub[32];
            uint8_t f_ad[12]; memcpy(f_ad, &msg->session_id, 4); memcpy(f_ad + 4, &msg->server_nonce, 8);
            uint8_t f_nonce[12] = {0}; memcpy(f_nonce, &msg->server_nonce, 8);

            if (!cp_aead_decrypt(cp_enc_key, msg->ciphertext, 32, f_ad, 12, f_nonce, msg->ciphertext + 32, peer_eph_pub)) continue;

            uint8_t eph_ss[32], session_master[32], tx_key[32], rx_key[32];
            do_ecdh(my_eph_priv, peer_eph_pub, eph_ss);
            derive_kdf(early_secret, 32, eph_ss, "Tachyon-Session-Master", session_master);
            derive_kdf(session_master, 32, (uint8_t*)"", "Tachyon-Cli-TX", tx_key);
            derive_kdf(session_master, 32, (uint8_t*)"", "Tachyon-Srv-TX", rx_key);

            inject_keys_to_kernel(obj, session_id, tx_key, rx_key);
            
            handshake_active = false; first_boot = false; last_rekey_success = now_sec;
            std::cout << "  [CP] Handshake/Rekey Complete. Datapath is armed!\n";

            OPENSSL_cleanse(eph_ss, 32); OPENSSL_cleanse(my_eph_priv, 32); OPENSSL_cleanse(session_master, 32);
        }
    }
    close(sock); free_crypto_globals();
}

void command_up(const std::string& conf_file) {
    auto conf = parse_config(conf_file);
    std::string name = tunnel_name_from_conf(conf_file);
    std::string BPF_DIR = BASE_BPF_DIR + "/" + name;
    struct stat st; if (stat(BPF_DIR.c_str(), &st) == 0) { std::cout << "Tunnel exists.\n"; return; }

    std::string v_in = "t_" + name + "_in", v_out = "t_" + name + "_out";
    std::string phys_if = conf["PhysIface"]; if (phys_if.empty()) phys_if = conf["PhysicalInterface"];
    std::string local_ip = conf["LocalIP"]; if (local_ip.empty()) local_ip = conf["LocalPhysicalIP"];
    std::string peer_ip = conf["Endpoint"]; if (peer_ip.empty()) peer_ip = conf["Peer.EndpointIP"];
    std::string peer_mac = conf["PeerMAC"]; if (peer_mac.empty()) peer_mac = conf["Peer.EndpointMAC"];
    std::string virt_ip = conf["VirtualIP"]; if (virt_ip.empty()) virt_ip = conf["Interface.VirtualIP"];
    std::string inner_ip = conf["InnerIP"]; if (inner_ip.empty()) inner_ip = conf["Peer.InnerIP"];
    
    std::string secret = conf["PresharedKey"]; if (secret.empty()) secret = conf["Secret"]; 
    std::string priv_key = conf["PrivateKey"]; std::string peer_pub = conf["PeerPublicKey"];
    int port = 5555; if (conf.count("ListenPort")) port = std::stoi(conf["ListenPort"]);

    if(priv_key.empty() || peer_pub.empty()) { std::cerr << "Fatal: PrivateKey and PeerPublicKey are required!\n"; return; }

    std::cout << "\n Tachyon: Creating Data Plane...\n";
    if (!run_cmd_check("ip link add " + v_in + " type veth peer name " + v_out)) return;
    run_cmd("ip link set dev " + v_in + " mtu 1420"); run_cmd("ip link set dev " + v_out + " mtu 1420");
    run_cmd("ip link set dev " + v_in + " arp off"); run_cmd("ip link set dev " + v_out + " arp off");
    run_cmd("ip addr add " + virt_ip + " peer " + inner_ip + " dev " + v_in);
    run_cmd("ip link set dev " + v_in + " up"); run_cmd("ip link set dev " + v_out + " up");
    run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1");
    run_cmd("sysctl -w net.ipv4.conf." + v_in + ".rp_filter=0 >/dev/null 2>&1");

    unsigned int p_idx = if_nametoindex(phys_if.c_str()), o_idx = if_nametoindex(v_out.c_str()), i_idx = if_nametoindex(v_in.c_str());

    char exe[PATH_MAX]; ssize_t l = readlink("/proc/self/exe", exe, sizeof(exe)-1);
    std::string base = std::string(exe, l); base = base.substr(0, base.find_last_of('/'));
    struct bpf_object *obj = bpf_object__open_file((base + "/../src/xdp_core.o").c_str(), NULL);
    if (bpf_object__load(obj)) exit(1);

    run_cmd("mkdir -p " + BPF_DIR); bpf_object__pin_maps(obj, BPF_DIR.c_str());

    int conf_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "config_map"));
    uint32_t zero = 0; global_config g{}; g.listen_port_net = htons(port); bpf_map_update_elem(conf_fd, &zero, &g, BPF_ANY);

    int tx_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "tx_port"));
    uint32_t k0 = 0, k1 = 1; bpf_map_update_elem(tx_fd, &k0, &o_idx, BPF_ANY); bpf_map_update_elem(tx_fd, &k1, &p_idx, BPF_ANY);

    int sess_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "session_map"));
    uint32_t session_id = 1; session_ctx sess{};
    inet_pton(AF_INET, peer_ip.c_str(), &sess.peer_ip);
    struct in_addr la; inet_pton(AF_INET, local_ip.c_str(), &la); sess.local_ip = la.s_addr;
    parse_mac(peer_mac, sess.peer_mac);
    bpf_map_update_elem(sess_fd, &session_id, &sess, BPF_ANY);

    int ip_sess_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "ip_to_session_map"));
    uint32_t inner_net; inet_pton(AF_INET, inner_ip.c_str(), &inner_net);
    bpf_map_update_elem(ip_sess_fd, &inner_net, &session_id, BPF_ANY);

    bpf_link__pin(bpf_program__attach_xdp(bpf_object__find_program_by_name(obj, "xdp_rx_path"), p_idx), (BPF_DIR + "/rx").c_str());
    bpf_link__pin(bpf_program__attach_xdp(bpf_object__find_program_by_name(obj, "xdp_tx_path"), o_idx), (BPF_DIR + "/tx").c_str());
    bpf_link__pin(bpf_program__attach_xdp(bpf_object__find_program_by_name(obj, "xdp_dummy"), i_idx), (BPF_DIR + "/dummy").c_str());

    std::cout << " Datapath is UP!\n";
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    
    run_control_plane(obj, secret, priv_key, peer_pub, port, session_id, peer_ip, local_ip, peer_mac);
    std::cout << "\n[!] Daemon stopped. XDP Datapath alive.\n";
}

void command_down(const std::string& conf_file) {
    std::string name = tunnel_name_from_conf(conf_file);
    run_cmd("ip link del t_" + name + "_in 2>/dev/null");
    run_cmd("rm -rf " + BASE_BPF_DIR + "/" + name);
    std::cout << " Cleaned up.\n";
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    std::string cmd = argv[1];
    if (cmd == "genkey") {
        EVP_PKEY *pk = EVP_PKEY_Q_keygen(NULL, NULL, "X25519"); uint8_t p[32]; size_t l = 32;
        EVP_PKEY_get_raw_private_key(pk, p, &l); 
        for(int i=0; i<32; i++) printf("%02x", p[i]); 
        printf("\n");
        OPENSSL_cleanse(p, 32); EVP_PKEY_free(pk); return 0;
    }
    if (cmd == "pubkey") {
        std::string priv_hex; std::cin >> priv_hex; uint8_t priv[32]; hex2bin(priv_hex, priv);
        EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
        uint8_t pub[32]; size_t len = 32; EVP_PKEY_get_raw_public_key(pk, pub, &len);
        for(int i=0; i<32; i++) printf("%02x", pub[i]); 
        printf("\n");
        OPENSSL_cleanse(priv, 32); OPENSSL_cleanse(pub, 32); EVP_PKEY_free(pk); return 0;
    }
    if (argc < 3) return 1;
    if (cmd == "up") command_up(argv[2]);
    else if (cmd == "down") command_down(argv[2]);
    return 0;
}