#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/tcp.h> 
#include <netinet/in.h>

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif
#ifndef IP_DF
#define IP_DF       0x4000
#endif
#ifndef ETH_ALEN
#define ETH_ALEN    6
#endif

#define DEBUG 1

#if DEBUG
#define tachyon_dbg(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define tachyon_dbg(fmt, ...)
#endif

enum { EVENT_REPLAY_DROP = 0, EVENT_CRYPTO_ERR = 1 };

#define OUTER_ETH_SIZE 14
#define OUTER_IP_SIZE  20
#define OUTER_UDP_SIZE 8
#define GHOST_HDR_SIZE 20   
#define AEAD_TAG_LEN   16
#define TX_HEAD_ADJUST 48   
#define MAX_SESSIONS   256
#define REPLAY_WINDOW  256
#define MAX_TX_CPUS 64
#define TARGET_MSS 1360

struct pkt_stats {
    __u64 rx_pkts;
    __u64 rx_bytes;
    __u64 tx_pkts;
    __u64 tx_bytes;
    __u64 replay_drops;
    __u64 crypto_errors;
    __u64 iv_reuse_drops;
};

struct ghost_hdr {
    __u8  quic_flags;
    __u8  pad[3];  
    __u32 session_id;
    __u64 seq;
    __u32 nonce_salt;
} __attribute__((packed));

struct global_config {
    __u16 listen_port_net;
    __u8  mimicry_type;
    __u8  pad;
};

struct session_ctx {
    struct bpf_spin_lock replay_lock;
    __u32 peer_ip;
    __u32 local_ip;
    __u8  peer_mac[6];
    __u8  pad1[2];
    __u32 pad2_align;
    __u64 rx_highest_seq[MAX_TX_CPUS];
    __u64 rx_bitmap[MAX_TX_CPUS][4];
};

struct key_init_data {
    __u32 session_id;
    __u8  tx_key[32];
    __u8  rx_key[32];
};

struct replay_event {
    int type;
    __u32 session_id;
    __u64 seq;
    __u64 timestamp;
};

/* ── MAPS ── */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct global_config); } config_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, MAX_SESSIONS); __type(key, __u32); __type(value, struct session_ctx); } session_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, MAX_SESSIONS); __type(key, __u32); __type(value, __u64); } session_tx_seq SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct pkt_stats); } stats_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 1024); __type(key, __u32); __type(value, __u32); } ip_to_session_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_DEVMAP); __uint(max_entries, 4); __type(key, __u32); __type(value, __u32); } tx_port SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct key_init_data); } key_init_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(key_size, sizeof(int)); __uint(value_size, sizeof(int)); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } cp_ratelimit_map SEC(".maps");
    
extern int bpf_ghost_encrypt(struct xdp_md *ctx, __u32 session_id) __ksym;
extern int bpf_ghost_decrypt(struct xdp_md *ctx, __u32 session_id) __ksym;
extern int bpf_ghost_set_key(__u32 session_id, __u8 *tx_key, __u32 tx_key__sz, __u8 *rx_key, __u32 rx_key__sz) __ksym;

static __always_inline void calc_ipv4_csum(struct iphdr *iph) {
    iph->check = 0;
    __u32 csum = 0;
    __u16 *ip_ptr = (__u16 *)iph;
    #pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
        csum += ip_ptr[i];
    }
    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    iph->check = ~(__u16)csum;
}

static __always_inline void emit_event(struct xdp_md *ctx, int type, __u32 session_id, __u64 seq) {
    struct replay_event evt = { .type = type, .session_id = session_id, .seq = seq, .timestamp = bpf_ktime_get_ns() };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
}

static __always_inline void update_tcp_csum(__u16 *csum, __be16 old_val, __be16 new_val) {
    __u32 res;
    res = (~((__u32)*csum) & 0xffff) + (~((__u32)old_val) & 0xffff) + new_val;
    res = (res & 0xffff) + (res >> 16);
    res = (res & 0xffff) + (res >> 16);
    *csum = ~(__u16)res;
}

static __always_inline void tcp_mss_clamp(struct iphdr *iph, void *data_end) {
    if (iph->protocol != IPPROTO_TCP) return;
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end) return;
    if (!tcph->syn) return;
    int tcp_hlen = tcph->doff * 4;
    if (tcp_hlen <= sizeof(struct tcphdr)) return; 

    __u8 *opt = (__u8 *)(tcph + 1);
    #pragma unroll
    for (int i = 0; i < 40; i++) { 
        if ((void *)(opt + 1) > data_end) break;
        if (*opt == 0) break;
        if (*opt == 1) { opt++; continue; }
        
        if ((void *)(opt + 2) > data_end) break;
        __u8 len = *(opt + 1);
        if (len < 2) break;
        
        if (*opt == 2 && len == 4) {
            if ((void *)(opt + 4) > data_end) break;
            __be16 *mss_ptr = (__be16 *)(opt + 2);
            __be16 old_mss = *mss_ptr;
            __u16 mss = bpf_ntohs(old_mss);
            
            if (mss > TARGET_MSS) {
                __be16 new_mss = bpf_htons(TARGET_MSS);
                *mss_ptr = new_mss;
                update_tcp_csum(&tcph->check, old_mss, new_mss);
            }
            break;
        }
        opt += len;
    }
}

// =======================
// TX PATH (Virtual -> Physical)
// =======================
SEC("xdp")
int xdp_tx_path(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph_inner = (void *)(eth + 1);
    if ((void *)(iph_inner + 1) > data_end) return XDP_PASS;

    tcp_mss_clamp(iph_inner, data_end);

    __u32 *session_id_p = bpf_map_lookup_elem(&ip_to_session_map, &iph_inner->daddr);
    if (!session_id_p) return XDP_PASS;
    __u32 session_id = *session_id_p;

    struct session_ctx *sess = bpf_map_lookup_elem(&session_map, &session_id);
    if (!sess) return XDP_DROP;

    __u64 *tx_seq_ptr = bpf_map_lookup_elem(&session_tx_seq, &session_id);
    if (!tx_seq_ptr) return XDP_DROP;
    
    __u64 local_seq = *tx_seq_ptr;
    *tx_seq_ptr = local_seq + 1;
    __u32 cpu_id = bpf_get_smp_processor_id();
    __u64 final_seq = ((__u64)cpu_id << 48) | (local_seq & 0xFFFFFFFFFFFFULL);

    __u8 src_mac[6];
    __builtin_memcpy(src_mac, eth->h_source, 6);

    __u32 zero = 0;
    struct global_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
    __u16 tport = cfg ? cfg->listen_port_net : bpf_htons(5555);
    __u8 mimic_type = cfg ? cfg->mimicry_type : 1; // 1 = QUIC Mimicry

    // 🔥 Mimicry V2: Packet Size Shaping (Bimodal Distribution)
    int current_inner_len = data_end - data;
    __u16 pad_len = 0;

    if (mimic_type == 1) {
        int max_pad = 1490 - (current_inner_len + TX_HEAD_ADJUST + AEAD_TAG_LEN);
        if (max_pad > 0 && max_pad < 1500) {
            __u32 rand_val = bpf_get_prandom_u32();
            __u32 prob = rand_val % 100;
            
            if (prob < 60) {
                // 60% مواقع: پکت را تا سقف MTU پر کن (شبیه‌سازی دانلود فایل)
                pad_len = max_pad - (rand_val & 0x0F); 
            } else if (prob < 90) {
                // 30% مواقع: پکت را کوچک نگه دار (شبیه‌سازی ACK های QUIC)
                pad_len = rand_val & 0x1F; // بین 0 تا 31 بایت
            } else {
                // 10% مواقع: سایز کاملاً رندوم
                pad_len = rand_val % max_pad;
            }
            
            // Safety bounds for verifier
            if (pad_len > max_pad) pad_len = max_pad;
            pad_len &= 0x7FF; 
        }
    }

    if (bpf_xdp_adjust_tail(ctx, AEAD_TAG_LEN + pad_len)) return XDP_DROP;
    if (bpf_xdp_adjust_head(ctx, -(int)TX_HEAD_ADJUST)) return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data + OUTER_ETH_SIZE + OUTER_IP_SIZE + OUTER_UDP_SIZE + GHOST_HDR_SIZE > data_end) {
        return XDP_DROP;
    }

    struct ethhdr *oeth = data;
    struct iphdr *oip = data + OUTER_ETH_SIZE;
    struct udphdr *oudp = data + OUTER_ETH_SIZE + OUTER_IP_SIZE;
    struct ghost_hdr *gh = data + OUTER_ETH_SIZE + OUTER_IP_SIZE + OUTER_UDP_SIZE;

    // 🔥 Mimicry V2: Fake QUIC Header & CID Entropy
    if (mimic_type == 1) {
        // فلگ‌های QUIC (Short Header): 0x40 ثابت + 0x20 (Spin Bit رندوم) + 0x03 (Length رندوم)
        __u8 spin_bit = (bpf_get_prandom_u32() & 1) << 5;
        __u8 pn_len = bpf_get_prandom_u32() & 0x03;
        gh->quic_flags = 0x40 | spin_bit | pn_len;

        // تولید Connection ID فیک با رندوم کردن بایت‌های پدینگ
        __u32 cid_entropy = bpf_get_prandom_u32();
        gh->pad[0] = cid_entropy & 0xFF;
        gh->pad[1] = (cid_entropy >> 8) & 0xFF;
        gh->pad[2] = (cid_entropy >> 16) & 0xFF;
    } else {
        gh->quic_flags = 0x40;
        gh->pad[0] = gh->pad[1] = gh->pad[2] = 0;
    }

    gh->session_id = bpf_htonl(session_id);
    gh->seq = bpf_cpu_to_be64(final_seq);
    gh->nonce_salt = bpf_get_prandom_u32();

    __builtin_memcpy(oeth->h_dest, sess->peer_mac, 6);
    __builtin_memcpy(oeth->h_source, src_mac, 6);
    oeth->h_proto = bpf_htons(ETH_P_IP);

    oip->version = 4; oip->ihl = 5; oip->tos = 0;
    oip->tot_len = bpf_htons(data_end - (void *)oip);
    oip->id = 0; oip->frag_off = bpf_htons(IP_DF);
    oip->ttl = 64; oip->protocol = IPPROTO_UDP;
    oip->saddr = sess->local_ip;
    oip->daddr = sess->peer_ip;
    calc_ipv4_csum(oip);

    oudp->source = tport;
    oudp->dest = tport;
    oudp->len = bpf_htons(data_end - (void *)oudp);
    oudp->check = 0;

    if (bpf_ghost_encrypt(ctx, session_id) != 0) {
        return XDP_DROP;
    }

    struct pkt_stats *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (stats) {
        stats->tx_pkts++;
        stats->tx_bytes += data_end - data;
    }

    return bpf_redirect_map(&tx_port, 1, 0);
}

// =======================
// RX PATH (Physical -> Virtual)
// =======================
SEC("xdp")
int xdp_rx_path(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u32 zero = 0;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udph = (void *)(iph + 1);
    if ((void *)(udph + 1) > data_end) return XDP_PASS;

    struct global_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (cfg && udph->dest != cfg->listen_port_net) return XDP_PASS;

    struct ghost_hdr *gh = (void *)(udph + 1);
    if ((void *)(gh + 1) > data_end) return XDP_DROP;

    // Control Plane Check
    if ((gh->quic_flags & 0xF0) == 0xC0) { 
        __u32 src_ip = iph->saddr; 
        __u64 now = bpf_ktime_get_ns(); 
        __u64 *last_ts = bpf_map_lookup_elem(&cp_ratelimit_map, &src_ip);
        if (last_ts) {
            if (now - *last_ts < 1000000ULL) return XDP_DROP;
            *last_ts = now; 
            return XDP_PASS;
        } else { 
            bpf_map_update_elem(&cp_ratelimit_map, &src_ip, &now, BPF_ANY);
            return XDP_PASS;
        }
    }

    __u32 session_id = bpf_ntohl(gh->session_id);
    if (session_id == 0 || session_id >= MAX_SESSIONS) return XDP_DROP;

    struct session_ctx *sess = bpf_map_lookup_elem(&session_map, &session_id);
    if (!sess) return XDP_DROP;

    __u64 raw_seq = bpf_be64_to_cpu(gh->seq);
    __u32 sender_cpu = (raw_seq >> 48) & (MAX_TX_CPUS - 1);
    __u64 pkt_seq = raw_seq & 0xFFFFFFFFFFFFULL;

    /* ── Phase 1: Replay check ── */
    bpf_spin_lock(&sess->replay_lock);
    __u64 drop = 0;
    if (pkt_seq <= sess->rx_highest_seq[sender_cpu]) {
        __u64 delta = sess->rx_highest_seq[sender_cpu] - pkt_seq;
        if (delta >= REPLAY_WINDOW) { drop = 1; } 
        else {
            __u64 word = delta / 64;
            __u64 bit  = delta % 64;
            __u64 mask = 1ULL << bit;
            if (word == 0 && (sess->rx_bitmap[sender_cpu][0] & mask)) drop = 1;
            else if (word == 1 && (sess->rx_bitmap[sender_cpu][1] & mask)) drop = 1;
            else if (word == 2 && (sess->rx_bitmap[sender_cpu][2] & mask)) drop = 1;
            else if (word == 3 && (sess->rx_bitmap[sender_cpu][3] & mask)) drop = 1;
        }
    }
    bpf_spin_unlock(&sess->replay_lock);
    if (drop) return XDP_DROP;

    /* ── Phase 2: Decrypt ── */
    if (bpf_ghost_decrypt(ctx, session_id) != 0) return XDP_DROP;

    /* ── Phase 3: Commit Bitmap ── */
    bpf_spin_lock(&sess->replay_lock);
    if (pkt_seq > sess->rx_highest_seq[sender_cpu]) {
        __u64 delta = pkt_seq - sess->rx_highest_seq[sender_cpu];
        if (delta >= REPLAY_WINDOW) {
            sess->rx_bitmap[sender_cpu][0] = 0; sess->rx_bitmap[sender_cpu][1] = 0;
            sess->rx_bitmap[sender_cpu][2] = 0; sess->rx_bitmap[sender_cpu][3] = 0;
        } else {
            __u64 w0 = sess->rx_bitmap[sender_cpu][0], w1 = sess->rx_bitmap[sender_cpu][1];
            __u64 w2 = sess->rx_bitmap[sender_cpu][2], w3 = sess->rx_bitmap[sender_cpu][3];
            #pragma unroll
            for (int i = 0; i < 3; i++) {
                if (delta >= 64) {
                    w3 = w2; w2 = w1; w1 = w0; w0 = 0;
                    delta -= 64;
                }
            }
            if (delta > 0) {
                w3 = (w3 << delta) | (w2 >> (64 - delta));
                w2 = (w2 << delta) | (w1 >> (64 - delta));
                w1 = (w1 << delta) | (w0 >> (64 - delta));
                w0 = (w0 << delta);
            }
            sess->rx_bitmap[sender_cpu][0] = w0; sess->rx_bitmap[sender_cpu][1] = w1;
            sess->rx_bitmap[sender_cpu][2] = w2; sess->rx_bitmap[sender_cpu][3] = w3;
        }
        sess->rx_highest_seq[sender_cpu] = pkt_seq;
        sess->rx_bitmap[sender_cpu][0] |= 1ULL;
    } else {
        __u64 delta = sess->rx_highest_seq[sender_cpu] - pkt_seq;
        __u64 word = delta / 64; __u64 bit  = delta % 64; __u64 mask = 1ULL << bit;
        __u8 dup = 0;
        if (word == 0) { if (sess->rx_bitmap[sender_cpu][0] & mask) dup = 1; else sess->rx_bitmap[sender_cpu][0] |= mask; }
        else if (word == 1) { if (sess->rx_bitmap[sender_cpu][1] & mask) dup = 1; else sess->rx_bitmap[sender_cpu][1] |= mask; }
        else if (word == 2) { if (sess->rx_bitmap[sender_cpu][2] & mask) dup = 1; else sess->rx_bitmap[sender_cpu][2] |= mask; }
        else if (word == 3) { if (sess->rx_bitmap[sender_cpu][3] & mask) dup = 1; else sess->rx_bitmap[sender_cpu][3] |= mask; }
        if (dup) { bpf_spin_unlock(&sess->replay_lock); return XDP_DROP; }
    }
    bpf_spin_unlock(&sess->replay_lock);

    /* ── Phase 4: Strip Outer Headers and Dynamic Pad Trim ── */
    if (bpf_xdp_adjust_head(ctx, TX_HEAD_ADJUST)) return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;

    struct iphdr *decrypted_iph = (void *)(eth + 1);
    if ((void *)(decrypted_iph + 1) > data_end) return XDP_DROP;

    __u32 inner_ip_len = bpf_ntohs(decrypted_iph->tot_len);
    if (inner_ip_len < 20 || inner_ip_len > 1500) return XDP_DROP;

    int current_frame_len = (int)(data_end - data);
    int expected_frame_len = sizeof(struct ethhdr) + inner_ip_len;
    int trim_amount = current_frame_len - expected_frame_len;

    if (trim_amount < AEAD_TAG_LEN || trim_amount > 1500) {
        return XDP_DROP;
    }

    if (bpf_xdp_adjust_tail(ctx, -trim_amount)) return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;
    
    decrypted_iph = (void *)(eth + 1);
    if ((void *)(decrypted_iph + 1) <= data_end) {
        tcp_mss_clamp(decrypted_iph, data_end);
    }

    __builtin_memset(eth->h_dest, 0xff, ETH_ALEN);
    __builtin_memset(eth->h_source, 0x00, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);

    struct pkt_stats *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (stats) {
        stats->rx_pkts++;
        stats->rx_bytes += data_end - data;
    }

    return bpf_redirect_map(&tx_port, 0, 0);
}

SEC("syscall")
int ghost_key_init(void *ctx) {
    __u32 zero = 0;
    struct key_init_data *kid = bpf_map_lookup_elem(&key_init_map, &zero);
    if (!kid) return -1;
    return bpf_ghost_set_key(kid->session_id, kid->tx_key, 32, kid->rx_key, 32);
}

SEC("xdp")
int xdp_dummy(struct xdp_md *ctx) { return XDP_PASS; }
char _license[] SEC("license") = "GPL";