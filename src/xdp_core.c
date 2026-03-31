/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Tachyon XDP Tunnel - Data Plane
 *
 * Two XDP programs implementing the fast-path packet processing:
 *   xdp_tx_path  - Encapsulate + encrypt outbound packets (virtual -> physical)
 *   xdp_rx_path  - Decrypt + decapsulate inbound packets (physical -> virtual)
 *
 * Plus a syscall program for key injection from userspace:
 *   ghost_key_init - Loads derived session keys into the kernel crypto module
 *
 * Design principles:
 *   - Zero-copy: all transforms happen in-place on the XDP buffer
 *   - Per-CPU: sequence numbers partitioned by CPU ID, no cross-CPU locks
 *   - Unified replay critical section: check + decrypt + commit under one lock
 *   - Comprehensive statistics for every drop/error path
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <netinet/in.h>

#include "common.h"

/* ══════════════════════════════════════════════════════════════════════════
 * Protocol Constants (fallbacks if not in system headers)
 * ══════════════════════════════════════════════════════════════════════════ */

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IP_DF
#define IP_DF 0x4000
#endif
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * Debug Logging
 * ══════════════════════════════════════════════════════════════════════════ */

#ifdef TACHYON_DEBUG
#define tachyon_dbg(fmt, ...) bpf_printk("tachyon: " fmt, ##__VA_ARGS__)
#else
#define tachyon_dbg(fmt, ...)
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * BPF Maps
 * ══════════════════════════════════════════════════════════════════════════ */

/* Global tunnel configuration (listen port, mimicry mode) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tachyon_config);
} config_map SEC(".maps");

/* Per-session state: peer addresses, replay protection window */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, TACHYON_MAX_SESSIONS);
	__type(key, __u32);
	__type(value, struct tachyon_session);
} session_map SEC(".maps");

/* Per-CPU TX sequence counters (lock-free increment) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, TACHYON_MAX_SESSIONS);
	__type(key, __u32);
	__type(value, __u64);
} session_tx_seq SEC(".maps");

/* Per-CPU packet and error statistics */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tachyon_stats);
} stats_map SEC(".maps");

/* Virtual IP -> session ID lookup (LRU for dynamic peers) */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, TACHYON_MAX_IP_SESSIONS);
	__type(key, __u32);
	__type(value, __u32);
} ip_to_session_map SEC(".maps");

/* Device map for XDP_REDIRECT targets: [0]=veth, [1]=physical */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} tx_port SEC(".maps");

/* Staging area for key injection from userspace */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tachyon_key_init);
} key_init_map SEC(".maps");

/* Perf event buffer for error/event reporting to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

/* Control plane packet rate limiter (per source IP) */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, TACHYON_MAX_RATELIMIT);
	__type(key, __u32);
	__type(value, __u64);
} cp_ratelimit_map SEC(".maps");

/* ══════════════════════════════════════════════════════════════════════════
 * External Kfuncs (provided by tachyon-crypto kernel module)
 * ══════════════════════════════════════════════════════════════════════════ */

extern int bpf_ghost_encrypt(struct xdp_md *ctx, __u32 session_id) __ksym;
extern int bpf_ghost_decrypt(struct xdp_md *ctx, __u32 session_id) __ksym;
extern int bpf_ghost_set_key(__u32 session_id,
			     __u8 *tx_key, __u32 tx_key__sz,
			     __u8 *rx_key, __u32 rx_key__sz) __ksym;

/* ══════════════════════════════════════════════════════════════════════════
 * Inline Helpers
 * ══════════════════════════════════════════════════════════════════════════ */

/* Compute IPv4 header checksum via incremental fold */
static __always_inline void calc_ipv4_csum(struct iphdr *iph)
{
	__u32 csum = 0;
	__u16 *p = (__u16 *)iph;

	iph->check = 0;

	#pragma unroll
	for (int i = 0; i < (int)(sizeof(struct iphdr) / 2); i++)
		csum += p[i];

	csum = (csum >> 16) + (csum & 0xffff);
	csum += (csum >> 16);
	iph->check = ~(__u16)csum;
}

/* Emit a structured event to the perf ring buffer */
static __always_inline void emit_event(struct xdp_md *ctx, __u32 type,
					__u32 session_id, __u64 seq)
{
	struct tachyon_event evt = {
		.type         = type,
		.session_id   = session_id,
		.seq          = seq,
		.timestamp_ns = bpf_ktime_get_ns(),
	};
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
}

/* Incremental TCP checksum update for a single 16-bit field change */
static __always_inline void update_tcp_csum(__u16 *csum, __be16 old_val,
					    __be16 new_val)
{
	__u32 res;

	res = (~((__u32)*csum) & 0xffff) + (~((__u32)old_val) & 0xffff) + new_val;
	res = (res & 0xffff) + (res >> 16);
	res = (res & 0xffff) + (res >> 16);
	*csum = ~(__u16)res;
}

/*
 * Clamp TCP MSS option to TACHYON_TARGET_MSS on SYN packets.
 * This hides tunnel overhead from TCP path MTU discovery, preventing
 * fragmentation of inner packets.
 */
static __always_inline void tcp_mss_clamp(struct iphdr *iph, void *data_end)
{
	struct tcphdr *tcph;
	int tcp_hlen;
	__u8 *opt;

	if (iph->protocol != IPPROTO_TCP)
		return;

	tcph = (void *)iph + (iph->ihl * 4);
	if ((void *)(tcph + 1) > data_end)
		return;

	if (!tcph->syn)
		return;

	tcp_hlen = tcph->doff * 4;
	if (tcp_hlen <= (int)sizeof(struct tcphdr))
		return;

	opt = (__u8 *)(tcph + 1);

	#pragma unroll
	for (int i = 0; i < 40; i++) {
		if ((void *)(opt + 1) > data_end)
			break;
		if (*opt == 0)   /* End of options */
			break;
		if (*opt == 1) { /* NOP */
			opt++;
			continue;
		}

		if ((void *)(opt + 2) > data_end)
			break;

		__u8 len = *(opt + 1);
		if (len < 2)
			break;

		/* MSS option: kind=2, length=4 */
		if (*opt == 2 && len == 4) {
			if ((void *)(opt + 4) > data_end)
				break;

			__be16 *mss_ptr = (__be16 *)(opt + 2);
			__be16 old_mss = *mss_ptr;

			if (bpf_ntohs(old_mss) > TACHYON_TARGET_MSS) {
				__be16 new_mss = bpf_htons(TACHYON_TARGET_MSS);
				*mss_ptr = new_mss;
				update_tcp_csum(&tcph->check, old_mss, new_mss);
			}
			break;
		}
		opt += len;
	}
}

/* Retrieve per-CPU stats pointer (map lookup with zero key) */
static __always_inline struct tachyon_stats *get_stats(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&stats_map, &zero);
}

/* Retrieve global config pointer */
static __always_inline struct tachyon_config *get_config(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&config_map, &zero);
}

/* ══════════════════════════════════════════════════════════════════════════
 * TX PATH: Virtual Interface -> Physical NIC
 *
 * Packet flow:
 *   1. Validate inner Ethernet + IPv4
 *   2. Clamp TCP MSS on SYN packets
 *   3. Lookup session by destination IP
 *   4. Generate per-CPU sequence number
 *   5. Apply QUIC mimicry padding (bimodal distribution)
 *   6. Prepend outer headers (ETH + IP + UDP + Ghost)
 *   7. Encrypt payload via kernel crypto module
 *   8. Redirect to physical NIC
 * ══════════════════════════════════════════════════════════════════════════ */

SEC("xdp")
int xdp_tx_path(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct tachyon_stats *stats = get_stats();

	/* --- Validate inner packet --- */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph_inner = (void *)(eth + 1);
	if ((void *)(iph_inner + 1) > data_end)
		return XDP_PASS;

	/* Clamp MSS before encapsulation to prevent inner fragmentation */
	tcp_mss_clamp(iph_inner, data_end);

	/* --- Session lookup by destination IP --- */
	__u32 *sid_p = bpf_map_lookup_elem(&ip_to_session_map, &iph_inner->daddr);
	if (!sid_p)
		return XDP_PASS;  /* Not a tunnel destination */
	__u32 session_id = *sid_p;

	struct tachyon_session *sess = bpf_map_lookup_elem(&session_map, &session_id);
	if (!sess) {
		if (stats) stats->rx_invalid_session++;
		return XDP_DROP;
	}

	/* --- Per-CPU sequence number generation --- */
	__u64 *tx_seq_ptr = bpf_map_lookup_elem(&session_tx_seq, &session_id);
	if (!tx_seq_ptr) {
		if (stats) stats->tx_headroom_errors++;
		return XDP_DROP;
	}

	__u64 local_seq = *tx_seq_ptr;
	*tx_seq_ptr = local_seq + 1;

	__u32 cpu_id = bpf_get_smp_processor_id();
	__u64 final_seq = ((__u64)cpu_id << TACHYON_SEQ_CPU_SHIFT) |
			  (local_seq & TACHYON_SEQ_NUM_MASK);

	/* Save source MAC before head adjustment overwrites it */
	__u8 src_mac[6];
	__builtin_memcpy(src_mac, eth->h_source, 6);

	/* --- Load global config --- */
	struct tachyon_config *cfg = get_config();
	__u16 tport  = cfg ? cfg->listen_port_net : bpf_htons(TACHYON_DEFAULT_PORT);
	__u8 mimicry = cfg ? cfg->mimicry_type : TACHYON_MIMICRY_QUIC;

	/* --- QUIC Mimicry: Bimodal packet-size shaping --- */
	int current_inner_len = data_end - data;
	__u16 pad_len = 0;

	if (mimicry == TACHYON_MIMICRY_QUIC) {
		int max_pad = TACHYON_TARGET_OUTER_LEN -
			      (current_inner_len + TACHYON_TX_HEAD_ADJUST + TACHYON_AEAD_TAG_LEN);

		if (max_pad > 0 && max_pad < TACHYON_MAX_FRAME_LEN) {
			__u32 rand_val = bpf_get_prandom_u32();
			__u32 prob = rand_val % 100;

			if (prob < TACHYON_PAD_FULL_THRESH) {
				/* 60%: Pad to near-MTU (mimic bulk transfer) */
				pad_len = max_pad - (rand_val & TACHYON_PAD_JITTER_MASK);
			} else if (prob < TACHYON_PAD_ACK_THRESH) {
				/* 30%: Small padding (mimic QUIC ACKs) */
				pad_len = rand_val & TACHYON_PAD_ACK_MAX;
			} else {
				/* 10%: Random size (break statistical patterns) */
				pad_len = rand_val % max_pad;
			}

			if (pad_len > (__u16)max_pad)
				pad_len = max_pad;
			pad_len &= TACHYON_PAD_MAX_BITS;
		}
	}

	/* --- Adjust buffer: add tail for AEAD tag + padding, prepend outer headers --- */
	if (bpf_xdp_adjust_tail(ctx, TACHYON_AEAD_TAG_LEN + pad_len)) {
		if (stats) stats->tx_headroom_errors++;
		return XDP_DROP;
	}
	if (bpf_xdp_adjust_head(ctx, -(int)TACHYON_TX_HEAD_ADJUST)) {
		if (stats) stats->tx_headroom_errors++;
		return XDP_DROP;
	}

	/* Re-derive pointers after buffer adjustment */
	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + TACHYON_OUTER_HDR_LEN > data_end) {
		if (stats) stats->tx_headroom_errors++;
		return XDP_DROP;
	}

	/* --- Construct outer headers --- */
	struct ethhdr          *oeth = data;
	struct iphdr           *oip  = data + TACHYON_ETH_HDR_LEN;
	struct udphdr          *oudp = data + TACHYON_ETH_HDR_LEN + TACHYON_IP_HDR_LEN;
	struct tachyon_ghost_hdr *gh = data + TACHYON_ETH_HDR_LEN + TACHYON_IP_HDR_LEN +
				       TACHYON_UDP_HDR_LEN;

	/* Ghost header: QUIC mimicry flags + session + sequence + nonce */
	if (mimicry == TACHYON_MIMICRY_QUIC) {
		__u8 spin_bit = (bpf_get_prandom_u32() & 1) << 5;
		__u8 pn_len   = bpf_get_prandom_u32() & TACHYON_QUIC_PN_LEN_MASK;
		gh->quic_flags = TACHYON_QUIC_FIXED_BIT | spin_bit | pn_len;

		/* Randomize padding bytes as fake QUIC Connection ID */
		__u32 cid_entropy = bpf_get_prandom_u32();
		gh->pad[0] = cid_entropy & 0xFF;
		gh->pad[1] = (cid_entropy >> 8) & 0xFF;
		gh->pad[2] = (cid_entropy >> 16) & 0xFF;
	} else {
		gh->quic_flags = TACHYON_QUIC_FIXED_BIT;
		gh->pad[0] = gh->pad[1] = gh->pad[2] = 0;
	}

	gh->session_id = bpf_htonl(session_id);
	gh->seq        = bpf_cpu_to_be64(final_seq);
	gh->nonce_salt = bpf_get_prandom_u32();

	/* Outer Ethernet */
	__builtin_memcpy(oeth->h_dest, sess->peer_mac, 6);
	__builtin_memcpy(oeth->h_source, src_mac, 6);
	oeth->h_proto = bpf_htons(ETH_P_IP);

	/* Outer IPv4 */
	oip->version  = 4;
	oip->ihl      = 5;
	oip->tos      = 0;
	oip->tot_len  = bpf_htons(data_end - (void *)oip);
	oip->id       = 0;
	oip->frag_off = bpf_htons(IP_DF);
	oip->ttl      = 64;
	oip->protocol = IPPROTO_UDP;
	oip->saddr    = sess->local_ip;
	oip->daddr    = sess->peer_ip;
	calc_ipv4_csum(oip);

	/* Outer UDP */
	oudp->source = tport;
	oudp->dest   = tport;
	oudp->len    = bpf_htons(data_end - (void *)oudp);
	oudp->check  = 0;

	/* --- Encrypt payload --- */
	if (bpf_ghost_encrypt(ctx, session_id) != 0) {
		if (stats) stats->tx_crypto_errors++;
		emit_event(ctx, TACHYON_EVT_CRYPTO_ERROR, session_id, final_seq);
		return XDP_DROP;
	}

	/* --- Update TX statistics --- */
	if (stats) {
		stats->tx_packets++;
		stats->tx_bytes += (data_end - data);
	}

	return bpf_redirect_map(&tx_port, TACHYON_TXPORT_PHYS, 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * RX PATH: Physical NIC -> Virtual Interface
 *
 * Packet flow:
 *   1. Validate outer ETH + IP + UDP headers
 *   2. Check destination port matches config
 *   3. Route control plane packets to userspace
 *   4. Unified critical section: replay check -> decrypt -> bitmap commit
 *   5. Strip outer headers and padding
 *   6. Clamp TCP MSS on decrypted SYN packets
 *   7. Redirect to virtual interface
 * ══════════════════════════════════════════════════════════════════════════ */

SEC("xdp")
int xdp_rx_path(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct tachyon_stats *stats = get_stats();

	/* --- Validate outer headers --- */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end || iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	struct udphdr *udph = (void *)(iph + 1);
	if ((void *)(udph + 1) > data_end)
		return XDP_PASS;

	/* Port filter: only process packets on our listen port */
	struct tachyon_config *cfg = get_config();
	if (cfg && udph->dest != cfg->listen_port_net)
		return XDP_PASS;

	struct tachyon_ghost_hdr *gh = (void *)(udph + 1);
	if ((void *)(gh + 1) > data_end) {
		if (stats) stats->rx_malformed++;
		return XDP_DROP;
	}

	/* --- Control plane packet routing --- */
	if ((gh->quic_flags & TACHYON_CP_FLAG_MASK) == TACHYON_CP_FLAG_PREFIX) {
		__u32 src_ip = iph->saddr;
		__u64 now = bpf_ktime_get_ns();
		__u64 *last_ts = bpf_map_lookup_elem(&cp_ratelimit_map, &src_ip);

		if (last_ts) {
			if (now - *last_ts < TACHYON_CP_RATELIMIT_NS) {
				if (stats) stats->rx_ratelimit_drops++;
				return XDP_DROP;
			}
			*last_ts = now;
		} else {
			bpf_map_update_elem(&cp_ratelimit_map, &src_ip, &now, BPF_ANY);
		}
		return XDP_PASS;
	}

	/* --- Session validation --- */
	__u32 session_id = bpf_ntohl(gh->session_id);
	if (session_id == 0 || session_id >= TACHYON_MAX_SESSIONS) {
		if (stats) stats->rx_invalid_session++;
		return XDP_DROP;
	}

	struct tachyon_session *sess = bpf_map_lookup_elem(&session_map, &session_id);
	if (!sess) {
		if (stats) stats->rx_invalid_session++;
		return XDP_DROP;
	}

	/* --- Decode sequence number --- */
	__u64 raw_seq    = bpf_be64_to_cpu(gh->seq);
	__u32 sender_cpu = (raw_seq >> TACHYON_SEQ_CPU_SHIFT) & (TACHYON_MAX_TX_CPUS - 1);
	__u64 pkt_seq    = raw_seq & TACHYON_SEQ_NUM_MASK;

	/* Bounds check for verifier (sender_cpu is already masked) */
	if (sender_cpu >= TACHYON_MAX_TX_CPUS) {
		if (stats) stats->rx_malformed++;
		return XDP_DROP;
	}

	/* ── Unified Critical Section: Replay Check + Decrypt + Bitmap Commit ──
	 *
	 * We perform replay pre-check, then decrypt, then commit the bitmap
	 * update all conceptually linked. The decrypt happens outside the lock
	 * to avoid holding the spinlock during crypto (which can be expensive).
	 * The two-phase lock approach prevents replay while allowing concurrent
	 * crypto operations.
	 */

	/* Phase 1: Replay pre-check (under lock) */
	bpf_spin_lock(&sess->replay_lock);
	__u64 drop_flag = 0;

	if (pkt_seq <= sess->rx_highest_seq[sender_cpu]) {
		__u64 delta = sess->rx_highest_seq[sender_cpu] - pkt_seq;
		if (delta >= TACHYON_REPLAY_WINDOW) {
			drop_flag = 1;
		} else {
			__u64 word = delta >> 6;       /* delta / 64 */
			__u64 bit  = delta & 63;       /* delta % 64 */
			__u64 mask = 1ULL << bit;

			/* Direct array indexing with verifier guard */
			if (word < TACHYON_REPLAY_WORDS &&
			    (sess->rx_bitmap[sender_cpu][word] & mask))
				drop_flag = 1;
		}
	}
	bpf_spin_unlock(&sess->replay_lock);

	if (drop_flag) {
		if (stats) stats->rx_replay_drops++;
		emit_event(ctx, TACHYON_EVT_REPLAY_DROP, session_id, pkt_seq);
		return XDP_DROP;
	}

	/* Phase 2: Decrypt and authenticate (outside lock) */
	if (bpf_ghost_decrypt(ctx, session_id) != 0) {
		if (stats) stats->rx_crypto_errors++;
		emit_event(ctx, TACHYON_EVT_CRYPTO_ERROR, session_id, pkt_seq);
		return XDP_DROP;
	}

	/* Phase 3: Commit bitmap update (under lock, after successful auth) */
	bpf_spin_lock(&sess->replay_lock);

	if (pkt_seq > sess->rx_highest_seq[sender_cpu]) {
		__u64 delta = pkt_seq - sess->rx_highest_seq[sender_cpu];

		if (delta >= TACHYON_REPLAY_WINDOW) {
			/* Sequence jumped beyond window - reset bitmap */
			sess->rx_bitmap[sender_cpu][0] = 0;
			sess->rx_bitmap[sender_cpu][1] = 0;
			sess->rx_bitmap[sender_cpu][2] = 0;
			sess->rx_bitmap[sender_cpu][3] = 0;
		} else {
			/* Slide the bitmap window forward by delta positions */
			__u64 w0 = sess->rx_bitmap[sender_cpu][0];
			__u64 w1 = sess->rx_bitmap[sender_cpu][1];
			__u64 w2 = sess->rx_bitmap[sender_cpu][2];
			__u64 w3 = sess->rx_bitmap[sender_cpu][3];

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

			sess->rx_bitmap[sender_cpu][0] = w0;
			sess->rx_bitmap[sender_cpu][1] = w1;
			sess->rx_bitmap[sender_cpu][2] = w2;
			sess->rx_bitmap[sender_cpu][3] = w3;
		}
		sess->rx_highest_seq[sender_cpu] = pkt_seq;
		sess->rx_bitmap[sender_cpu][0] |= 1ULL; /* Mark current packet */
	} else {
		/* Out-of-order packet within window - mark its bit */
		__u64 delta = sess->rx_highest_seq[sender_cpu] - pkt_seq;
		__u64 word = delta >> 6;
		__u64 bit  = delta & 63;
		__u64 mask = 1ULL << bit;

		/* Check for duplicate (shouldn't happen after Phase 1, but guard) */
		if (word < TACHYON_REPLAY_WORDS) {
			if (sess->rx_bitmap[sender_cpu][word] & mask) {
				bpf_spin_unlock(&sess->replay_lock);
				if (stats) stats->rx_replay_drops++;
				return XDP_DROP;
			}
			sess->rx_bitmap[sender_cpu][word] |= mask;
		}
	}
	bpf_spin_unlock(&sess->replay_lock);

	/* ── Strip Outer Headers and Trim Dynamic Padding ── */
	if (bpf_xdp_adjust_head(ctx, TACHYON_TX_HEAD_ADJUST)) {
		if (stats) stats->rx_malformed++;
		return XDP_DROP;
	}

	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end) {
		if (stats) stats->rx_malformed++;
		return XDP_DROP;
	}

	struct iphdr *decrypted_iph = (void *)(eth + 1);
	if ((void *)(decrypted_iph + 1) > data_end) {
		if (stats) stats->rx_malformed++;
		return XDP_DROP;
	}

	/* Validate inner IPv4 total length */
	__u32 inner_ip_len = bpf_ntohs(decrypted_iph->tot_len);
	if (inner_ip_len < sizeof(struct iphdr) || inner_ip_len > TACHYON_MAX_FRAME_LEN) {
		if (stats) stats->rx_malformed++;
		return XDP_DROP;
	}

	/* Trim AEAD tag and padding from the tail */
	int current_frame_len  = (int)(data_end - data);
	int expected_frame_len = (int)(sizeof(struct ethhdr) + inner_ip_len);
	int trim_amount        = current_frame_len - expected_frame_len;

	if (trim_amount < TACHYON_AEAD_TAG_LEN || trim_amount > TACHYON_MAX_FRAME_LEN) {
		if (stats) stats->rx_malformed++;
		return XDP_DROP;
	}

	if (bpf_xdp_adjust_tail(ctx, -trim_amount)) {
		if (stats) stats->rx_malformed++;
		return XDP_DROP;
	}

	/* Re-derive pointers after tail adjustment */
	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	/* Clamp MSS on decrypted SYN packets too */
	decrypted_iph = (void *)(eth + 1);
	if ((void *)(decrypted_iph + 1) <= data_end)
		tcp_mss_clamp(decrypted_iph, data_end);

	/* Rewrite Ethernet: broadcast dest, zero source (for local delivery) */
	__builtin_memset(eth->h_dest, 0xff, ETH_ALEN);
	__builtin_memset(eth->h_source, 0x00, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);

	/* --- Update RX statistics --- */
	if (stats) {
		stats->rx_packets++;
		stats->rx_bytes += (data_end - data);
	}

	return bpf_redirect_map(&tx_port, TACHYON_TXPORT_VETH, 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Key Injection Syscall Program
 *
 * Called from userspace via bpf_prog_test_run_opts() to transfer derived
 * session keys from the control plane into the kernel crypto module.
 * ══════════════════════════════════════════════════════════════════════════ */

SEC("syscall")
int ghost_key_init(void *ctx)
{
	__u32 zero = 0;
	struct tachyon_key_init *kid = bpf_map_lookup_elem(&key_init_map, &zero);

	if (!kid)
		return -1;

	return bpf_ghost_set_key(kid->session_id,
				 kid->tx_key, TACHYON_AEAD_KEY_LEN,
				 kid->rx_key, TACHYON_AEAD_KEY_LEN);
}

/* Dummy XDP program for the ingress veth (prevents kernel stack processing) */
SEC("xdp")
int xdp_dummy(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
