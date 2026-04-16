/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Tachyon XDP Tunnel - Shared Protocol Definitions
 *
 * This header is the single source of truth for all wire-format structures,
 * protocol constants, and shared types used across the eBPF data plane,
 * kernel crypto module, and userspace control plane.
 *
 * Contexts:
 *   - eBPF/XDP programs  (clang -target bpf)
 *   - Kernel module       (kbuild)
 *   - Userspace C++17     (g++)
 */
#ifndef TACHYON_COMMON_H
#define TACHYON_COMMON_H

/* ──────────────────────────────────────────────────────────────────────────
 * Type Compatibility Layer
 *
 * eBPF and kernel code get __u32 etc. from <linux/types.h>.
 * Userspace C/C++ needs explicit typedefs.
 * ────────────────────────────────────────────────────────────────────────── */
#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__KERNEL__) && !defined(__BPF__)
#include <stdint.h>
#include <string.h>
/* Avoid conflicts with kernel types from <linux/types.h> which
 * may be pulled in transitively by <sys/stat.h> in C++ builds. */
#if !defined(_LINUX_TYPES_H)
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t __s32;
#endif
#endif

/* ──────────────────────────────────────────────────────────────────────────
 * Protocol Version & Identity
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_PROTO_VERSION 4 /* AKE v4.0                      */
#define TACHYON_MODULE_NAME "tachyon-crypto"

/* ──────────────────────────────────────────────────────────────────────────
 * Capacity Limits
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_MAX_SESSIONS 256
#define TACHYON_MAX_TX_CPUS 64        /* Per-CPU sequence partitioning */
#define TACHYON_MAX_IP_SESSIONS 1024  /* ip_to_session LRU capacity    */
#define TACHYON_MAX_RATELIMIT 65536   /* Control plane rate-limit LRU  */
#define TACHYON_NONCE_CACHE_MAX 50000 /* Userspace nonce dedup cache   */

/* ──────────────────────────────────────────────────────────────────────────
 * Wire Format Sizes (bytes)
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_ETH_HDR_LEN 14
#define TACHYON_IP_HDR_LEN 20
#define TACHYON_UDP_HDR_LEN 8
#define TACHYON_GHOST_HDR_LEN 20
#define TACHYON_AEAD_TAG_LEN 16 /* Poly1305 tag                  */
#define TACHYON_AEAD_KEY_LEN 32 /* ChaCha20 key                  */
#define TACHYON_AEAD_IV_LEN 12  /* ChaCha20-Poly1305 nonce       */
#define TACHYON_X25519_KEY_LEN 32
#define TACHYON_HMAC_LEN 32 /* SHA-256 HMAC output           */

/*
 * TX_HEAD_ADJUST = ETH(14) + IP(20) + UDP(8) + Ghost(20) = 62 ... but the
 * original protocol uses 48 because the inner Ethernet header (14 bytes) is
 * reused as part of the outer frame. Net new headers = 48 bytes.
 *
 * Encapsulated packet layout:
 *   [Outer ETH 14B][Outer IP 20B][UDP 8B][Ghost 20B][Inner ETH+IP+...][TAG 16B][PAD]
 *                                                     ^-- inner starts at +48 from original
 */
#define TACHYON_TX_HEAD_ADJUST 48
#define TACHYON_OUTER_HDR_LEN                                                                      \
    (TACHYON_ETH_HDR_LEN + TACHYON_IP_HDR_LEN + TACHYON_UDP_HDR_LEN + TACHYON_GHOST_HDR_LEN)

/* Minimum encapsulated packet: outer headers + ghost + at least 1 byte + tag */
#define TACHYON_MIN_ENCAP_LEN (TACHYON_OUTER_HDR_LEN + TACHYON_AEAD_TAG_LEN + 1)

/* ──────────────────────────────────────────────────────────────────────────
 * Replay Protection
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_REPLAY_WINDOW 256 /* Sliding window size in packets */
#define TACHYON_REPLAY_WORDS 4    /* 256 / 64 = 4 bitmap words     */

/* ──────────────────────────────────────────────────────────────────────────
 * Network Tuning
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_TARGET_MSS 1360    /* Clamped MSS to hide overhead   */
#define TACHYON_TUNNEL_MTU 1420    /* Virtual interface MTU          */
#define TACHYON_MAX_FRAME_LEN 1500 /* Physical MTU assumption        */
#define TACHYON_DEFAULT_PORT 443   /* Default listen port            */

/* ──────────────────────────────────────────────────────────────────────────
 * Timing Constants (seconds)
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_KEEPALIVE_BASE 8           /* Keepalive base interval        */
#define TACHYON_KEEPALIVE_JITTER 8         /* Keepalive jitter range         */
#define TACHYON_RETRY_BASE 2               /* Handshake retry base interval  */
#define TACHYON_RETRY_JITTER 3             /* Handshake retry jitter range   */
#define TACHYON_DPD_TIMEOUT 35             /* Dead Peer Detection timeout    */
#define TACHYON_REKEY_INTERVAL 60          /* Key rotation interval          */
#define TACHYON_COOKIE_ROTATION 120        /* Cookie secret rotation (secs)  */
#define TACHYON_NONCE_EXPIRY 180           /* Nonce cache entry TTL (secs)   */
#define TACHYON_CP_RATELIMIT_NS 1000000ULL /* 1ms between CP packets   */

/* ──────────────────────────────────────────────────────────────────────────
 * Sequence Number Encoding
 *
 * Format: [CPU_ID : 16 bits][Sequence : 48 bits]
 * This allows per-CPU lock-free sequence generation with 281 trillion
 * packets per CPU before wrap-around.
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_SEQ_CPU_SHIFT 48
#define TACHYON_SEQ_CPU_MASK 0xFFFF000000000000ULL
#define TACHYON_SEQ_NUM_MASK 0x0000FFFFFFFFFFFFULL

/* ──────────────────────────────────────────────────────────────────────────
 * QUIC Mimicry Constants
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_MIMICRY_NONE 0 /* Standard UDP encapsulation     */
#define TACHYON_MIMICRY_QUIC 1 /* QUIC short-header mimicry      */

#define TACHYON_QUIC_FIXED_BIT 0x40   /* QUIC short header marker       */
#define TACHYON_QUIC_SPIN_BIT 0x20    /* QUIC spin bit position         */
#define TACHYON_QUIC_PN_LEN_MASK 0x03 /* Packet number length bits      */

/* Bimodal padding distribution thresholds (percentage) */
#define TACHYON_PAD_FULL_THRESH 60    /* % packets padded to MTU        */
#define TACHYON_PAD_ACK_THRESH 90     /* % packets with small padding   */
#define TACHYON_PAD_ACK_MAX 31        /* Max small-padding bytes        */
#define TACHYON_PAD_MAX_BITS 0x7FF    /* Safety mask for verifier       */
#define TACHYON_PAD_JITTER_MASK 0x0F  /* Full-pad jitter mask           */
#define TACHYON_TARGET_OUTER_LEN 1490 /* Target outer frame length      */

/* ──────────────────────────────────────────────────────────────────────────
 * Control Plane Packet Types
 *
 * Identified by the high nibble 0xC0 in the quic_flags field.
 * The XDP RX path uses (flags & 0xF0) == 0xC0 to route to userspace.
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_PKT_INIT 0xC0      /* Handshake initiation           */
#define TACHYON_PKT_COOKIE 0xC1    /* Stateless cookie response      */
#define TACHYON_PKT_AUTH 0xC2      /* Authenticated key exchange      */
#define TACHYON_PKT_FINISH 0xC3    /* Handshake completion           */
#define TACHYON_PKT_KEEPALIVE 0xC4 /* Encrypted keepalive            */

#define TACHYON_CP_FLAG_MASK 0xF0   /* Mask for CP type detection     */
#define TACHYON_CP_FLAG_PREFIX 0xC0 /* CP packet prefix               */

/* QUIC Initial minimum size (RFC 9000, Section 14.1) */
#define TACHYON_QUIC_INIT_MIN_LEN 1200

/* ──────────────────────────────────────────────────────────────────────────
 * KDF Labels (used in HKDF-SHA256 derivation)
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_KDF_EARLY_SECRET "Tachyon-EarlySecret"
#define TACHYON_KDF_CP_AEAD "Tachyon-CP-AEAD"
#define TACHYON_KDF_SESSION_MASTER "Tachyon-Session-Master"
#define TACHYON_KDF_SERVER_TX "Tachyon-Srv-TX"
#define TACHYON_KDF_CLIENT_TX "Tachyon-Cli-TX"
#define TACHYON_KDF_DEFAULT_PSK "Tachyon-Default-PSK"

/* ──────────────────────────────────────────────────────────────────────────
 * Event Types (perf event reporting from eBPF to userspace)
 * ────────────────────────────────────────────────────────────────────────── */
enum tachyon_event_type {
    TACHYON_EVT_REPLAY_DROP = 0,
    TACHYON_EVT_CRYPTO_ERROR = 1,
    TACHYON_EVT_INVALID_SESSION = 2,
    TACHYON_EVT_MALFORMED_PKT = 3,
    TACHYON_EVT_RATELIMIT_DROP = 4,
    TACHYON_EVT_PEER_ROAM = 5,
};

/* ──────────────────────────────────────────────────────────────────────────
 * Wire-Format Structures
 *
 * These structures define the on-wire layout and MUST remain packed and
 * consistent across all three compilation contexts.
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * Ghost Header - Tunnel encapsulation header (20 bytes)
 *
 * Sits between outer UDP header and encrypted payload.
 * For QUIC mimicry mode, quic_flags and pad[] are crafted to resemble
 * a QUIC short header with Connection ID bytes.
 *
 * Layout:
 *   [quic_flags:1][pad:3][session_id:4][seq:8][nonce_salt:4] = 20 bytes
 */
struct tachyon_ghost_hdr {
    __u8 quic_flags;  /* QUIC mimicry flags / pkt type  */
    __u8 pad[3];      /* Fake CID bytes for mimicry     */
    __u32 session_id; /* Session identifier (network)   */
    __u64 seq;        /* Sequence number (network)      */
    __u32 nonce_salt; /* Per-packet random IV component */
} __attribute__((packed));

/* ──────────────────────────────────────────────────────────────────────────
 * BPF Map Value Structures
 * ────────────────────────────────────────────────────────────────────────── */

/* Global tunnel configuration (single-entry array map) */
struct tachyon_config {
    __u16 listen_port_net; /* UDP port in network byte order */
    __u8 mimicry_type;     /* TACHYON_MIMICRY_*              */
    __u8 pad;
};

/* Per-session state including replay protection window */
struct tachyon_session {
#if defined(__BPF__) || defined(__TARGET_ARCH_x86)
    struct bpf_spin_lock replay_lock; /* Protects replay state          */
#else
    __u32 lock_pad; /* Placeholder for non-BPF ctx    */
#endif
    __u32 peer_ip;                                              /* Remote physical IP (network)   */
    __u32 local_ip;                                             /* Local physical IP (network)    */
    __u8 peer_mac[6];                                           /* Remote MAC for L2 redirect     */
    __u16 peer_port;                                            /* Remote UDP port (network)      */
    __u64 tx_rl_tokens;                                         /* TX token bucket current tokens */
    __u64 tx_rl_last_ns;                                        /* TX token bucket last refill ts */
    __u64 rx_rl_tokens;                                         /* RX token bucket current tokens */
    __u64 rx_rl_last_ns;                                        /* RX token bucket last refill ts */
    __u64 rx_highest_seq[TACHYON_MAX_TX_CPUS];                  /* Highest seq per sender CPU */
    __u64 rx_bitmap[TACHYON_MAX_TX_CPUS][TACHYON_REPLAY_WORDS]; /* Replay bitmap */
};

/* Staging structure for key injection via BPF syscall program */
struct tachyon_key_init {
    __u32 session_id;
    __u8 tx_key[TACHYON_AEAD_KEY_LEN];
    __u8 rx_key[TACHYON_AEAD_KEY_LEN];
};

/* Per-CPU packet statistics */
struct tachyon_stats {
    __u64 rx_packets; /* Successfully received          */
    __u64 rx_bytes;
    __u64 tx_packets; /* Successfully transmitted       */
    __u64 tx_bytes;
    __u64 rx_replay_drops;         /* Replay window violations       */
    __u64 rx_crypto_errors;        /* AEAD authentication failures   */
    __u64 rx_invalid_session;      /* Unknown session ID             */
    __u64 rx_malformed;            /* Malformed packets              */
    __u64 rx_ratelimit_drops;      /* Control plane rate limited     */
    __u64 tx_crypto_errors;        /* TX encryption failures         */
    __u64 tx_headroom_errors;      /* Failed to adjust head/tail     */
    __u64 tx_ratelimit_drops;      /* TX data plane rate limited     */
    __u64 rx_ratelimit_data_drops; /* RX data plane rate limited     */
    __u64 rx_roam_events;          /* Peer roaming detections        */
};

/* LPM trie key for IPv4 multi-peer routing */
struct tachyon_lpm_key_v4 {
    __u32 prefixlen; /* Prefix length in bits          */
    __u32 addr;      /* IPv4 address (network order)   */
};

/* Per-session token-bucket rate limiting configuration */
struct tachyon_rate_cfg {
    __u64 tx_rate_bps; /* TX rate limit (bytes/sec)      */
    __u64 tx_burst;    /* TX burst allowance (bytes)     */
    __u64 rx_rate_bps; /* RX rate limit (bytes/sec)      */
    __u64 rx_burst;    /* RX burst allowance (bytes)     */
};

/* Event structure for perf_event reporting */
struct tachyon_event {
    __u32 type; /* tachyon_event_type             */
    __u32 session_id;
    __u64 seq;
    __u64 timestamp_ns;
};

/* ──────────────────────────────────────────────────────────────────────────
 * Control Plane Message Structures
 *
 * All messages use the ghost_hdr quic_flags field for type identification.
 * Messages are padded with random bytes for QUIC mimicry before transmission.
 * ────────────────────────────────────────────────────────────────────────── */

/* PKT_INIT: Handshake initiation (Initiator -> Responder) */
struct tachyon_msg_init {
    __u8 flags;         /* TACHYON_PKT_INIT               */
    __u8 pad[3];        /* CID mimicry bytes              */
    __u32 session_id;   /* Session ID (network order)     */
    __u64 client_nonce; /* Random nonce for this attempt  */
    __u8 is_rekey;      /* 1 = rekey, 0 = fresh session   */
    __u8 _reserved[3];
} __attribute__((packed));

/* PKT_COOKIE: Stateless cookie (Responder -> Initiator) */
struct tachyon_msg_cookie {
    __u8 flags; /* TACHYON_PKT_COOKIE             */
    __u8 pad[3];
    __u32 session_id;
    __u64 client_nonce;            /* Echo of client's nonce         */
    __u8 cookie[TACHYON_HMAC_LEN]; /* HMAC(secret, ip|nonce|window)  */
} __attribute__((packed));

/* PKT_AUTH: Authenticated key exchange (Initiator -> Responder) */
struct tachyon_msg_auth {
    __u8 flags; /* TACHYON_PKT_AUTH               */
    __u8 pad[3];
    __u32 session_id;
    __u64 client_nonce;
    __u8 is_rekey;
    __u8 _reserved[3];
    __u8 cookie[TACHYON_HMAC_LEN]; /* Cookie from PKT_COOKIE         */
    __u8 ciphertext[48];           /* Encrypted eph pubkey (32+16)   */
} __attribute__((packed));

/* PKT_FINISH: Handshake completion (Responder -> Initiator) */
struct tachyon_msg_finish {
    __u8 flags; /* TACHYON_PKT_FINISH             */
    __u8 pad[3];
    __u32 session_id;
    __u64 server_nonce;
    __u8 ciphertext[48]; /* Encrypted eph pubkey (32+16)   */
} __attribute__((packed));

/* PKT_KEEPALIVE: Encrypted keepalive (bidirectional) */
struct tachyon_msg_keepalive {
    __u8 flags; /* TACHYON_PKT_KEEPALIVE          */
    __u8 pad[3];
    __u32 session_id;
    __u64 timestamp;     /* Sender's wall-clock time       */
    __u8 ciphertext[32]; /* Encrypted dummy (16+16 tag)    */
} __attribute__((packed));

/* ──────────────────────────────────────────────────────────────────────────
 * BPF Map Index Constants
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_TXPORT_VETH 0 /* tx_port[0] = virtual interface */
#define TACHYON_TXPORT_PHYS 1 /* tx_port[1] = physical NIC      */

/* ──────────────────────────────────────────────────────────────────────────
 * Filesystem Paths
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_BPF_PIN_BASE "/sys/fs/bpf/tachyon"

#ifdef __cplusplus
}
#endif

#endif /* TACHYON_COMMON_H */
