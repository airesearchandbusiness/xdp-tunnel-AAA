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
#include <stddef.h> /* offsetof */
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
#define TACHYON_PROTO_VERSION 5 /* AKE v5.0 "Ghost-PQ"           */
#define TACHYON_PROTO_VERSION_V4 4 /* Legacy v4 for compat flag   */
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
#define TACHYON_CP_RATELIMIT_NS 1000000ULL /* 1ms between CP packets        */
#define TACHYON_DECOY_BASE 3               /* Decoy chaff base interval (s)  */
#define TACHYON_DECOY_JITTER 5             /* Decoy chaff jitter range (s)   */
#define TACHYON_KEY_RATCHET_INTERVAL 300   /* Forward secrecy ratchet (5min) */

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
 * Traffic Obfuscation Flags (tachyon_config.obfs_flags bitmask)
 *
 * Each bit enables an independent traffic analysis countermeasure in the
 * XDP datapath. Combining all flags produces a tunnel whose external
 * traffic is statistically indistinguishable from random UDP/QUIC traffic.
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_OBFS_TTL_JITTER 0x01 /* Randomize outer TTL (63-65)    */
#define TACHYON_OBFS_IPID_RAND 0x02  /* Randomize IP Identification    */
#define TACHYON_OBFS_DF_VARY 0x04    /* Probabilistic DF bit clearing  */
#define TACHYON_OBFS_DSCP_STRIP 0x08 /* Zero inner DSCP in outer hdr   */
#define TACHYON_OBFS_CONST_PAD 0x10  /* Constant-size padding to MTU   */
#define TACHYON_OBFS_DECOY 0x20      /* Enable decoy chaff traffic     */

/* Combine all obfuscation flags for maximum traffic analysis resistance */
#define TACHYON_OBFS_ALL 0x3F

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
#define TACHYON_KDF_KEY_RATCHET "Tachyon-Key-Ratchet" /* Forward secrecy chain */
#define TACHYON_KDF_DECOY_SEED "Tachyon-Decoy-Seed"   /* Decoy traffic keying  */

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
    __u8 obfs_flags;       /* TACHYON_OBFS_* bitmask         */
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
 * v5 "Ghost-PQ" Wire-Format Structures
 *
 * These extend the v4 control-plane messages with post-quantum hybrid
 * key exchange (X25519 ‖ ML-KEM-768), transport-ID negotiation, and
 * forward-secrecy ratchet counter. Wire compatibility with v4 is
 * maintained through the magic field: v4 peers see an unknown magic and
 * drop; v5 peers accept both TCH4 and TCH5 magic values.
 *
 * Size targets (packed, no padding):
 *   MsgInitV5   = 1260 bytes   (magic4 + version + flags + x25519_pk32 +
 *                                mlkem_pk1184 + nonce16 + timestamp8 + cookie16)
 *   MsgCookieV5 = 1168 bytes   (magic4 + x25519_pk32 + mlkem_ct1088 +
 *                                transport1 + cookie16 + hmac32)
 *   MsgDataV5   = 28 bytes hdr (flags1 + transport1 + session_id4 + seq8 +
 *                                nonce_salt4 + ratchet_ctr8 + pad2)
 * ────────────────────────────────────────────────────────────────────────── */
#define TACHYON_V5_MAGIC     0x54434835 /* "TCH5" in big-endian       */
#define TACHYON_V4_MAGIC     0x54434834 /* "TCH4" for compat detect   */

/* v5 handshake flags (bit field in MsgInitV5.flags) */
#define TACHYON_V5_FLAG_PQ_HYBRID   0x01 /* ML-KEM-768 present in pk  */
#define TACHYON_V5_FLAG_CLASSICAL   0x02 /* X25519-only (fallback)    */
#define TACHYON_V5_FLAG_REKEY       0x04 /* Rekey of existing session */
#define TACHYON_V5_FLAG_TRANSPORT   0x08 /* Transport ID negotiation  */

/* ML-KEM-768 sizes (FIPS 203) */
#define TACHYON_MLKEM768_PK_LEN   1184
#define TACHYON_MLKEM768_SK_LEN   2400
#define TACHYON_MLKEM768_CT_LEN   1088
#define TACHYON_MLKEM768_SS_LEN   32

/* HKDF-SHA384 PRK width for the v5 combiner */
#define TACHYON_V5_PRK_LEN        48

/* v5 KDF labels */
#define TACHYON_V5_KDF_LABEL_MASTER "tch5 master v5"
#define TACHYON_V5_KDF_LABEL_TX_KEY "tch5 tx-key"
#define TACHYON_V5_KDF_LABEL_RX_KEY "tch5 rx-key"
#define TACHYON_V5_KDF_LABEL_MAC    "tch5 mac-key"

/* PKT_INIT v5: Hybrid handshake initiation (1260 bytes) */
struct tachyon_msg_init_v5 {
    __u32 magic;           /* TACHYON_V5_MAGIC               */
    __u8  version;         /* 5                              */
    __u8  flags;           /* TACHYON_V5_FLAG_*              */
    __u8  transport_id;    /* Preferred transport (TransportId) */
    __u8  _reserved;
    __u8  client_x25519_pk[32];
    __u8  client_mlkem768_pk[1184];
    __u8  nonce[16];
    __u8  timestamp_be[8]; /* Milliseconds since epoch, BE   */
    __u8  cookie[16];      /* 0 for initial, echoed on retry */
} __attribute__((packed));

/* PKT_COOKIE v5: Server's KEM ciphertext + cookie (1168 bytes) */
struct tachyon_msg_cookie_v5 {
    __u32 magic;            /* TACHYON_V5_MAGIC              */
    __u8  server_x25519_pk[32];
    __u8  mlkem768_ct[1088]; /* Server encaps to client's KEM pk */
    __u8  transport_id;     /* Server's accepted transport    */
    __u8  _reserved[3];
    __u8  cookie[16];       /* HMAC(cookie_secret, ...)       */
    __u8  hmac[32];         /* HMAC-SHA256 over preceding     */
} __attribute__((packed));

/* Data-plane header for v5 (28 bytes, replaces ghost_hdr for v5 sessions) */
struct tachyon_data_hdr_v5 {
    __u8  flags;           /* High nibble = type; low = transport */
    __u8  transport_id;    /* Active transport (for outer framing) */
    __u16 _reserved;
    __u32 session_id;      /* Network byte order              */
    __u64 seq;             /* Per-CPU partitioned sequence     */
    __u32 nonce_salt;      /* Per-packet IV component          */
    __u64 ratchet_ctr;     /* Forward-secrecy ratchet counter  */
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

/* ──────────────────────────────────────────────────────────────────────────
 * Compile-Time Layout Verification
 *
 * Catch struct size / offset regressions before they cause silent
 * data corruption across the BPF, kernel-module, and userspace
 * compilation contexts.  Skipped in kernel-module builds (no stddef.h).
 *
 * In C contexts:    uses _Static_assert + __builtin_offsetof (clang/gcc)
 * In C++ contexts:  uses static_assert  + offsetof (C++11)
 * ────────────────────────────────────────────────────────────────────────── */
#ifndef __KERNEL__

#ifdef __cplusplus
#define TACHYON_SASSERT(cond, msg) static_assert((cond), msg)
#define TACHYON_FIELD_OFFSET(T, f) offsetof(T, f)
#else
#define TACHYON_SASSERT(cond, msg) _Static_assert((cond), msg)
#define TACHYON_FIELD_OFFSET(T, f) __builtin_offsetof(T, f)
#endif

/* Ghost header — 20-byte wire format */
TACHYON_SASSERT(sizeof(struct tachyon_ghost_hdr) == 20,
                "tachyon_ghost_hdr must be exactly 20 bytes on the wire");
TACHYON_SASSERT(TACHYON_FIELD_OFFSET(struct tachyon_ghost_hdr, session_id) == 4,
                "ghost_hdr.session_id must be at wire offset 4");
TACHYON_SASSERT(TACHYON_FIELD_OFFSET(struct tachyon_ghost_hdr, seq) == 8,
                "ghost_hdr.seq must be at wire offset 8");
TACHYON_SASSERT(TACHYON_FIELD_OFFSET(struct tachyon_ghost_hdr, nonce_salt) == 16,
                "ghost_hdr.nonce_salt must be at wire offset 16");

/* BPF map value types */
TACHYON_SASSERT(sizeof(struct tachyon_config) == 4, "tachyon_config must be 4 bytes");
TACHYON_SASSERT(sizeof(struct tachyon_key_init) == 68,
                "tachyon_key_init must be 68 bytes (4 + 32 + 32)");
TACHYON_SASSERT(sizeof(struct tachyon_lpm_key_v4) == 8,
                "tachyon_lpm_key_v4 must be 8 bytes (4 + 4)");
TACHYON_SASSERT(sizeof(struct tachyon_rate_cfg) == 32, "tachyon_rate_cfg must be 32 bytes (4 x 8)");
TACHYON_SASSERT(sizeof(struct tachyon_event) == 24,
                "tachyon_event must be 24 bytes (4 + 4 + 8 + 8)");
TACHYON_SASSERT(sizeof(struct tachyon_stats) == 112, "tachyon_stats must be 112 bytes (14 x 8)");

/* Control-plane message structs (all packed) */
TACHYON_SASSERT(sizeof(struct tachyon_msg_init) == 20,
                "tachyon_msg_init must be 20 bytes on the wire");
TACHYON_SASSERT(sizeof(struct tachyon_msg_cookie) == 48,
                "tachyon_msg_cookie must be 48 bytes on the wire");
TACHYON_SASSERT(sizeof(struct tachyon_msg_auth) == 100,
                "tachyon_msg_auth must be 100 bytes on the wire");
TACHYON_SASSERT(sizeof(struct tachyon_msg_finish) == 64,
                "tachyon_msg_finish must be 64 bytes on the wire");
TACHYON_SASSERT(sizeof(struct tachyon_msg_keepalive) == 48,
                "tachyon_msg_keepalive must be 48 bytes on the wire");

/* v5 "Ghost-PQ" control-plane messages */
TACHYON_SASSERT(sizeof(struct tachyon_msg_init_v5) == 1264,
                "tachyon_msg_init_v5 must be 1264 bytes");
TACHYON_SASSERT(sizeof(struct tachyon_msg_cookie_v5) == 1176,
                "tachyon_msg_cookie_v5 must be 1176 bytes (4+32+1088+1+3+16+32)");
TACHYON_SASSERT(sizeof(struct tachyon_data_hdr_v5) == 28,
                "tachyon_data_hdr_v5 must be 28 bytes (1+1+2+4+8+4+8)");

/* v5 constant sanity */
TACHYON_SASSERT(TACHYON_MLKEM768_PK_LEN == 1184, "ML-KEM-768 pk must be 1184 bytes (FIPS 203)");
TACHYON_SASSERT(TACHYON_MLKEM768_CT_LEN == 1088, "ML-KEM-768 ct must be 1088 bytes (FIPS 203)");

/* Constant relationships */
TACHYON_SASSERT(TACHYON_OUTER_HDR_LEN == 62, "outer header sum must be 62 bytes (14+20+8+20)");
TACHYON_SASSERT(TACHYON_REPLAY_WINDOW == TACHYON_REPLAY_WORDS * 64,
                "replay window must equal replay words times bitmap word width");
TACHYON_SASSERT((TACHYON_SEQ_CPU_MASK | TACHYON_SEQ_NUM_MASK) == 0xFFFFFFFFFFFFFFFFULL,
                "seq masks must cover all 64 bits with no gaps");
TACHYON_SASSERT((TACHYON_SEQ_CPU_MASK & TACHYON_SEQ_NUM_MASK) == 0, "seq masks must not overlap");
TACHYON_SASSERT(TACHYON_AEAD_TAG_LEN == 16, "Poly1305 tag must be 16 bytes");
TACHYON_SASSERT(TACHYON_AEAD_KEY_LEN == 32, "ChaCha20 key must be 32 bytes");
TACHYON_SASSERT(TACHYON_X25519_KEY_LEN == 32, "X25519 key must be 32 bytes");
TACHYON_SASSERT(TACHYON_HMAC_LEN == 32, "HMAC-SHA256 output must be 32 bytes");

#undef TACHYON_SASSERT
#undef TACHYON_FIELD_OFFSET

#endif /* !__KERNEL__ */

#ifdef __cplusplus
}
#endif

#endif /* TACHYON_COMMON_H */
