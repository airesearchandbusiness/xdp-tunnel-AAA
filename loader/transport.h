/* SPDX-License-Identifier: MIT */
/*
 * Pluggable transport framework — registry, scoring, and auto-selection.
 *
 * Each protocol-mimicry engine (QUIC, HTTP/2, DoH, STUN, REALITY) wraps
 * tunnel payloads in real wire-protocol framing so DPI sees legitimate
 * traffic. This header defines the common types, the function-pointer
 * table that every engine populates, and the environment-aware auto-
 * selector that picks the best transport for the deployment context.
 *
 * Architecture:
 *   1. Each engine exports a `register_<name>()` function that pushes a
 *      TransportOps struct into the global registry.
 *   2. `transport_auto_select()` scores every registered engine against an
 *      EnvProfile (port, protocol, region hint, bandwidth tier) and returns
 *      the highest-scoring ID.
 *   3. Callers invoke `transport_wrap / transport_unwrap` with the chosen
 *      ID — the registry dispatches to the correct engine.
 *
 * Thread-safety: the registry is populated once at startup (single-
 * threaded init) and read-only thereafter. Wrap/unwrap are pure.
 */
#ifndef TACHYON_TRANSPORT_H
#define TACHYON_TRANSPORT_H

#include <cstddef>
#include <cstdint>

namespace tachyon::transport {

/* ── Transport identifiers ─────────────────────────────────────────── */

enum class TransportId : uint8_t {
    NONE     = 0, /* raw UDP, no outer framing */
    REALITY  = 1, /* TLS 1.3 ClientHello mimicry (obfs.cpp) */
    QUIC     = 2, /* QUIC v1 Initial long header (RFC 9000) */
    HTTP2    = 3, /* HTTP/2 DATA frames over TLS */
    DOH      = 4, /* DNS-over-HTTPS (RFC 8484) wire format */
    STUN     = 5, /* STUN Binding Req/Resp (RFC 8489) */
    AUTO     = 255,
};

constexpr int TRANSPORT_COUNT = 6; /* NONE through STUN */

const char *transport_id_to_string(TransportId id);
TransportId transport_id_from_string(const char *s);

/* ── Environment profile — input to auto-selection ─────────────────── */

enum class BandwidthTier : uint8_t {
    LOW,     /* < 1 Mbps — satellite, GPRS */
    MEDIUM,  /* 1–50 Mbps — typical broadband */
    HIGH,    /* > 50 Mbps — datacenter, fibre */
};

enum class RegionHint : uint8_t {
    OPEN,       /* minimal DPI — most protocols work */
    MODERATE,   /* some DPI (corporate, light national) */
    RESTRICTIVE,/* heavy DPI: China, Iran, Russia, Turkmenistan */
};

struct EnvProfile {
    uint16_t      port           = 443;
    bool          udp            = true; /* outer is UDP; false → TCP */
    BandwidthTier bandwidth      = BandwidthTier::MEDIUM;
    RegionHint    region         = RegionHint::OPEN;
    const char   *sni_hint       = nullptr; /* preferred camouflage domain */
};

/* ── Wrap / unwrap result ──────────────────────────────────────────── */

struct FrameResult {
    size_t bytes;  /* bytes written (0 on failure) */
    bool   ok;
};

/* ── Per-connection context passed to wrap/unwrap ──────────────────── */

struct FrameContext {
    uint8_t  conn_id[20];   /* connection / transaction ID */
    uint8_t  conn_id_len;
    uint32_t stream_id;     /* HTTP/2 stream, QUIC packet number */
    uint32_t seq;           /* monotonic frame counter */
    const char *sni;        /* SNI for REALITY / DoH Host header */
};

/* ── Engine function table ─────────────────────────────────────────── */

typedef FrameResult (*WrapFn)(const uint8_t *payload, size_t payload_len,
                              uint8_t *out, size_t out_cap,
                              const FrameContext *ctx);

typedef FrameResult (*UnwrapFn)(const uint8_t *frame, size_t frame_len,
                                uint8_t *out, size_t out_cap);

struct TransportOps {
    TransportId  id;
    const char  *name;
    size_t       overhead;        /* fixed per-frame bytes added */
    size_t       max_payload;     /* maximum inner payload per frame */
    WrapFn       wrap;
    UnwrapFn     unwrap;

    /* Suitability score ∈ [0, 100] for a given environment. 0 means
     * "cannot function at all" (e.g., QUIC on a TCP-only path). */
    int (*score)(const EnvProfile &env);
};

/* ── Registry ─────────────────────────────────────────────────────── */

/* Called once at startup by each engine's compilation unit. */
void transport_register(const TransportOps *ops);

/* Look up an engine by ID. Returns nullptr for NONE or unregistered. */
const TransportOps *transport_get(TransportId id);

/* Score every registered engine and return the best one's ID. Falls
 * back to NONE if nothing scores above 0. */
TransportId transport_auto_select(const EnvProfile &env);

/* Convenience: wrap / unwrap via the registry. */
FrameResult transport_wrap(TransportId id, const uint8_t *payload, size_t len,
                           uint8_t *out, size_t cap, const FrameContext *ctx);
FrameResult transport_unwrap(TransportId id, const uint8_t *frame, size_t len,
                             uint8_t *out, size_t cap);

/* Iterate all registered engines (for diagnostics / `tachyon show`). */
int transport_list(const TransportOps **out, int max);

} /* namespace tachyon::transport */

#endif /* TACHYON_TRANSPORT_H */
