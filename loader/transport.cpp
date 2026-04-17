/* SPDX-License-Identifier: MIT */
#include "transport.h"

#include <algorithm>
#include <cstring>

namespace tachyon::transport {

/* ── Static registry ──────────────────────────────────────────────── */

static const TransportOps *g_engines[TRANSPORT_COUNT] = {};
static int g_count = 0;

void transport_register(const TransportOps *ops) {
    if (!ops || g_count >= TRANSPORT_COUNT)
        return;
    for (int i = 0; i < g_count; ++i)
        if (g_engines[i]->id == ops->id)
            return; /* already registered */
    g_engines[g_count++] = ops;
}

const TransportOps *transport_get(TransportId id) {
    for (int i = 0; i < g_count; ++i)
        if (g_engines[i]->id == id)
            return g_engines[i];
    return nullptr;
}

TransportId transport_auto_select(const EnvProfile &env) {
    int best_score = 0;
    TransportId best = TransportId::NONE;
    for (int i = 0; i < g_count; ++i) {
        const int s = g_engines[i]->score(env);
        if (s > best_score) {
            best_score = s;
            best       = g_engines[i]->id;
        }
    }
    return best;
}

FrameResult transport_wrap(TransportId id, const uint8_t *payload, size_t len,
                           uint8_t *out, size_t cap, const FrameContext *ctx) {
    const TransportOps *ops = transport_get(id);
    if (!ops || !ops->wrap)
        return {0, false};
    return ops->wrap(payload, len, out, cap, ctx);
}

FrameResult transport_unwrap(TransportId id, const uint8_t *frame, size_t len,
                             uint8_t *out, size_t cap) {
    const TransportOps *ops = transport_get(id);
    if (!ops || !ops->unwrap)
        return {0, false};
    return ops->unwrap(frame, len, out, cap);
}

int transport_list(const TransportOps **out, int max) {
    const int n = std::min(g_count, max);
    for (int i = 0; i < n; ++i)
        out[i] = g_engines[i];
    return n;
}

/* ── String table ─────────────────────────────────────────────────── */

const char *transport_id_to_string(TransportId id) {
    switch (id) {
    case TransportId::NONE:    return "none";
    case TransportId::REALITY: return "reality";
    case TransportId::QUIC:    return "quic";
    case TransportId::HTTP2:   return "http2";
    case TransportId::DOH:     return "doh";
    case TransportId::STUN:    return "stun";
    case TransportId::AUTO:    return "auto";
    }
    return "none";
}

TransportId transport_id_from_string(const char *s) {
    if (!s || !*s)
        return TransportId::NONE;
    if (!strcasecmp(s, "reality") || !strcasecmp(s, "tls"))
        return TransportId::REALITY;
    if (!strcasecmp(s, "quic") || !strcasecmp(s, "quic_initial"))
        return TransportId::QUIC;
    if (!strcasecmp(s, "http2") || !strcasecmp(s, "https") || !strcasecmp(s, "h2"))
        return TransportId::HTTP2;
    if (!strcasecmp(s, "doh") || !strcasecmp(s, "dns"))
        return TransportId::DOH;
    if (!strcasecmp(s, "stun") || !strcasecmp(s, "turn") || !strcasecmp(s, "webrtc"))
        return TransportId::STUN;
    if (!strcasecmp(s, "auto"))
        return TransportId::AUTO;
    return TransportId::NONE;
}

} /* namespace tachyon::transport */
