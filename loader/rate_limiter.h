/* SPDX-License-Identifier: MIT */
/*
 * Userspace token-bucket rate limiter.
 *
 * Controls the per-session control-plane send rate and per-transport
 * framing rate. The XDP data plane has its own in-kernel token bucket
 * (tachyon_rate_cfg); this module governs the slower handshake, cover-
 * traffic, and management paths.
 *
 * Algorithm:
 *   Classic token bucket with lazy refill. On `allow(bytes)`:
 *     1. Compute elapsed_ns since last refill.
 *     2. Add (elapsed_ns × rate_bps / 8 / 1e9) tokens, capped at burst.
 *     3. If tokens >= bytes → consume and return true.
 *     4. Else → reject without consuming, return false.
 *
 * Time source: user-provided nanosecond timestamps (so tests can drive
 * time synthetically). In production, pass `clock_gettime(MONOTONIC)`.
 *
 * Thread-safety: none — one bucket per session, accessed under the
 * session's serialisation context.
 */
#ifndef TACHYON_RATE_LIMITER_H
#define TACHYON_RATE_LIMITER_H

#include <cstdint>

namespace tachyon::rl {

struct TokenBucket {
    uint64_t tokens;     /* current tokens (in bytes) */
    uint64_t burst;      /* max tokens */
    uint64_t rate_bps;   /* bytes per second refill rate */
    uint64_t last_ns;    /* last refill timestamp (ns) */
};

/* Initialise a bucket. If rate_bps==0 the bucket is unlimited
 * (allow() always returns true). */
void bucket_init(TokenBucket &b, uint64_t rate_bps, uint64_t burst, uint64_t now_ns);

/* Try to consume `bytes` tokens. Returns true on success (tokens
 * consumed), false on rate-limit (no state change). */
bool bucket_allow(TokenBucket &b, uint64_t bytes, uint64_t now_ns);

/* Query current fill level without consuming. */
uint64_t bucket_tokens(const TokenBucket &b, uint64_t now_ns);

/* Reconfigure rate and burst live (e.g., after config reload). */
void bucket_set_rate(TokenBucket &b, uint64_t rate_bps, uint64_t burst, uint64_t now_ns);

/* Reset to full burst. Called on rekey to avoid a stall at the start
 * of a new session. */
void bucket_reset(TokenBucket &b, uint64_t now_ns);

} /* namespace tachyon::rl */

#endif /* TACHYON_RATE_LIMITER_H */
