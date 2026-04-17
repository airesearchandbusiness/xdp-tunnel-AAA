/* SPDX-License-Identifier: MIT */
#include "rate_limiter.h"

#include <algorithm>

namespace tachyon::rl {

void bucket_init(TokenBucket &b, uint64_t rate_bps, uint64_t burst, uint64_t now_ns) {
    b.rate_bps = rate_bps;
    b.burst    = (burst > 0) ? burst : rate_bps; /* default burst = 1s worth */
    b.tokens   = b.burst;
    b.last_ns  = now_ns;
}

static void refill(TokenBucket &b, uint64_t now_ns) {
    if (b.rate_bps == 0)
        return; /* unlimited */
    if (now_ns <= b.last_ns)
        return; /* clock didn't advance */
    const uint64_t elapsed_ns = now_ns - b.last_ns;
    /* tokens_to_add = elapsed_ns * rate_bps / 1e9.
     * To avoid overflow on large elapsed, split the multiplication. */
    const uint64_t secs = elapsed_ns / 1'000'000'000ULL;
    const uint64_t frac_ns = elapsed_ns % 1'000'000'000ULL;
    uint64_t add = secs * b.rate_bps + (frac_ns * b.rate_bps) / 1'000'000'000ULL;
    b.tokens = std::min(b.tokens + add, b.burst);
    b.last_ns = now_ns;
}

bool bucket_allow(TokenBucket &b, uint64_t bytes, uint64_t now_ns) {
    if (b.rate_bps == 0)
        return true; /* unlimited */
    refill(b, now_ns);
    if (b.tokens >= bytes) {
        b.tokens -= bytes;
        return true;
    }
    return false;
}

uint64_t bucket_tokens(const TokenBucket &b, uint64_t now_ns) {
    if (b.rate_bps == 0)
        return UINT64_MAX;
    TokenBucket tmp = b; /* non-const copy for refill */
    refill(tmp, now_ns);
    return tmp.tokens;
}

void bucket_set_rate(TokenBucket &b, uint64_t rate_bps, uint64_t burst, uint64_t now_ns) {
    refill(b, now_ns);
    b.rate_bps = rate_bps;
    b.burst    = (burst > 0) ? burst : rate_bps;
    b.tokens   = std::min(b.tokens, b.burst);
}

void bucket_reset(TokenBucket &b, uint64_t now_ns) {
    b.tokens  = b.burst;
    b.last_ns = now_ns;
}

} /* namespace tachyon::rl */
