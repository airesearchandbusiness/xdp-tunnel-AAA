/* SPDX-License-Identifier: MIT */
#include "padding.h"

#include <cstring>
#include <cmath>
#include <openssl/rand.h>

namespace tachyon::padding {

/* ── Policy string table ────────────────────────────────────────────────── */

Policy policy_from_string(const char *s) {
    if (!s || !*s)
        return Policy::NONE;
    if (!strcasecmp(s, "none") || !strcasecmp(s, "off") || !strcasecmp(s, "false"))
        return Policy::NONE;
    if (!strcasecmp(s, "padme"))
        return Policy::PADME;
    if (!strcasecmp(s, "constant") || !strcasecmp(s, "constant_rate"))
        return Policy::CONSTANT_RATE;
    if (!strcasecmp(s, "random") || !strcasecmp(s, "bimodal"))
        return Policy::RANDOM;
    return Policy::NONE;
}

const char *policy_to_string(Policy p) {
    switch (p) {
    case Policy::NONE:
        return "none";
    case Policy::PADME:
        return "padme";
    case Policy::CONSTANT_RATE:
        return "constant_rate";
    case Policy::RANDOM:
        return "random";
    }
    return "none";
}

/* ── PADME quantisation ─────────────────────────────────────────────────── */

/*
 * PADME reference algorithm (Caltagirone 2019 §4.1):
 *
 *   E = floor(log2(n))
 *   S = floor(log2(E)) + 1
 *   low_bits = max(E - S, 0)          (number of low bits to clear)
 *   padded   = ceil(n / 2^low_bits) * 2^low_bits
 *
 * Uses __builtin_clz for branch-free log2 on unsigned 32-bit values. The
 * function is strictly monotone non-decreasing and always returns >= n.
 */
uint32_t padme_round(uint32_t n) {
    if (n <= 1)
        return 1;

    /* E = floor(log2(n)) — at least 1 because n >= 2. */
    const uint32_t E = 31u - static_cast<uint32_t>(__builtin_clz(n));

    /* S = floor(log2(E)) + 1 — for E=1 we'd take clz(1)=31 producing log2E=0. */
    const uint32_t log2E = (E <= 1) ? 0u : (31u - static_cast<uint32_t>(__builtin_clz(E)));
    const uint32_t S = log2E + 1u;

    /* low_bits = max(E-S, 0). When S >= E the formula degenerates to step=1
     * (no rounding), which preserves monotonicity at the small end of the
     * range. */
    const uint32_t low_bits = (S >= E) ? 0u : (E - S);
    const uint32_t step = 1u << low_bits;
    const uint32_t mask = step - 1u;
    return (n + mask) & ~mask;
}

/* ── Cover-traffic shaper ───────────────────────────────────────────────── */

static uint64_t rand_u64() {
    uint64_t r = 0;
    RAND_bytes(reinterpret_cast<unsigned char *>(&r), sizeof(r));
    return r;
}

/*
 * Sample from exponential distribution with mean mean_ns using inverse CDF
 * transform: -mean * ln(u) where u in (0,1]. Uses CSPRNG entropy.
 */
static uint64_t sample_exponential_ns(uint64_t mean_ns) {
    if (mean_ns == 0)
        return 0;
    /* Uniform in (0, 1] — avoid log(0) by excluding zero */
    uint64_t u_int;
    do {
        u_int = rand_u64();
    } while (u_int == 0);
    const double u = static_cast<double>(u_int) / static_cast<double>(UINT64_MAX);
    const double sample = -static_cast<double>(mean_ns) * log(u);
    if (sample < 0 || sample > 1e18)
        return mean_ns;  /* clamp pathological outliers */
    return static_cast<uint64_t>(sample);
}

void shaper_init(ShaperState &s, uint32_t cover_rate_hz) {
    s = ShaperState{};
    if (cover_rate_hz == 0) {
        s.cover_interval_mean_ms = 0; /* disabled */
    } else {
        s.cover_interval_mean_ms = 1000u / cover_rate_hz;
        if (s.cover_interval_mean_ms == 0)
            s.cover_interval_mean_ms = 1;
    }
    s.bulk_idle_threshold_ms = 50;
}

void shaper_on_real_frame(ShaperState &s, uint64_t now_ns) {
    s.state = State::BULK;
    s.last_activity_ns = now_ns;
    s.real_frames_shaped++;
    /* Reset cover-timer into the future so we don't immediately emit cover
     * on top of a real burst. */
    if (s.cover_interval_mean_ms > 0) {
        const uint64_t mean_ns = static_cast<uint64_t>(s.cover_interval_mean_ms) * 1'000'000ull;
        s.next_cover_ns = now_ns + sample_exponential_ns(mean_ns);
    }
}

uint32_t shaper_poll_cover(ShaperState &s, uint64_t now_ns, uint32_t min_size,
                           uint32_t max_size) {
    /* Cover disabled */
    if (s.cover_interval_mean_ms == 0)
        return 0;
    if (max_size <= min_size)
        return 0;

    const uint64_t idle_threshold_ns =
        static_cast<uint64_t>(s.bulk_idle_threshold_ms) * 1'000'000ull;
    /* Transition BULK → IDLE after inactivity */
    if (s.state == State::BULK && (now_ns - s.last_activity_ns) >= idle_threshold_ns)
        s.state = State::IDLE;

    /* Only emit cover during IDLE */
    if (s.state != State::IDLE)
        return 0;

    /* Not yet time */
    if (now_ns < s.next_cover_ns)
        return 0;

    /* Pick a random size in [min_size, max_size] and round up via PADME so the
     * decoy frame is indistinguishable from a real padded frame. Rejection-
     * sample up to 10 tries to ensure the chosen bin fits within max_size —
     * PADME overhead is < 12% so convergence is effectively instant. */
    uint32_t final_size = 0;
    for (int tries = 0; tries < 10; ++tries) {
        uint32_t rng;
        RAND_bytes(reinterpret_cast<unsigned char *>(&rng), sizeof(rng));
        const uint32_t range = max_size - min_size;
        const uint32_t target = min_size + (rng % range);
        const uint32_t sized = padme_round(target);
        if (sized <= max_size) {
            final_size = sized;
            break;
        }
    }
    if (final_size == 0)
        final_size = padme_round(min_size);

    /* Reschedule next cover frame */
    const uint64_t mean_ns = static_cast<uint64_t>(s.cover_interval_mean_ms) * 1'000'000ull;
    s.next_cover_ns = now_ns + sample_exponential_ns(mean_ns);
    s.cover_frames_emitted++;

    return final_size;
}

uint32_t padding_bin_count(uint32_t min_size, uint32_t max_size) {
    if (min_size >= max_size)
        return 0;
    uint32_t count = 0;
    uint32_t cur = padme_round(min_size);
    while (cur <= max_size) {
        count++;
        uint32_t next = padme_round(cur + 1);
        if (next <= cur) /* safety against infinite loop on overflow */
            break;
        cur = next;
    }
    return count;
}

} /* namespace tachyon::padding */
