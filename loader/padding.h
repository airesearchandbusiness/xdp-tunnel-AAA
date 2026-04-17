/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Control Plane - Traffic Analysis Resistance
 *
 * Two orthogonal defenses:
 *
 *  1. PADME (Padmé) size quantisation
 *     Caltagirone et al., USENIX Security 2019. Rounds every packet to one of
 *     a small set of bin sizes, leaking at most log2(log2(n)) bits of size
 *     information per packet (vs. log2(n) for raw length).
 *
 *  2. Maybenot-inspired cover-traffic state machine
 *     Pulls & Dahlberg, PETS 2023. A 3-state FSM (BULK / IDLE / COVER) that
 *     injects decoy frames during idle periods and pads bursts to uniform
 *     length, defeating website-fingerprinting / timing-side-channel attacks
 *     (also used by Mullvad's DAITA).
 *
 * Both modules are pure maths over POD state and carry no external
 * dependencies beyond libc and OpenSSL RAND_bytes() for unbiased PRNG.
 */
#ifndef TACHYON_PADDING_H
#define TACHYON_PADDING_H

#include <cstdint>
#include <cstddef>

namespace tachyon::padding {

/* ── Policy enum ────────────────────────────────────────────────────────── */

enum class Policy : uint8_t {
    NONE = 0,          /* No padding (passthrough) */
    PADME = 1,         /* PADME size quantisation only */
    CONSTANT_RATE = 2, /* Maybenot cover traffic + PADME */
    RANDOM = 3,        /* Legacy bimodal random padding */
};

Policy policy_from_string(const char *s);
const char *policy_to_string(Policy p);

/* ── PADME bin calculator ───────────────────────────────────────────────── */

/*
 * padme_round - Return the smallest PADME bin >= n.
 *
 * PADME formula: given n, compute E = floor(log2(n)), S = floor(log2(E)) + 1,
 * then round n up to a multiple of 2^(E - S).  Pre-computed via bit-twiddle;
 * worst-case overhead is <11% and is provably optimal for the "log-log-bits"
 * leak model.
 *
 * Edge cases:
 *   n <= 1 -> 1
 *   Guaranteed padme_round(n) >= n for all n <= UINT32_MAX / 2.
 */
uint32_t padme_round(uint32_t n);

/*
 * padme_overhead_bytes - padme_round(n) - n, the bytes of added padding.
 */
static inline uint32_t padme_overhead_bytes(uint32_t n) {
    return padme_round(n) - n;
}

/* ── Maybenot-style cover-traffic state machine ────────────────────────── */

enum class State : uint8_t {
    IDLE = 0,  /* No traffic in recent window; may emit cover */
    BULK = 1,  /* Active transfer; may pad within burst */
    COVER = 2, /* Emitting decoy frame */
};

/*
 * A small POD carrying the full state required for shaping decisions.
 * One instance per session/peer. No heap allocation, safe to copy.
 */
struct ShaperState {
    State state = State::IDLE;
    uint64_t last_activity_ns = 0;
    uint64_t next_cover_ns = 0;        /* When to emit the next decoy frame */
    uint32_t cover_interval_mean_ms = 500;
    uint32_t bulk_idle_threshold_ms = 50;
    uint64_t cover_frames_emitted = 0; /* diagnostics */
    uint64_t real_frames_shaped = 0;   /* diagnostics */
};

/*
 * Initialise a shaper. cover_rate_hz is the mean rate of decoy emission during
 * IDLE; pass 0 to disable cover traffic (PADME-only mode).
 */
void shaper_init(ShaperState &s, uint32_t cover_rate_hz);

/*
 * Update the shaper on a real transmitted or received frame. Transitions the
 * state to BULK and rearms the IDLE timer.
 */
void shaper_on_real_frame(ShaperState &s, uint64_t now_ns);

/*
 * Check whether a decoy frame should be emitted right now. Returns the size
 * (in bytes) of the decoy to generate, or 0 if no cover is due. The caller is
 * expected to poll this helper at ~100-500 Hz (e.g. in the existing keepalive
 * tick) and, when a nonzero size is returned, send a sealed decoy frame of
 * that exact length.
 *
 * The emitted size is drawn uniformly from one of the canonical PADME bins
 * bounded by [min_size, max_size], so decoy frames are indistinguishable from
 * real padded frames at the outer-packet level.
 */
uint32_t shaper_poll_cover(ShaperState &s, uint64_t now_ns, uint32_t min_size, uint32_t max_size);

/* ── Diagnostics ────────────────────────────────────────────────────────── */

/*
 * padding_bin_count - Number of distinct PADME bins between [min,max].
 * Useful for χ² uniformity tests on cover-frame size distribution.
 */
uint32_t padding_bin_count(uint32_t min_size, uint32_t max_size);

} /* namespace tachyon::padding */

#endif /* TACHYON_PADDING_H */
