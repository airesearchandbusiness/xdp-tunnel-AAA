/* SPDX-License-Identifier: MIT */
/*
 * Userspace sliding-window replay detector.
 *
 * Mirror of the per-CPU bitmap in src/xdp_core.c, but in plain C++ for
 * control-plane paths (handshake messages, management-channel AEADs).
 * The kernel version is the one in the data-plane hot loop — this one is
 * for the handful of messages that the loader itself authenticates.
 *
 * Semantics (RFC 4303 §3.4.3 style):
 *   - `check_and_commit(seq)` returns ACCEPTED on the first sighting of a
 *     sequence number, REPLAY on a repeat, STALE when the number is below
 *     the current window.
 *   - ACCEPTED is the only outcome that mutates state.
 *   - Window advances lazily on the first accepted seq that exceeds the
 *     current highest — shifted-in bits are cleared in O(window/64).
 *
 * Window:
 *   Default 1024 bits (128 bytes). Tunable at construction — any multiple
 *   of 64 in [64, 65536] is accepted. Larger windows tolerate more
 *   reordering but allocate linearly more memory.
 *
 * Thread-safety:
 *   Not thread-safe; use one instance per session and serialize from the
 *   owning session's lock. The XDP data-plane has its own CAS-based
 *   equivalent for the hot path.
 */
#ifndef TACHYON_REPLAY_H
#define TACHYON_REPLAY_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tachyon::replay {

enum class Result {
    ACCEPTED, /* new, below-or-equal horizon: stored */
    REPLAY,   /* within window but already seen */
    STALE,    /* below window: too old to judge */
};

class Window {
  public:
    /* width_bits must be a multiple of 64 in [64, 65536]. Any other value
     * clamps to the nearest valid boundary and logs a warning once. */
    explicit Window(size_t width_bits = 1024);

    Result check_and_commit(uint64_t seq);

    /* Pure check — does not mutate. Useful for speculative validation. */
    Result peek(uint64_t seq) const;

    /* Reset to initial "nothing seen" state. Called on rekey. */
    void reset();

    /* Introspection */
    uint64_t highest() const noexcept { return highest_; }
    size_t   width()   const noexcept { return width_; }

    /* Stats — all monotonically increasing counters. */
    uint64_t accepted() const noexcept { return accepted_; }
    uint64_t replays()  const noexcept { return replays_; }
    uint64_t stale()    const noexcept { return stale_; }

  private:
    bool get_bit(uint64_t seq) const;
    void set_bit(uint64_t seq);
    void shift_window(uint64_t delta);

    std::vector<uint64_t> bits_;   /* width_/64 words */
    size_t                width_   = 0;
    uint64_t              highest_ = 0; /* highest accepted seq; 0 = none yet */
    bool                  any_seen_ = false;

    uint64_t accepted_ = 0;
    uint64_t replays_  = 0;
    uint64_t stale_    = 0;
};

} /* namespace tachyon::replay */

#endif /* TACHYON_REPLAY_H */
