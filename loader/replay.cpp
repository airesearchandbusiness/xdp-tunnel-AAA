/* SPDX-License-Identifier: MIT */
#include "replay.h"

#include <algorithm>

namespace tachyon::replay {

Window::Window(size_t width_bits) {
    /* Clamp to a sane, 64-aligned range. Callers get the exact size they
     * asked for whenever possible; out-of-range values are silently
     * corrected rather than rejected so that a misconfigured .conf still
     * boots the tunnel. */
    if (width_bits < 64)
        width_bits = 64;
    if (width_bits > 65536)
        width_bits = 65536;
    width_bits &= ~static_cast<size_t>(63); /* round down to multiple of 64 */
    if (width_bits == 0)
        width_bits = 64;
    width_ = width_bits;
    bits_.assign(width_bits / 64, 0);
}

void Window::reset() {
    std::fill(bits_.begin(), bits_.end(), 0);
    highest_  = 0;
    any_seen_ = false;
    /* Counters persist across rekeys — they're lifetime stats for the
     * session, not per-window. */
}

bool Window::get_bit(uint64_t seq) const {
    /* seq occupies bit (highest_ - seq) from the top of the window. */
    const uint64_t offset = highest_ - seq;
    if (offset >= width_)
        return false;
    const size_t idx = static_cast<size_t>(offset >> 6);
    const uint64_t mask = 1ULL << (offset & 63);
    return (bits_[idx] & mask) != 0;
}

void Window::set_bit(uint64_t seq) {
    const uint64_t offset = highest_ - seq;
    if (offset >= width_)
        return;
    const size_t idx = static_cast<size_t>(offset >> 6);
    bits_[idx] |= 1ULL << (offset & 63);
}

void Window::shift_window(uint64_t delta) {
    /* The window slides so that the new MSB (offset 0) is the newest seq.
     * Larger offsets are older. A shift by `delta` pushes bits toward
     * higher offsets; anything that falls off the far end is lost — that's
     * exactly the "too old to judge" case callers see as STALE. */
    if (delta == 0)
        return;
    if (delta >= width_) {
        std::fill(bits_.begin(), bits_.end(), 0);
        return;
    }
    const size_t word_shift = static_cast<size_t>(delta >> 6);
    const size_t bit_shift  = static_cast<size_t>(delta & 63);

    if (word_shift) {
        for (size_t i = bits_.size(); i-- > 0;) {
            bits_[i] = (i >= word_shift) ? bits_[i - word_shift] : 0;
        }
    }
    if (bit_shift) {
        uint64_t carry = 0;
        for (size_t i = 0; i < bits_.size(); ++i) {
            const uint64_t new_carry = bits_[i] >> (64 - bit_shift);
            bits_[i]                 = (bits_[i] << bit_shift) | carry;
            carry                    = new_carry;
        }
    }
}

Result Window::peek(uint64_t seq) const {
    if (!any_seen_)
        return Result::ACCEPTED;
    if (seq > highest_)
        return Result::ACCEPTED;
    if (highest_ - seq >= width_)
        return Result::STALE;
    return get_bit(seq) ? Result::REPLAY : Result::ACCEPTED;
}

Result Window::check_and_commit(uint64_t seq) {
    if (!any_seen_) {
        any_seen_ = true;
        highest_  = seq;
        /* bit at offset 0 = the highest seen seq */
        bits_[0]  = 1ULL;
        ++accepted_;
        return Result::ACCEPTED;
    }

    if (seq > highest_) {
        const uint64_t delta = seq - highest_;
        shift_window(delta);
        highest_ = seq;
        bits_[0] |= 1ULL;
        ++accepted_;
        return Result::ACCEPTED;
    }

    if (highest_ - seq >= width_) {
        ++stale_;
        return Result::STALE;
    }

    if (get_bit(seq)) {
        ++replays_;
        return Result::REPLAY;
    }
    set_bit(seq);
    ++accepted_;
    return Result::ACCEPTED;
}

} /* namespace tachyon::replay */
