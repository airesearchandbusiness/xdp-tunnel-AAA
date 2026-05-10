/* SPDX-License-Identifier: MIT */
#include "circuit_breaker.h"

#include <algorithm>

namespace tachyon {

CircuitBreaker::CircuitBreaker(uint32_t failure_threshold, uint64_t cooldown_sec,
                               uint64_t base_backoff_sec, uint64_t max_backoff_sec)
    : failure_threshold_(failure_threshold), cooldown_sec_(cooldown_sec),
      base_backoff_sec_(base_backoff_sec), max_backoff_sec_(max_backoff_sec) {}

bool CircuitBreaker::allow_request(uint64_t now_sec) {
    switch (state_) {
    case State::CLOSED:
        return true;

    case State::OPEN:
        if (now_sec >= opened_at_ + cooldown_sec_) {
            state_ = State::HALF_OPEN;
            half_open_probe_issued_ = false;
            return allow_request(now_sec);
        }
        return false;

    case State::HALF_OPEN:
        if (!half_open_probe_issued_) {
            half_open_probe_issued_ = true;
            return true;
        }
        return false;
    }
    return false; // unreachable
}

void CircuitBreaker::record_success(uint64_t /*now_sec*/) {
    if (state_ == State::HALF_OPEN) {
        state_ = State::CLOSED;
        consecutive_failures_ = 0;
        last_failure_ts_ = 0;
        half_open_probe_issued_ = false;
    } else if (state_ == State::CLOSED) {
        consecutive_failures_ = 0;
    }
}

void CircuitBreaker::record_failure(uint64_t now_sec) {
    last_failure_ts_ = now_sec;

    switch (state_) {
    case State::CLOSED:
        ++consecutive_failures_;
        if (consecutive_failures_ >= failure_threshold_) {
            state_ = State::OPEN;
            opened_at_ = now_sec;
        }
        break;

    case State::HALF_OPEN:
        state_ = State::OPEN;
        opened_at_ = now_sec;
        break;

    case State::OPEN:
        // Already open; nothing to do.
        break;
    }
}

CircuitBreaker::State CircuitBreaker::state() const {
    return state_;
}

uint64_t CircuitBreaker::next_retry_sec(uint64_t now_sec) const {
    switch (state_) {
    case State::CLOSED: {
        // Exponential backoff: base * 2^failures, capped at max.
        uint64_t backoff = base_backoff_sec_;
        for (uint32_t i = 0; i < consecutive_failures_; ++i) {
            backoff *= 2;
            if (backoff >= max_backoff_sec_) {
                backoff = max_backoff_sec_;
                break;
            }
        }
        backoff = std::min(backoff, max_backoff_sec_);
        // Cheap deterministic jitter for testability.
        uint64_t jitter = now_sec % 3;
        return backoff + jitter;
    }

    case State::OPEN:
        return opened_at_ + cooldown_sec_;

    case State::HALF_OPEN:
        return now_sec;
    }
    return now_sec; // unreachable
}

void CircuitBreaker::reset() {
    state_ = State::CLOSED;
    consecutive_failures_ = 0;
    last_failure_ts_ = 0;
    opened_at_ = 0;
    half_open_probe_issued_ = false;
}

} // namespace tachyon
