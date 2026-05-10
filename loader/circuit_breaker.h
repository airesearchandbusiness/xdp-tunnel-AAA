/* SPDX-License-Identifier: MIT */
/*
 * Circuit breaker for the Tachyon XDP Tunnel.
 *
 * Implements a three-state circuit breaker (CLOSED, OPEN, HALF_OPEN) that
 * protects upstream paths from cascading failures. When consecutive failures
 * reach the configured threshold the breaker trips OPEN, blocking all
 * requests until a cooldown period elapses. After cooldown, a single probe
 * request is allowed (HALF_OPEN); success resets the breaker, failure
 * re-opens it.
 *
 * Time source: caller-provided seconds timestamps for deterministic testing.
 */
#pragma once
#include <cstdint>

namespace tachyon {

class CircuitBreaker {
  public:
    enum class State { CLOSED, OPEN, HALF_OPEN };

    CircuitBreaker(uint32_t failure_threshold = 5, uint64_t cooldown_sec = 30,
                   uint64_t base_backoff_sec = 2, uint64_t max_backoff_sec = 60);

    bool allow_request(uint64_t now_sec);
    void record_success(uint64_t now_sec);
    void record_failure(uint64_t now_sec);
    State state() const;
    uint64_t next_retry_sec(uint64_t now_sec) const;
    void reset();

  private:
    uint32_t failure_threshold_;
    uint64_t cooldown_sec_;
    uint64_t base_backoff_sec_;
    uint64_t max_backoff_sec_;

    State state_ = State::CLOSED;
    uint32_t consecutive_failures_ = 0;
    uint64_t last_failure_ts_ = 0;
    uint64_t opened_at_ = 0;
    bool half_open_probe_issued_ = false;
};

} // namespace tachyon
