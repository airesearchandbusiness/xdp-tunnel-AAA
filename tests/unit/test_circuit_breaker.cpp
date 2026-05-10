/* SPDX-License-Identifier: MIT */
#include "../../loader/circuit_breaker.h"

#include <cassert>
#include <cstdio>

using tachyon::CircuitBreaker;
using State = CircuitBreaker::State;

static void test_initial_state_is_closed() {
    CircuitBreaker cb;
    assert(cb.state() == State::CLOSED);
    std::printf("PASS: test_initial_state_is_closed\n");
}

static void test_allow_request_in_closed() {
    CircuitBreaker cb;
    assert(cb.allow_request(100));
    assert(cb.allow_request(101));
    assert(cb.allow_request(102));
    std::printf("PASS: test_allow_request_in_closed\n");
}

static void test_failures_below_threshold_keep_closed() {
    CircuitBreaker cb(5, 30, 2, 60);
    for (uint32_t i = 0; i < 4; ++i) {
        cb.record_failure(100 + i);
    }
    assert(cb.state() == State::CLOSED);
    assert(cb.allow_request(105));
    std::printf("PASS: test_failures_below_threshold_keep_closed\n");
}

static void test_failures_at_threshold_transition_to_open() {
    CircuitBreaker cb(5, 30, 2, 60);
    for (uint32_t i = 0; i < 5; ++i) {
        cb.record_failure(100 + i);
    }
    assert(cb.state() == State::OPEN);
    std::printf("PASS: test_failures_at_threshold_transition_to_open\n");
}

static void test_open_blocks_requests() {
    CircuitBreaker cb(3, 30, 2, 60);
    for (uint32_t i = 0; i < 3; ++i) {
        cb.record_failure(100 + i);
    }
    assert(cb.state() == State::OPEN);
    assert(!cb.allow_request(105));
    assert(!cb.allow_request(110));
    assert(!cb.allow_request(120));
    std::printf("PASS: test_open_blocks_requests\n");
}

static void test_after_cooldown_transitions_to_half_open() {
    CircuitBreaker cb(3, 30, 2, 60);
    for (uint32_t i = 0; i < 3; ++i) {
        cb.record_failure(100);
    }
    assert(cb.state() == State::OPEN);
    // At exactly cooldown boundary (100 + 30 = 130).
    assert(cb.allow_request(130));
    assert(cb.state() == State::HALF_OPEN);
    std::printf("PASS: test_after_cooldown_transitions_to_half_open\n");
}

static void test_success_in_half_open_returns_to_closed() {
    CircuitBreaker cb(3, 30, 2, 60);
    for (uint32_t i = 0; i < 3; ++i) {
        cb.record_failure(100);
    }
    // Transition to HALF_OPEN.
    cb.allow_request(130);
    assert(cb.state() == State::HALF_OPEN);
    cb.record_success(131);
    assert(cb.state() == State::CLOSED);
    // Requests flow again.
    assert(cb.allow_request(132));
    std::printf("PASS: test_success_in_half_open_returns_to_closed\n");
}

static void test_failure_in_half_open_returns_to_open() {
    CircuitBreaker cb(3, 30, 2, 60);
    for (uint32_t i = 0; i < 3; ++i) {
        cb.record_failure(100);
    }
    // Transition to HALF_OPEN.
    cb.allow_request(130);
    assert(cb.state() == State::HALF_OPEN);
    cb.record_failure(131);
    assert(cb.state() == State::OPEN);
    // Should be blocked again until new cooldown from 131.
    assert(!cb.allow_request(140));
    assert(cb.allow_request(161));
    assert(cb.state() == State::HALF_OPEN);
    std::printf("PASS: test_failure_in_half_open_returns_to_open\n");
}

static void test_next_retry_sec_exponential_backoff() {
    CircuitBreaker cb(10, 30, 2, 60);
    // Use now_sec=300 so jitter = 300 % 3 = 0 for clean assertions.
    uint64_t now = 300;

    // 0 failures: base_backoff * 2^0 = 2
    assert(cb.next_retry_sec(now) == 2);

    cb.record_failure(now);
    // 1 failure: 2 * 2^1 = 4
    assert(cb.next_retry_sec(now) == 4);

    cb.record_failure(now);
    // 2 failures: 2 * 2^2 = 8
    assert(cb.next_retry_sec(now) == 8);

    cb.record_failure(now);
    // 3 failures: 2 * 2^3 = 16
    assert(cb.next_retry_sec(now) == 16);

    cb.record_failure(now);
    // 4 failures: 2 * 2^4 = 32
    assert(cb.next_retry_sec(now) == 32);

    cb.record_failure(now);
    // 5 failures: 2 * 2^5 = 64 -> capped at 60
    assert(cb.next_retry_sec(now) == 60);

    cb.record_failure(now);
    // 6 failures: still capped at 60
    assert(cb.next_retry_sec(now) == 60);

    // Test jitter: now_sec=301 -> jitter = 301 % 3 = 1
    cb.reset();
    assert(cb.next_retry_sec(301) == 3); // 2 + 1

    std::printf("PASS: test_next_retry_sec_exponential_backoff\n");
}

static void test_reset_returns_to_initial_state() {
    CircuitBreaker cb(3, 30, 2, 60);
    for (uint32_t i = 0; i < 3; ++i) {
        cb.record_failure(100);
    }
    assert(cb.state() == State::OPEN);
    cb.reset();
    assert(cb.state() == State::CLOSED);
    assert(cb.allow_request(200));
    // next_retry_sec should reflect zero failures (base backoff only).
    // now=300 -> jitter=0, backoff=2
    assert(cb.next_retry_sec(300) == 2);
    std::printf("PASS: test_reset_returns_to_initial_state\n");
}

int main() {
    test_initial_state_is_closed();
    test_allow_request_in_closed();
    test_failures_below_threshold_keep_closed();
    test_failures_at_threshold_transition_to_open();
    test_open_blocks_requests();
    test_after_cooldown_transitions_to_half_open();
    test_success_in_half_open_returns_to_closed();
    test_failure_in_half_open_returns_to_open();
    test_next_retry_sec_exponential_backoff();
    test_reset_returns_to_initial_state();
    std::printf("\nAll circuit breaker tests passed.\n");
    return 0;
}
