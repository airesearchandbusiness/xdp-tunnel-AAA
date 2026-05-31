/* SPDX-License-Identifier: MIT */
#pragma once

#include <atomic>
#include <csignal>
#include <cstdint>

namespace tachyon::shutdown {

/* Process-wide signal flags (sig_atomic_t for async-signal safety). Each
 * flag is set by a signal handler and consumed by the main loop. */
extern volatile sig_atomic_t g_exiting;
extern volatile sig_atomic_t g_draining;
extern volatile sig_atomic_t g_reload_config;
extern volatile sig_atomic_t g_hot_restart;

/* Configurable drain budget (seconds). Read once at startup. */
extern std::atomic<uint32_t> g_drain_seconds;

/* Drain phase API. */
struct DrainState {
    uint64_t entered_ts = 0;
    uint64_t budget_sec = 5;
    bool active = false;
};

/* Install handlers for SIGINT, SIGTERM, SIGHUP, SIGUSR1. Idempotent. */
void install_handlers();

/* Initialise drain state with the given budget. Caller stores DrainState. */
void enter_drain(DrainState &state, uint32_t budget_sec, uint64_t now_ts);

/* Returns true if the drain budget has been exhausted (or no drain active). */
bool drain_expired(const DrainState &state, uint64_t now_ts);

/* Convenience: should the main loop exit immediately? After drain expires
 * or g_exiting is set without a drain in progress. */
bool should_exit(const DrainState &state, uint64_t now_ts);

} /* namespace tachyon::shutdown */
