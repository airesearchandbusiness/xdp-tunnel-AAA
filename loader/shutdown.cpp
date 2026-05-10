/* SPDX-License-Identifier: MIT */
#include "shutdown.h"

#include <csignal>
#include <cstring>

namespace tachyon::shutdown {

volatile sig_atomic_t g_exiting = 0;
volatile sig_atomic_t g_draining = 0;
volatile sig_atomic_t g_reload_config = 0;
volatile sig_atomic_t g_hot_restart = 0;

std::atomic<uint32_t> g_drain_seconds{5};

static void term_handler(int) {
    g_exiting = 1;
    g_draining = 1;
}

static void hup_handler(int) {
    g_reload_config = 1;
}

static void usr1_handler(int) {
    g_hot_restart = 1;
}

void install_handlers() {
    struct sigaction sa {};
    sa.sa_handler = term_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    struct sigaction sa_hup {};
    sa_hup.sa_handler = hup_handler;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = SA_RESTART;
    sigaction(SIGHUP, &sa_hup, nullptr);

    struct sigaction sa_usr1 {};
    sa_usr1.sa_handler = usr1_handler;
    sigemptyset(&sa_usr1.sa_mask);
    sa_usr1.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa_usr1, nullptr);

    /* Ignore SIGPIPE — we handle EPIPE explicitly on socket writes. */
    struct sigaction sa_pipe {};
    sa_pipe.sa_handler = SIG_IGN;
    sigemptyset(&sa_pipe.sa_mask);
    sigaction(SIGPIPE, &sa_pipe, nullptr);
}

void enter_drain(DrainState &state, uint32_t budget_sec, uint64_t now_ts) {
    if (state.active)
        return;
    state.active = true;
    state.entered_ts = now_ts;
    state.budget_sec = budget_sec;
}

bool drain_expired(const DrainState &state, uint64_t now_ts) {
    if (!state.active)
        return true;
    return (now_ts - state.entered_ts) >= state.budget_sec;
}

bool should_exit(const DrainState &state, uint64_t now_ts) {
    if (!g_exiting)
        return false;
    if (!state.active)
        return true; /* Hard exit if drain wasn't entered. */
    return drain_expired(state, now_ts);
}

} /* namespace tachyon::shutdown */
