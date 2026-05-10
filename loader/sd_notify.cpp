/* SPDX-License-Identifier: MIT */
#include "sd_notify.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace tachyon::sd {

namespace {
std::atomic<int> g_fd{-1};
std::string g_path;
std::mutex g_mu;
} /* namespace */

bool enabled() {
    return g_fd.load(std::memory_order_relaxed) >= 0;
}

bool init() {
    const char *sock = std::getenv("NOTIFY_SOCKET");
    if (!sock || sock[0] == '\0')
        return false;

    /* systemd uses either a path (starts with '/') or an abstract namespace
     * socket (starts with '@'). Reject anything else. */
    if (sock[0] != '/' && sock[0] != '@')
        return false;

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;

    g_fd.store(fd, std::memory_order_release);
    g_path = sock;
    return true;
}

bool notify(const char *state) {
    int fd = g_fd.load(std::memory_order_acquire);
    if (fd < 0 || !state)
        return false;

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;

    if (g_path[0] == '@') {
        /* Abstract socket: leading NUL + remainder of path. */
        size_t n = g_path.size();
        if (n >= sizeof(addr.sun_path))
            return false;
        addr.sun_path[0] = '\0';
        memcpy(&addr.sun_path[1], g_path.data() + 1, n - 1);
    } else {
        if (g_path.size() >= sizeof(addr.sun_path))
            return false;
        memcpy(addr.sun_path, g_path.data(), g_path.size());
    }

    size_t addrlen = offsetof(struct sockaddr_un, sun_path) +
                     (g_path[0] == '@' ? g_path.size() : g_path.size() + 1);

    std::lock_guard<std::mutex> lock(g_mu);
    ssize_t n = sendto(fd, state, std::strlen(state), MSG_NOSIGNAL,
                       reinterpret_cast<const struct sockaddr *>(&addr), addrlen);
    return n > 0;
}

bool notify_status(const std::string &status, bool kick_watchdog) {
    std::string msg = "STATUS=" + status;
    if (kick_watchdog)
        msg += "\nWATCHDOG=1";
    return notify(msg.c_str());
}

void shutdown() {
    int fd = g_fd.exchange(-1, std::memory_order_acq_rel);
    if (fd < 0)
        return;
    /* Best-effort STOPPING notification before close. */
    static const char stopping[] = "STOPPING=1\nSTATUS=Shutting down";
    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (g_path[0] == '@') {
        size_t n = g_path.size();
        if (n < sizeof(addr.sun_path)) {
            addr.sun_path[0] = '\0';
            memcpy(&addr.sun_path[1], g_path.data() + 1, n - 1);
        }
    } else if (g_path.size() < sizeof(addr.sun_path)) {
        memcpy(addr.sun_path, g_path.data(), g_path.size());
    }
    size_t addrlen = offsetof(struct sockaddr_un, sun_path) +
                     (g_path[0] == '@' ? g_path.size() : g_path.size() + 1);
    (void)sendto(fd, stopping, sizeof(stopping) - 1, MSG_NOSIGNAL,
                 reinterpret_cast<const struct sockaddr *>(&addr), addrlen);
    close(fd);
    g_path.clear();
}

} /* namespace tachyon::sd */
