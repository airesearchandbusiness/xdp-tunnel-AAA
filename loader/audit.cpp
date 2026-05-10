/* SPDX-License-Identifier: MIT */
#include "audit.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <netinet/in.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>

namespace tachyon::audit {

namespace {

std::mutex g_mu;
int g_fd = -1; // -1 → syslog mode
bool g_initialized = false;
bool g_syslog_open = false;

void ensure_syslog_open() {
    if (!g_syslog_open) {
        openlog("tachyon-audit", LOG_PID | LOG_NDELAY, LOG_AUTH);
        g_syslog_open = true;
    }
}

void format_timestamp(char *out, size_t n) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct tm tm;
    gmtime_r(&now.tv_sec, &tm);
    snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, now.tv_nsec / 1000000);
}

int build_record(char *buf, size_t buflen, const EventInfo &info) {
    char ts[64];
    format_timestamp(ts, sizeof(ts));

    int n = snprintf(buf, buflen, "{\"ts\":\"%s\",\"event\":\"%s\"", ts, event_name(info.event));
    if (n < 0 || static_cast<size_t>(n) >= buflen)
        return n;

    if (info.peer_ip != 0) {
        struct in_addr addr;
        addr.s_addr = info.peer_ip;
        char ip_str[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)) == nullptr)
            ip_str[0] = '\0';
        int m = snprintf(buf + n, buflen - n, ",\"peer_ip\":\"%s\"", ip_str);
        if (m < 0)
            return m;
        n += m;
        if (static_cast<size_t>(n) >= buflen)
            return n;
    }

    {
        int m = snprintf(buf + n, buflen - n, ",\"session_id\":%u", info.session_id);
        if (m < 0)
            return m;
        n += m;
        if (static_cast<size_t>(n) >= buflen)
            return n;
    }

    if (info.outcome) {
        int m = snprintf(buf + n, buflen - n, ",\"outcome\":\"%s\"", info.outcome);
        if (m < 0)
            return m;
        n += m;
        if (static_cast<size_t>(n) >= buflen)
            return n;
    }

    if (info.details) {
        int m = snprintf(buf + n, buflen - n, ",\"details\":\"%s\"", info.details);
        if (m < 0)
            return m;
        n += m;
        if (static_cast<size_t>(n) >= buflen)
            return n;
    }

    int m = snprintf(buf + n, buflen - n, "}\n");
    if (m < 0)
        return m;
    n += m;
    return n;
}

} // namespace

bool init(const std::string &file_path) {
    std::lock_guard<std::mutex> lock(g_mu);

    // Reset prior state if re-initializing.
    if (g_fd >= 0) {
        ::close(g_fd);
        g_fd = -1;
    }

    g_initialized = true;

    if (file_path.empty()) {
        ensure_syslog_open();
        return true;
    }

    int fd = ::open(file_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if (fd < 0) {
        ensure_syslog_open();
        return false;
    }
    g_fd = fd;
    // Always have syslog available as a fallback.
    ensure_syslog_open();
    return true;
}

void shutdown() {
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_fd >= 0) {
        ::close(g_fd);
        g_fd = -1;
    }
    if (g_syslog_open) {
        closelog();
        g_syslog_open = false;
    }
    g_initialized = false;
}

void emit(const EventInfo &info) {
    std::lock_guard<std::mutex> lock(g_mu);

    if (!g_initialized) {
        ensure_syslog_open();
    }

    char buf[1024];
    int len = build_record(buf, sizeof(buf), info);
    if (len <= 0)
        return;
    if (static_cast<size_t>(len) >= sizeof(buf)) {
        // Truncated; ensure newline terminator at end.
        buf[sizeof(buf) - 2] = '}';
        buf[sizeof(buf) - 1] = '\n';
        len = static_cast<int>(sizeof(buf));
    }

    bool wrote_to_file = false;
    if (g_fd >= 0) {
        ssize_t off = 0;
        bool ok = true;
        while (off < len) {
            ssize_t w = ::write(g_fd, buf + off, static_cast<size_t>(len) - off);
            if (w < 0) {
                ok = false;
                break;
            }
            off += w;
        }
        if (ok) {
            ::fsync(g_fd);
            wrote_to_file = true;
        }
    }

    if (!wrote_to_file) {
        ensure_syslog_open();
        // syslog message must not contain trailing newline.
        size_t slen = static_cast<size_t>(len);
        if (slen > 0 && buf[slen - 1] == '\n') {
            buf[slen - 1] = '\0';
        } else if (slen < sizeof(buf)) {
            buf[slen] = '\0';
        } else {
            buf[sizeof(buf) - 1] = '\0';
        }
        syslog(LOG_AUTH | LOG_INFO, "%s", buf);
    }
}

const char *event_name(Event ev) {
    switch (ev) {
    case Event::SERVICE_START:
        return "service_start";
    case Event::SERVICE_STOP:
        return "service_stop";
    case Event::HANDSHAKE_INIT:
        return "handshake_init";
    case Event::HANDSHAKE_COMPLETE:
        return "handshake_complete";
    case Event::HANDSHAKE_FAIL:
        return "handshake_fail";
    case Event::AUTH_FAIL:
        return "auth_fail";
    case Event::COOKIE_INVALID:
        return "cookie_invalid";
    case Event::REPLAY_DETECTED:
        return "replay_detected";
    case Event::KEY_ROTATION:
        return "key_rotation";
    case Event::CONFIG_RELOAD:
        return "config_reload";
    case Event::PEER_BLOCKED:
        return "peer_blocked";
    }
    return "unknown";
}

} // namespace tachyon::audit
