/* SPDX-License-Identifier: MIT */
#pragma once

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <syslog.h>

namespace tachyon::log {

enum class Level : uint8_t { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

struct Config {
    bool json = false;
    bool use_syslog = false;
    Level min_level = Level::INFO;
};

inline std::atomic<uint8_t> g_min_level{static_cast<uint8_t>(Level::INFO)};
inline std::atomic<bool> g_json_mode{false};
inline std::atomic<bool> g_syslog{false};

inline void init(const Config &cfg) {
    g_min_level.store(static_cast<uint8_t>(cfg.min_level), std::memory_order_relaxed);
    g_json_mode.store(cfg.json, std::memory_order_relaxed);
    g_syslog.store(cfg.use_syslog, std::memory_order_relaxed);
    if (cfg.use_syslog)
        openlog("tachyon", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

inline void set_level(Level lvl) {
    g_min_level.store(static_cast<uint8_t>(lvl), std::memory_order_relaxed);
}

inline Level current_level() {
    return static_cast<Level>(g_min_level.load(std::memory_order_relaxed));
}

struct Context {
    const char *session_id = nullptr;
    const char *peer_ip = nullptr;
    const char *event = nullptr;
};

inline thread_local Context g_ctx{};

inline void set_context(const char *key, const char *value) {
    if (strcmp(key, "session_id") == 0)
        g_ctx.session_id = value;
    else if (strcmp(key, "peer_ip") == 0)
        g_ctx.peer_ip = value;
    else if (strcmp(key, "event") == 0)
        g_ctx.event = value;
}

inline void clear_context() {
    g_ctx = {};
}

inline const char *level_str(Level lvl) {
    switch (lvl) {
    case Level::DEBUG:
        return "DEBUG";
    case Level::INFO:
        return "INFO";
    case Level::WARN:
        return "WARN";
    case Level::ERROR:
        return "ERROR";
    }
    return "UNKNOWN";
}

inline int level_to_syslog(Level lvl) {
    switch (lvl) {
    case Level::DEBUG:
        return 7; /* LOG_DEBUG */
    case Level::INFO:
        return 6; /* LOG_INFO */
    case Level::WARN:
        return 4; /* LOG_WARNING */
    case Level::ERROR:
        return 3; /* LOG_ERR */
    }
    return 6;
}

__attribute__((format(printf, 4, 0))) inline void vemit(Level lvl, const char *file, int line,
                                                        const char *fmt, va_list ap) {
    if (static_cast<uint8_t>(lvl) < g_min_level.load(std::memory_order_relaxed))
        return;

    char msg[512];
    vsnprintf(msg, sizeof(msg), fmt, ap);

    char ts[64];
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct tm tm;
    gmtime_r(&now.tv_sec, &tm);
    snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ", tm.tm_year + 1900,
             tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, now.tv_nsec / 1000000);

    if (g_json_mode.load(std::memory_order_relaxed)) {
        char buf[1024];
        int n = snprintf(buf, sizeof(buf), "{\"ts\":\"%s\",\"level\":\"%s\",\"msg\":\"%s\"", ts,
                         level_str(lvl), msg);
        if (file && n < static_cast<int>(sizeof(buf)) - 1)
            n += snprintf(buf + n, sizeof(buf) - n, ",\"file\":\"%s\",\"line\":%d", file, line);
        if (g_ctx.session_id && n < static_cast<int>(sizeof(buf)) - 1)
            n += snprintf(buf + n, sizeof(buf) - n, ",\"session_id\":\"%s\"", g_ctx.session_id);
        if (g_ctx.peer_ip && n < static_cast<int>(sizeof(buf)) - 1)
            n += snprintf(buf + n, sizeof(buf) - n, ",\"peer_ip\":\"%s\"", g_ctx.peer_ip);
        if (g_ctx.event && n < static_cast<int>(sizeof(buf)) - 1)
            n += snprintf(buf + n, sizeof(buf) - n, ",\"event\":\"%s\"", g_ctx.event);
        if (n < static_cast<int>(sizeof(buf)) - 1)
            n += snprintf(buf + n, sizeof(buf) - n, "}");
        fprintf(stderr, "%s\n", buf);
        if (g_syslog.load(std::memory_order_relaxed))
            syslog(level_to_syslog(lvl), "%s", buf);
    } else {
        fprintf(stderr, "%s [%-5s] %s\n", ts, level_str(lvl), msg);
        if (g_syslog.load(std::memory_order_relaxed))
            syslog(level_to_syslog(lvl), "[%s] %s", level_str(lvl), msg);
    }
}

__attribute__((format(printf, 4, 5))) inline void emit(Level lvl, const char *file, int line,
                                                       const char *fmt, ...) {
    if (static_cast<uint8_t>(lvl) < g_min_level.load(std::memory_order_relaxed))
        return;
    va_list ap;
    va_start(ap, fmt);
    vemit(lvl, file, line, fmt, ap);
    va_end(ap);
}

} /* namespace tachyon::log */

/* Undefine syslog.h level constants that collide with our macro names */
#undef LOG_DEBUG
#undef LOG_INFO
#undef LOG_WARN
#undef LOG_ERR

/* Variadic-first form: forwards every argument (including the format string)
 * straight to emit(). This avoids the GNU `##__VA_ARGS__` extension which
 * trips `-Wgnu-zero-variadic-macro-arguments` under strict clang builds. */
#define LOG_DEBUG(...) tachyon::log::emit(tachyon::log::Level::DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)  tachyon::log::emit(tachyon::log::Level::INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  tachyon::log::emit(tachyon::log::Level::WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERR(...)   tachyon::log::emit(tachyon::log::Level::ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_CRYPTO(...) tachyon::log::emit(tachyon::log::Level::DEBUG, __FILE__, __LINE__, __VA_ARGS__)
