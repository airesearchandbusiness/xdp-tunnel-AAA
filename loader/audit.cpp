/* SPDX-License-Identifier: MIT */
#include "audit.h"

#include <arpa/inet.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <string>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>

namespace tachyon::audit {

namespace {

#ifndef TACHYON_VERSION
#define TACHYON_VERSION "0"
#endif

constexpr size_t kHashLen = 32; // SHA-256 digest length in bytes.

std::mutex g_mu;
int g_fd = -1; // -1 → syslog mode
bool g_initialized = false;
bool g_syslog_open = false;
AuditFormat g_format = AuditFormat::TEXT;

// Tamper-evident hash chain state. g_prev_hash holds the raw digest of the most
// recently emitted record (all-zero genesis before the first record). g_seq is
// the monotonic record number of the next record to be emitted (1-based).
std::array<uint8_t, kHashLen> g_prev_hash{};
uint64_t g_seq = 1;

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

// Map an event to a CEF-style severity (0-10) and the matching ArcSight numeric
// signature/event id. Higher severity for security-relevant failures.
int event_severity(Event ev) {
    switch (ev) {
    case Event::SERVICE_START:
    case Event::SERVICE_STOP:
    case Event::HANDSHAKE_INIT:
    case Event::HANDSHAKE_COMPLETE:
    case Event::KEY_ROTATION:
    case Event::CONFIG_RELOAD:
        return 3;
    case Event::HANDSHAKE_FAIL:
    case Event::COOKIE_INVALID:
        return 6;
    case Event::AUTH_FAIL:
    case Event::REPLAY_DETECTED:
    case Event::PEER_BLOCKED:
        return 8;
    }
    return 5;
}

// Render the peer IP (network byte order) into dotted-quad. Empty string when
// the field is unset (0).
std::string peer_ip_string(uint32_t peer_ip) {
    if (peer_ip == 0)
        return std::string();
    struct in_addr addr;
    addr.s_addr = peer_ip;
    char ip_str[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)) == nullptr)
        ip_str[0] = '\0';
    return std::string(ip_str);
}

void to_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = digits[(bytes[i] >> 4) & 0xF];
        out[i * 2 + 1] = digits[bytes[i] & 0xF];
    }
    out[len * 2] = '\0';
}

std::string hex_string(const std::array<uint8_t, kHashLen> &bytes) {
    char hex[kHashLen * 2 + 1];
    to_hex(bytes.data(), bytes.size(), hex);
    return std::string(hex, kHashLen * 2);
}

// Append a JSON-escaped copy of [s, s+len) to out (no surrounding quotes).
void json_escape_into(std::string &out, const char *s, size_t len) {
    static const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20) {
                out += "\\u00";
                out += digits[(c >> 4) & 0xF];
                out += digits[c & 0xF];
            } else {
                out += static_cast<char>(c);
            }
            break;
        }
    }
}

// Append a CEF-extension-escaped copy of s to out. In CEF extension values the
// characters '\', '=' and newlines must be backslash-escaped.
void cef_escape_into(std::string &out, const char *s, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        char c = s[i];
        switch (c) {
        case '\\':
            out += "\\\\";
            break;
        case '=':
            out += "\\=";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        default:
            out += c;
            break;
        }
    }
}

void cef_escape_into(std::string &out, const std::string &s) {
    cef_escape_into(out, s.data(), s.size());
}

// In the CEF header (pipe-delimited prefix) '\' and '|' must be escaped.
void cef_header_escape_into(std::string &out, const char *s) {
    for (const char *p = s; *p; ++p) {
        if (*p == '\\' || *p == '|')
            out += '\\';
        out += *p;
    }
}

// Build the canonical serialisation that is fed to SHA-256 for record `seq`.
// This is a stable, format-independent representation of exactly the fields
// that appear in the rendered output, so a verifier can reconstruct it from any
// emitted format. Fields are length-prefixed and pipe-joined to avoid any
// ambiguity / injection across field boundaries.
std::string build_canonical(uint64_t seq, const char *ts, const EventInfo &info,
                            const std::string &peer_ip, int severity) {
    auto field = [](std::string &dst, const std::string &v) {
        dst += std::to_string(v.size());
        dst += ':';
        dst += v;
        dst += '|';
    };

    std::string c;
    c.reserve(256);
    c += "tachyon-audit-v1|";
    field(c, std::to_string(seq));
    field(c, ts);
    field(c, event_name(info.event));
    field(c, std::to_string(severity));
    field(c, peer_ip);
    field(c, std::to_string(info.session_id));
    field(c, info.outcome ? std::string(info.outcome) : std::string());
    field(c, info.details ? std::string(info.details) : std::string());
    return c;
}

// Compute SHA-256(prev_hash || canonical) into out.
bool compute_hash(const std::array<uint8_t, kHashLen> &prev, const std::string &canonical,
                  std::array<uint8_t, kHashLen> &out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        return false;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
              EVP_DigestUpdate(ctx, prev.data(), prev.size()) == 1 &&
              EVP_DigestUpdate(ctx, canonical.data(), canonical.size()) == 1;
    unsigned int outlen = 0;
    if (ok)
        ok = EVP_DigestFinal_ex(ctx, out.data(), &outlen) == 1 && outlen == kHashLen;
    EVP_MD_CTX_free(ctx);
    return ok;
}

void render_text(std::string &rec, uint64_t seq, const char *ts, const EventInfo &info,
                 const std::string &peer_ip, const std::string &prev_hex,
                 const std::string &hash_hex) {
    rec += "{\"ts\":\"";
    rec += ts;
    rec += "\",\"event\":\"";
    rec += event_name(info.event);
    rec += "\"";
    if (!peer_ip.empty()) {
        rec += ",\"peer_ip\":\"";
        rec += peer_ip;
        rec += "\"";
    }
    rec += ",\"session_id\":";
    rec += std::to_string(info.session_id);
    if (info.outcome) {
        rec += ",\"outcome\":\"";
        json_escape_into(rec, info.outcome, std::strlen(info.outcome));
        rec += "\"";
    }
    if (info.details) {
        rec += ",\"details\":\"";
        json_escape_into(rec, info.details, std::strlen(info.details));
        rec += "\"";
    }
    rec += ",\"seq\":";
    rec += std::to_string(seq);
    rec += ",\"prev_hash\":\"";
    rec += prev_hex;
    rec += "\",\"hash\":\"";
    rec += hash_hex;
    rec += "\"}\n";
}

void render_json(std::string &rec, uint64_t seq, const char *ts, const EventInfo &info,
                 const std::string &peer_ip, int severity, const std::string &prev_hex,
                 const std::string &hash_hex) {
    rec += "{\"ts\":\"";
    rec += ts;
    rec += "\",\"event\":\"";
    rec += event_name(info.event);
    rec += "\",\"severity\":";
    rec += std::to_string(severity);
    if (!peer_ip.empty()) {
        rec += ",\"peer_ip\":\"";
        rec += peer_ip;
        rec += "\"";
    }
    rec += ",\"session_id\":";
    rec += std::to_string(info.session_id);
    if (info.outcome) {
        rec += ",\"outcome\":\"";
        json_escape_into(rec, info.outcome, std::strlen(info.outcome));
        rec += "\"";
    }
    if (info.details) {
        rec += ",\"details\":\"";
        json_escape_into(rec, info.details, std::strlen(info.details));
        rec += "\"";
    }
    rec += ",\"seq\":";
    rec += std::to_string(seq);
    rec += ",\"prev_hash\":\"";
    rec += prev_hex;
    rec += "\",\"hash\":\"";
    rec += hash_hex;
    rec += "\"}\n";
}

void render_cef(std::string &rec, uint64_t seq, const char *ts, const EventInfo &info,
                const std::string &peer_ip, int severity, const std::string &prev_hex,
                const std::string &hash_hex) {
    // CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    rec += "CEF:0|Tachyon|tunnel|";
    cef_header_escape_into(rec, TACHYON_VERSION);
    rec += "|";
    rec += std::to_string(static_cast<unsigned>(info.event)); // numeric event id
    rec += "|";
    cef_header_escape_into(rec, event_name(info.event));
    rec += "|";
    rec += std::to_string(severity);
    rec += "|";
    // Extension key=value pairs.
    rec += "rt=";
    cef_escape_into(rec, ts, std::strlen(ts));
    if (!peer_ip.empty()) {
        rec += " src=";
        cef_escape_into(rec, peer_ip);
    }
    rec += " cs1Label=sessionId cs1=";
    rec += std::to_string(info.session_id);
    if (info.outcome) {
        rec += " outcome=";
        cef_escape_into(rec, info.outcome, std::strlen(info.outcome));
    }
    if (info.details) {
        rec += " msg=";
        cef_escape_into(rec, info.details, std::strlen(info.details));
    }
    rec += " cn1Label=seq cn1=";
    rec += std::to_string(seq);
    rec += " prevHash=";
    rec += prev_hex;
    rec += " hash=";
    rec += hash_hex;
    rec += "\n";
}

// Build the full record string for the next sequence number and advance the
// chain state. Caller must hold g_mu. Returns empty on hashing failure.
std::string build_record(const EventInfo &info) {
    char ts[64];
    format_timestamp(ts, sizeof(ts));

    std::string peer_ip = peer_ip_string(info.peer_ip);
    int severity = event_severity(info.event);
    uint64_t seq = g_seq;

    std::string canonical = build_canonical(seq, ts, info, peer_ip, severity);

    std::array<uint8_t, kHashLen> hash{};
    if (!compute_hash(g_prev_hash, canonical, hash))
        return std::string();

    std::string prev_hex = hex_string(g_prev_hash);
    std::string hash_hex = hex_string(hash);

    std::string rec;
    rec.reserve(512);
    switch (g_format) {
    case AuditFormat::TEXT:
        render_text(rec, seq, ts, info, peer_ip, prev_hex, hash_hex);
        break;
    case AuditFormat::JSON:
        render_json(rec, seq, ts, info, peer_ip, severity, prev_hex, hash_hex);
        break;
    case AuditFormat::CEF:
        render_cef(rec, seq, ts, info, peer_ip, severity, prev_hex, hash_hex);
        break;
    }

    // Advance chain only after the record has been fully rendered.
    g_prev_hash = hash;
    ++g_seq;
    return rec;
}

} // namespace

bool init(const std::string &file_path, AuditFormat fmt) {
    std::lock_guard<std::mutex> lock(g_mu);

    // Reset prior state if re-initializing.
    if (g_fd >= 0) {
        ::close(g_fd);
        g_fd = -1;
    }

    g_format = fmt;
    // Reset the hash chain to genesis on (re-)initialisation.
    g_prev_hash.fill(0);
    g_seq = 1;
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

void set_format(AuditFormat fmt) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_format = fmt;
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

    std::string rec = build_record(info);
    if (rec.empty())
        return;
    const char *buf = rec.data();
    size_t len = rec.size();

    bool wrote_to_file = false;
    if (g_fd >= 0) {
        size_t off = 0;
        bool ok = true;
        while (off < len) {
            ssize_t w = ::write(g_fd, buf + off, len - off);
            if (w < 0) {
                ok = false;
                break;
            }
            off += static_cast<size_t>(w);
        }
        if (ok) {
            ::fsync(g_fd);
            wrote_to_file = true;
        }
    }

    if (!wrote_to_file) {
        ensure_syslog_open();
        // syslog message must not contain a trailing newline.
        std::string line = rec;
        while (!line.empty() && line.back() == '\n')
            line.pop_back();
        syslog(LOG_AUTH | LOG_INFO, "%s", line.c_str());
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

std::string chain_head() {
    std::lock_guard<std::mutex> lock(g_mu);
    return hex_string(g_prev_hash);
}

} // namespace tachyon::audit
