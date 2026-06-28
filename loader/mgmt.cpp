/* SPDX-License-Identifier: MIT */
#include "mgmt.h"

#include "log.h"

#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef TACHYON_VERSION
#define TACHYON_VERSION "1.x"
#endif

namespace tachyon::mgmt {

namespace {

/* Maximum request we will read from a single client (bytes). Anything larger
 * is rejected as malformed; this bounds memory and parsing work per poll(). */
constexpr size_t kMaxRequest = 8192;

/* Upper bound on clients serviced in one poll() call, so a flood of pending
 * connections cannot starve the data-plane loop that owns the thread. */
constexpr int kMaxClientsPerPoll = 16;

/* JSON-RPC error codes (subset of the spec we actually emit). */
constexpr int kErrParse = -32700;
constexpr int kErrInvalidRequest = -32600;
constexpr int kErrMethodNotFound = -32601;
constexpr int kErrNotSupported = -32000; // server-defined: handler is null

/* Module state. The control server is a process-global singleton, mirroring
 * the other loader subsystems (audit, sd_notify, metrics). */
int g_listen_fd = -1;
std::string g_path;
Handlers g_handlers;

/* ----------------------------------------------------------------------------
 * JSON helpers
 * ------------------------------------------------------------------------- */

/* Escape a string so it can be embedded inside JSON double quotes. Control
 * characters are emitted as \u00XX; the standard short escapes are used where
 * defined. The result does NOT include the surrounding quotes. */
std::string json_escape(const std::string &in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (unsigned char c : in) {
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
                static const char hex[] = "0123456789abcdef";
                out += "\\u00";
                out += hex[(c >> 4) & 0xF];
                out += hex[c & 0xF];
            } else {
                out += static_cast<char>(c);
            }
            break;
        }
    }
    return out;
}

/* Skip ASCII whitespace starting at pos. */
void skip_ws(const std::string &s, size_t &pos) {
    while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos])))
        ++pos;
}

/* Extract the value of a top-level string member named `key` from a JSON
 * object. Tolerant: scans for "key" then the following ':' and a quoted string,
 * decoding the common backslash escapes. Returns false if not found.
 *
 * This is intentionally minimal — it is not a general JSON parser. It is only
 * ever fed short, single-object control requests, and rejects oversized input
 * before reaching here. */
bool extract_string_member(const std::string &s, const char *key, std::string &out) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = 0;
    while ((pos = s.find(needle, pos)) != std::string::npos) {
        size_t p = pos + needle.size();
        skip_ws(s, p);
        if (p >= s.size() || s[p] != ':') {
            pos += needle.size();
            continue;
        }
        ++p;
        skip_ws(s, p);
        if (p >= s.size() || s[p] != '"') {
            pos += needle.size();
            continue;
        }
        ++p; // past opening quote
        std::string value;
        bool closed = false;
        while (p < s.size()) {
            char c = s[p++];
            if (c == '\\') {
                if (p >= s.size())
                    break;
                char e = s[p++];
                switch (e) {
                case '"':
                    value += '"';
                    break;
                case '\\':
                    value += '\\';
                    break;
                case '/':
                    value += '/';
                    break;
                case 'b':
                    value += '\b';
                    break;
                case 'f':
                    value += '\f';
                    break;
                case 'n':
                    value += '\n';
                    break;
                case 'r':
                    value += '\r';
                    break;
                case 't':
                    value += '\t';
                    break;
                case 'u': {
                    // Skip the 4 hex digits; we do not decode the code point but
                    // must not let them leak into the value verbatim.
                    for (int i = 0; i < 4 && p < s.size(); ++i)
                        ++p;
                    break;
                }
                default:
                    value += e;
                    break;
                }
            } else if (c == '"') {
                closed = true;
                break;
            } else {
                value += c;
            }
        }
        if (closed) {
            out = value;
            return true;
        }
        return false; // unterminated string
    }
    return false;
}

/* Extract the raw "id" token to echo back verbatim. The id may be a JSON
 * number, a quoted string, or null. We capture the exact source text (quotes
 * included for strings) so the reply mirrors the request, per JSON-RPC. On
 * failure, defaults to the literal null. Returns false if no id member found. */
bool extract_id_token(const std::string &s, std::string &out) {
    const std::string needle = "\"id\"";
    size_t pos = s.find(needle);
    if (pos == std::string::npos)
        return false;
    size_t p = pos + needle.size();
    skip_ws(s, p);
    if (p >= s.size() || s[p] != ':')
        return false;
    ++p;
    skip_ws(s, p);
    if (p >= s.size())
        return false;

    if (s[p] == '"') {
        // Quoted string id: capture from opening to matching closing quote,
        // keeping the surrounding quotes and inner escapes intact.
        size_t start = p;
        ++p;
        while (p < s.size()) {
            if (s[p] == '\\') {
                p += 2;
                continue;
            }
            if (s[p] == '"') {
                ++p;
                out = s.substr(start, p - start);
                return true;
            }
            ++p;
        }
        return false; // unterminated
    }

    // Number, true/false/null, or other bare token: read until a delimiter.
    size_t start = p;
    while (p < s.size()) {
        char c = s[p];
        if (c == ',' || c == '}' || c == ']' || std::isspace(static_cast<unsigned char>(c)))
            break;
        ++p;
    }
    if (p == start)
        return false;
    out = s.substr(start, p - start);
    return true;
}

/* ----------------------------------------------------------------------------
 * Response assembly
 * ------------------------------------------------------------------------- */

std::string make_result(const std::string &id, const std::string &result_obj) {
    return std::string("{\"jsonrpc\":\"2.0\",\"result\":") + result_obj + ",\"id\":" + id + "}";
}

std::string make_error(const std::string &id, int code, const std::string &message) {
    return std::string("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":") + std::to_string(code) +
           ",\"message\":\"" + json_escape(message) + "\"},\"id\":" + id + "}";
}

/* Build the JSON-RPC response for a single raw request payload. */
std::string dispatch(const std::string &request) {
    // An id we can echo even when the request is malformed (then null).
    std::string id = "null";
    extract_id_token(request, id);

    // Reject obviously non-object payloads early as a parse error.
    {
        size_t first = 0;
        skip_ws(request, first);
        if (first >= request.size() || request[first] != '{')
            return make_error(id, kErrParse, "Parse error");
    }

    std::string method;
    if (!extract_string_member(request, "method", method))
        return make_error(id, kErrInvalidRequest, "Invalid Request: missing method");

    if (method == "ping") {
        return make_result(id, "{\"pong\":true}");
    } else if (method == "version") {
        return make_result(id,
                           std::string("{\"version\":\"") + json_escape(TACHYON_VERSION) + "\"}");
    } else if (method == "status") {
        if (!g_handlers.status)
            return make_error(id, kErrNotSupported, "Method not supported: status");
        std::string body = g_handlers.status();
        if (body.empty())
            body = "{}";
        return make_result(id, body);
    } else if (method == "stats") {
        if (!g_handlers.stats)
            return make_error(id, kErrNotSupported, "Method not supported: stats");
        std::string body = g_handlers.stats();
        if (body.empty())
            body = "{}";
        return make_result(id, body);
    } else if (method == "reload") {
        if (!g_handlers.reload)
            return make_error(id, kErrNotSupported, "Method not supported: reload");
        bool ok = g_handlers.reload();
        return make_result(id, std::string("{\"reloaded\":") + (ok ? "true" : "false") + "}");
    }

    return make_error(id, kErrMethodNotFound, "Method not found");
}

/* ----------------------------------------------------------------------------
 * Socket I/O
 * ------------------------------------------------------------------------- */

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Read one bounded request from a connected client. Returns the bytes read, or
 * an empty string if nothing usable arrived. Tolerates short reads and stops at
 * the request cap. */
std::string read_request(int fd) {
    std::string buf;
    buf.reserve(512);
    char tmp[1024];
    for (;;) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n > 0) {
            size_t want = kMaxRequest - buf.size();
            size_t take = (static_cast<size_t>(n) < want) ? static_cast<size_t>(n) : want;
            buf.append(tmp, take);
            if (buf.size() >= kMaxRequest)
                break; // request too large; truncate (will fail to parse)
            if (static_cast<size_t>(n) < sizeof(tmp))
                break; // drained what was available for now
            continue;
        }
        if (n == 0)
            break; // peer closed its write side
        if (errno == EINTR)
            continue;
        // EAGAIN/EWOULDBLOCK: no more data buffered right now.
        break;
    }
    return buf;
}

/* Write the full response to the client, retrying short writes. Best-effort. */
void write_all(int fd, const std::string &data) {
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        break; // EAGAIN or hard error: drop the rest, client will close.
    }
}

void serve_client(int fd) {
    std::string request = read_request(fd);
    std::string response;
    if (request.empty()) {
        // Nothing arrived (or peer hung up): still emit a parse error so a
        // probing client sees a well-formed reply, but only if we can.
        response = make_error("null", kErrParse, "Parse error: empty request");
    } else {
        response = dispatch(request);
    }
    write_all(fd, response);
}

} // namespace

bool init(const std::string &socket_path, const Handlers &h) {
    // Replace any prior server.
    shutdown();

    if (socket_path.empty()) {
        LOG_ERR("mgmt: empty socket path");
        return false;
    }

    struct sockaddr_un addr {};
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        LOG_ERR("mgmt: socket path too long (%zu >= %zu)", socket_path.size(),
                sizeof(addr.sun_path));
        return false;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        LOG_ERR("mgmt: socket() failed: %s", std::strerror(errno));
        return false;
    }

    // Remove a stale socket node left by a previous (crashed) run. We only
    // unlink it after a successful bind would otherwise hit EADDRINUSE; doing
    // it up front matches the "unlink stale, bind" requirement.
    if (::unlink(socket_path.c_str()) < 0 && errno != ENOENT) {
        LOG_WARN("mgmt: could not unlink stale socket %s: %s", socket_path.c_str(),
                 std::strerror(errno));
    }

    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, socket_path.data(), socket_path.size());

    if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        LOG_ERR("mgmt: bind(%s) failed: %s", socket_path.c_str(), std::strerror(errno));
        ::close(fd);
        return false;
    }

    // Owner-only access. Do this before listen() so no other principal can
    // connect during the window between bind and chmod.
    if (::chmod(socket_path.c_str(), S_IRUSR | S_IWUSR) < 0) {
        LOG_ERR("mgmt: chmod(%s, 0600) failed: %s", socket_path.c_str(), std::strerror(errno));
        ::close(fd);
        ::unlink(socket_path.c_str());
        return false;
    }

    if (listen(fd, 8) < 0) {
        LOG_ERR("mgmt: listen(%s) failed: %s", socket_path.c_str(), std::strerror(errno));
        ::close(fd);
        ::unlink(socket_path.c_str());
        return false;
    }

    set_nonblocking(fd);

    g_listen_fd = fd;
    g_path = socket_path;
    g_handlers = h;
    LOG_INFO("mgmt: control socket listening on %s", socket_path.c_str());
    return true;
}

void poll() {
    if (g_listen_fd < 0)
        return;

    for (int i = 0; i < kMaxClientsPerPoll; ++i) {
        int client = accept(g_listen_fd, nullptr, nullptr);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            // EAGAIN/EWOULDBLOCK: no more pending connections. Any other error
            // (e.g. ECONNABORTED) also ends this poll cycle.
            break;
        }
        // accept() does not inherit O_NONBLOCK, so the client fd is blocking.
        // Bound recv() so a client that connects but stalls cannot hang the
        // data-plane loop that owns this thread.
        struct timeval to {};
        to.tv_usec = 200000; // 200 ms
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
        serve_client(client);
        ::close(client);
    }
}

void shutdown() {
    if (g_listen_fd >= 0) {
        ::close(g_listen_fd);
        g_listen_fd = -1;
    }
    if (!g_path.empty()) {
        ::unlink(g_path.c_str());
        g_path.clear();
    }
    g_handlers = Handlers{};
}

bool is_active() {
    return g_listen_fd >= 0;
}

bool client_call(const std::string &socket_path, const std::string &request,
                 std::string &response) {
    response.clear();
    struct sockaddr_un addr {};
    if (socket_path.empty() || socket_path.size() >= sizeof(addr.sun_path)) {
        LOG_ERR("mgmt: invalid socket path");
        return false;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        LOG_ERR("mgmt: client socket() failed: %s", std::strerror(errno));
        return false;
    }

    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, socket_path.data(), socket_path.size());
    if (connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        LOG_ERR("mgmt: connect(%s) failed: %s", socket_path.c_str(), std::strerror(errno));
        ::close(fd);
        return false;
    }

    // Bound the round-trip; the server services requests cooperatively (~1Hz)
    // so allow a couple of seconds before giving up.
    struct timeval to {};
    to.tv_sec = 2;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));

    // Send the request then half-close so the server reads a clean EOF.
    write_all(fd, request);
    ::shutdown(fd, SHUT_WR);

    char tmp[1024];
    for (;;) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n > 0) {
            size_t want = kMaxRequest - response.size();
            size_t take = (static_cast<size_t>(n) < want) ? static_cast<size_t>(n) : want;
            response.append(tmp, take);
            if (response.size() >= kMaxRequest)
                break;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        break; // EOF, timeout, or error
    }

    ::close(fd);
    return !response.empty();
}

} // namespace tachyon::mgmt
