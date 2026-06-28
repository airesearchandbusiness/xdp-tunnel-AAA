/* SPDX-License-Identifier: MIT */
/*
 * Runtime management API for the Tachyon XDP Tunnel.
 *
 * Exposes a minimal JSON-RPC 2.0 control server over a Unix-domain stream
 * socket so operators (and the `tachyonctl` helper) can query live status,
 * scrape counters and trigger a configuration reload without restarting the
 * daemon. The server is deliberately tiny and dependency-free: requests are
 * parsed with a tolerant hand-rolled scanner and responses are assembled by
 * string concatenation (no external JSON / RPC library is pulled in).
 *
 * The socket is created with mode 0600 (owner-only) and the run loop drives
 * the server cooperatively via poll(): every call is non-blocking and bounded,
 * so it never stalls the data-plane loop and never leaks file descriptors.
 *
 * The run loop supplies behaviour through the Handlers struct of std::function
 * callbacks, binding them to its own state. Any callback may be null, in which
 * case the corresponding method returns a JSON-RPC "not supported" error.
 *
 * Typical wiring in the run loop:
 *
 *     tachyon::mgmt::Handlers h;
 *     h.status = [&]{ return build_status_json(); };
 *     h.stats  = [&]{ return build_stats_json(); };
 *     h.reload = [&]{ return reload_config(); };
 *     tachyon::mgmt::init("/run/tachyon/mgmt.sock", h);
 *     while (running) {
 *         // ... data-plane work ...
 *         tachyon::mgmt::poll();   // services pending control connections
 *     }
 *     tachyon::mgmt::shutdown();
 */
#ifndef TACHYON_MGMT_H
#define TACHYON_MGMT_H

#include <functional>
#include <string>

namespace tachyon::mgmt {

/*
 * Callbacks supplied by the run loop. Each returns a freshly built JSON value:
 *   - status / stats return a JSON *object* body (e.g. "{\"sessions\":1}").
 *   - reload performs the reload and returns whether it succeeded.
 * Any std::function may be left null; the matching RPC method then replies with
 * a JSON-RPC error indicating the method is not supported.
 */
struct Handlers {
    std::function<std::string()> status; // JSON object body of runtime status
    std::function<std::string()> stats;  // JSON object body of counters
    std::function<bool()> reload;        // trigger config reload; true on success
};

/*
 * Create the control socket: AF_UNIX SOCK_STREAM, unlink any stale node, bind
 * to socket_path, chmod 0600, listen, and switch to non-blocking mode. The
 * supplied Handlers are copied and used by subsequent poll() calls.
 *
 * Returns false (and logs via LOG_*) on any error, including a socket_path that
 * does not fit in sockaddr_un.sun_path. A second call replaces the previous
 * server (the old socket is closed/unlinked first).
 */
bool init(const std::string &socket_path, const Handlers &h);

/*
 * Service the control socket without blocking. Accepts every currently pending
 * connection (capped per call to avoid starving the caller), reads one bounded
 * request from each, dispatches it, writes the response and closes the client.
 * Safe to call when the server is inactive (it is then a no-op). Never blocks.
 */
void poll();

/* Close the listening socket and unlink the socket path. Idempotent. */
void shutdown();

/* True while the listening socket is open (i.e. init() succeeded). */
bool is_active();

/*
 * Client helper used by `tachyon ctl`: connect to a mgmt socket, send `request`
 * (a single JSON-RPC line), half-close, and read the reply into `response`.
 * The round-trip is bounded (2s) so a hung daemon cannot wedge the CLI.
 * Returns false (logged) on connect/IO failure or an empty reply.
 */
bool client_call(const std::string &socket_path, const std::string &request, std::string &response);

} // namespace tachyon::mgmt

#endif /* TACHYON_MGMT_H */
