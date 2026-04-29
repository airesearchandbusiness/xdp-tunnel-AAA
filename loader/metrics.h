/* SPDX-License-Identifier: MIT */
/*
 * Tachyon - Prometheus/OpenMetrics Exporter
 *
 * Serves tunnel statistics in OpenMetrics text format (RFC 9090) on a
 * configurable localhost TCP port. Zero external dependencies: the HTTP
 * server is a minimal ~100-line embedded implementation.
 *
 * Protocol: HTTP/1.1 GET /metrics → 200 OK + text/plain; version=0.0.4
 * Binding:  localhost (127.0.0.1) only — never exposed externally.
 *
 * Integration:
 *   MetricsExporter mx;
 *   mx.start(9090);                      // bind port
 *   mx.update(stats_snapshot, "tun0");   // update counters
 *   // In CP main loop:
 *   mx.poll();                           // non-blocking accept + serve
 *   mx.stop();                           // close on exit
 *
 * Configuration directives (loader/config.cpp):
 *   MetricsEnabled = true        (default: false)
 *   MetricsPort    = 9090        (default: 9090, range 1024–65535)
 */
#pragma once

#include <cstdint>
#include <string>

/* Forward-declare to avoid including full tachyon.h here */
struct userspace_stats;

namespace tachyon {

class MetricsExporter {
public:
    MetricsExporter()  = default;
    ~MetricsExporter() { stop(); }

    /* Non-copyable: owns socket fd */
    MetricsExporter(const MetricsExporter &) = delete;
    MetricsExporter &operator=(const MetricsExporter &) = delete;

    /* Bind a TCP listening socket on localhost:port.
     * Returns true on success, false on bind/listen failure. */
    bool start(uint16_t port);

    /* Close the listener (idempotent). */
    void stop();

    /* Update the snapshot of tunnel statistics. Thread-unsafe;
     * call from the CP main loop before poll(). */
    void update(const userspace_stats &stats, const std::string &tunnel_name);

    /* Non-blocking: accept up to `max_clients` pending connections per call,
     * serve each with the current snapshot, then close. */
    void poll(int max_clients = 4);

    /* Render current snapshot to OpenMetrics text format. */
    std::string render() const;

    bool     is_running() const { return listen_fd_ >= 0; }
    uint16_t port()       const { return port_; }

private:
    void serve_client(int client_fd) const;

    int         listen_fd_   = -1;
    uint16_t    port_        = 0;
    std::string tunnel_name_;

    /* Snapshot — plain POD copy; updated atomically from CP loop */
    uint64_t snap_rx_packets            = 0;
    uint64_t snap_rx_bytes              = 0;
    uint64_t snap_tx_packets            = 0;
    uint64_t snap_tx_bytes              = 0;
    uint64_t snap_rx_replay_drops       = 0;
    uint64_t snap_rx_crypto_errors      = 0;
    uint64_t snap_rx_invalid_session    = 0;
    uint64_t snap_rx_malformed          = 0;
    uint64_t snap_rx_ratelimit_drops    = 0;
    uint64_t snap_tx_crypto_errors      = 0;
    uint64_t snap_tx_headroom_errors    = 0;
    uint64_t snap_tx_ratelimit_drops    = 0;
    uint64_t snap_rx_ratelimit_data_drops = 0;
    uint64_t snap_rx_roam_events        = 0;
};

} /* namespace tachyon */
