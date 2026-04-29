/* SPDX-License-Identifier: MIT */
#include "metrics.h"
#include "tachyon.h"   /* userspace_stats */

#include <cstring>
#include <cstdio>
#include <sstream>
#include <cerrno>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace tachyon {

/* ── Start / Stop ──────────────────────────────────────────────────────── */

bool MetricsExporter::start(uint16_t port) {
    if (port == 0)
        return false;

    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0)
        return false;

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Non-blocking accept loop — never blocks the CP main loop */
    int flags = fcntl(listen_fd_, F_GETFL, 0);
    if (flags >= 0)
        fcntl(listen_fd_, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* localhost-only binding */

    if (bind(listen_fd_, reinterpret_cast<struct sockaddr *>(&addr),
             sizeof(addr)) < 0 ||
        listen(listen_fd_, 8) < 0) {
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    port_ = port;
    return true;
}

void MetricsExporter::stop() {
    if (listen_fd_ >= 0) {
        close(listen_fd_);
        listen_fd_ = -1;
    }
}

/* ── Stats snapshot ────────────────────────────────────────────────────── */

void MetricsExporter::update(const userspace_stats &s,
                              const std::string &name) {
    tunnel_name_                  = name;
    snap_rx_packets               = s.rx_packets;
    snap_rx_bytes                 = s.rx_bytes;
    snap_tx_packets               = s.tx_packets;
    snap_tx_bytes                 = s.tx_bytes;
    snap_rx_replay_drops          = s.rx_replay_drops;
    snap_rx_crypto_errors         = s.rx_crypto_errors;
    snap_rx_invalid_session       = s.rx_invalid_session;
    snap_rx_malformed             = s.rx_malformed;
    snap_rx_ratelimit_drops       = s.rx_ratelimit_drops;
    snap_tx_crypto_errors         = s.tx_crypto_errors;
    snap_tx_headroom_errors       = s.tx_headroom_errors;
    snap_tx_ratelimit_drops       = s.tx_ratelimit_drops;
    snap_rx_ratelimit_data_drops  = s.rx_ratelimit_data_drops;
    snap_rx_roam_events           = s.rx_roam_events;
}

/* ── Rendering ─────────────────────────────────────────────────────────── */

std::string MetricsExporter::render() const {
    const std::string &tn = tunnel_name_;
    std::ostringstream ss;

    auto counter = [&](const char *metric, const char *help, uint64_t val) {
        ss << "# HELP tachyon_" << metric << " " << help << "\n"
           << "# TYPE tachyon_" << metric << " counter\n"
           << "tachyon_" << metric << "{tunnel=\"" << tn << "\"} "
           << val << "\n";
    };

    ss << "# Tachyon XDP Tunnel — OpenMetrics exposition\n";
    ss << "# tunnel=\"" << tn << "\"\n\n";

    counter("rx_packets_total",
            "Total data packets received and decrypted successfully",
            snap_rx_packets);
    counter("rx_bytes_total",
            "Total payload bytes received",
            snap_rx_bytes);
    counter("tx_packets_total",
            "Total data packets transmitted and encrypted successfully",
            snap_tx_packets);
    counter("tx_bytes_total",
            "Total payload bytes transmitted",
            snap_tx_bytes);
    counter("rx_replay_drops_total",
            "Packets dropped by the sliding-window replay detector",
            snap_rx_replay_drops);
    counter("rx_crypto_errors_total",
            "AEAD authentication failures on received packets",
            snap_rx_crypto_errors);
    counter("rx_invalid_session_total",
            "Packets dropped due to unknown or expired session ID",
            snap_rx_invalid_session);
    counter("rx_malformed_total",
            "Packets dropped due to malformed encapsulation header",
            snap_rx_malformed);
    counter("rx_ratelimit_drops_total",
            "Control-plane packets dropped by the CP rate limiter",
            snap_rx_ratelimit_drops);
    counter("tx_crypto_errors_total",
            "TX encryption failures",
            snap_tx_crypto_errors);
    counter("tx_headroom_errors_total",
            "TX failures due to insufficient XDP headroom",
            snap_tx_headroom_errors);
    counter("tx_ratelimit_drops_total",
            "TX packets dropped by the data-plane token-bucket rate limiter",
            snap_tx_ratelimit_drops);
    counter("rx_ratelimit_data_drops_total",
            "RX data packets dropped by the data-plane token-bucket rate limiter",
            snap_rx_ratelimit_data_drops);
    counter("rx_roam_events_total",
            "Peer IP or port changes detected (roaming events)",
            snap_rx_roam_events);

    ss << "# EOF\n";
    return ss.str();
}

/* ── HTTP serving ──────────────────────────────────────────────────────── */

void MetricsExporter::poll(int max_clients) {
    if (listen_fd_ < 0)
        return;

    for (int i = 0; i < max_clients; ++i) {
        const int client = accept(listen_fd_, nullptr, nullptr);
        if (client < 0)
            break; /* EAGAIN / EWOULDBLOCK — no more pending connections */
        serve_client(client);
        close(client);
    }
}

void MetricsExporter::serve_client(int client_fd) const {
    /* Drain the HTTP request line (we serve /metrics regardless of path) */
    char req_buf[512];
    /* MSG_DONTWAIT: we already set O_NONBLOCK on the listener, but the
     * accepted socket inherits blocking mode — use MSG_DONTWAIT for safety. */
    recv(client_fd, req_buf, sizeof(req_buf) - 1, MSG_DONTWAIT);

    const std::string body = render();
    std::ostringstream resp;
    resp << "HTTP/1.1 200 OK\r\n"
         << "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
         << "Content-Length: " << body.size() << "\r\n"
         << "Connection: close\r\n"
         << "\r\n"
         << body;

    const std::string r = resp.str();
    /* MSG_NOSIGNAL: prevent SIGPIPE if the client disconnects mid-send */
    send(client_fd, r.data(), r.size(), MSG_NOSIGNAL);
}

} /* namespace tachyon */
