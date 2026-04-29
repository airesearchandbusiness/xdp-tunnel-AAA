/* SPDX-License-Identifier: MIT */
#include "metrics.h"

namespace tachyon::metrics {

static Counters g_counters;

Counters &global() { return g_counters; }

void reset() {
    auto &c = g_counters;
    c.hs_initiated.store(0, std::memory_order_relaxed);
    c.hs_completed.store(0, std::memory_order_relaxed);
    c.hs_failed.store(0, std::memory_order_relaxed);
    c.hs_rekeys.store(0, std::memory_order_relaxed);
    c.tx_packets.store(0, std::memory_order_relaxed);
    c.tx_bytes.store(0, std::memory_order_relaxed);
    c.rx_packets.store(0, std::memory_order_relaxed);
    c.rx_bytes.store(0, std::memory_order_relaxed);
    c.replay_accepted.store(0, std::memory_order_relaxed);
    c.replay_dropped.store(0, std::memory_order_relaxed);
    c.replay_stale.store(0, std::memory_order_relaxed);
    c.cover_frames_sent.store(0, std::memory_order_relaxed);
    c.padme_bytes_overhead.store(0, std::memory_order_relaxed);
    c.transport_wrap_ok.store(0, std::memory_order_relaxed);
    c.transport_wrap_fail.store(0, std::memory_order_relaxed);
    c.transport_unwrap_ok.store(0, std::memory_order_relaxed);
    c.transport_unwrap_fail.store(0, std::memory_order_relaxed);
    c.rl_tx_drops.store(0, std::memory_order_relaxed);
    c.rl_rx_drops.store(0, std::memory_order_relaxed);
}

Snapshot snapshot() {
    auto &c = g_counters;
    return {
        c.hs_initiated.load(std::memory_order_relaxed),
        c.hs_completed.load(std::memory_order_relaxed),
        c.hs_failed.load(std::memory_order_relaxed),
        c.hs_rekeys.load(std::memory_order_relaxed),
        c.tx_packets.load(std::memory_order_relaxed),
        c.tx_bytes.load(std::memory_order_relaxed),
        c.rx_packets.load(std::memory_order_relaxed),
        c.rx_bytes.load(std::memory_order_relaxed),
        c.replay_accepted.load(std::memory_order_relaxed),
        c.replay_dropped.load(std::memory_order_relaxed),
        c.replay_stale.load(std::memory_order_relaxed),
        c.cover_frames_sent.load(std::memory_order_relaxed),
        c.padme_bytes_overhead.load(std::memory_order_relaxed),
        c.transport_wrap_ok.load(std::memory_order_relaxed),
        c.transport_wrap_fail.load(std::memory_order_relaxed),
        c.transport_unwrap_ok.load(std::memory_order_relaxed),
        c.transport_unwrap_fail.load(std::memory_order_relaxed),
        c.rl_tx_drops.load(std::memory_order_relaxed),
        c.rl_rx_drops.load(std::memory_order_relaxed),
    };
}

} /* namespace tachyon::metrics */

/* ══════════════════════════════════════════════════════════════════════════
 * MetricsExporter — Prometheus HTTP endpoint (Phase 23)
 * ══════════════════════════════════════════════════════════════════════════ */

#include "tachyon.h"
#include <sstream>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace tachyon {

bool MetricsExporter::start(uint16_t port) {
    if (port == 0) return false;
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) return false;
    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int flags = fcntl(listen_fd_, F_GETFL, 0);
    if (flags >= 0) fcntl(listen_fd_, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listen_fd_, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0 ||
        listen(listen_fd_, 8) < 0) {
        close(listen_fd_); listen_fd_ = -1; return false;
    }
    port_ = port;
    return true;
}

void MetricsExporter::stop() {
    if (listen_fd_ >= 0) { close(listen_fd_); listen_fd_ = -1; }
}

void MetricsExporter::update(const ::userspace_stats &s, const std::string &name) {
    tunnel_name_ = name;
    snap_rx_packets = s.rx_packets; snap_rx_bytes = s.rx_bytes;
    snap_tx_packets = s.tx_packets; snap_tx_bytes = s.tx_bytes;
    snap_rx_replay_drops = s.rx_replay_drops;
    snap_rx_crypto_errors = s.rx_crypto_errors;
    snap_rx_invalid_session = s.rx_invalid_session;
    snap_rx_malformed = s.rx_malformed;
    snap_rx_ratelimit_drops = s.rx_ratelimit_drops;
    snap_tx_crypto_errors = s.tx_crypto_errors;
    snap_tx_headroom_errors = s.tx_headroom_errors;
    snap_tx_ratelimit_drops = s.tx_ratelimit_drops;
    snap_rx_ratelimit_data_drops = s.rx_ratelimit_data_drops;
    snap_rx_roam_events = s.rx_roam_events;
}

std::string MetricsExporter::render() const {
    const auto &tn = tunnel_name_;
    std::ostringstream ss;
    auto counter = [&](const char *m, const char *h, uint64_t v) {
        ss << "# HELP tachyon_" << m << " " << h << "\n"
           << "# TYPE tachyon_" << m << " counter\n"
           << "tachyon_" << m << "{tunnel=\"" << tn << "\"} " << v << "\n";
    };
    counter("rx_packets_total", "Total received packets", snap_rx_packets);
    counter("rx_bytes_total", "Total received bytes", snap_rx_bytes);
    counter("tx_packets_total", "Total transmitted packets", snap_tx_packets);
    counter("tx_bytes_total", "Total transmitted bytes", snap_tx_bytes);
    counter("rx_replay_drops_total", "Replay drops", snap_rx_replay_drops);
    counter("rx_crypto_errors_total", "AEAD failures", snap_rx_crypto_errors);
    counter("rx_invalid_session_total", "Unknown session drops", snap_rx_invalid_session);
    counter("rx_malformed_total", "Malformed drops", snap_rx_malformed);
    counter("rx_ratelimit_drops_total", "CP rate-limit drops", snap_rx_ratelimit_drops);
    counter("tx_crypto_errors_total", "TX crypto failures", snap_tx_crypto_errors);
    counter("tx_headroom_errors_total", "TX headroom failures", snap_tx_headroom_errors);
    counter("tx_ratelimit_drops_total", "TX rate-limit drops", snap_tx_ratelimit_drops);
    counter("rx_ratelimit_data_drops_total", "RX data rate-limit drops", snap_rx_ratelimit_data_drops);
    counter("rx_roam_events_total", "Peer roaming events", snap_rx_roam_events);
    ss << "# EOF\n";
    return ss.str();
}

void MetricsExporter::poll(int max_clients) {
    if (listen_fd_ < 0) return;
    for (int i = 0; i < max_clients; ++i) {
        int client = accept(listen_fd_, nullptr, nullptr);
        if (client < 0) break;
        serve_client(client);
        close(client);
    }
}

void MetricsExporter::serve_client(int client_fd) const {
    char req[512];
    recv(client_fd, req, sizeof(req) - 1, MSG_DONTWAIT);
    std::string body = render();
    std::ostringstream resp;
    resp << "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n"
         << "Content-Length: " << body.size() << "\r\nConnection: close\r\n\r\n" << body;
    std::string r = resp.str();
    send(client_fd, r.data(), r.size(), MSG_NOSIGNAL);
}

} /* namespace tachyon */
