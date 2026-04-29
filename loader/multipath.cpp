/* SPDX-License-Identifier: MIT */
#include "multipath.h"

#include <algorithm>
#include <cmath>
#include <unistd.h>

namespace tachyon::multipath {

/* ── Internal helpers ──────────────────────────────────────────────────── */

uint64_t PathManager::mono_us() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000ULL +
           static_cast<uint64_t>(ts.tv_nsec) / 1'000ULL;
}

/* ── Lifecycle ─────────────────────────────────────────────────────────── */

PathManager::~PathManager() {
    for (auto &p : paths_) {
        if (p.sock_fd >= 0)
            close(p.sock_fd);
    }
}

size_t PathManager::add_path(int sock_fd, const std::string &local_ip,
                              uint16_t local_port) {
    PathMetrics m;
    m.sock_fd    = sock_fd;
    m.local_ip   = local_ip;
    m.local_port = local_port;
    m.active     = true;
    m.last_rx_us = mono_us();

    paths_.push_back(std::move(m));
    const size_t idx = paths_.size() - 1;

    /* First path is automatically the primary until reelect() is called. */
    if (best_idx_ < 0) {
        best_idx_ = static_cast<int>(idx);
        paths_[idx].primary = true;
    }
    return idx;
}

void PathManager::remove_path(size_t idx) {
    if (idx >= paths_.size())
        return;
    PathMetrics &m = paths_[idx];
    if (m.sock_fd >= 0) {
        close(m.sock_fd);
        m.sock_fd = -1;
    }
    m.active  = false;
    m.primary = false;
    if (best_idx_ == static_cast<int>(idx))
        reelect();
}

/* ── Probe feedback ────────────────────────────────────────────────────── */

void PathManager::on_probe_ack(size_t path_idx, uint64_t rtt_us) {
    if (path_idx >= paths_.size())
        return;
    PathMetrics &m = paths_[path_idx];
    m.probes_acked++;
    m.consecutive_lost = 0;
    m.active = true;
    m.last_rx_us = mono_us();

    if (m.rtt_ewma_us == 0) {
        /* First sample: initialize directly (RFC 6298 §2.2) */
        m.rtt_ewma_us = rtt_us;
        m.rtt_min_us  = rtt_us;
        m.jitter_us   = rtt_us / 2;
    } else {
        /* SRTT = (1-α)·SRTT + α·rtt */
        m.rtt_ewma_us = static_cast<uint64_t>(
            (1.0 - kRttAlpha) * static_cast<double>(m.rtt_ewma_us) +
            kRttAlpha * static_cast<double>(rtt_us));

        /* RTTVAR = (1-β)·RTTVAR + β·|SRTT - rtt| */
        const uint64_t dev = (rtt_us > m.rtt_ewma_us)
                             ? (rtt_us - m.rtt_ewma_us)
                             : (m.rtt_ewma_us - rtt_us);
        m.jitter_us = static_cast<uint64_t>(
            (1.0 - kRttBeta) * static_cast<double>(m.jitter_us) +
            kRttBeta * static_cast<double>(dev));

        if (rtt_us < m.rtt_min_us)
            m.rtt_min_us = rtt_us;
    }

    /* Loss EWMA: ack = 0 loss event */
    m.loss_ppm = static_cast<uint32_t>(
        (1.0 - kLossAlpha) * static_cast<double>(m.loss_ppm));
}

void PathManager::on_probe_timeout(size_t path_idx) {
    if (path_idx >= paths_.size())
        return;
    PathMetrics &m = paths_[path_idx];
    m.probes_sent++;
    m.consecutive_lost++;

    /* Loss EWMA: timeout = 1,000,000 ppm (full-loss event) */
    m.loss_ppm = static_cast<uint32_t>(
        (1.0 - kLossAlpha) * static_cast<double>(m.loss_ppm) +
        kLossAlpha * 1'000'000.0);

    if (m.consecutive_lost >= kDeadProbeThresh) {
        m.active = false;
        if (best_idx_ == static_cast<int>(path_idx))
            reelect();
    }
}

void PathManager::on_data_rx(size_t path_idx, uint64_t now_us) {
    if (path_idx >= paths_.size())
        return;
    PathMetrics &m = paths_[path_idx];
    m.last_rx_us      = now_us;
    m.consecutive_lost = 0;
    m.active           = true;
}

/* ── Election ──────────────────────────────────────────────────────────── */

uint64_t PathManager::score(const PathMetrics &m) {
    if (!m.active || m.sock_fd < 0)
        return std::numeric_limits<uint64_t>::max();

    const double rtt = static_cast<double>(
        m.rtt_ewma_us > 0 ? m.rtt_ewma_us : kDefaultBaseRtt);
    const double loss_factor    = 1.0 + static_cast<double>(m.loss_ppm) / 1e6;
    const double jitter_factor  = 1.0 + static_cast<double>(m.jitter_us) / rtt;
    const double s = rtt * loss_factor * jitter_factor;

    /* Clamp to uint64_t range */
    if (s >= static_cast<double>(std::numeric_limits<uint64_t>::max()))
        return std::numeric_limits<uint64_t>::max() - 1;
    return static_cast<uint64_t>(s);
}

void PathManager::reelect() {
    int      best       = -1;
    uint64_t best_score = std::numeric_limits<uint64_t>::max();

    for (size_t i = 0; i < paths_.size(); ++i) {
        const uint64_t s = score(paths_[i]);
        if (s < best_score) {
            best_score = s;
            best       = static_cast<int>(i);
        }
    }

    for (auto &p : paths_)
        p.primary = false;
    if (best >= 0)
        paths_[best].primary = true;
    best_idx_ = best;
}

/* ── Accessors ─────────────────────────────────────────────────────────── */

int PathManager::best_fd() const {
    if (best_idx_ < 0 || static_cast<size_t>(best_idx_) >= paths_.size())
        return -1;
    return paths_[best_idx_].sock_fd;
}

size_t PathManager::active_count() const {
    size_t n = 0;
    for (const auto &p : paths_)
        if (p.active)
            ++n;
    return n;
}

} /* namespace tachyon::multipath */
