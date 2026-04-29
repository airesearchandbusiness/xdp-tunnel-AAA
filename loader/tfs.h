/* SPDX-License-Identifier: MIT */
/*
 * Tachyon - Traffic Flow Shaper (TFS) — header-only
 *
 * Implements constant-rate traffic output per RFC 9329 §4 (TLS Traffic
 * Flow Shaping) and analogous to IETF IPsec TFC (RFC 4303 §2.7).
 *
 * Objective:
 *   Eliminate packet-size and inter-packet-timing leakage by emitting a
 *   perfectly metronomic stream of fixed-length packets regardless of
 *   actual application traffic rate.
 *
 *   - Real payloads are enqueued and consumed at the scheduled rate.
 *   - When the queue is empty, dummy (zero-filled) packets are emitted.
 *   - Both real and dummy packets are the same pkt_len_ bytes wide.
 *   - The caller is responsible for encrypting dummy packets (they become
 *     indistinguishable from real traffic after AEAD encryption).
 *
 * Configuration:
 *   TFSController tfs(100, 1400);   // 100 pps, 1400 B/packet
 *   tfs.enqueue(buf, len);           // add real payload
 *   std::vector<uint8_t> out;
 *   bool dummy;
 *   if (tfs.get_next(now_us, out, dummy))
 *       send_and_encrypt(out, dummy);
 *
 * Dynamic control:
 *   tfs.set_rate(200);               // double the rate
 *   tfs.set_pkt_len(1200);           // shrink packet size
 *
 * Thread-safety: not thread-safe; single-threaded CP main loop use only.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <vector>
#include <queue>

namespace tachyon {

class TFSController {
public:
    static constexpr uint16_t kMinPktLen  = 64;
    static constexpr uint16_t kMaxPktLen  = 1500;
    static constexpr uint32_t kMaxPps     = 100'000; /* safety cap */

    /* pps: packets per second (0 = disabled). pkt_len: fixed output size. */
    explicit TFSController(uint32_t pps = 0, uint16_t pkt_len = 1400) {
        set_pkt_len(pkt_len);
        set_rate(pps);
    }

    /* ── Enqueue ─────────────────────────────────────────────────────── */

    /* Enqueue a real payload. Chunks larger than pkt_len are fragmented
     * into multiple fixed-size slots transparently. */
    void enqueue(const uint8_t *data, size_t len) {
        while (len > 0) {
            const size_t chunk =
                std::min(len, static_cast<size_t>(pkt_len_));

            Slot s;
            s.data.assign(data, data + chunk);
            s.is_dummy = false;
            queue_.push(std::move(s));

            data += chunk;
            len  -= chunk;
        }
    }

    void enqueue(const std::vector<uint8_t> &data) {
        enqueue(data.data(), data.size());
    }

    /* ── Emit ────────────────────────────────────────────────────────── */

    /* Returns true when it is time to send the next scheduled packet.
     *
     *   now_us   : current monotonic time in microseconds
     *   out      : filled with exactly pkt_len_ bytes
     *   out_dummy: true when the packet is a dummy fill (real data = false)
     *
     * Returns false when TFS is disabled (pps == 0) or the next scheduled
     * send time has not arrived yet. */
    bool get_next(uint64_t now_us, std::vector<uint8_t> &out, bool &out_dummy) {
        if (interval_us_ == 0)
            return false; /* disabled */

        /* Initialise schedule on first call */
        if (next_send_us_ == 0)
            next_send_us_ = now_us;

        if (now_us < next_send_us_)
            return false;

        /* Advance schedule (clamp bursts: skip at most 1 missed slot) */
        next_send_us_ += interval_us_;
        if (next_send_us_ + interval_us_ < now_us)
            next_send_us_ = now_us; /* large gap: re-anchor to now */

        if (!queue_.empty()) {
            const Slot &s = queue_.front();
            out = pad_to_len(s.data);
            out_dummy = false;
            queue_.pop();
        } else {
            out.assign(pkt_len_, 0x00);
            out_dummy = true;
            dummy_count_++;
        }

        total_sent_++;
        return true;
    }

    /* ── Dynamic control ─────────────────────────────────────────────── */

    void set_rate(uint32_t pps) {
        if (pps > kMaxPps)
            pps = kMaxPps;
        target_pps_  = pps;
        interval_us_ = (pps > 0) ? (1'000'000ULL / pps) : 0;
        next_send_us_ = 0; /* re-anchor schedule on rate change */
    }

    void set_pkt_len(uint16_t len) {
        if (len < kMinPktLen)  len = kMinPktLen;
        if (len > kMaxPktLen)  len = kMaxPktLen;
        pkt_len_ = len;
    }

    /* ── Introspection ───────────────────────────────────────────────── */

    uint32_t target_pps()   const { return target_pps_; }
    uint16_t pkt_len()      const { return pkt_len_; }
    uint64_t interval_us()  const { return interval_us_; }
    size_t   queue_depth()  const { return queue_.size(); }
    uint64_t total_sent()   const { return total_sent_; }
    uint64_t dummy_count()  const { return dummy_count_; }
    bool     enabled()      const { return interval_us_ > 0; }

    /* Fraction of sent packets that were dummies (0.0–1.0). */
    double dummy_ratio() const {
        if (total_sent_ == 0) return 0.0;
        return static_cast<double>(dummy_count_) /
               static_cast<double>(total_sent_);
    }

    /* Drop all queued real data (e.g., on shutdown or path change). */
    void flush() {
        std::queue<Slot> empty;
        queue_.swap(empty);
    }

private:
    struct Slot {
        std::vector<uint8_t> data;
        bool is_dummy = false;
    };

    /* Pad or truncate `data` to exactly pkt_len_ bytes. */
    std::vector<uint8_t> pad_to_len(const std::vector<uint8_t> &data) const {
        std::vector<uint8_t> out(pkt_len_, 0x00);
        const size_t copy_len =
            std::min(data.size(), static_cast<size_t>(pkt_len_));
        if (copy_len > 0)
            std::memcpy(out.data(), data.data(), copy_len);
        return out;
    }

    uint16_t pkt_len_      = 1400;
    uint32_t target_pps_   = 0;
    uint64_t interval_us_  = 0;   /* µs per packet (1e6 / pps) */
    uint64_t next_send_us_ = 0;   /* next scheduled emit time  */
    uint64_t total_sent_   = 0;
    uint64_t dummy_count_  = 0;

    std::queue<Slot> queue_;
};

} /* namespace tachyon */
