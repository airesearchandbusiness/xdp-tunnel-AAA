/* SPDX-License-Identifier: MIT */
/*
 * Per-IP handshake rate limiter.
 *
 * Tracks per-IP handshake failure counts and applies exponential backoff
 * to slow down or block misbehaving peers. Uses an LRU eviction policy
 * to bound memory usage.
 *
 * Verdicts:
 *   ALLOW   — IP has no history or is below thresholds; proceed.
 *   BACKOFF — IP has failed enough times; client should wait (exp. backoff).
 *   BLOCK   — IP has exceeded the block threshold within the window; drop.
 *
 * Thread-safety: none — protect externally if shared across threads.
 */
#pragma once

#include <cstdint>
#include <list>
#include <unordered_map>

namespace tachyon::rl {

class IpRateLimiter {
  public:
    enum class Verdict { ALLOW, BACKOFF, BLOCK };

    IpRateLimiter(uint32_t max_entries = 4096, uint32_t fail_threshold = 3,
                  uint32_t block_threshold = 10, uint64_t window_sec = 60);

    Verdict check(uint32_t ip, uint64_t now_sec);
    void record_failure(uint32_t ip, uint64_t now_sec);
    void record_success(uint32_t ip);
    size_t size() const;

  private:
    struct Entry {
        uint32_t ip;
        uint32_t failure_count = 0;
        uint64_t first_failure_ts = 0;
        uint64_t backoff_until = 0;
    };

    void evict_oldest();
    Entry &get_or_create(uint32_t ip, uint64_t now_sec);

    uint32_t max_entries_;
    uint32_t fail_threshold_;
    uint32_t block_threshold_;
    uint64_t window_sec_;

    std::list<uint32_t> lru_;
    std::unordered_map<uint32_t, std::pair<std::list<uint32_t>::iterator, Entry>> map_;
};

} // namespace tachyon::rl
