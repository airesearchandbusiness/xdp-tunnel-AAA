/* SPDX-License-Identifier: MIT */
#include "ip_rate_limiter.h"

#include <algorithm>

namespace tachyon::rl {

static constexpr uint64_t kBackoffBaseSec = 2;
static constexpr uint64_t kBackoffMaxSec = 60;

IpRateLimiter::IpRateLimiter(uint32_t max_entries, uint32_t fail_threshold,
                             uint32_t block_threshold, uint64_t window_sec)
    : max_entries_(max_entries), fail_threshold_(fail_threshold), block_threshold_(block_threshold),
      window_sec_(window_sec) {}

IpRateLimiter::Verdict IpRateLimiter::check(uint32_t ip, uint64_t now_sec) {
    auto it = map_.find(ip);
    if (it == map_.end())
        return Verdict::ALLOW;

    Entry &entry = it->second.second;

    // Window expiry: reset if the window has elapsed since first failure.
    // Guard against a non-monotonic clock going backwards (now < first_failure):
    // an unsigned underflow here would silently lift a block (CWE-191).
    if (now_sec >= entry.first_failure_ts && now_sec - entry.first_failure_ts > window_sec_) {
        // Remove the entry entirely — clean slate.
        lru_.erase(it->second.first);
        map_.erase(it);
        return Verdict::ALLOW;
    }

    if (entry.failure_count >= block_threshold_)
        return Verdict::BLOCK;

    if (entry.failure_count >= fail_threshold_ && now_sec < entry.backoff_until)
        return Verdict::BACKOFF;

    return Verdict::ALLOW;
}

void IpRateLimiter::record_failure(uint32_t ip, uint64_t now_sec) {
    Entry &entry = get_or_create(ip, now_sec);

    if (entry.failure_count == 0)
        entry.first_failure_ts = now_sec;

    entry.failure_count++;

    // Compute exponential backoff once we reach the fail threshold.
    if (entry.failure_count >= fail_threshold_) {
        uint32_t exponent = entry.failure_count - fail_threshold_;
        // Clamp the shift: 2 << 6 already exceeds kBackoffMaxSec, and a shift
        // >= 64 is undefined behaviour (CWE-758). Saturate instead.
        uint64_t backoff = (exponent >= 6) ? kBackoffMaxSec : (kBackoffBaseSec << exponent);
        backoff = std::min(backoff, kBackoffMaxSec);
        entry.backoff_until = now_sec + backoff;
    }
}

void IpRateLimiter::record_success(uint32_t ip) {
    auto it = map_.find(ip);
    if (it == map_.end())
        return;

    lru_.erase(it->second.first);
    map_.erase(it);
}

size_t IpRateLimiter::size() const {
    return map_.size();
}

void IpRateLimiter::evict_oldest() {
    if (lru_.empty())
        return;

    uint32_t oldest_ip = lru_.back();
    lru_.pop_back();
    map_.erase(oldest_ip);
}

IpRateLimiter::Entry &IpRateLimiter::get_or_create(uint32_t ip, uint64_t now_sec) {
    auto it = map_.find(ip);
    if (it != map_.end()) {
        // Move to front of LRU.
        lru_.erase(it->second.first);
        lru_.push_front(ip);
        it->second.first = lru_.begin();
        return it->second.second;
    }

    // Evict if at capacity.
    while (map_.size() >= max_entries_)
        evict_oldest();

    lru_.push_front(ip);
    Entry entry{};
    entry.ip = ip;
    entry.first_failure_ts = now_sec;
    auto [inserted, _] = map_.emplace(ip, std::make_pair(lru_.begin(), entry));
    (void)_;
    return inserted->second.second;
}

} // namespace tachyon::rl
