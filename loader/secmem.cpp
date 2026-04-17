/* SPDX-License-Identifier: MIT */
#include "secmem.h"

#include <cstdlib>
#include <cstring>
#include <new>
#include <utility>

#include <sys/mman.h>
#include <openssl/crypto.h>

namespace tachyon::secmem {

/* ── Free functions ───────────────────────────────────────────────────── */

void secure_zero(void *p, size_t n) {
    if (p && n)
        OPENSSL_cleanse(p, n); /* asm memory barrier, not elide-able */
}

int const_time_eq(const void *a, const void *b, size_t n) {
    /* CRYPTO_memcmp returns 0 iff equal, in constant time w.r.t. content. */
    return n == 0 ? 1 : (CRYPTO_memcmp(a, b, n) == 0 ? 1 : 0);
}

/* cond ∈ {0, 1}. Build a byte-wide mask (0x00 or 0xFF) with no branch. */
static inline uint8_t mask8(uint8_t cond) {
    return static_cast<uint8_t>(-(static_cast<int>(cond) & 1));
}
static inline uint32_t mask32(uint8_t cond) {
    return static_cast<uint32_t>(-(static_cast<int32_t>(cond) & 1));
}

uint8_t const_time_select_u8(uint8_t cond, uint8_t a, uint8_t b) {
    const uint8_t m = mask8(cond);
    return static_cast<uint8_t>((a & ~m) | (b & m));
}

uint32_t const_time_select_u32(uint8_t cond, uint32_t a, uint32_t b) {
    const uint32_t m = mask32(cond);
    return (a & ~m) | (b & m);
}

void const_time_copy(uint8_t cond, void *dst, const void *src, size_t n) {
    const uint8_t m    = mask8(cond);
    uint8_t       *d   = static_cast<uint8_t *>(dst);
    const uint8_t *s   = static_cast<const uint8_t *>(src);
    for (size_t i = 0; i < n; ++i)
        d[i] = static_cast<uint8_t>((d[i] & ~m) | (s[i] & m));
}

bool lock_region(void *p, size_t n) {
    if (!p || !n)
        return true;
    if (mlock(p, n) != 0)
        return false;
#ifdef MADV_DONTDUMP
    /* Ignore failure — some filesystems / LSMs reject this; it's advisory. */
    (void)madvise(p, n, MADV_DONTDUMP);
#endif
    return true;
}

void unlock_region(void *p, size_t n) {
    if (!p || !n)
        return;
    (void)munlock(p, n); /* best-effort */
}

/* ── SecureBytes ──────────────────────────────────────────────────────── */

SecureBytes::SecureBytes(size_t n) {
    if (n == 0)
        return;
    data_ = static_cast<uint8_t *>(std::calloc(1, n));
    if (!data_)
        throw std::bad_alloc();
    size_   = n;
    locked_ = lock_region(data_, size_);
}

SecureBytes::SecureBytes(const uint8_t *src, size_t n) : SecureBytes(n) {
    if (src && n)
        std::memcpy(data_, src, n);
}

SecureBytes::~SecureBytes() { wipe(); }

SecureBytes::SecureBytes(SecureBytes &&other) noexcept
    : data_(other.data_), size_(other.size_), locked_(other.locked_) {
    other.data_   = nullptr;
    other.size_   = 0;
    other.locked_ = false;
}

SecureBytes &SecureBytes::operator=(SecureBytes &&other) noexcept {
    if (this != &other) {
        wipe();
        data_         = other.data_;
        size_         = other.size_;
        locked_       = other.locked_;
        other.data_   = nullptr;
        other.size_   = 0;
        other.locked_ = false;
    }
    return *this;
}

void SecureBytes::wipe() noexcept {
    if (!data_)
        return;
    secure_zero(data_, size_);
    if (locked_)
        unlock_region(data_, size_);
    std::free(data_);
    data_   = nullptr;
    size_   = 0;
    locked_ = false;
}

void SecureBytes::resize(size_t n) {
    if (n == size_)
        return;
    SecureBytes next(n);
    const size_t keep = (n < size_) ? n : size_;
    if (keep && data_)
        std::memcpy(next.data_, data_, keep);
    *this = std::move(next);
}

} /* namespace tachyon::secmem */
