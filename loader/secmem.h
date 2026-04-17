/* SPDX-License-Identifier: MIT */
/*
 * Secure-memory utilities.
 *
 * Three responsibilities:
 *   1. RAII buffers for key material: zeroised on destruction, mlock'd so
 *      the kernel can't page them to swap, never copied (moves only).
 *   2. Constant-time primitives for anything touching secrets — equality,
 *      conditional select, swap.
 *   3. A zeroise-me-now hammer (secure_zero) that actually clears the
 *      memory — unlike memset, which the compiler may elide under LTO.
 *
 * Portability:
 *   - mlock(2) requires sufficient RLIMIT_MEMLOCK. If it fails we log a
 *     warning and fall through; the zeroisation guarantee still holds.
 *   - secure_zero uses OPENSSL_cleanse (an asm memory barrier under the
 *     hood), guaranteed not to be optimised away even across LTO.
 *   - const_time_* helpers are branch-free at -O2+ — the compiler turns
 *     the arithmetic into cmov / and / or sequences with no data-dependent
 *     jumps.
 *
 * Thread-safety: SecureBytes is non-thread-safe by construction (owning
 * single-writer). The free functions are pure.
 */
#ifndef TACHYON_SECMEM_H
#define TACHYON_SECMEM_H

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace tachyon::secmem {

/* ── Free functions ─────────────────────────────────────────────────── */

/* Zero `n` bytes at `p`, guaranteed not elided by the optimiser. */
void secure_zero(void *p, size_t n);

/* Constant-time equality for secret comparisons. Returns 1 iff bytes match.
 * Time and memory-access pattern depend only on n, never on contents. */
int const_time_eq(const void *a, const void *b, size_t n);

/* Constant-time selection: returns a if cond == 0, b if cond == 1. cond
 * MUST be exactly 0 or 1 — larger values yield undefined output but no UB. */
uint8_t  const_time_select_u8 (uint8_t cond, uint8_t  a, uint8_t  b);
uint32_t const_time_select_u32(uint8_t cond, uint32_t a, uint32_t b);

/* Constant-time conditional copy of n bytes from src into dst. */
void const_time_copy(uint8_t cond, void *dst, const void *src, size_t n);

/* mlock + madvise(DONTDUMP) on a region, if the kernel allows. Returns
 * true on full success, false on any failure. A false return is advisory
 * — the pointer remains usable, just not protected. */
bool lock_region(void *p, size_t n);
void unlock_region(void *p, size_t n);

/* ── SecureBytes ────────────────────────────────────────────────────── */

/*
 * Heap-owning buffer for secrets. Non-copyable, movable. Destructor
 * zero-fills and munlocks. Constructor mlocks (best-effort).
 *
 * Usage:
 *   SecureBytes tx_key(32);
 *   // ... hkdf_expand into tx_key.data() ...
 *   aead_encrypt(tx_key.data(), ...);
 *   // implicit zero-wipe at end of scope
 */
class SecureBytes {
  public:
    SecureBytes() noexcept = default;
    explicit SecureBytes(size_t n);
    SecureBytes(const uint8_t *src, size_t n);

    ~SecureBytes();

    SecureBytes(const SecureBytes &)            = delete;
    SecureBytes &operator=(const SecureBytes &) = delete;

    SecureBytes(SecureBytes &&other) noexcept;
    SecureBytes &operator=(SecureBytes &&other) noexcept;

    uint8_t       *data() noexcept { return data_; }
    const uint8_t *data() const noexcept { return data_; }
    size_t         size() const noexcept { return size_; }
    bool           empty() const noexcept { return size_ == 0; }

    /* Drop in-place: zero-wipe + release immediately, without waiting for
     * scope exit. Safe to call multiple times. */
    void wipe() noexcept;

    /* Resize with zero-wipe of any bytes being dropped. */
    void resize(size_t n);

  private:
    uint8_t *data_   = nullptr;
    size_t   size_   = 0;
    bool     locked_ = false;
};

} /* namespace tachyon::secmem */

#endif /* TACHYON_SECMEM_H */
