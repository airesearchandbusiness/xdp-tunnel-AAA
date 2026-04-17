/* SPDX-License-Identifier: MIT */
/*
 * Incremental transcript hash (SHA-384).
 *
 * The v5 handshake uses a running transcript hash to bind every message
 * field into the derived keys: any in-flight modification produces a
 * different transcript, therefore a different session key, therefore AEAD
 * tag failure at the receiver. This file exposes a small OO wrapper that
 * handles the EVP_MD_CTX lifetime, length-prefixing, and branching.
 *
 * Why SHA-384?
 *   - Matches the hybrid-KEX combiner (HKDF-SHA384), so we derive every
 *     session secret with a single hash choice. Saves code and gives a
 *     uniform 192-bit security level that stays above the ML-KEM-768
 *     IND-CCA margin.
 *   - Resists length-extension by construction (truncated SHA-512 output).
 *
 * Absorb semantics:
 *   Every `absorb` call prepends a 4-byte big-endian length field. That
 *   makes the hash unambiguous across variable-length fields — without
 *   it, absorb("ab","c") and absorb("a","bc") would hash to the same
 *   value, a classic length-extension / canonicalisation hazard.
 *
 * Branching:
 *   `clone()` returns a deep copy of the hash state so callers can commit
 *   different prefix histories to separate keys (e.g., PSK vs no-PSK
 *   branches in a single handshake). The MD context is memcpy-safe under
 *   OpenSSL's EVP_MD_CTX_copy_ex semantics.
 */
#ifndef TACHYON_TRANSCRIPT_H
#define TACHYON_TRANSCRIPT_H

#include <cstddef>
#include <cstdint>

#include <openssl/evp.h>

namespace tachyon::transcript {

constexpr size_t DIGEST_LEN = 48; /* SHA-384 */

class Transcript {
  public:
    /* Fresh hash with an application label absorbed as the very first
     * field. This domain-separates transcripts across different protocol
     * stages (e.g., "tch5-akev5" vs "tch5-rekey"). */
    explicit Transcript(const char *label);

    ~Transcript();

    Transcript(const Transcript &)            = delete;
    Transcript &operator=(const Transcript &) = delete;

    Transcript(Transcript &&other) noexcept;
    Transcript &operator=(Transcript &&other) noexcept;

    /* Prepend a 4-byte big-endian length, then the bytes themselves.
     * Returns false on any underlying EVP failure. */
    bool absorb(const void *data, size_t len);

    /* Produce the digest without consuming the context — callers can keep
     * absorbing afterwards. Copies the state internally. */
    bool snapshot(uint8_t out[DIGEST_LEN]) const;

    /* Like snapshot(), but destroys the context afterward — slightly
     * cheaper when you won't absorb again. */
    bool finalize(uint8_t out[DIGEST_LEN]);

    /* Deep-copy the current state. Returns a default-constructed object
     * (check `valid()`) on failure. */
    Transcript clone() const;

    bool valid() const noexcept { return ctx_ != nullptr; }

  private:
    Transcript() = default; /* private — used by clone() on failure */
    EVP_MD_CTX *ctx_ = nullptr;
};

} /* namespace tachyon::transcript */

#endif /* TACHYON_TRANSCRIPT_H */
