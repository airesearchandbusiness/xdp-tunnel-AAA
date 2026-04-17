/* SPDX-License-Identifier: MIT */
/*
 * Forward-secure symmetric key ratchet.
 *
 * Produces a one-way chain of AEAD message keys from a 32-byte root secret.
 * Each call to `ratchet_next` derives a fresh message key and overwrites
 * the chain state — compromise of the current state cannot recover any
 * prior key. This is the symmetric half of the Signal Double Ratchet, also
 * used by WireGuard for its derived-key rekeying.
 *
 * Construction:
 *   chain_key ← HKDF-Expand(root, "tch5-ratchet-chain", 32)
 *   for each step i:
 *       msg_key_i  = HKDF-Expand(chain_key, "tch5-ratchet-msg"  || i, 44)
 *                    (32-byte AEAD key followed by a 12-byte nonce prefix)
 *       chain_key  ← HKDF-Expand(chain_key, "tch5-ratchet-next", 32)
 *       wipe old chain_key
 *
 * Out-of-order delivery support:
 *   `ratchet_derive_at(root, counter, out)` is a pure function that returns
 *   the message key for any counter value ≥ 0 without mutating state.
 *   Useful for the receive side when packets arrive reordered — combine
 *   with the replay window to bound how far back you'll decrypt.
 *
 * Zero dynamic allocation; every state structure is a POD that callers
 * keep on their stack or in a SecureBytes buffer.
 */
#ifndef TACHYON_RATCHET_H
#define TACHYON_RATCHET_H

#include <cstddef>
#include <cstdint>

namespace tachyon::ratchet {

constexpr size_t ROOT_KEY_LEN  = 32;
constexpr size_t MSG_KEY_LEN   = 32;
constexpr size_t NONCE_PREFIX_LEN = 12;
constexpr size_t DERIVED_LEN   = MSG_KEY_LEN + NONCE_PREFIX_LEN; /* 44 */

/*
 * Send-side ratchet: mutates state on every advance.
 */
struct SendState {
    uint8_t  chain_key[ROOT_KEY_LEN];
    uint64_t counter; /* next message index to emit */
};

/* Initialise from a root secret. Wipes any prior chain contents. */
void ratchet_init(SendState &s, const uint8_t root[ROOT_KEY_LEN]);

/*
 * Emit the next message key + nonce prefix.
 *
 *   out_key   <- 32-byte AEAD key for this message
 *   out_nonce <- 12-byte nonce prefix; callers append the counter as the
 *                last 4 bytes to form the full AEAD nonce.
 *   out_counter <- the counter that was just consumed (same as .counter
 *                  before the call). Suitable for the wire-format header.
 *
 * After return, the chain is advanced and the previous chain_key is wiped
 * in-place. Overflow at counter==UINT64_MAX is signalled by returning
 * false — callers must rekey the session.
 */
bool ratchet_next(SendState &s, uint8_t out_key[MSG_KEY_LEN],
                  uint8_t out_nonce[NONCE_PREFIX_LEN], uint64_t *out_counter);

/* Destroy all key material in `s`. Idempotent. */
void ratchet_wipe(SendState &s);

/*
 * Pure derivation from a root secret at a specific counter. Does not
 * mutate any state — purely a function of (root, counter). O(1): uses
 * a single HKDF-Expand with the counter mixed into the info label.
 *
 * Returns false on any crypto backend failure; never on counter values.
 */
bool ratchet_derive_at(const uint8_t root[ROOT_KEY_LEN], uint64_t counter,
                       uint8_t out_key[MSG_KEY_LEN],
                       uint8_t out_nonce[NONCE_PREFIX_LEN]);

} /* namespace tachyon::ratchet */

#endif /* TACHYON_RATCHET_H */
