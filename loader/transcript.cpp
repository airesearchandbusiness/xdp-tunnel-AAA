/* SPDX-License-Identifier: MIT */
#include "transcript.h"

#include <cstring>

namespace tachyon::transcript {

namespace {

bool init_ctx(EVP_MD_CTX *ctx) {
    return ctx && EVP_DigestInit_ex(ctx, EVP_sha384(), nullptr) == 1;
}

/* Prepend 4-byte big-endian length then the payload. Anonymous helper so
 * both the constructor's label-absorb and the public absorb() share a
 * single canonicalisation path. */
bool absorb_framed(EVP_MD_CTX *ctx, const void *data, size_t len) {
    if (!ctx)
        return false;
    if (len > UINT32_MAX)
        return false; /* 4-byte length field can't represent >4GiB fields */
    uint8_t lb[4] = {
        static_cast<uint8_t>((len >> 24) & 0xFF),
        static_cast<uint8_t>((len >> 16) & 0xFF),
        static_cast<uint8_t>((len >> 8) & 0xFF),
        static_cast<uint8_t>(len & 0xFF),
    };
    if (EVP_DigestUpdate(ctx, lb, sizeof(lb)) != 1)
        return false;
    if (len && EVP_DigestUpdate(ctx, data, len) != 1)
        return false;
    return true;
}

} /* namespace */

Transcript::Transcript(const char *label) {
    ctx_ = EVP_MD_CTX_new();
    if (!init_ctx(ctx_)) {
        EVP_MD_CTX_free(ctx_);
        ctx_ = nullptr;
        return;
    }
    /* Always absorb the label — even "" — so the framing prefix (4 zero
     * bytes in that case) still distinguishes "no label" from "label of
     * length 1 containing a NUL". */
    const size_t n = label ? std::strlen(label) : 0;
    if (!absorb_framed(ctx_, label, n)) {
        EVP_MD_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

Transcript::~Transcript() {
    EVP_MD_CTX_free(ctx_);
    ctx_ = nullptr;
}

Transcript::Transcript(Transcript &&other) noexcept : ctx_(other.ctx_) { other.ctx_ = nullptr; }

Transcript &Transcript::operator=(Transcript &&other) noexcept {
    if (this != &other) {
        EVP_MD_CTX_free(ctx_);
        ctx_       = other.ctx_;
        other.ctx_ = nullptr;
    }
    return *this;
}

bool Transcript::absorb(const void *data, size_t len) { return absorb_framed(ctx_, data, len); }

bool Transcript::snapshot(uint8_t out[DIGEST_LEN]) const {
    if (!ctx_)
        return false;
    EVP_MD_CTX *copy = EVP_MD_CTX_new();
    if (!copy)
        return false;
    bool ok = EVP_MD_CTX_copy_ex(copy, ctx_) == 1;
    unsigned int olen = 0;
    if (ok)
        ok = EVP_DigestFinal_ex(copy, out, &olen) == 1 && olen == DIGEST_LEN;
    EVP_MD_CTX_free(copy);
    return ok;
}

bool Transcript::finalize(uint8_t out[DIGEST_LEN]) {
    if (!ctx_)
        return false;
    unsigned int olen = 0;
    const bool ok = EVP_DigestFinal_ex(ctx_, out, &olen) == 1 && olen == DIGEST_LEN;
    EVP_MD_CTX_free(ctx_);
    ctx_ = nullptr;
    return ok;
}

Transcript Transcript::clone() const {
    Transcript copy;
    if (!ctx_)
        return copy;
    copy.ctx_ = EVP_MD_CTX_new();
    if (!copy.ctx_)
        return copy;
    if (EVP_MD_CTX_copy_ex(copy.ctx_, ctx_) != 1) {
        EVP_MD_CTX_free(copy.ctx_);
        copy.ctx_ = nullptr;
    }
    return copy;
}

} /* namespace tachyon::transcript */
