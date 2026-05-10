/* SPDX-License-Identifier: MIT */
#ifndef TACHYON_WIRE_UTILS_H
#define TACHYON_WIRE_UTILS_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <openssl/rand.h>

namespace tachyon::wire {

struct Writer {
    uint8_t *buf;
    size_t cap;
    size_t pos;

    bool put_u8(uint8_t v) {
        if (pos + 1 > cap)
            return false;
        buf[pos++] = v;
        return true;
    }
    bool put_u16(uint16_t v) {
        if (pos + 2 > cap)
            return false;
        buf[pos++] = static_cast<uint8_t>(v >> 8);
        buf[pos++] = static_cast<uint8_t>(v);
        return true;
    }
    bool put_u24(uint32_t v) {
        if (pos + 3 > cap)
            return false;
        buf[pos++] = static_cast<uint8_t>(v >> 16);
        buf[pos++] = static_cast<uint8_t>(v >> 8);
        buf[pos++] = static_cast<uint8_t>(v);
        return true;
    }
    bool put_u32(uint32_t v) {
        if (pos + 4 > cap)
            return false;
        buf[pos++] = static_cast<uint8_t>(v >> 24);
        buf[pos++] = static_cast<uint8_t>(v >> 16);
        buf[pos++] = static_cast<uint8_t>(v >> 8);
        buf[pos++] = static_cast<uint8_t>(v);
        return true;
    }
    bool put_bytes(const uint8_t *src, size_t len) {
        if (pos + len > cap)
            return false;
        std::memcpy(buf + pos, src, len);
        pos += len;
        return true;
    }
    void patch_u16(size_t at, uint16_t v) {
        assert(at + 2 <= cap); /* CWE-787: catch out-of-bounds patch in debug builds */
        buf[at] = static_cast<uint8_t>(v >> 8);
        buf[at + 1] = static_cast<uint8_t>(v);
    }
    void patch_u24(size_t at, uint32_t v) {
        assert(at + 3 <= cap); /* CWE-787: catch out-of-bounds patch in debug builds */
        buf[at] = static_cast<uint8_t>(v >> 16);
        buf[at + 1] = static_cast<uint8_t>(v >> 8);
        buf[at + 2] = static_cast<uint8_t>(v);
    }
};

inline uint16_t read_u16(const uint8_t *p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
inline uint32_t read_u32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
inline void write_u16(uint8_t *p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}
inline void write_u32(uint8_t *p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
}

inline uint32_t rand_u32() {
    uint32_t r;
    RAND_bytes(reinterpret_cast<uint8_t *>(&r), sizeof(r));
    return r;
}
inline uint64_t rand_u64() {
    uint64_t r;
    RAND_bytes(reinterpret_cast<uint8_t *>(&r), sizeof(r));
    return r;
}

inline size_t pad4(size_t n) {
    return (n + 3) & ~static_cast<size_t>(3);
}

} /* namespace tachyon::wire */

#endif /* TACHYON_WIRE_UTILS_H */
