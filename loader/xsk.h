/* SPDX-License-Identifier: MIT */
#pragma once
#include <cstdint>
#include <cstddef>

namespace tachyon::xsk {

struct XskConfig {
    uint32_t queue_id = 0;
    uint32_t frame_size = 4096;
    uint32_t num_frames = 4096;
};

class XskSocket {
public:
    XskSocket() = default;
    ~XskSocket() { close(); }
    XskSocket(const XskSocket &) = delete;
    XskSocket &operator=(const XskSocket &) = delete;

    bool open(const char *ifname, const XskConfig &cfg) {
        (void)ifname; (void)cfg;
        return false;
    }
    void close() { fd_ = -1; }
    int fd() const { return fd_; }
    bool is_open() const { return fd_ >= 0; }

    const uint8_t *recv(size_t *out_len) {
        (void)out_len;
        return nullptr;
    }

    bool send(const uint8_t *data, size_t len) {
        (void)data; (void)len;
        return false;
    }

private:
    int fd_ = -1;
};

} /* namespace tachyon::xsk */
