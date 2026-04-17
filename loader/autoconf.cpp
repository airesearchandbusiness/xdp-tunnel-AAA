/* SPDX-License-Identifier: MIT */
/*
 * Tachyon - Hardware Auto-Configuration
 */

#include "tachyon.h"
#include "autoconf.h"

#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#elif defined(__aarch64__)
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * AES-NI / Hardware Crypto Detection
 * ══════════════════════════════════════════════════════════════════════════ */

bool cpu_has_aesni() {
#if defined(__x86_64__) || defined(__i386__)
    /* CPUID leaf 1, ECX bit 25 = AES-NI (Intel/AMD) */
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    __cpuid(1, eax, ebx, ecx, edx);
    return (ecx >> 25) & 1;
#elif defined(__aarch64__)
    /* ARM Cryptography Extension — available via AT_HWCAP */
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#else
    return false;
#endif
}

/* ══════════════════════════════════════════════════════════════════════════
 * Interface MTU Query
 * ══════════════════════════════════════════════════════════════════════════ */

uint16_t iface_mtu(const std::string &iface_name) {
    if (iface_name.empty())
        return 1500;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 1500;

    struct ifreq ifr {};
    /* iface_name is validated by is_valid_tunnel_name before this call */
    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);

    uint16_t mtu = 1500;
    if (ioctl(fd, SIOCGIFMTU, &ifr) == 0) {
        int m = ifr.ifr_mtu;
        if (m >= 576 && m <= 9000)
            mtu = static_cast<uint16_t>(m);
    }
    close(fd);
    return mtu;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Hardware Probe Entry Point
 * ══════════════════════════════════════════════════════════════════════════ */

AutoDetectedConfig probe_hardware(const std::string &phys_iface) {
    AutoDetectedConfig result{};

    result.has_aesni = cpu_has_aesni();
    result.cipher_type = result.has_aesni
                             ? TACHYON_CIPHER_AES256GCM
                             : TACHYON_CIPHER_CHACHA20;

    result.interface_mtu = iface_mtu(phys_iface);

    LOG_INFO("AutoConf: AES-NI=%s  cipher=%s  iface_mtu=%u",
             result.has_aesni ? "yes" : "no",
             result.has_aesni ? "AES-256-GCM" : "ChaCha20-Poly1305",
             result.interface_mtu);

    return result;
}
