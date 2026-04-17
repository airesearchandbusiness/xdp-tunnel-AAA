/* SPDX-License-Identifier: MIT */
/*
 * Tachyon - Hardware Auto-Configuration
 *
 * Probes local hardware to choose optimal defaults:
 *   - CPUID AES-NI detection → prefer AES-256-GCM when available
 *   - Network interface MTU query via SIOCGIFMTU ioctl
 *   - Conservative obfuscation flags based on environment
 *
 * All probes are best-effort: failures return safe defaults.
 */
#pragma once

#include <cstdint>
#include <string>

/* Result of hardware probing. */
struct AutoDetectedConfig {
    uint8_t  cipher_type;     /* TACHYON_CIPHER_* best for this CPU  */
    uint16_t interface_mtu;   /* Physical interface MTU (bytes)       */
    bool     has_aesni;       /* True if AES-NI / ARM Crypto detected */
};

/* Probe CPU and network interface, return recommended config.
 * phys_iface: physical interface name (e.g. "eth0"). May be empty. */
AutoDetectedConfig probe_hardware(const std::string &phys_iface);

/* Return true if the CPU supports AES hardware acceleration.
 * x86-64: checks CPUID leaf 1, ECX bit 25 (AES-NI).
 * ARM64:  checks AT_HWCAP HWCAP_AES.
 * Other:  returns false (ChaCha20 is the safe universal fallback). */
bool cpu_has_aesni();

/* Query MTU of a network interface via SIOCGIFMTU.
 * Returns 1500 on failure (safe default). */
uint16_t iface_mtu(const std::string &iface_name);
