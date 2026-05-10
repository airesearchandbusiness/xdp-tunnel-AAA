/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for loader/autoconf.cpp — hardware capability detection.
 *
 * Coverage:
 *   - cpu_has_aesni() returns deterministically (same value across calls)
 *   - iface_mtu("lo") returns the loopback MTU (typically 65536, but at
 *     minimum 576 since the function clamps to [576, 9000])
 *   - iface_mtu("") returns the safe default 1500
 *   - iface_mtu("nonexistent_interface_zzz") returns 1500
 *   - iface_mtu(too-long-name) returns 1500 (graceful failure)
 *   - probe_hardware() picks AES-256-GCM when AES-NI present, ChaCha20 otherwise
 *   - probe_hardware().interface_mtu matches iface_mtu() output
 */

#include <gtest/gtest.h>
#include "autoconf.h"
#include "../src/common.h"

#include <string>

TEST(Autoconf, CpuHasAesniIsDeterministic) {
    /* CPUID is a pure read of fixed CPU bits; calling twice must return
     * the same value. This catches accidental state mutations. */
    bool a = cpu_has_aesni();
    bool b = cpu_has_aesni();
    bool c = cpu_has_aesni();
    EXPECT_EQ(a, b);
    EXPECT_EQ(b, c);
}

TEST(Autoconf, IfaceMtuLoopback) {
    /* Loopback's MTU is 65536 by default but the autoconf function clamps
     * to [576, 9000] for safety. Either the raw kernel value (65536) is
     * rejected and we get the 1500 default, OR the kernel reports a value
     * within [576, 9000] and we accept it. Both outcomes are valid. */
    uint16_t mtu = iface_mtu("lo");
    EXPECT_TRUE(mtu == 1500 || (mtu >= 576 && mtu <= 9000))
        << "Loopback MTU out of expected range: " << mtu;
}

TEST(Autoconf, IfaceMtuEmptyName) {
    /* Empty interface name should return safe default without crashing. */
    EXPECT_EQ(iface_mtu(""), 1500u);
}

TEST(Autoconf, IfaceMtuNonexistentInterface) {
    /* SIOCGIFMTU on a nonexistent interface returns -1; autoconf catches
     * and returns the 1500 default. */
    EXPECT_EQ(iface_mtu("nonexistent_iface_xyz123"), 1500u);
}

TEST(Autoconf, IfaceMtuLongName) {
    /* IFNAMSIZ is 16; passing a longer name is truncated by strncpy.
     * Function should return cleanly (default 1500 or truncated lookup). */
    std::string very_long(64, 'x');
    uint16_t mtu = iface_mtu(very_long);
    EXPECT_TRUE(mtu == 1500 || (mtu >= 576 && mtu <= 9000));
}

TEST(Autoconf, ProbeHardwarePicksConsistentCipher) {
    /* AES-NI presence dictates cipher choice. Verify the contract:
     *   AES-NI present  → AES-256-GCM
     *   AES-NI absent   → ChaCha20-Poly1305
     * Calling probe_hardware twice must yield the same cipher. */
    AutoDetectedConfig a = probe_hardware("lo");
    AutoDetectedConfig b = probe_hardware("lo");

    EXPECT_EQ(a.has_aesni, b.has_aesni);
    EXPECT_EQ(a.cipher_type, b.cipher_type);

    if (a.has_aesni)
        EXPECT_EQ(a.cipher_type, TACHYON_CIPHER_AES256GCM);
    else
        EXPECT_EQ(a.cipher_type, TACHYON_CIPHER_CHACHA20);
}

TEST(Autoconf, ProbeHardwareIfaceMtuMatchesQuery) {
    /* The bundled probe_hardware result should match the standalone
     * iface_mtu() call for the same interface. */
    AutoDetectedConfig probe = probe_hardware("lo");
    uint16_t standalone_mtu = iface_mtu("lo");
    EXPECT_EQ(probe.interface_mtu, standalone_mtu);
}

TEST(Autoconf, ProbeHardwareEmptyIface) {
    /* probe_hardware with empty iface should still produce sensible defaults. */
    AutoDetectedConfig p = probe_hardware("");
    EXPECT_EQ(p.interface_mtu, 1500u);
    /* cipher choice depends on CPU only */
    EXPECT_TRUE(p.cipher_type == TACHYON_CIPHER_AES256GCM ||
                p.cipher_type == TACHYON_CIPHER_CHACHA20);
}
