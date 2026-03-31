/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Unit Tests - Configuration Parser & Validator
 *
 * Tests parse_config(), validate_config(), and tunnel_name_from_conf()
 * from loader/config.cpp against valid, invalid, and edge-case inputs.
 */

#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>
#include <string>
#include <filesystem>

#include "tachyon.h"

/* ══════════════════════════════════════════════════════════════════════════
 * Test Fixture - Creates and cleans up temp config files
 * ══════════════════════════════════════════════════════════════════════════ */

class ConfigTest : public ::testing::Test
{
  protected:
    std::string tmp_dir_;
    std::vector<std::string> tmp_files_;

    void SetUp() override
    {
        tmp_dir_ = std::filesystem::temp_directory_path().string() + "/tachyon_test_XXXXXX";
        char *dir = mkdtemp(tmp_dir_.data());
        ASSERT_NE(dir, nullptr) << "Failed to create temp directory";
        tmp_dir_ = dir;
    }

    void TearDown() override
    {
        for (const auto &f : tmp_files_)
            std::remove(f.c_str());
        std::filesystem::remove_all(tmp_dir_);
    }

    std::string write_config(const std::string &name, const std::string &content)
    {
        std::string path = tmp_dir_ + "/" + name;
        std::ofstream ofs(path);
        EXPECT_TRUE(ofs.is_open()) << "Failed to create " << path;
        ofs << content;
        ofs.close();
        tmp_files_.push_back(path);
        return path;
    }

    /* Full valid config matching tun.conf.example format */
    static constexpr const char *VALID_CONFIG =
        "[Interface]\n"
        "PrivateKey = "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = "
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "PresharedKey = "
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n"
        "ListenPort = 443\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "MimicryType = 1\n"
        "EnableEncryption = true\n"
        "\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n";
};

/* ══════════════════════════════════════════════════════════════════════════
 * parse_config tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(ConfigTest, ParseValidFullConfig)
{
    auto path = write_config("valid.conf", VALID_CONFIG);
    TunnelConfig cfg = parse_config(path);

    EXPECT_EQ(cfg.private_key, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    EXPECT_EQ(cfg.peer_public_key,
              "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    EXPECT_EQ(cfg.psk, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    EXPECT_EQ(cfg.listen_port, 443);
    EXPECT_EQ(cfg.virtual_ip, "10.8.0.1/24");
    EXPECT_EQ(cfg.local_physical_ip, "192.168.1.10");
    EXPECT_EQ(cfg.physical_interface, "eth0");
    EXPECT_EQ(cfg.peer_endpoint_ip, "192.168.1.20");
    EXPECT_EQ(cfg.peer_endpoint_mac, "aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(cfg.peer_inner_ip, "10.8.0.2");
    EXPECT_EQ(cfg.mimicry_type, 1);
    EXPECT_TRUE(cfg.encryption);
}

TEST_F(ConfigTest, ParseMinimalConfigDefaults)
{
    const char *minimal = "PrivateKey = "
                          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                          "PeerPublicKey = "
                          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
                          "VirtualIP = 10.8.0.1/24\n"
                          "LocalPhysicalIP = 192.168.1.10\n"
                          "PhysicalInterface = eth0\n"
                          "[Peer]\n"
                          "EndpointIP = 192.168.1.20\n"
                          "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
                          "InnerIP = 10.8.0.2\n";

    auto path = write_config("minimal.conf", minimal);
    TunnelConfig cfg = parse_config(path);

    /* Verify defaults */
    EXPECT_EQ(cfg.listen_port, TACHYON_DEFAULT_PORT);
    EXPECT_EQ(cfg.mimicry_type, TACHYON_MIMICRY_QUIC);
    EXPECT_TRUE(cfg.encryption);
    EXPECT_TRUE(cfg.psk.empty());
}

TEST_F(ConfigTest, ParseEncryptionDisabled)
{
    std::string content = std::string(VALID_CONFIG) + "EnableEncryption = false\n";
    auto path = write_config("noenc.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(cfg.encryption);
}

TEST_F(ConfigTest, ParseEncryptionDisabledNumeric)
{
    std::string content = std::string(VALID_CONFIG) + "EnableEncryption = 0\n";
    auto path = write_config("noenc0.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(cfg.encryption);
}

TEST_F(ConfigTest, ParseCustomPort)
{
    auto path = write_config(
        "port.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "ListenPort = 51820\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.listen_port, 51820);
}

TEST_F(ConfigTest, ParseCommentsAndWhitespace)
{
    auto path = write_config(
        "comments.conf",
        "# This is a comment\n"
        "; This is also a comment\n"
        "\n"
        "  PrivateKey  =  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  \n"
        "\t PeerPublicKey\t=\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.private_key, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    EXPECT_EQ(cfg.peer_public_key,
              "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
}

TEST_F(ConfigTest, ParseEmptyFile)
{
    auto path = write_config("empty.conf", "");
    TunnelConfig cfg = parse_config(path);
    EXPECT_TRUE(cfg.private_key.empty());
    EXPECT_TRUE(cfg.peer_public_key.empty());
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ParseNonexistentFile)
{
    TunnelConfig cfg = parse_config("/nonexistent/path/does_not_exist.conf");
    EXPECT_TRUE(cfg.private_key.empty());
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ParseMimicryTypeNone)
{
    std::string content =
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "MimicryType = 0\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n";
    auto path = write_config("nomimicry.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.mimicry_type, TACHYON_MIMICRY_NONE);
}

/* ══════════════════════════════════════════════════════════════════════════
 * validate_config tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(ConfigTest, ValidateFullConfig)
{
    auto path = write_config("full.conf", VALID_CONFIG);
    TunnelConfig cfg = parse_config(path);
    EXPECT_TRUE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidateMissingPrivateKey)
{
    auto path = write_config(
        "no_privkey.conf",
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidateMissingPeerPublicKey)
{
    auto path = write_config(
        "no_peerpub.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidateMissingVirtualIP)
{
    auto path = write_config(
        "no_vip.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidateMissingPhysicalInterface)
{
    auto path = write_config(
        "no_iface.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidateShortPrivateKey)
{
    auto path = write_config(
        "short_key.conf",
        "PrivateKey = aabbccdd\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidateInvalidMACFormat)
{
    auto path = write_config(
        "bad_mac.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = not_a_mac\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidateInvalidEndpointIP)
{
    auto path = write_config(
        "bad_ip.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "[Peer]\n"
        "EndpointIP = not_an_ip\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidatePortZero)
{
    auto path = write_config(
        "port0.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "ListenPort = 0\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidatePortTooHigh)
{
    auto path = write_config(
        "port_high.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "ListenPort = 70000\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(validate_config(cfg));
}

/* ══════════════════════════════════════════════════════════════════════════
 * tunnel_name_from_conf tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(ConfigTest, TunnelNameFromFullPath)
{
    EXPECT_EQ(tunnel_name_from_conf("/etc/tachyon/test.conf"), "test");
}

TEST_F(ConfigTest, TunnelNameFromRelativePath)
{
    EXPECT_EQ(tunnel_name_from_conf("./test.conf"), "test");
}

TEST_F(ConfigTest, TunnelNameFromBareName)
{
    EXPECT_EQ(tunnel_name_from_conf("mytest.conf"), "mytest");
}

TEST_F(ConfigTest, TunnelNameFromMultipleDots)
{
    EXPECT_EQ(tunnel_name_from_conf("/path/to/foo.bar.conf"), "foo");
}

TEST_F(ConfigTest, TunnelNameNoExtension)
{
    EXPECT_EQ(tunnel_name_from_conf("/path/to/tunnelname"), "tunnelname");
}

TEST_F(ConfigTest, TunnelNameDeepPath)
{
    EXPECT_EQ(tunnel_name_from_conf("/a/b/c/d/e/tunnel.conf"), "tunnel");
}
