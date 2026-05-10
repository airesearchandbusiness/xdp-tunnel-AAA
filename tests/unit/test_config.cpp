/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Unit Tests - Configuration Parser & Validator
 */

#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>
#include <string>
#include <filesystem>

#include "tachyon.h"

class ConfigTest : public ::testing::Test {
  protected:
    std::string tmp_dir_;
    std::vector<std::string> tmp_files_;

    void SetUp() override {
        tmp_dir_ = std::filesystem::temp_directory_path().string() + "/tachyon_test_XXXXXX";
        char *dir = mkdtemp(tmp_dir_.data());
        ASSERT_NE(dir, nullptr) << "Failed to create temp directory";
        tmp_dir_ = dir;
    }

    void TearDown() override {
        for (const auto &f : tmp_files_)
            std::remove(f.c_str());
        std::filesystem::remove_all(tmp_dir_);
    }

    std::string write_config(const std::string &name, const std::string &content) {
        std::string path = tmp_dir_ + "/" + name;
        std::ofstream ofs(path);
        EXPECT_TRUE(ofs.is_open()) << "Failed to create " << path;
        ofs << content;
        ofs.close();
        tmp_files_.push_back(path);
        return path;
    }

    static constexpr const char *VALID_CONFIG =
        "[Interface]\n"
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "PresharedKey = cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n"
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

TEST_F(ConfigTest, ParseValidFullConfig) {
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

TEST_F(ConfigTest, ParseMinimalConfigDefaults) {
    const char *minimal =
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n";
    auto path = write_config("minimal.conf", minimal);
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.listen_port, TACHYON_DEFAULT_PORT);
    EXPECT_EQ(cfg.mimicry_type, TACHYON_MIMICRY_QUIC);
    EXPECT_TRUE(cfg.encryption);
    EXPECT_TRUE(cfg.psk.empty());
    EXPECT_EQ(cfg.obfs_flags, TACHYON_OBFS_ALL);
}

TEST_F(ConfigTest, ParseEncryptionDisabled) {
    std::string content = std::string(VALID_CONFIG) + "EnableEncryption = false\n";
    auto path = write_config("noenc.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(cfg.encryption);
}

TEST_F(ConfigTest, ParseEncryptionDisabledNumeric) {
    std::string content = std::string(VALID_CONFIG) + "EnableEncryption = 0\n";
    auto path = write_config("noenc0.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(cfg.encryption);
}

TEST_F(ConfigTest, ParseObfuscationFlagsHex) {
    std::string content = std::string(VALID_CONFIG) + "ObfuscationFlags = 0x15\n";
    auto path = write_config("obfs_hex.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.obfs_flags, 0x15);
}

TEST_F(ConfigTest, ParseObfuscationFlagsDecimal) {
    std::string content = std::string(VALID_CONFIG) + "ObfuscationFlags = 0\n";
    auto path = write_config("obfs_off.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.obfs_flags, 0);
}

TEST_F(ConfigTest, ParseObfuscationFlagsDefault) {
    auto path = write_config("obfs_default.conf", VALID_CONFIG);
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.obfs_flags, TACHYON_OBFS_ALL);
}

TEST_F(ConfigTest, ParseCustomPort) {
    auto path = write_config(
        "port.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "ListenPort = 51820\n[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = "
        "aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.listen_port, 51820);
}

TEST_F(ConfigTest, ParseNonNumericPort) {
    auto path = write_config(
        "bad_port.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "ListenPort = abc\n[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = "
        "aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.listen_port, TACHYON_DEFAULT_PORT);
}

TEST_F(ConfigTest, ParseNonNumericMimicry) {
    auto path = write_config(
        "bad_mimicry.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "MimicryType = notanumber\n[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = "
        "aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.mimicry_type, TACHYON_MIMICRY_QUIC);
}

TEST_F(ConfigTest, ParseCommentsAndWhitespace) {
    auto path = write_config(
        "comments.conf",
        "# This is a comment\n; This is also a comment\n\n"
        "  PrivateKey  =  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  \n"
        "\t PeerPublicKey\t=\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.private_key, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    EXPECT_EQ(cfg.peer_public_key,
              "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
}

TEST_F(ConfigTest, ParseEmptyFile) {
    auto path = write_config("empty.conf", "");
    TunnelConfig cfg = parse_config(path);
    EXPECT_TRUE(cfg.private_key.empty());
    EXPECT_TRUE(cfg.peer_public_key.empty());
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ParseNonexistentFile) {
    TunnelConfig cfg = parse_config("/nonexistent/path/does_not_exist.conf");
    EXPECT_TRUE(cfg.private_key.empty());
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ParseMimicryTypeNone) {
    std::string content =
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "MimicryType = 0\nVirtualIP = 10.8.0.1/24\nLocalPhysicalIP = "
        "192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n";
    auto path = write_config("nomimicry.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.mimicry_type, TACHYON_MIMICRY_NONE);
}

TEST_F(ConfigTest, ValidateFullConfig) {
    auto path = write_config("full.conf", VALID_CONFIG);
    TunnelConfig cfg = parse_config(path);
    EXPECT_TRUE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidateMissingPrivateKey) {
    auto path = write_config(
        "no_privkey.conf",
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ValidateMissingPeerPublicKey) {
    auto path = write_config(
        "no_peerpub.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ValidateMissingVirtualIP) {
    auto path = write_config(
        "no_vip.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "LocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ValidateMissingPhysicalInterface) {
    auto path = write_config(
        "no_iface.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ValidateShortPrivateKey) {
    auto path = write_config(
        "short_key.conf",
        "PrivateKey = aabbccdd\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ValidateInvalidMACFormat) {
    auto path = write_config(
        "bad_mac.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = not_a_mac\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ValidateInvalidEndpointIP) {
    auto path = write_config(
        "bad_ip.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = not_an_ip\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ParsePortZeroFallsBackToDefault) {
    /* parse_config now rejects out-of-range ports immediately and keeps the
     * default (defense-in-depth alongside validate_config). */
    auto path = write_config(
        "port0.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "ListenPort = 0\nVirtualIP = 10.8.0.1/24\nLocalPhysicalIP = "
        "192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.listen_port, TACHYON_DEFAULT_PORT);
    EXPECT_TRUE(validate_config(cfg));
}

TEST_F(ConfigTest, ParsePortTooHighFallsBackToDefault) {
    auto path = write_config(
        "port_high.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "ListenPort = 70000\nVirtualIP = 10.8.0.1/24\nLocalPhysicalIP = "
        "192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.listen_port, TACHYON_DEFAULT_PORT);
    EXPECT_TRUE(validate_config(cfg));
}

TEST_F(ConfigTest, TunnelNameFromFullPath) {
    EXPECT_EQ(tunnel_name_from_conf("/etc/tachyon/test.conf"), "test");
}
TEST_F(ConfigTest, TunnelNameFromRelativePath) {
    EXPECT_EQ(tunnel_name_from_conf("./test.conf"), "test");
}
TEST_F(ConfigTest, TunnelNameFromBareName) {
    EXPECT_EQ(tunnel_name_from_conf("mytest.conf"), "mytest");
}
TEST_F(ConfigTest, TunnelNameFromMultipleDots) {
    EXPECT_EQ(tunnel_name_from_conf("/path/to/foo.bar.conf"), "foo");
}
TEST_F(ConfigTest, TunnelNameNoExtension) {
    EXPECT_EQ(tunnel_name_from_conf("/path/to/tunnelname"), "tunnelname");
}
TEST_F(ConfigTest, TunnelNameDeepPath) {
    EXPECT_EQ(tunnel_name_from_conf("/a/b/c/d/e/tunnel.conf"), "tunnel");
}

TEST_F(ConfigTest, ParseConfigWithExtremelyLongKey) {
    std::string long_key(2000, 'a');
    auto path = write_config(
        "longkey.conf",
        "PrivateKey = " + long_key +
            "\n"
            "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
            "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
            "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = "
            "10.8.0.2\n");
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.private_key.size(), 2000u);
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ParseConfigWithUtf8Comment) {
    auto path = write_config(
        "utf8.conf",
        "# Comment with UTF-8: donnees reseau\n"
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_TRUE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ParseConfigRejectsOversizedFile) {
    std::string huge(70000, 'x');
    auto path = write_config("huge.conf", huge);
    TunnelConfig cfg = parse_config(path);
    EXPECT_TRUE(cfg.private_key.empty());
}

TEST_F(ConfigTest, ParseConfigAcceptsMaxSizeFile) {
    std::string content =
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n";
    while (content.size() < 65536)
        content += "# padding comment line to fill config file to boundary size\n";
    content.resize(65536);
    auto path = write_config("maxsize.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(cfg.private_key.empty());
}

TEST_F(ConfigTest, ValidateConfigCatchesInvalidTunnelName) {
    TunnelConfig cfg;
    cfg.name = "evil;name";
    cfg.private_key = std::string(64, 'a');
    cfg.peer_public_key = std::string(64, 'b');
    cfg.virtual_ip = "10.8.0.1/24";
    cfg.local_physical_ip = "192.168.1.10";
    cfg.physical_interface = "eth0";
    cfg.peer_endpoint_ip = "192.168.1.20";
    cfg.peer_endpoint_mac = "aa:bb:cc:dd:ee:ff";
    cfg.peer_inner_ip = "10.8.0.2";
    EXPECT_FALSE(validate_config(cfg));
}

TEST_F(ConfigTest, ValidateZeroEndpointIP) {
    auto path = write_config(
        "zero_ip.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 0.0.0.0\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, TunnelNameRejectsShellMetachars) {
    EXPECT_EQ(tunnel_name_from_conf("; rm -rf /.conf"), "");
}
TEST_F(ConfigTest, TunnelNameRejectsSpaces) {
    EXPECT_EQ(tunnel_name_from_conf("my tunnel.conf"), "");
}
TEST_F(ConfigTest, TunnelNameRejectsDollarSign) {
    EXPECT_EQ(tunnel_name_from_conf("$(whoami).conf"), "");
}
TEST_F(ConfigTest, TunnelNameRejectsBacktick) {
    EXPECT_EQ(tunnel_name_from_conf("`id`.conf"), "");
}
TEST_F(ConfigTest, TunnelNameRejectsPipe) {
    EXPECT_EQ(tunnel_name_from_conf("test|evil.conf"), "");
}
TEST_F(ConfigTest, TunnelNameAcceptsHyphenUnderscore) {
    EXPECT_EQ(tunnel_name_from_conf("my-tun_1.conf"), "my-tun_1");
}
TEST_F(ConfigTest, TunnelNameAcceptsAlphanumeric) {
    EXPECT_EQ(tunnel_name_from_conf("tunnel42.conf"), "tunnel42");
}
TEST_F(ConfigTest, TunnelNameTooLong) {
    EXPECT_EQ(tunnel_name_from_conf("abcdefghijk.conf"), "");
}
TEST_F(ConfigTest, TunnelNameMaxLength) {
    EXPECT_EQ(tunnel_name_from_conf("abcdefghij.conf"), "abcdefghij");
}

TEST_F(ConfigTest, ValidateLoopbackEndpointIP) {
    auto path = write_config(
        "loopback.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 127.0.0.1\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ValidateBroadcastEndpointIP) {
    auto path = write_config(
        "broadcast.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 255.255.255.255\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = "
        "10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ValidateLinkLocalEndpointIP) {
    auto path = write_config(
        "linklocal.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 169.254.1.1\nEndpointMAC = aa:bb:cc:dd:ee:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ValidateBroadcastMAC) {
    auto path = write_config(
        "bcast_mac.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = ff:ff:ff:ff:ff:ff\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, ValidateZeroMAC) {
    auto path = write_config(
        "zero_mac.conf",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "VirtualIP = 10.8.0.1/24\nLocalPhysicalIP = 192.168.1.10\nPhysicalInterface = eth0\n"
        "[Peer]\nEndpointIP = 192.168.1.20\nEndpointMAC = 00:00:00:00:00:00\nInnerIP = 10.8.0.2\n");
    EXPECT_FALSE(validate_config(parse_config(path)));
}

TEST_F(ConfigTest, V5DefaultsAreBackwardsCompatible) {
    auto path = write_config("v4_legacy.conf", VALID_CONFIG);
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.pqc_mode, "classical");
    EXPECT_EQ(cfg.obfuscation, "none");
    EXPECT_EQ(cfg.padding, "none");
    EXPECT_FALSE(cfg.ttl_random);
    EXPECT_FALSE(cfg.mac_random);
    EXPECT_EQ(cfg.cover_rate_hz, 0u);
    EXPECT_EQ(cfg.port_hop_seconds, 0u);
}

TEST_F(ConfigTest, V5AllKnobsParsed) {
    const std::string content =
        std::string(VALID_CONFIG) +
        "Pqc = hybrid\nObfuscation = reality\nObfuscationSNI = cdn.cloudflare.com\n"
        "Padding = padme\nCoverRateHz = 10\nPortHopSeconds = 60\nTTLRandom = true\nMACRandom = "
        "yes\n";
    auto path = write_config("v5_full.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.pqc_mode, "hybrid");
    EXPECT_EQ(cfg.obfuscation, "reality");
    EXPECT_EQ(cfg.obfuscation_sni, "cdn.cloudflare.com");
    EXPECT_EQ(cfg.padding, "padme");
    EXPECT_EQ(cfg.cover_rate_hz, 10u);
    EXPECT_EQ(cfg.port_hop_seconds, 60u);
    EXPECT_TRUE(cfg.ttl_random);
    EXPECT_TRUE(cfg.mac_random);
}

TEST_F(ConfigTest, V5BoolSynonyms) {
    const std::string content = std::string(VALID_CONFIG) + "TTLRandom = off\nMACRandom = 0\n";
    auto path = write_config("v5_bool_synonyms.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_FALSE(cfg.ttl_random);
    EXPECT_FALSE(cfg.mac_random);
}

TEST_F(ConfigTest, V5InvalidIntIsIgnored) {
    const std::string content =
        std::string(VALID_CONFIG) + "CoverRateHz = not-a-number\nPortHopSeconds = 99999\n";
    auto path = write_config("v5_bad_int.conf", content);
    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.cover_rate_hz, 0u);
    EXPECT_EQ(cfg.port_hop_seconds, 0u);
}
