/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Test Suite - Configuration Parsing & Validation
 */

#include "test_harness.h"
#include "../loader/tachyon.h"
#include <fstream>

/* RAII temp config file - auto-deleted when scope exits (even on ASSERT failure) */
struct TempConfig {
    std::string path;
    TempConfig(const std::string &content) {
        static int counter = 0;
        path = "/tmp/tachyon_test_" + std::to_string(getpid()) + "_" + std::to_string(counter++) +
               ".conf";
        std::ofstream f(path);
        f << content;
    }
    ~TempConfig() { unlink(path.c_str()); }
    const char *c_str() const { return path.c_str(); }
    operator std::string() const { return path; }
};

/* ── tunnel_name_from_conf Tests ── */

TEST(name_from_simple_path) {
    ASSERT_TRUE(tunnel_name_from_conf("test.conf") == "test");
}

TEST(name_from_dir_path) {
    ASSERT_TRUE(tunnel_name_from_conf("/etc/tachyon/prod.conf") == "prod");
}

TEST(name_from_no_extension) {
    ASSERT_TRUE(tunnel_name_from_conf("tunnel") == "tunnel");
}

TEST(name_from_nested_path) {
    ASSERT_TRUE(tunnel_name_from_conf("/a/b/c/wg0.conf") == "wg0");
}

/* ── parse_config Tests ── */

TEST(parse_valid_config) {
    TempConfig conf(
        "[Interface]\n"
        "PrivateKey = aabbccdd00112233445566778899aabbccddeeff0011223344556677889900aa\n"
        "PeerPublicKey = 1122334455667788990011223344556677889900aabbccddeeff00112233aabb\n"
        "ListenPort = 5555\n"
        "VirtualIP = 10.8.0.1/24\n"
        "LocalPhysicalIP = 192.168.1.10\n"
        "PhysicalInterface = eth0\n"
        "MimicryType = 1\n"
        "\n"
        "[Peer]\n"
        "EndpointIP = 192.168.1.20\n"
        "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
        "InnerIP = 10.8.0.2\n");

    TunnelConfig cfg = parse_config(conf);
    ASSERT_EQ(cfg.listen_port, 5555);
    ASSERT_EQ(cfg.mimicry_type, 1);
    ASSERT_TRUE(cfg.peer_endpoint_ip == "192.168.1.20");
    ASSERT_TRUE(cfg.peer_endpoint_mac == "aa:bb:cc:dd:ee:ff");
    ASSERT_TRUE(cfg.peer_inner_ip == "10.8.0.2");
    ASSERT_TRUE(cfg.virtual_ip == "10.8.0.1/24");
}

TEST(parse_comments_and_empty_lines) {
    TempConfig conf(
        "# This is a comment\n"
        "; Another comment style\n"
        "\n"
        "[Interface]\n"
        "PrivateKey = aabbccdd00112233445566778899aabbccddeeff0011223344556677889900aa\n"
        "ListenPort = 443\n");

    TunnelConfig cfg = parse_config(conf);
    ASSERT_EQ(cfg.listen_port, 443);
    ASSERT_TRUE(cfg.private_key.size() == 64);
}

TEST(parse_default_port) {
    TempConfig conf(
        "[Interface]\n"
        "PrivateKey = aabbccdd00112233445566778899aabbccddeeff0011223344556677889900aa\n");

    TunnelConfig cfg = parse_config(conf);
    ASSERT_EQ(cfg.listen_port, TACHYON_DEFAULT_PORT);
}

/* ── validate_config Tests ── */

TEST(validate_complete_config) {
    TunnelConfig cfg;
    cfg.private_key = "aabbccdd00112233445566778899aabbccddeeff0011223344556677889900aa";
    cfg.peer_public_key = "1122334455667788990011223344556677889900aabbccddeeff00112233aabb";
    cfg.virtual_ip = "10.8.0.1/24";
    cfg.local_physical_ip = "192.168.1.10";
    cfg.physical_interface = "eth0";
    cfg.peer_endpoint_ip = "192.168.1.20";
    cfg.peer_endpoint_mac = "aa:bb:cc:dd:ee:ff";
    cfg.peer_inner_ip = "10.8.0.2";
    cfg.listen_port = 443;

    ASSERT_TRUE(validate_config(cfg));
}

TEST(validate_missing_private_key) {
    TunnelConfig cfg;
    cfg.peer_public_key = "1122334455667788990011223344556677889900aabbccddeeff00112233aabb";
    cfg.virtual_ip = "10.8.0.1/24";
    cfg.local_physical_ip = "192.168.1.10";
    cfg.physical_interface = "eth0";
    cfg.peer_endpoint_ip = "192.168.1.20";
    cfg.peer_endpoint_mac = "aa:bb:cc:dd:ee:ff";
    cfg.peer_inner_ip = "10.8.0.2";

    ASSERT_FALSE(validate_config(cfg));
}

TEST(validate_invalid_key_length) {
    TunnelConfig cfg;
    cfg.private_key = "tooshort";
    cfg.peer_public_key = "1122334455667788990011223344556677889900aabbccddeeff00112233aabb";
    cfg.virtual_ip = "10.8.0.1/24";
    cfg.local_physical_ip = "192.168.1.10";
    cfg.physical_interface = "eth0";
    cfg.peer_endpoint_ip = "192.168.1.20";
    cfg.peer_endpoint_mac = "aa:bb:cc:dd:ee:ff";
    cfg.peer_inner_ip = "10.8.0.2";

    ASSERT_FALSE(validate_config(cfg));
}

TEST(validate_invalid_mac) {
    TunnelConfig cfg;
    cfg.private_key = "aabbccdd00112233445566778899aabbccddeeff0011223344556677889900aa";
    cfg.peer_public_key = "1122334455667788990011223344556677889900aabbccddeeff00112233aabb";
    cfg.virtual_ip = "10.8.0.1/24";
    cfg.local_physical_ip = "192.168.1.10";
    cfg.physical_interface = "eth0";
    cfg.peer_endpoint_ip = "192.168.1.20";
    cfg.peer_endpoint_mac = "not-a-mac";
    cfg.peer_inner_ip = "10.8.0.2";

    ASSERT_FALSE(validate_config(cfg));
}

TEST(validate_invalid_port) {
    TunnelConfig cfg;
    cfg.private_key = "aabbccdd00112233445566778899aabbccddeeff0011223344556677889900aa";
    cfg.peer_public_key = "1122334455667788990011223344556677889900aabbccddeeff00112233aabb";
    cfg.virtual_ip = "10.8.0.1/24";
    cfg.local_physical_ip = "192.168.1.10";
    cfg.physical_interface = "eth0";
    cfg.peer_endpoint_ip = "192.168.1.20";
    cfg.peer_endpoint_mac = "aa:bb:cc:dd:ee:ff";
    cfg.peer_inner_ip = "10.8.0.2";
    cfg.listen_port = 70000;

    ASSERT_FALSE(validate_config(cfg));
}

/* ── Runner ── */

int main() {
    printf("\n  Tachyon Config Tests\n");
    printf("  ─────────────────────────────────\n");

    RUN_TEST(name_from_simple_path);
    RUN_TEST(name_from_dir_path);
    RUN_TEST(name_from_no_extension);
    RUN_TEST(name_from_nested_path);
    RUN_TEST(parse_valid_config);
    RUN_TEST(parse_comments_and_empty_lines);
    RUN_TEST(parse_default_port);
    RUN_TEST(validate_complete_config);
    RUN_TEST(validate_missing_private_key);
    RUN_TEST(validate_invalid_key_length);
    RUN_TEST(validate_invalid_mac);
    RUN_TEST(validate_invalid_port);

    return test_summary();
}
