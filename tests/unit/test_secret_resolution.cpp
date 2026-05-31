/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Unit Tests — Secret Resolution (env-var + file:// URI)
 *
 * resolve_secret() is a static helper inside loader/config.cpp; we exercise
 * it through parse_config(), which feeds the secret-bearing fields
 * (PrivateKey, PeerPublicKey, PresharedKey) through the resolver.
 *
 * Coverage:
 *   1. Plain config value passes through unchanged
 *   2. Env var override takes priority over the config value
 *   3. Env var slot is cleared from the environment after resolution
 *   4. file:///abs/path reads file contents
 *   5. file:// with non-existent path returns the original string (and warns)
 *   6. file:// content has trailing newline trimmed
 *   7. Empty config + no env var → empty string
 *   8. file://relative/path (without ///) is treated as a relative path
 */

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "tachyon.h"

namespace {

class SecretResolutionTest : public ::testing::Test {
  protected:
    std::string tmp_dir_;
    std::string orig_cwd_;
    std::vector<std::string> env_vars_to_clear_;

    void SetUp() override {
        char cwd_buf[4096];
        ASSERT_NE(getcwd(cwd_buf, sizeof(cwd_buf)), nullptr);
        orig_cwd_ = cwd_buf;

        tmp_dir_ = std::filesystem::temp_directory_path().string() + "/tachyon_secret_XXXXXX";
        char *dir = mkdtemp(tmp_dir_.data());
        ASSERT_NE(dir, nullptr) << "Failed to create temp directory";
        tmp_dir_ = dir;

        /* Defensive: clear any pre-existing env vars so tests start from
         * a known state. parse_config() unset()s on use, but tests may run
         * in any order. */
        unsetenv("TACHYON_PRIVATE_KEY");
        unsetenv("TACHYON_PSK");
        unsetenv("TACHYON_PEER_PUBLIC_KEY");
    }

    void TearDown() override {
        for (const auto &v : env_vars_to_clear_)
            unsetenv(v.c_str());
        /* Restore cwd in case a test chdir()'d into tmp_dir_. Failure
         * here is non-fatal — the temp dir is removed below regardless
         * — so we deliberately ignore the result via a sink variable to
         * silence -Wunused-result without triggering it via cast. */
        if (!orig_cwd_.empty()) {
            int rc = chdir(orig_cwd_.c_str());
            (void)rc;
        }
        std::error_code ec;
        std::filesystem::remove_all(tmp_dir_, ec);
    }

    /* Write a config file with the supplied PrivateKey/PeerPublicKey/PSK
     * literal values. Other required fields use harmless placeholders so
     * parse_config() can return; we never call validate_config() here, so
     * fake hex of any length is acceptable. */
    std::string write_config(const std::string &name, const std::string &priv,
                             const std::string &peer, const std::string &psk) {
        std::string path = tmp_dir_ + "/" + name;
        std::ofstream ofs(path);
        EXPECT_TRUE(ofs.is_open()) << "Failed to create " << path;
        ofs << "[Interface]\n"
            << "PrivateKey = " << priv << "\n"
            << "PeerPublicKey = " << peer << "\n"
            << "PresharedKey = " << psk << "\n"
            << "VirtualIP = 10.8.0.1/24\n"
            << "LocalPhysicalIP = 192.168.1.10\n"
            << "PhysicalInterface = eth0\n"
            << "[Peer]\n"
            << "EndpointIP = 192.168.1.20\n"
            << "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
            << "InnerIP = 10.8.0.2\n";
        return path;
    }

    std::string write_secret_file(const std::string &name, const std::string &content) {
        std::string path = tmp_dir_ + "/" + name;
        std::ofstream ofs(path, std::ios::binary);
        EXPECT_TRUE(ofs.is_open()) << "Failed to create " << path;
        ofs << content;
        return path;
    }

    void set_env(const char *name, const std::string &value) {
        ASSERT_EQ(setenv(name, value.c_str(), 1), 0);
        env_vars_to_clear_.emplace_back(name);
    }
};

/* (1) A literal hex secret in the config flows through unchanged when no
 * env var is set and no file:// scheme is present. */
TEST_F(SecretResolutionTest, PlainValuePassesThroughUnchanged) {
    const std::string priv = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const std::string peer = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
    const std::string psk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    auto path = write_config("plain.conf", priv, peer, psk);

    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.private_key, priv);
    EXPECT_EQ(cfg.peer_public_key, peer);
    EXPECT_EQ(cfg.psk, psk);
}

/* (2) Env var wins over the config value. We seed all three env vars at
 * once to confirm the wiring is correct for each field. */
TEST_F(SecretResolutionTest, EnvVarOverridesConfigValue) {
    auto path = write_config("env_override.conf", "config_priv", "config_peer", "config_psk");

    set_env("TACHYON_PRIVATE_KEY", "env_priv_value");
    set_env("TACHYON_PEER_PUBLIC_KEY", "env_peer_value");
    set_env("TACHYON_PSK", "env_psk_value");

    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.private_key, "env_priv_value");
    EXPECT_EQ(cfg.peer_public_key, "env_peer_value");
    EXPECT_EQ(cfg.psk, "env_psk_value");
}

/* (3) After resolve_secret() consumes an env var, that slot must be
 * absent from getenv() so /proc/<pid>/environ no longer leaks the secret. */
TEST_F(SecretResolutionTest, EnvVarIsClearedAfterResolution) {
    auto path = write_config("env_clear.conf", "x", "y", "z");

    set_env("TACHYON_PRIVATE_KEY", "secret_to_be_erased");
    ASSERT_NE(std::getenv("TACHYON_PRIVATE_KEY"), nullptr);

    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.private_key, "secret_to_be_erased");
    EXPECT_EQ(std::getenv("TACHYON_PRIVATE_KEY"), nullptr)
        << "TACHYON_PRIVATE_KEY must be unset() after resolution";
}

/* (4) file:///abs/path reads file contents (no trailing newline in source). */
TEST_F(SecretResolutionTest, FileSchemeReadsAbsolutePath) {
    const std::string priv_value =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    auto secret_path = write_secret_file("priv.key", priv_value);
    auto path = write_config("file_abs.conf", "file://" + secret_path, "config_peer", "config_psk");

    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.private_key, priv_value);
    /* Other fields remain unaffected. */
    EXPECT_EQ(cfg.peer_public_key, "config_peer");
}

/* (5) file:// pointing at a missing path falls back to the original
 * string so misconfiguration is loud rather than silently empty. */
TEST_F(SecretResolutionTest, FileSchemeMissingPathReturnsOriginal) {
    const std::string bogus = "file://" + tmp_dir_ + "/does_not_exist.key";
    auto path = write_config("file_missing.conf", bogus, "p", "k");

    TunnelConfig cfg = parse_config(path);
    /* Original literal (including the file:// prefix) is returned verbatim. */
    EXPECT_EQ(cfg.private_key, bogus);
}

/* (6) `echo "secret" > file` adds a trailing newline; resolve_secret()
 * must trim it so downstream hex validators do not reject the secret. */
TEST_F(SecretResolutionTest, FileSchemeTrimsTrailingWhitespace) {
    const std::string raw_secret =
        "1111111111111111111111111111111111111111111111111111111111111111";
    /* Trailing newline + extra whitespace mirrors common shell idioms. */
    auto secret_path = write_secret_file("psk.key", raw_secret + "\n  \t\r\n");
    auto path = write_config("file_trim.conf", "p", "q", "file://" + secret_path);

    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.psk, raw_secret);
}

/* (7) Empty config value with no env var → empty string (no crash, no
 * surprise default). */
TEST_F(SecretResolutionTest, EmptyConfigAndNoEnvReturnsEmpty) {
    /* Skip writing PSK altogether: parse_ini will not find the key. */
    std::string path = tmp_dir_ + "/empty_psk.conf";
    {
        std::ofstream ofs(path);
        ofs << "[Interface]\n"
            << "PrivateKey = aa\n"
            << "PeerPublicKey = bb\n"
            << "VirtualIP = 10.8.0.1/24\n"
            << "LocalPhysicalIP = 192.168.1.10\n"
            << "PhysicalInterface = eth0\n"
            << "[Peer]\n"
            << "EndpointIP = 192.168.1.20\n"
            << "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
            << "InnerIP = 10.8.0.2\n";
    }

    TunnelConfig cfg = parse_config(path);
    EXPECT_TRUE(cfg.psk.empty()) << "psk='" << cfg.psk << "'";
}

/* (8) file://relative/path (only two slashes) is treated as a path
 * relative to the current working directory. We chdir() into the temp
 * directory so the relative resolution lands on a real file. */
TEST_F(SecretResolutionTest, FileSchemeRelativePath) {
    const std::string peer_value =
        "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";
    /* Place the secret file inside the temp directory and cd there so a
     * bare relative path resolves to it. */
    write_secret_file("peer.key", peer_value);
    ASSERT_EQ(chdir(tmp_dir_.c_str()), 0);

    /* file://peer.key — only two slashes, so the path is "peer.key". */
    auto path = write_config("file_rel.conf", "p", "file://peer.key", "k");

    TunnelConfig cfg = parse_config(path);
    EXPECT_EQ(cfg.peer_public_key, peer_value);
}

} // namespace
