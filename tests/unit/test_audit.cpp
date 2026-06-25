/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>

#include "audit.h"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace audit = tachyon::audit;

namespace {

std::string make_temp_path() {
    char tmpl[] = "/tmp/tachyon_audit_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd >= 0) {
        ::close(fd);
        ::unlink(tmpl);
    }
    return std::string(tmpl);
}

std::string read_file(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

class AuditTest : public ::testing::Test {
  protected:
    void TearDown() override {
        audit::shutdown();
        if (!path_.empty()) {
            ::unlink(path_.c_str());
        }
    }

    std::string path_;
};

} // namespace

TEST_F(AuditTest, InitWithValidPathReturnsTrue) {
    path_ = make_temp_path();
    EXPECT_TRUE(audit::init(path_));
    // Verify file exists and is writable.
    struct stat st;
    EXPECT_EQ(::stat(path_.c_str(), &st), 0);
}

TEST_F(AuditTest, InitWithEmptyPathReturnsTrue) {
    EXPECT_TRUE(audit::init(""));
    // No file should be created; syslog mode silently swallows the call.
    audit::EventInfo info{audit::Event::SERVICE_START, 0, 0, "success", nullptr};
    audit::emit(info);
    SUCCEED();
}

TEST_F(AuditTest, InitWithUnwritablePathReturnsFalse) {
    // /proc/1 is owned by root and not a directory we can create files in
    // even as a non-root user.
    const std::string bad = "/proc/1/nonexistent_dir/audit.log";
    EXPECT_FALSE(audit::init(bad));
}

TEST_F(AuditTest, EmitWritesJsonToFile) {
    path_ = make_temp_path();
    ASSERT_TRUE(audit::init(path_));

    audit::EventInfo info{};
    info.event = audit::Event::HANDSHAKE_INIT;
    info.session_id = 12345;
    info.outcome = "success";
    info.details = "test-details";
    audit::emit(info);

    std::string contents = read_file(path_);
    // Single-line JSON.
    EXPECT_NE(contents.find("\"event\":\"handshake_init\""), std::string::npos);
    EXPECT_NE(contents.find("\"session_id\":12345"), std::string::npos);
    EXPECT_NE(contents.find("\"outcome\":\"success\""), std::string::npos);
    EXPECT_NE(contents.find("\"details\":\"test-details\""), std::string::npos);
    EXPECT_NE(contents.find("\"ts\":\""), std::string::npos);
    EXPECT_EQ(contents.back(), '\n');
    // Should be exactly one line.
    EXPECT_EQ(std::count(contents.begin(), contents.end(), '\n'), 1);
}

TEST_F(AuditTest, EmitIncludesPeerIpWhenNonzero) {
    path_ = make_temp_path();
    ASSERT_TRUE(audit::init(path_));

    audit::EventInfo info{};
    info.event = audit::Event::AUTH_FAIL;
    // 192.0.2.42 in network byte order.
    struct in_addr addr;
    ASSERT_EQ(inet_pton(AF_INET, "192.0.2.42", &addr), 1);
    info.peer_ip = addr.s_addr;
    info.outcome = "bad-mac";
    audit::emit(info);

    std::string contents = read_file(path_);
    EXPECT_NE(contents.find("\"peer_ip\":\"192.0.2.42\""), std::string::npos);
    EXPECT_NE(contents.find("\"event\":\"auth_fail\""), std::string::npos);
}

TEST_F(AuditTest, EmitOmitsPeerIpWhenZero) {
    path_ = make_temp_path();
    ASSERT_TRUE(audit::init(path_));

    audit::EventInfo info{};
    info.event = audit::Event::SERVICE_START;
    info.peer_ip = 0;
    info.outcome = "success";
    audit::emit(info);

    std::string contents = read_file(path_);
    EXPECT_EQ(contents.find("\"peer_ip\""), std::string::npos);
    EXPECT_NE(contents.find("\"event\":\"service_start\""), std::string::npos);
}

TEST_F(AuditTest, EventNameReturnsCorrectStrings) {
    EXPECT_STREQ(audit::event_name(audit::Event::SERVICE_START), "service_start");
    EXPECT_STREQ(audit::event_name(audit::Event::SERVICE_STOP), "service_stop");
    EXPECT_STREQ(audit::event_name(audit::Event::HANDSHAKE_INIT), "handshake_init");
    EXPECT_STREQ(audit::event_name(audit::Event::HANDSHAKE_COMPLETE), "handshake_complete");
    EXPECT_STREQ(audit::event_name(audit::Event::HANDSHAKE_FAIL), "handshake_fail");
    EXPECT_STREQ(audit::event_name(audit::Event::AUTH_FAIL), "auth_fail");
    EXPECT_STREQ(audit::event_name(audit::Event::COOKIE_INVALID), "cookie_invalid");
    EXPECT_STREQ(audit::event_name(audit::Event::REPLAY_DETECTED), "replay_detected");
    EXPECT_STREQ(audit::event_name(audit::Event::KEY_ROTATION), "key_rotation");
    EXPECT_STREQ(audit::event_name(audit::Event::CONFIG_RELOAD), "config_reload");
    EXPECT_STREQ(audit::event_name(audit::Event::PEER_BLOCKED), "peer_blocked");
}

TEST_F(AuditTest, MultiThreadedEmitDoesNotCorruptOutput) {
    path_ = make_temp_path();
    ASSERT_TRUE(audit::init(path_));

    constexpr int kThreads = 8;
    constexpr int kPerThread = 100;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t]() {
            for (int i = 0; i < kPerThread; ++i) {
                audit::EventInfo info{};
                info.event = audit::Event::HANDSHAKE_COMPLETE;
                // Avoid session_id == 0 (omitted from output by design).
                info.session_id = static_cast<uint32_t>(t * 10000 + i + 1);
                info.outcome = "success";
                audit::emit(info);
            }
        });
    }
    for (auto &th : threads) {
        th.join();
    }

    std::string contents = read_file(path_);
    // Each emit produces exactly one line.
    auto line_count = std::count(contents.begin(), contents.end(), '\n');
    EXPECT_EQ(line_count, kThreads * kPerThread);

    // Every line must be a complete, well-formed JSON object on its own line:
    // begins with '{', ends with '}'. No interleaving allowed.
    std::istringstream iss(contents);
    std::string line;
    int seen = 0;
    std::set<uint32_t> seen_ids;
    while (std::getline(iss, line)) {
        ASSERT_FALSE(line.empty());
        EXPECT_EQ(line.front(), '{');
        EXPECT_EQ(line.back(), '}');
        EXPECT_NE(line.find("\"event\":\"handshake_complete\""), std::string::npos);
        // Extract session_id to verify all writes appear.
        auto pos = line.find("\"session_id\":");
        ASSERT_NE(pos, std::string::npos);
        uint32_t id = static_cast<uint32_t>(
            std::strtoul(line.c_str() + pos + std::strlen("\"session_id\":"), nullptr, 10));
        seen_ids.insert(id);
        ++seen;
    }
    EXPECT_EQ(seen, kThreads * kPerThread);
    EXPECT_EQ(seen_ids.size(), static_cast<size_t>(kThreads * kPerThread));
}
