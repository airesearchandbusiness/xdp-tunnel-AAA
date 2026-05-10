/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>
#include "log.h"

#include <cstdio>
#include <cstring>
#include <string>

static std::string capture_stderr(std::function<void()> fn) {
    fflush(stderr);
    int pipefd[2];
    EXPECT_EQ(pipe(pipefd), 0);

    int saved = dup(STDERR_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);

    fn();
    fflush(stderr);

    dup2(saved, STDERR_FILENO);
    close(saved);

    char buf[2048] = {};
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);
    if (n > 0)
        buf[n] = '\0';
    return std::string(buf);
}

TEST(LogTest, TextModeEmitsLevel) {
    tachyon::log::init(
        tachyon::log::Config{false, false, tachyon::log::Level::INFO});
    auto out = capture_stderr([] { LOG_INFO("hello %s", "world"); });
    EXPECT_NE(out.find("[INFO ]"), std::string::npos);
    EXPECT_NE(out.find("hello world"), std::string::npos);
}

TEST(LogTest, JsonModeEmitsValidJson) {
    tachyon::log::init(tachyon::log::Config{true, false, tachyon::log::Level::INFO});
    auto out = capture_stderr([] { LOG_WARN("bad thing %d", 42); });
    EXPECT_NE(out.find("{\"ts\":\""), std::string::npos);
    EXPECT_NE(out.find("\"level\":\"WARN\""), std::string::npos);
    EXPECT_NE(out.find("\"msg\":\"bad thing 42\""), std::string::npos);
    EXPECT_NE(out.find("}"), std::string::npos);
}

TEST(LogTest, LevelFilteringSuppressesLowerLevels) {
    tachyon::log::init(
        tachyon::log::Config{false, false, tachyon::log::Level::WARN});
    auto out = capture_stderr([] { LOG_INFO("should not appear"); });
    EXPECT_EQ(out.find("should not appear"), std::string::npos);
}

TEST(LogTest, LevelFilteringPassesHigherLevels) {
    tachyon::log::init(
        tachyon::log::Config{false, false, tachyon::log::Level::WARN});
    auto out = capture_stderr([] { LOG_ERR("should appear"); });
    EXPECT_NE(out.find("should appear"), std::string::npos);
}

TEST(LogTest, ContextFieldsAppearInJson) {
    tachyon::log::init(tachyon::log::Config{true, false, tachyon::log::Level::INFO});
    tachyon::log::set_context("session_id", "42");
    tachyon::log::set_context("peer_ip", "10.0.0.1");
    auto out = capture_stderr([] { LOG_INFO("connected"); });
    EXPECT_NE(out.find("\"session_id\":\"42\""), std::string::npos);
    EXPECT_NE(out.find("\"peer_ip\":\"10.0.0.1\""), std::string::npos);
    tachyon::log::clear_context();
}

TEST(LogTest, ClearContextRemovesFields) {
    tachyon::log::init(tachyon::log::Config{true, false, tachyon::log::Level::INFO});
    tachyon::log::set_context("session_id", "99");
    tachyon::log::clear_context();
    auto out = capture_stderr([] { LOG_INFO("after clear"); });
    EXPECT_EQ(out.find("\"session_id\""), std::string::npos);
}

TEST(LogTest, TimestampPresent) {
    tachyon::log::init(
        tachyon::log::Config{false, false, tachyon::log::Level::INFO});
    auto out = capture_stderr([] { LOG_INFO("ts test"); });
    EXPECT_NE(out.find("202"), std::string::npos); /* year prefix */
    EXPECT_NE(out.find("T"), std::string::npos);   /* ISO separator */
}

TEST(LogTest, SetLevelDynamically) {
    tachyon::log::init(
        tachyon::log::Config{false, false, tachyon::log::Level::ERROR});
    auto out1 = capture_stderr([] { LOG_WARN("hidden"); });
    EXPECT_EQ(out1.find("hidden"), std::string::npos);

    tachyon::log::set_level(tachyon::log::Level::DEBUG);
    auto out2 = capture_stderr([] { LOG_WARN("visible"); });
    EXPECT_NE(out2.find("visible"), std::string::npos);
}
