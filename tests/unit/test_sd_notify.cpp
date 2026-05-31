/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>
#include "sd_notify.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

class SdNotifyTest : public ::testing::Test {
  protected:
    void SetUp() override {
        unsetenv("NOTIFY_SOCKET");
        tachyon::sd::shutdown(); /* clear any prior state */
    }
    void TearDown() override {
        tachyon::sd::shutdown();
        unsetenv("NOTIFY_SOCKET");
        if (!socket_path_.empty())
            unlink(socket_path_.c_str());
    }

    /* Bind a unix datagram socket and return both its FD and path. */
    int bind_listener(std::string &out_path) {
        char path[] = "/tmp/tachyon_sdtest_XXXXXX";
        int tmp = mkstemp(path);
        if (tmp < 0)
            return -1;
        close(tmp);
        unlink(path);

        int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd < 0)
            return -1;
        struct sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }
        out_path = path;
        socket_path_ = path;
        return fd;
    }

    std::string socket_path_;
};

TEST_F(SdNotifyTest, InitFailsWithoutEnvVar) {
    EXPECT_FALSE(tachyon::sd::init());
    EXPECT_FALSE(tachyon::sd::enabled());
}

TEST_F(SdNotifyTest, NotifyNoOpWithoutInit) {
    EXPECT_FALSE(tachyon::sd::notify("READY=1"));
}

TEST_F(SdNotifyTest, InitWithValidSocketSucceeds) {
    std::string path;
    int listener = bind_listener(path);
    ASSERT_GE(listener, 0);

    setenv("NOTIFY_SOCKET", path.c_str(), 1);
    EXPECT_TRUE(tachyon::sd::init());
    EXPECT_TRUE(tachyon::sd::enabled());

    close(listener);
}

TEST_F(SdNotifyTest, NotifyDeliversToListener) {
    std::string path;
    int listener = bind_listener(path);
    ASSERT_GE(listener, 0);

    setenv("NOTIFY_SOCKET", path.c_str(), 1);
    ASSERT_TRUE(tachyon::sd::init());

    EXPECT_TRUE(tachyon::sd::notify("READY=1"));

    char buf[128] = {};
    ssize_t n = recv(listener, buf, sizeof(buf) - 1, 0);
    EXPECT_GT(n, 0);
    EXPECT_NE(std::string(buf).find("READY=1"), std::string::npos);

    close(listener);
}

TEST_F(SdNotifyTest, NotifyStatusComposesProperly) {
    std::string path;
    int listener = bind_listener(path);
    ASSERT_GE(listener, 0);

    setenv("NOTIFY_SOCKET", path.c_str(), 1);
    ASSERT_TRUE(tachyon::sd::init());

    EXPECT_TRUE(tachyon::sd::notify_status("active session", true));
    char buf[128] = {};
    ssize_t n = recv(listener, buf, sizeof(buf) - 1, 0);
    ASSERT_GT(n, 0);
    std::string msg(buf, n);
    EXPECT_NE(msg.find("STATUS=active session"), std::string::npos);
    EXPECT_NE(msg.find("WATCHDOG=1"), std::string::npos);

    close(listener);
}

TEST_F(SdNotifyTest, ShutdownSendsStoppingAndDisables) {
    std::string path;
    int listener = bind_listener(path);
    ASSERT_GE(listener, 0);

    setenv("NOTIFY_SOCKET", path.c_str(), 1);
    ASSERT_TRUE(tachyon::sd::init());
    tachyon::sd::shutdown();
    EXPECT_FALSE(tachyon::sd::enabled());

    char buf[128] = {};
    ssize_t n = recv(listener, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        std::string msg(buf, n);
        EXPECT_NE(msg.find("STOPPING=1"), std::string::npos);
    }

    close(listener);
}

TEST_F(SdNotifyTest, RejectsInvalidSocketPath) {
    setenv("NOTIFY_SOCKET", "relative-path", 1);
    EXPECT_FALSE(tachyon::sd::init());
}

TEST_F(SdNotifyTest, EmptyEnvVarRejected) {
    setenv("NOTIFY_SOCKET", "", 1);
    EXPECT_FALSE(tachyon::sd::init());
}
