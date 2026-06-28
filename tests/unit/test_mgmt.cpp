/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>

#include "mgmt.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <thread>

namespace mgmt = tachyon::mgmt;

namespace {

/* Create a private temp directory and return a socket path inside it. Using a
 * dedicated directory keeps the test hermetic and lets us assert on the node's
 * (non-)existence without colliding with other processes. */
std::string make_socket_path(std::string &dir_out) {
    char tmpl[] = "/tmp/tachyon_mgmt_XXXXXX";
    char *d = mkdtemp(tmpl);
    if (d == nullptr)
        return std::string();
    dir_out = d;
    return dir_out + "/mgmt.sock";
}

/* Connect a fresh blocking AF_UNIX SOCK_STREAM client to `path`. Returns the
 * connected fd, or -1 on failure. */
int connect_client(const std::string &path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    if (connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Drive one full request/response exchange against the server.
 *
 * The server is cooperatively polled by the test thread, so we:
 *   1. connect,
 *   2. write the request (and half-close our write side so the server's recv
 *      sees EOF and reads a complete request without blocking),
 *   3. call mgmt::poll() to accept + service the connection,
 *   4. read the response back.
 */
std::string round_trip(const std::string &path, const std::string &request) {
    int fd = connect_client(path);
    if (fd < 0)
        return std::string();

    if (send(fd, request.data(), request.size(), 0) < 0) {
        close(fd);
        return std::string();
    }
    // Signal end-of-request so the server-side recv() returns promptly.
    shutdown(fd, SHUT_WR);

    mgmt::poll();

    std::string out;
    char buf[2048];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n > 0) {
            out.append(buf, static_cast<size_t>(n));
            if (static_cast<size_t>(n) < sizeof(buf))
                break;
            continue;
        }
        break;
    }
    close(fd);
    return out;
}

class MgmtTest : public ::testing::Test {
  protected:
    void TearDown() override {
        mgmt::shutdown();
        if (!path_.empty())
            ::unlink(path_.c_str());
        if (!dir_.empty())
            ::rmdir(dir_.c_str());
    }

    std::string dir_;
    std::string path_;
};

} // namespace

TEST_F(MgmtTest, InitCreatesSocketWithMode0600) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    mgmt::Handlers h;
    ASSERT_TRUE(mgmt::init(path_, h));
    EXPECT_TRUE(mgmt::is_active());

    struct stat st {};
    ASSERT_EQ(::stat(path_.c_str(), &st), 0);
    EXPECT_TRUE(S_ISSOCK(st.st_mode));
    // Owner-only permission bits.
    EXPECT_EQ(st.st_mode & 0777, static_cast<mode_t>(0600));
}

TEST_F(MgmtTest, InitRejectsOverlongPath) {
    // Build a path far longer than sockaddr_un.sun_path can hold.
    std::string too_long(sizeof(sockaddr_un::sun_path) + 16, 'a');
    too_long = "/tmp/" + too_long;

    mgmt::Handlers h;
    EXPECT_FALSE(mgmt::init(too_long, h));
    EXPECT_FALSE(mgmt::is_active());
}

TEST_F(MgmtTest, PingReturnsPong) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    mgmt::Handlers h;
    ASSERT_TRUE(mgmt::init(path_, h));

    std::string resp = round_trip(path_, R"({"jsonrpc":"2.0","method":"ping","id":1})");
    EXPECT_NE(resp.find("\"pong\":true"), std::string::npos);
    EXPECT_NE(resp.find("\"result\""), std::string::npos);
    // The numeric id must be echoed verbatim.
    EXPECT_NE(resp.find("\"id\":1"), std::string::npos);
}

TEST_F(MgmtTest, StatusEchoesHandlerBody) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    const std::string body = R"({"state":"running","sessions":3})";
    mgmt::Handlers h;
    h.status = [&]() { return body; };
    ASSERT_TRUE(mgmt::init(path_, h));

    std::string resp = round_trip(path_, R"({"jsonrpc":"2.0","method":"status","id":"abc"})");
    EXPECT_NE(resp.find(R"("state":"running")"), std::string::npos);
    EXPECT_NE(resp.find(R"("sessions":3)"), std::string::npos);
    // String id echoed verbatim (with quotes).
    EXPECT_NE(resp.find(R"("id":"abc")"), std::string::npos);
}

TEST_F(MgmtTest, StatsEchoesHandlerBody) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    const std::string body = R"({"rx_packets":42,"tx_packets":7})";
    mgmt::Handlers h;
    h.stats = [&]() { return body; };
    ASSERT_TRUE(mgmt::init(path_, h));

    std::string resp = round_trip(path_, R"({"jsonrpc":"2.0","method":"stats","id":9})");
    EXPECT_NE(resp.find(R"("rx_packets":42)"), std::string::npos);
    EXPECT_NE(resp.find(R"("tx_packets":7)"), std::string::npos);
}

TEST_F(MgmtTest, ReloadReportsHandlerResult) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    mgmt::Handlers h;
    h.reload = [&]() { return true; };
    ASSERT_TRUE(mgmt::init(path_, h));

    std::string resp = round_trip(path_, R"({"jsonrpc":"2.0","method":"reload","id":2})");
    EXPECT_NE(resp.find("\"reloaded\":true"), std::string::npos);
}

TEST_F(MgmtTest, NullHandlerReportsNotSupported) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    // No handlers bound -> status must report a JSON-RPC error.
    mgmt::Handlers h;
    ASSERT_TRUE(mgmt::init(path_, h));

    std::string resp = round_trip(path_, R"({"jsonrpc":"2.0","method":"status","id":3})");
    EXPECT_NE(resp.find("\"error\""), std::string::npos);
    EXPECT_NE(resp.find("-32000"), std::string::npos);
}

TEST_F(MgmtTest, UnknownMethodReturnsMethodNotFound) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    mgmt::Handlers h;
    ASSERT_TRUE(mgmt::init(path_, h));

    std::string resp = round_trip(path_, R"({"jsonrpc":"2.0","method":"frobnicate","id":5})");
    EXPECT_NE(resp.find("\"error\""), std::string::npos);
    EXPECT_NE(resp.find("-32601"), std::string::npos);
}

TEST_F(MgmtTest, MalformedRequestReturnsParseOrInvalid) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    mgmt::Handlers h;
    ASSERT_TRUE(mgmt::init(path_, h));

    // Not a JSON object at all.
    std::string resp = round_trip(path_, "this is not json");
    EXPECT_NE(resp.find("\"error\""), std::string::npos);
    EXPECT_NE(resp.find("-327"), std::string::npos); // -32700 or -32600
}

TEST_F(MgmtTest, VersionReturnsVersionField) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    mgmt::Handlers h;
    ASSERT_TRUE(mgmt::init(path_, h));

    std::string resp = round_trip(path_, R"({"jsonrpc":"2.0","method":"version","id":1})");
    EXPECT_NE(resp.find("\"version\""), std::string::npos);
}

TEST_F(MgmtTest, PollWithNoServerIsNoOp) {
    // Must be safe to call before init / after shutdown.
    mgmt::shutdown();
    EXPECT_FALSE(mgmt::is_active());
    mgmt::poll(); // no crash
    SUCCEED();
}

TEST_F(MgmtTest, ShutdownUnlinksSocket) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    mgmt::Handlers h;
    ASSERT_TRUE(mgmt::init(path_, h));

    struct stat st {};
    ASSERT_EQ(::stat(path_.c_str(), &st), 0); // exists while active

    mgmt::shutdown();
    EXPECT_FALSE(mgmt::is_active());
    // The socket node must be gone.
    EXPECT_NE(::stat(path_.c_str(), &st), 0);
    EXPECT_EQ(errno, ENOENT);
}

TEST_F(MgmtTest, ClientCallRoundTrip) {
    path_ = make_socket_path(dir_);
    ASSERT_FALSE(path_.empty());

    mgmt::Handlers h;
    h.status = [] { return std::string("{\"ok\":true}"); };
    ASSERT_TRUE(mgmt::init(path_, h));

    // client_call() blocks on the reply, so drive it from a thread while this
    // thread pumps the cooperative, single-threaded server until it answers.
    std::string response;
    bool ok = false;
    std::atomic<bool> done{false};
    std::thread client([&] {
        ok = mgmt::client_call(path_, R"({"jsonrpc":"2.0","method":"status","id":7})", response);
        done = true;
    });
    for (int i = 0; i < 400 && !done.load(); ++i) {
        mgmt::poll();
        usleep(5000); // 5 ms
    }
    client.join();

    EXPECT_TRUE(ok);
    EXPECT_NE(response.find("\"ok\":true"), std::string::npos);
    EXPECT_NE(response.find("\"id\":7"), std::string::npos);

    // A connect to a non-existent socket must fail cleanly (no hang/crash).
    std::string none;
    EXPECT_FALSE(mgmt::client_call(dir_ + "/does_not_exist.sock",
                                   R"({"jsonrpc":"2.0","method":"ping","id":1})", none));
}
