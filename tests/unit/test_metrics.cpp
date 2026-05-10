/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>
#include "metrics.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <string>

using namespace tachyon::metrics;

class MetricsTest : public ::testing::Test {
  protected:
    void SetUp() override { reset(); }
};

TEST_F(MetricsTest, InitialCountersAreZero) {
    const auto s = snapshot();
    EXPECT_EQ(s.hs_initiated, 0u);
    EXPECT_EQ(s.tx_packets, 0u);
    EXPECT_EQ(s.replay_dropped, 0u);
    EXPECT_EQ(s.rl_tx_drops, 0u);
}

TEST_F(MetricsTest, IncrementAndSnapshot) {
    auto &c = global();
    c.hs_initiated.fetch_add(1, std::memory_order_relaxed);
    c.hs_initiated.fetch_add(1, std::memory_order_relaxed);
    c.tx_packets.fetch_add(100, std::memory_order_relaxed);
    c.tx_bytes.fetch_add(150000, std::memory_order_relaxed);

    const auto s = snapshot();
    EXPECT_EQ(s.hs_initiated, 2u);
    EXPECT_EQ(s.tx_packets, 100u);
    EXPECT_EQ(s.tx_bytes, 150000u);
}

TEST_F(MetricsTest, ResetClearsAll) {
    auto &c = global();
    c.hs_completed.fetch_add(5, std::memory_order_relaxed);
    c.replay_dropped.fetch_add(3, std::memory_order_relaxed);
    reset();
    const auto s = snapshot();
    EXPECT_EQ(s.hs_completed, 0u);
    EXPECT_EQ(s.replay_dropped, 0u);
}

TEST_F(MetricsTest, AllFieldsExercised) {
    auto &c = global();
    c.hs_failed.fetch_add(1);
    c.hs_rekeys.fetch_add(1);
    c.rx_packets.fetch_add(1);
    c.rx_bytes.fetch_add(1);
    c.replay_accepted.fetch_add(1);
    c.replay_stale.fetch_add(1);
    c.cover_frames_sent.fetch_add(1);
    c.padme_bytes_overhead.fetch_add(1);
    c.transport_wrap_ok.fetch_add(1);
    c.transport_wrap_fail.fetch_add(1);
    c.transport_unwrap_ok.fetch_add(1);
    c.transport_unwrap_fail.fetch_add(1);
    c.rl_rx_drops.fetch_add(1);

    const auto s = snapshot();
    EXPECT_EQ(s.hs_failed, 1u);
    EXPECT_EQ(s.hs_rekeys, 1u);
    EXPECT_EQ(s.rx_packets, 1u);
    EXPECT_EQ(s.replay_stale, 1u);
    EXPECT_EQ(s.cover_frames_sent, 1u);
    EXPECT_EQ(s.transport_wrap_ok, 1u);
    EXPECT_EQ(s.transport_unwrap_fail, 1u);
    EXPECT_EQ(s.rl_rx_drops, 1u);
}

/* ═══════════════════════════════════════════════════════════════════
 * MetricsExporter Health / Readiness Endpoint Tests
 * ═══════════════════════════════════════════════════════════════════ */

static std::string http_exchange(tachyon::MetricsExporter &ex, const char *path) {
    uint16_t port = ex.port();
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return "";
    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return "";
    }
    std::string req = std::string("GET ") + path + " HTTP/1.1\r\nHost: localhost\r\n\r\n";
    send(fd, req.data(), req.size(), 0);
    ex.poll(4);
    struct timeval tv = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    std::string result;
    char buf[4096];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        result.append(buf, n);
    }
    close(fd);
    return result;
}

TEST(MetricsExporterTest, HealthReturns200) {
    tachyon::MetricsExporter ex;
    ASSERT_TRUE(ex.start(0));
    ASSERT_GT(ex.port(), 0);
    std::string resp = http_exchange(ex, "/health");
    EXPECT_NE(resp.find("200 OK"), std::string::npos);
    EXPECT_NE(resp.find("\"status\":\"ok\""), std::string::npos);
    ex.stop();
}

TEST(MetricsExporterTest, ReadyReturns503WhenNotReady) {
    tachyon::MetricsExporter ex;
    ASSERT_TRUE(ex.start(0));
    std::string resp = http_exchange(ex, "/ready");
    EXPECT_NE(resp.find("503"), std::string::npos);
    EXPECT_NE(resp.find("not_ready"), std::string::npos);
    ex.stop();
}

TEST(MetricsExporterTest, ReadyReturns200WhenReady) {
    tachyon::MetricsExporter ex;
    ASSERT_TRUE(ex.start(0));
    ex.set_ready(true);
    std::string resp = http_exchange(ex, "/ready");
    EXPECT_NE(resp.find("200 OK"), std::string::npos);
    EXPECT_NE(resp.find("\"status\":\"ready\""), std::string::npos);
    ex.stop();
}

TEST(MetricsExporterTest, MetricsEndpointStillWorks) {
    tachyon::MetricsExporter ex;
    ASSERT_TRUE(ex.start(0));
    std::string resp = http_exchange(ex, "/metrics");
    EXPECT_NE(resp.find("200 OK"), std::string::npos);
    EXPECT_NE(resp.find("tachyon_rx_packets_total"), std::string::npos);
    ex.stop();
}

TEST(MetricsExporterTest, VersionReturns200) {
    tachyon::MetricsExporter ex;
    ASSERT_TRUE(ex.start(0));
    std::string resp = http_exchange(ex, "/version");
    EXPECT_NE(resp.find("200 OK"), std::string::npos);
    EXPECT_NE(resp.find("\"version\":"), std::string::npos);
    EXPECT_NE(resp.find("\"protocol\":\"v5\""), std::string::npos);
    ex.stop();
}

TEST(MetricsExporterTest, SetReadyToggle) {
    tachyon::MetricsExporter ex;
    ASSERT_TRUE(ex.start(0));
    EXPECT_FALSE(ex.is_ready());
    ex.set_ready(true);
    EXPECT_TRUE(ex.is_ready());
    ex.set_ready(false);
    EXPECT_FALSE(ex.is_ready());
    ex.stop();
}
