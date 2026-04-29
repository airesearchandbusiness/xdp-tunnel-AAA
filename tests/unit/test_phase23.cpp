/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Unit Tests - Phase 23: Advanced Transport & Observability
 *
 * Tests:
 *   - PathManager (multi-path transport with RTT/loss/jitter EWMA)
 *   - BandwidthEstimator (BBR-inspired BtlBw + RTTProp)
 *   - TFSController (constant-rate Traffic Flow Shaping)
 *   - MetricsExporter (Prometheus/OpenMetrics rendering)
 *   - CipherRenegotiator (mid-session cipher change protocol)
 *   - Config parsing for Phase 23 directives
 *   - Wire format size verification for new message types
 */

#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <vector>
#include <limits>
#include <unistd.h>

#include "tachyon.h"
#include "multipath.h"
#include "bandwidth_estimator.h"
#include "tfs.h"
#include "metrics.h"

/* ══════════════════════════════════════════════════════════════════════════
 * Helpers
 * ══════════════════════════════════════════════════════════════════════════ */

static int make_test_fd() {
    return dup(STDOUT_FILENO);
}

static TunnelConfig parse_from_string(const std::string &content) {
    char path[] = "/tmp/tachyon_test_XXXXXX.conf";
    int fd = mkstemps(path, 5);
    EXPECT_GE(fd, 0);
    if (fd < 0) return {};
    write(fd, content.data(), content.size());
    close(fd);
    TunnelConfig cfg = parse_config(path);
    unlink(path);
    return cfg;
}

static const std::string kBaseConf =
    "[Interface]\n"
    "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    "PeerPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
    "VirtualIP = 10.8.0.1/24\n"
    "LocalPhysicalIP = 192.168.1.10\n"
    "PhysicalInterface = eth0\n"
    "ListenPort = 443\n"
    "[Peer]\n"
    "EndpointIP = 192.168.1.20\n"
    "EndpointMAC = aa:bb:cc:dd:ee:ff\n"
    "InnerIP = 10.8.0.2\n";

/* ══════════════════════════════════════════════════════════════════════════
 * PathManager Tests
 * ══════════════════════════════════════════════════════════════════════════ */

using namespace tachyon::multipath;

TEST(PathManagerTest, AddPathReturnsIndex) {
    PathManager pm;
    EXPECT_EQ(pm.add_path(make_test_fd(), "10.0.0.1", 5000), 0u);
    EXPECT_EQ(pm.add_path(make_test_fd(), "10.0.0.2", 5001), 1u);
    EXPECT_EQ(pm.path_count(), 2u);
}

TEST(PathManagerTest, FirstPathIsPrimary) {
    PathManager pm;
    pm.add_path(make_test_fd(), "10.0.0.1", 5000);
    EXPECT_TRUE(pm.paths()[0].primary);
    EXPECT_EQ(pm.best_idx(), 0);
}

TEST(PathManagerTest, RemovePathTriggersReelect) {
    PathManager pm;
    pm.add_path(make_test_fd(), "10.0.0.1", 5000);
    pm.add_path(make_test_fd(), "10.0.0.2", 5001);
    pm.remove_path(0);
    EXPECT_EQ(pm.best_idx(), 1);
    EXPECT_TRUE(pm.paths()[1].primary);
}

TEST(PathManagerTest, OnProbeAckUpdatesRTT) {
    PathManager pm;
    pm.add_path(make_test_fd(), "10.0.0.1", 5000);
    pm.on_probe_ack(0, 10000);
    EXPECT_EQ(pm.paths()[0].rtt_ewma_us, 10000u);
    EXPECT_EQ(pm.paths()[0].rtt_min_us, 10000u);
}

TEST(PathManagerTest, OnProbeAckSmooths) {
    PathManager pm;
    pm.add_path(make_test_fd(), "10.0.0.1", 5000);
    pm.on_probe_ack(0, 10000);
    pm.on_probe_ack(0, 18000);
    uint64_t expected = static_cast<uint64_t>(0.875 * 10000 + 0.125 * 18000);
    EXPECT_EQ(pm.paths()[0].rtt_ewma_us, expected);
}

TEST(PathManagerTest, OnProbeAckResetsLossStreak) {
    PathManager pm;
    pm.add_path(make_test_fd(), "10.0.0.1", 5000);
    pm.on_probe_timeout(0);
    pm.on_probe_timeout(0);
    EXPECT_EQ(pm.paths()[0].consecutive_lost, 2u);
    pm.on_probe_ack(0, 5000);
    EXPECT_EQ(pm.paths()[0].consecutive_lost, 0u);
    EXPECT_TRUE(pm.paths()[0].active);
}

TEST(PathManagerTest, OnProbeTimeoutIncrementsLoss) {
    PathManager pm;
    pm.add_path(make_test_fd(), "10.0.0.1", 5000);
    pm.on_probe_timeout(0);
    pm.on_probe_timeout(0);
    pm.on_probe_timeout(0);
    EXPECT_EQ(pm.paths()[0].consecutive_lost, 3u);
    EXPECT_GT(pm.paths()[0].loss_ppm, 0u);
}

TEST(PathManagerTest, DeadPathAfterThreshold) {
    PathManager pm;
    pm.add_path(make_test_fd(), "10.0.0.1", 5000);
    for (int i = 0; i < 5; ++i)
        pm.on_probe_timeout(0);
    EXPECT_FALSE(pm.paths()[0].active);
}

TEST(PathManagerTest, DeadPathTriggersReelect) {
    PathManager pm;
    pm.add_path(make_test_fd(), "10.0.0.1", 5000);
    pm.add_path(make_test_fd(), "10.0.0.2", 5001);
    pm.on_probe_ack(1, 5000);
    for (int i = 0; i < 5; ++i)
        pm.on_probe_timeout(0);
    EXPECT_EQ(pm.best_idx(), 1);
}

TEST(PathManagerTest, ScoreInactiveIsMax) {
    PathMetrics m;
    m.active = false;
    EXPECT_EQ(PathManager::score(m), std::numeric_limits<uint64_t>::max());
}

TEST(PathManagerTest, ScoreLowerRTTIsBetter) {
    PathMetrics fast, slow;
    fast.active = true; fast.sock_fd = 1; fast.rtt_ewma_us = 1000;
    slow.active = true; slow.sock_fd = 2; slow.rtt_ewma_us = 50000;
    EXPECT_LT(PathManager::score(fast), PathManager::score(slow));
}

TEST(PathManagerTest, BestFdMatchesPrimary) {
    PathManager pm;
    int fd1 = make_test_fd();
    int fd2 = make_test_fd();
    pm.add_path(fd1, "10.0.0.1", 5000);
    pm.add_path(fd2, "10.0.0.2", 5001);
    EXPECT_EQ(pm.best_fd(), fd1);
}

TEST(PathManagerTest, ActiveCountTracksState) {
    PathManager pm;
    pm.add_path(make_test_fd(), "10.0.0.1", 5000);
    pm.add_path(make_test_fd(), "10.0.0.2", 5001);
    EXPECT_EQ(pm.active_count(), 2u);
    for (int i = 0; i < 5; ++i)
        pm.on_probe_timeout(0);
    EXPECT_EQ(pm.active_count(), 1u);
}

TEST(PathManagerTest, OnDataRxResetsState) {
    PathManager pm;
    pm.add_path(make_test_fd(), "10.0.0.1", 5000);
    for (int i = 0; i < 4; ++i)
        pm.on_probe_timeout(0);
    EXPECT_EQ(pm.paths()[0].consecutive_lost, 4u);
    pm.on_data_rx(0, 1000000);
    EXPECT_EQ(pm.paths()[0].consecutive_lost, 0u);
    EXPECT_TRUE(pm.paths()[0].active);
}

/* ══════════════════════════════════════════════════════════════════════════
 * BandwidthEstimator Tests
 * ══════════════════════════════════════════════════════════════════════════ */

using tachyon::BandwidthEstimator;

TEST(BandwidthEstimatorTest, InitialStateZero) {
    BandwidthEstimator be;
    EXPECT_EQ(be.bandwidth_bps(), 0u);
    EXPECT_FALSE(be.has_samples());
    EXPECT_EQ(be.rtt_prop_ns(), std::numeric_limits<uint64_t>::max());
}

TEST(BandwidthEstimatorTest, OnAckSetsBandwidth) {
    BandwidthEstimator be;
    be.on_ack(1000, 1'000'000, 10'000'000, 1'000'000'000ULL);
    EXPECT_GT(be.bandwidth_bps(), 0u);
}

TEST(BandwidthEstimatorTest, OnAckUpdatesSRTT) {
    BandwidthEstimator be;
    be.on_ack(100, 1'000'000, 50'000'000, 1'000'000'000ULL);
    EXPECT_EQ(be.srtt_ns(), 50'000'000u);
    be.on_ack(100, 1'000'000, 90'000'000, 2'000'000'000ULL);
    uint64_t expected = (7 * 50'000'000ULL + 90'000'000ULL) / 8;
    EXPECT_EQ(be.srtt_ns(), expected);
}

TEST(BandwidthEstimatorTest, RTTPropTracksMinimum) {
    BandwidthEstimator be;
    be.on_ack(100, 1'000'000, 100'000'000, 1'000'000'000ULL);
    be.on_ack(100, 1'000'000, 50'000'000, 2'000'000'000ULL);
    be.on_ack(100, 1'000'000, 80'000'000, 3'000'000'000ULL);
    EXPECT_EQ(be.rtt_prop_ns(), 50'000'000u);
}

TEST(BandwidthEstimatorTest, PacingRateIsGainedBW) {
    BandwidthEstimator be;
    be.on_ack(1000, 1'000'000, 10'000'000, 1'000'000'000ULL);
    uint64_t bw = be.bandwidth_bps();
    uint64_t expected_pacing = static_cast<uint64_t>(bw * 1.25);
    EXPECT_EQ(be.pacing_rate_bps(), expected_pacing);
}

TEST(BandwidthEstimatorTest, InflightCapComputation) {
    BandwidthEstimator be;
    be.on_ack(1000, 1'000'000, 10'000'000, 1'000'000'000ULL);
    uint64_t cap = be.inflight_cap_bytes();
    EXPECT_GT(cap, 0u);
}

TEST(BandwidthEstimatorTest, LossRatioTracksLoss) {
    BandwidthEstimator be;
    be.on_ack(900, 1'000'000, 10'000'000, 1'000'000'000ULL);
    be.on_loss(100);
    double ratio = be.loss_ratio();
    EXPECT_NEAR(ratio, 0.1, 0.01);
}

TEST(BandwidthEstimatorTest, IsCongestedAboveThreshold) {
    BandwidthEstimator be;
    be.on_ack(900, 1'000'000, 10'000'000, 1'000'000'000ULL);
    be.on_loss(100);
    EXPECT_TRUE(be.is_congested());
}

TEST(BandwidthEstimatorTest, RTODefaultOneSecond) {
    BandwidthEstimator be;
    EXPECT_EQ(be.rto_ns(), 1'000'000'000ULL);
}

TEST(BandwidthEstimatorTest, ResetClearsAll) {
    BandwidthEstimator be;
    be.on_ack(1000, 1'000'000, 10'000'000, 1'000'000'000ULL);
    be.reset();
    EXPECT_EQ(be.bandwidth_bps(), 0u);
    EXPECT_FALSE(be.has_samples());
}

TEST(BandwidthEstimatorTest, ZeroIntervalIgnored) {
    BandwidthEstimator be;
    be.on_ack(1000, 0, 10'000'000, 1'000'000'000ULL);
    EXPECT_EQ(be.bandwidth_bps(), 0u);
}

/* ══════════════════════════════════════════════════════════════════════════
 * TFSController Tests
 * ══════════════════════════════════════════════════════════════════════════ */

using tachyon::TFSController;

TEST(TFSControllerTest, DisabledByDefault) {
    TFSController tfs;
    EXPECT_FALSE(tfs.enabled());
    std::vector<uint8_t> out;
    bool dummy;
    EXPECT_FALSE(tfs.get_next(0, out, dummy));
}

TEST(TFSControllerTest, EnabledWithPPS) {
    TFSController tfs(100, 1400);
    EXPECT_TRUE(tfs.enabled());
    EXPECT_EQ(tfs.interval_us(), 10000u);
    EXPECT_EQ(tfs.target_pps(), 100u);
    EXPECT_EQ(tfs.pkt_len(), 1400u);
}

TEST(TFSControllerTest, EnqueueAndGetReal) {
    TFSController tfs(100, 1400);
    uint8_t data[100];
    memset(data, 0xAB, sizeof(data));
    tfs.enqueue(data, sizeof(data));
    std::vector<uint8_t> out;
    bool dummy;
    EXPECT_TRUE(tfs.get_next(0, out, dummy));
    EXPECT_FALSE(dummy);
    EXPECT_EQ(out.size(), 1400u);
    EXPECT_EQ(out[0], 0xAB);
}

TEST(TFSControllerTest, DummyWhenQueueEmpty) {
    TFSController tfs(100, 1400);
    std::vector<uint8_t> out;
    bool dummy;
    EXPECT_TRUE(tfs.get_next(0, out, dummy));
    EXPECT_TRUE(dummy);
    EXPECT_EQ(out.size(), 1400u);
}

TEST(TFSControllerTest, PacketPaddedToFixedLen) {
    TFSController tfs(100, 1400);
    uint8_t data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    tfs.enqueue(data, 10);
    std::vector<uint8_t> out;
    bool dummy;
    tfs.get_next(0, out, dummy);
    EXPECT_EQ(out.size(), 1400u);
    EXPECT_EQ(out[9], 10);
    EXPECT_EQ(out[10], 0);
}

TEST(TFSControllerTest, FragmentLargePayload) {
    TFSController tfs(100, 1400);
    std::vector<uint8_t> data(3000, 0xFF);
    tfs.enqueue(data.data(), data.size());
    EXPECT_EQ(tfs.queue_depth(), 3u);
}

TEST(TFSControllerTest, RateChange) {
    TFSController tfs(100, 1400);
    tfs.set_rate(200);
    EXPECT_EQ(tfs.interval_us(), 5000u);
    EXPECT_EQ(tfs.target_pps(), 200u);
}

TEST(TFSControllerTest, PktLenClamped) {
    TFSController tfs(100, 1400);
    tfs.set_pkt_len(10);
    EXPECT_EQ(tfs.pkt_len(), 64u);
    tfs.set_pkt_len(9999);
    EXPECT_EQ(tfs.pkt_len(), 1500u);
}

TEST(TFSControllerTest, DummyRatio) {
    TFSController tfs(1000, 100);
    std::vector<uint8_t> out;
    bool dummy;
    for (int i = 0; i < 5; ++i)
        tfs.get_next(i * 1000, out, dummy);
    uint8_t data[50] = {};
    for (int i = 0; i < 5; ++i)
        tfs.enqueue(data, sizeof(data));
    for (int i = 5; i < 10; ++i)
        tfs.get_next(i * 1000, out, dummy);
    EXPECT_EQ(tfs.total_sent(), 10u);
    EXPECT_EQ(tfs.dummy_count(), 5u);
    EXPECT_NEAR(tfs.dummy_ratio(), 0.5, 0.01);
}

TEST(TFSControllerTest, FlushClearsQueue) {
    TFSController tfs(100, 1400);
    uint8_t data[100] = {};
    tfs.enqueue(data, sizeof(data));
    EXPECT_EQ(tfs.queue_depth(), 1u);
    tfs.flush();
    EXPECT_EQ(tfs.queue_depth(), 0u);
}

TEST(TFSControllerTest, ScheduleReanchorsOnLargeGap) {
    TFSController tfs(100, 1400);
    std::vector<uint8_t> out;
    bool dummy;
    tfs.get_next(0, out, dummy);
    EXPECT_TRUE(tfs.get_next(10'000'000, out, dummy));
    /* After re-anchor, schedule advances to 10'010'000; a midpoint call is blocked */
    tfs.get_next(10'000'000, out, dummy);
    EXPECT_FALSE(tfs.get_next(10'005'000, out, dummy));
}

/* ══════════════════════════════════════════════════════════════════════════
 * MetricsExporter Tests
 * ══════════════════════════════════════════════════════════════════════════ */

using tachyon::MetricsExporter;

TEST(MetricsExporterTest, RenderContainsAllCounters) {
    MetricsExporter mx;
    userspace_stats stats{};
    mx.update(stats, "test");
    std::string out = mx.render();
    EXPECT_NE(out.find("tachyon_rx_packets_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_rx_bytes_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_tx_packets_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_tx_bytes_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_rx_replay_drops_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_rx_crypto_errors_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_rx_invalid_session_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_rx_malformed_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_rx_ratelimit_drops_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_tx_crypto_errors_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_tx_headroom_errors_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_tx_ratelimit_drops_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_rx_ratelimit_data_drops_total"), std::string::npos);
    EXPECT_NE(out.find("tachyon_rx_roam_events_total"), std::string::npos);
}

TEST(MetricsExporterTest, RenderContainsTunnelLabel) {
    MetricsExporter mx;
    userspace_stats stats{};
    mx.update(stats, "myTunnel");
    std::string out = mx.render();
    EXPECT_NE(out.find("tunnel=\"myTunnel\""), std::string::npos);
}

TEST(MetricsExporterTest, RenderContainsHelpAndType) {
    MetricsExporter mx;
    userspace_stats stats{};
    mx.update(stats, "test");
    std::string out = mx.render();
    EXPECT_NE(out.find("# HELP"), std::string::npos);
    EXPECT_NE(out.find("# TYPE"), std::string::npos);
    EXPECT_NE(out.find("counter"), std::string::npos);
}

TEST(MetricsExporterTest, UpdateChangesSnapshot) {
    MetricsExporter mx;
    userspace_stats stats{};
    stats.rx_packets = 42;
    stats.tx_bytes = 99999;
    mx.update(stats, "test");
    std::string out = mx.render();
    EXPECT_NE(out.find("42"), std::string::npos);
    EXPECT_NE(out.find("99999"), std::string::npos);
}

TEST(MetricsExporterTest, NotRunningByDefault) {
    MetricsExporter mx;
    EXPECT_FALSE(mx.is_running());
    EXPECT_EQ(mx.port(), 0u);
}

TEST(MetricsExporterTest, RenderEOFTerminated) {
    MetricsExporter mx;
    userspace_stats stats{};
    mx.update(stats, "test");
    std::string out = mx.render();
    EXPECT_NE(out.find("# EOF"), std::string::npos);
}

/* ══════════════════════════════════════════════════════════════════════════
 * CipherRenegotiator Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(CipherRenegotiatorTest, InitialStateIdle) {
    CipherRenegotiator cr;
    EXPECT_EQ(cr.state(), CipherRenegotiator::State::IDLE);
    EXPECT_EQ(cr.current_cipher(), TACHYON_CIPHER_CHACHA20);
}

TEST(CipherRenegotiatorTest, ProposeTransitionsToProposed) {
    CipherRenegotiator cr;
    uint8_t key[32] = {};
    cr.propose(0x1234, TACHYON_CIPHER_AES256GCM, key, sizeof(key));
    EXPECT_EQ(cr.state(), CipherRenegotiator::State::PROPOSED);
}

TEST(CipherRenegotiatorTest, ProposeReturnValidMsg) {
    CipherRenegotiator cr;
    uint8_t key[32] = {};
    MsgCipherNeg msg = cr.propose(0x1234, TACHYON_CIPHER_AES256GCM, key, sizeof(key));
    EXPECT_EQ(msg.flags, TACHYON_PKT_CIPHER_NEG);
    EXPECT_EQ(msg.proposed_cipher, TACHYON_CIPHER_AES256GCM);
    EXPECT_GT(msg.epoch, 0);
    EXPECT_EQ(msg.session_id, 0x1234u);
}

TEST(CipherRenegotiatorTest, HandleProposalReturnsAck) {
    CipherRenegotiator initiator, responder;
    uint8_t key[32] = {0x42};
    MsgCipherNeg msg = initiator.propose(0x1234, TACHYON_CIPHER_AES256GCM, key, sizeof(key));
    MsgCipherAck ack = responder.handle_proposal(msg, 0x1234, TACHYON_CIPHER_CHACHA20, key, sizeof(key));
    EXPECT_EQ(ack.flags, TACHYON_PKT_CIPHER_ACK);
    EXPECT_EQ(ack.selected_cipher, TACHYON_CIPHER_AES256GCM);
}

TEST(CipherRenegotiatorTest, HandleProposalEchoesEpoch) {
    CipherRenegotiator initiator, responder;
    uint8_t key[32] = {0x42};
    MsgCipherNeg msg = initiator.propose(0x1234, TACHYON_CIPHER_AES128GCM, key, sizeof(key));
    MsgCipherAck ack = responder.handle_proposal(msg, 0x1234, TACHYON_CIPHER_CHACHA20, key, sizeof(key));
    EXPECT_EQ(ack.epoch, msg.epoch);
    EXPECT_EQ(ack.nonce, msg.nonce);
}

TEST(CipherRenegotiatorTest, HandleProposalBadSession) {
    CipherRenegotiator initiator, responder;
    uint8_t key[32] = {0x42};
    MsgCipherNeg msg = initiator.propose(0x1234, TACHYON_CIPHER_AES256GCM, key, sizeof(key));
    MsgCipherAck ack = responder.handle_proposal(msg, 0x9999, TACHYON_CIPHER_CHACHA20, key, sizeof(key));
    EXPECT_EQ(ack.flags, 0);
}

TEST(CipherRenegotiatorTest, HandleAckSucceeds) {
    CipherRenegotiator initiator, responder;
    uint8_t key[32] = {0x42};
    MsgCipherNeg msg = initiator.propose(0x1234, TACHYON_CIPHER_AES256GCM, key, sizeof(key));
    MsgCipherAck ack = responder.handle_proposal(msg, 0x1234, TACHYON_CIPHER_CHACHA20, key, sizeof(key));
    uint8_t out_cipher = 0xFF;
    EXPECT_TRUE(initiator.handle_ack(ack, &out_cipher, key, sizeof(key)));
    EXPECT_EQ(out_cipher, TACHYON_CIPHER_AES256GCM);
    EXPECT_EQ(initiator.state(), CipherRenegotiator::State::COMMITTED);
}

TEST(CipherRenegotiatorTest, HandleAckBadEpoch) {
    CipherRenegotiator initiator, responder;
    uint8_t key[32] = {0x42};
    MsgCipherNeg msg = initiator.propose(0x1234, TACHYON_CIPHER_AES256GCM, key, sizeof(key));
    MsgCipherAck ack = responder.handle_proposal(msg, 0x1234, TACHYON_CIPHER_CHACHA20, key, sizeof(key));
    ack.epoch = 0xFF;
    uint8_t out_cipher = 0;
    EXPECT_FALSE(initiator.handle_ack(ack, &out_cipher, key, sizeof(key)));
}

TEST(CipherRenegotiatorTest, HandleAckNotProposedFails) {
    CipherRenegotiator cr;
    uint8_t key[32] = {};
    MsgCipherAck ack{};
    ack.flags = TACHYON_PKT_CIPHER_ACK;
    uint8_t out_cipher = 0;
    EXPECT_FALSE(cr.handle_ack(ack, &out_cipher, key, sizeof(key)));
}

TEST(CipherRenegotiatorTest, CommitDoneToIdle) {
    CipherRenegotiator initiator, responder;
    uint8_t key[32] = {0x42};
    MsgCipherNeg msg = initiator.propose(0x1234, TACHYON_CIPHER_AES256GCM, key, sizeof(key));
    MsgCipherAck ack = responder.handle_proposal(msg, 0x1234, TACHYON_CIPHER_CHACHA20, key, sizeof(key));
    uint8_t out_cipher = 0;
    initiator.handle_ack(ack, &out_cipher, key, sizeof(key));
    EXPECT_EQ(initiator.state(), CipherRenegotiator::State::COMMITTED);
    initiator.commit_done();
    EXPECT_EQ(initiator.state(), CipherRenegotiator::State::IDLE);
}

TEST(CipherRenegotiatorTest, ResetCancelsProposal) {
    CipherRenegotiator cr;
    uint8_t key[32] = {};
    cr.propose(0x1234, TACHYON_CIPHER_AES256GCM, key, sizeof(key));
    EXPECT_EQ(cr.state(), CipherRenegotiator::State::PROPOSED);
    cr.reset();
    EXPECT_EQ(cr.state(), CipherRenegotiator::State::IDLE);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Config Parsing — Phase 23 Directives
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(ConfigPhase23Test, ReplayWindowSizeDefault) {
    TunnelConfig cfg = parse_from_string(kBaseConf);
    EXPECT_EQ(cfg.replay_window_size, 4096u);
}

TEST(ConfigPhase23Test, ReplayWindowSizeParsed) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "ReplayWindowSize = 8192\n");
    EXPECT_EQ(cfg.replay_window_size, 8192u);
}

TEST(ConfigPhase23Test, ReplayWindowSizeBadAlignment) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "ReplayWindowSize = 100\n");
    EXPECT_EQ(cfg.replay_window_size, 4096u);
}

TEST(ConfigPhase23Test, MetricsEnabledParsed) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "MetricsEnabled = true\n");
    EXPECT_TRUE(cfg.metrics_enabled);
}

TEST(ConfigPhase23Test, MetricsPortParsed) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "MetricsPort = 9191\n");
    EXPECT_EQ(cfg.metrics_port, 9191u);
}

TEST(ConfigPhase23Test, TrafficShapingPPSParsed) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "TrafficShapingPPS = 500\n");
    EXPECT_EQ(cfg.tfs_pps, 500u);
}

TEST(ConfigPhase23Test, MultiPathInterfacesParsed) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "MultiPathInterfaces = eth1,wlan0\n");
    ASSERT_EQ(cfg.multipath_interfaces.size(), 2u);
    EXPECT_EQ(cfg.multipath_interfaces[0], "eth1");
    EXPECT_EQ(cfg.multipath_interfaces[1], "wlan0");
}

TEST(ConfigPhase23Test, TFSPktLenParsed) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "TrafficShapingPktLen = 1200\n");
    EXPECT_EQ(cfg.tfs_pkt_len, 1200u);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Wire Format — Phase 23 Size Verification
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(WireFormatPhase23Test, CipherNegSize20) {
    EXPECT_EQ(sizeof(MsgCipherNeg), 20u);
    EXPECT_EQ(sizeof(struct tachyon_msg_cipher_neg), 20u);
}

TEST(WireFormatPhase23Test, CipherAckSize20) {
    EXPECT_EQ(sizeof(MsgCipherAck), 20u);
    EXPECT_EQ(sizeof(struct tachyon_msg_cipher_ack), 20u);
}

TEST(WireFormatPhase23Test, PacketTypeConstants) {
    EXPECT_EQ(TACHYON_PKT_CIPHER_NEG, 0xC5);
    EXPECT_EQ(TACHYON_PKT_CIPHER_ACK, 0xC6);
}
