/* SPDX-License-Identifier: MIT */
/*
 * Tachyon XDP Test Runner
 *
 * Loads the XDP/eBPF object (src/xdp_core.o) and uses BPF_PROG_TEST_RUN
 * to verify packet processing logic with crafted packets.
 *
 * REQUIRES: root or CAP_BPF + CAP_NET_ADMIN
 *
 * Tests:
 *   - TX path encapsulation (inner packet -> outer headers)
 *   - TX non-IPv4 passthrough
 *   - TX unknown destination passthrough
 *   - RX control plane packet routing
 *   - RX malformed packet rejection
 *   - RX invalid session rejection
 *   - MSS clamping on SYN packets
 *   - Packet structure validation
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Must not pull in C++ headers from tachyon.h before BPF headers */
extern "C" {
#include "../src/common.h"
}

/* XDP action codes */
#ifndef XDP_DROP
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * Test Fixture - Loads BPF object and initializes maps
 * ══════════════════════════════════════════════════════════════════════════ */

class XdpTest : public ::testing::Test {
  protected:
    struct bpf_object *obj_ = nullptr;
    int tx_prog_fd_ = -1;
    int rx_prog_fd_ = -1;
    int config_fd_ = -1;
    int session_fd_ = -1;
    int ip_sess_fd_ = -1;
    int stats_fd_ = -1;

    void SetUp() override {
        /* Check for root privileges */
        if (geteuid() != 0) {
            GTEST_SKIP() << "XDP tests require root privileges";
        }

        /* Load BPF object */
        const char *obj_path = XDP_OBJ_PATH;
        obj_ = bpf_object__open_file(obj_path, nullptr);
        if (!obj_) {
            GTEST_SKIP() << "Cannot open BPF object: " << obj_path
                         << " (build with 'make xdp' first)";
        }

        if (bpf_object__load(obj_)) {
            bpf_object__close(obj_);
            obj_ = nullptr;
            GTEST_SKIP() << "Cannot load BPF object into kernel "
                         << "(kernel module may need to be loaded first)";
        }

        /* Find programs */
        struct bpf_program *tx_prog = bpf_object__find_program_by_name(obj_, "xdp_tx_path");
        struct bpf_program *rx_prog = bpf_object__find_program_by_name(obj_, "xdp_rx_path");

        if (tx_prog)
            tx_prog_fd_ = bpf_program__fd(tx_prog);
        if (rx_prog)
            rx_prog_fd_ = bpf_program__fd(rx_prog);

        /* Find maps */
        struct bpf_map *m;
        m = bpf_object__find_map_by_name(obj_, "config_map");
        if (m)
            config_fd_ = bpf_map__fd(m);
        m = bpf_object__find_map_by_name(obj_, "session_map");
        if (m)
            session_fd_ = bpf_map__fd(m);
        m = bpf_object__find_map_by_name(obj_, "ip_to_session_map");
        if (m)
            ip_sess_fd_ = bpf_map__fd(m);
        m = bpf_object__find_map_by_name(obj_, "stats_map");
        if (m)
            stats_fd_ = bpf_map__fd(m);

        /* Initialize config map */
        if (config_fd_ >= 0) {
            struct tachyon_config cfg = {};
            cfg.listen_port_net = htons(443);
            cfg.mimicry_type = TACHYON_MIMICRY_QUIC;
            uint32_t zero = 0;
            bpf_map_update_elem(config_fd_, &zero, &cfg, BPF_ANY);
        }

        /* Initialize a test session (session_id=1) */
        if (session_fd_ >= 0) {
            struct tachyon_session sess = {};
            sess.peer_ip = inet_addr("192.168.1.20");
            sess.local_ip = inet_addr("192.168.1.10");
            uint8_t mac[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
            memcpy(sess.peer_mac, mac, 6);
            uint32_t sid = 1;
            bpf_map_update_elem(session_fd_, &sid, &sess, BPF_ANY);
        }

        /* Map peer inner IP -> session 1 */
        if (ip_sess_fd_ >= 0) {
            uint32_t inner_ip = inet_addr("10.8.0.2");
            uint32_t sid = 1;
            bpf_map_update_elem(ip_sess_fd_, &inner_ip, &sid, BPF_ANY);
        }
    }

    void TearDown() override {
        if (obj_)
            bpf_object__close(obj_);
    }

    /* ── Packet Builders ── */

    /* Build a minimal Ethernet + IPv4 + TCP packet */
    std::vector<uint8_t> build_inner_tcp_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
                                                uint16_t dst_port, bool syn = false,
                                                uint16_t mss = 0) {
        size_t eth_len = sizeof(struct ethhdr);
        size_t ip_len = sizeof(struct iphdr);
        size_t tcp_len = sizeof(struct tcphdr);
        size_t opts_len = (mss > 0) ? 4 : 0; /* MSS option: kind(1)+len(1)+mss(2) */
        size_t total = eth_len + ip_len + tcp_len + opts_len + 20; /* 20 bytes payload */

        std::vector<uint8_t> pkt(total, 0);

        /* Ethernet header */
        auto *eth = reinterpret_cast<struct ethhdr *>(pkt.data());
        eth->h_proto = htons(ETH_P_IP);

        /* IP header */
        auto *ip = reinterpret_cast<struct iphdr *>(pkt.data() + eth_len);
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = htons(total - eth_len);
        ip->protocol = IPPROTO_TCP;
        ip->saddr = src_ip;
        ip->daddr = dst_ip;
        ip->ttl = 64;

        /* TCP header */
        auto *tcp = reinterpret_cast<struct tcphdr *>(pkt.data() + eth_len + ip_len);
        tcp->source = htons(src_port);
        tcp->dest = htons(dst_port);
        tcp->doff = (tcp_len + opts_len) / 4;
        if (syn)
            tcp->syn = 1;

        /* MSS option */
        if (mss > 0) {
            uint8_t *opts = pkt.data() + eth_len + ip_len + tcp_len;
            opts[0] = 2; /* MSS option kind */
            opts[1] = 4; /* MSS option length */
            opts[2] = (mss >> 8) & 0xFF;
            opts[3] = mss & 0xFF;
        }

        return pkt;
    }

    /* Build a minimal Ethernet + ARP packet */
    std::vector<uint8_t> build_arp_packet() {
        size_t total = sizeof(struct ethhdr) + 28; /* ARP is 28 bytes */
        std::vector<uint8_t> pkt(total, 0);

        auto *eth = reinterpret_cast<struct ethhdr *>(pkt.data());
        eth->h_proto = htons(ETH_P_ARP);

        return pkt;
    }

    /* Build a minimal encapsulated packet for RX path */
    std::vector<uint8_t> build_encap_packet(uint32_t session_id, uint8_t quic_flags,
                                            size_t payload_len) {
        size_t total = TACHYON_OUTER_HDR_LEN + payload_len + TACHYON_AEAD_TAG_LEN;
        std::vector<uint8_t> pkt(total, 0);

        /* Outer Ethernet */
        auto *eth = reinterpret_cast<struct ethhdr *>(pkt.data());
        eth->h_proto = htons(ETH_P_IP);

        /* Outer IP */
        auto *ip = reinterpret_cast<struct iphdr *>(pkt.data() + sizeof(struct ethhdr));
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = htons(total - sizeof(struct ethhdr));
        ip->protocol = IPPROTO_UDP;
        ip->saddr = inet_addr("192.168.1.20");
        ip->daddr = inet_addr("192.168.1.10");
        ip->ttl = 64;

        /* Outer UDP */
        auto *udp = reinterpret_cast<struct udphdr *>(pkt.data() + sizeof(struct ethhdr) +
                                                      sizeof(struct iphdr));
        udp->source = htons(443);
        udp->dest = htons(443);
        udp->len = htons(total - sizeof(struct ethhdr) - sizeof(struct iphdr));

        /* Ghost header */
        auto *ghost = reinterpret_cast<struct tachyon_ghost_hdr *>(
            pkt.data() + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
        ghost->quic_flags = quic_flags;
        ghost->session_id = htonl(session_id);
        ghost->seq = htobe64(1);
        ghost->nonce_salt = htonl(0x12345678);

        return pkt;
    }

    /* Run BPF_PROG_TEST_RUN on a given program */
    struct test_result {
        uint32_t retval;
        std::vector<uint8_t> data_out;
        bool success;
    };

    test_result run_xdp_test(int prog_fd, const std::vector<uint8_t> &pkt_in) {
        test_result result = {};
        result.data_out.resize(4096, 0);

        DECLARE_LIBBPF_OPTS(
            bpf_test_run_opts, opts, .data_in = pkt_in.data(),
            .data_size_in = static_cast<__u32>(pkt_in.size()), .data_out = result.data_out.data(),
            .data_size_out = static_cast<__u32>(result.data_out.size()), .repeat = 1, );

        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        result.success = (err == 0);
        result.retval = opts.retval;
        result.data_out.resize(opts.data_size_out);
        return result;
    }
};

/* ══════════════════════════════════════════════════════════════════════════
 * TX Path Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(XdpTest, TxPathRequiresProgram) {
    if (tx_prog_fd_ < 0)
        GTEST_SKIP() << "TX program not found";

    /* Valid inner packet to known peer IP */
    auto pkt = build_inner_tcp_packet(inet_addr("10.8.0.1"), inet_addr("10.8.0.2"), 12345, 80);

    auto result = run_xdp_test(tx_prog_fd_, pkt);
    ASSERT_TRUE(result.success) << "BPF_PROG_TEST_RUN failed";

    /* Should be XDP_REDIRECT (encapsulate and send) or XDP_DROP (no tx_port map entry) */
    /* Without devmap populated, the program may return XDP_PASS or similar */
    EXPECT_NE(result.retval, (uint32_t)XDP_DROP)
        << "Valid packet to known peer should not be dropped";
}

TEST_F(XdpTest, TxNonIpv4Passthrough) {
    if (tx_prog_fd_ < 0)
        GTEST_SKIP() << "TX program not found";

    auto pkt = build_arp_packet();
    auto result = run_xdp_test(tx_prog_fd_, pkt);
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.retval, (uint32_t)XDP_PASS) << "Non-IPv4 packets should pass through";
}

TEST_F(XdpTest, TxUnknownDestination) {
    if (tx_prog_fd_ < 0)
        GTEST_SKIP() << "TX program not found";

    /* Packet to IP not in ip_to_session_map */
    auto pkt = build_inner_tcp_packet(inet_addr("10.8.0.1"), inet_addr("10.8.0.99"), 12345, 80);

    auto result = run_xdp_test(tx_prog_fd_, pkt);
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.retval, (uint32_t)XDP_PASS) << "Unknown destination should pass through";
}

/* ══════════════════════════════════════════════════════════════════════════
 * RX Path Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(XdpTest, RxControlPlaneRouting) {
    if (rx_prog_fd_ < 0)
        GTEST_SKIP() << "RX program not found";

    /* Build a control plane packet (flags & 0xF0 == 0xC0) */
    auto pkt = build_encap_packet(1, TACHYON_PKT_INIT, 100);
    auto result = run_xdp_test(rx_prog_fd_, pkt);
    ASSERT_TRUE(result.success);

    /* Control plane packets should be passed to userspace */
    EXPECT_EQ(result.retval, (uint32_t)XDP_PASS)
        << "Control plane packets should be passed to userspace";
}

TEST_F(XdpTest, RxMalformedTooShort) {
    if (rx_prog_fd_ < 0)
        GTEST_SKIP() << "RX program not found";

    /* Packet shorter than minimum encapsulated length */
    std::vector<uint8_t> pkt(TACHYON_OUTER_HDR_LEN - 1, 0);
    auto *eth = reinterpret_cast<struct ethhdr *>(pkt.data());
    eth->h_proto = htons(ETH_P_IP);

    auto result = run_xdp_test(rx_prog_fd_, pkt);
    ASSERT_TRUE(result.success);

    /* Too-short packets should be dropped or passed (not crash) */
    EXPECT_TRUE(result.retval == XDP_DROP || result.retval == XDP_PASS)
        << "Malformed packet should be safely handled";
}

TEST_F(XdpTest, RxNonUdpPassthrough) {
    if (rx_prog_fd_ < 0)
        GTEST_SKIP() << "RX program not found";

    /* Build a TCP packet (not UDP, so not a tunnel packet) */
    size_t total = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    std::vector<uint8_t> pkt(total, 0);

    auto *eth = reinterpret_cast<struct ethhdr *>(pkt.data());
    eth->h_proto = htons(ETH_P_IP);

    auto *ip = reinterpret_cast<struct iphdr *>(pkt.data() + sizeof(struct ethhdr));
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = htons(total - sizeof(struct ethhdr));
    ip->protocol = IPPROTO_TCP;
    ip->ttl = 64;

    auto result = run_xdp_test(rx_prog_fd_, pkt);
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.retval, (uint32_t)XDP_PASS) << "Non-UDP packets should pass through RX path";
}

TEST_F(XdpTest, RxWrongPort) {
    if (rx_prog_fd_ < 0)
        GTEST_SKIP() << "RX program not found";

    /* Build encapsulated packet but with wrong destination port */
    auto pkt = build_encap_packet(1, 0x40, 100);

    /* Change UDP dest port to non-listen port */
    auto *udp = reinterpret_cast<struct udphdr *>(pkt.data() + sizeof(struct ethhdr) +
                                                  sizeof(struct iphdr));
    udp->dest = htons(9999);

    auto result = run_xdp_test(rx_prog_fd_, pkt);
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.retval, (uint32_t)XDP_PASS) << "Packets to wrong port should pass through";
}

/* ══════════════════════════════════════════════════════════════════════════
 * MSS Clamping Test
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(XdpTest, TxMssClamping) {
    if (tx_prog_fd_ < 0)
        GTEST_SKIP() << "TX program not found";

    /* Build a TCP SYN with MSS=1460 to a known peer */
    auto pkt =
        build_inner_tcp_packet(inet_addr("10.8.0.1"), inet_addr("10.8.0.2"), 12345, 80, true, 1460);

    auto result = run_xdp_test(tx_prog_fd_, pkt);
    ASSERT_TRUE(result.success);

    /* If the packet was processed (not dropped), check MSS was clamped.
     * Note: Full MSS verification requires parsing the output packet
     * which may have outer headers prepended. */
    if (result.retval == XDP_REDIRECT && !result.data_out.empty()) {
        /* The output packet has outer headers prepended.
         * Find the TCP header in the output and check MSS option. */
        size_t outer_hdr = TACHYON_OUTER_HDR_LEN;
        if (result.data_out.size() >
            outer_hdr + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + 4) {

            size_t tcp_offset = outer_hdr + sizeof(struct ethhdr) + sizeof(struct iphdr);
            auto *tcp = reinterpret_cast<struct tcphdr *>(result.data_out.data() + tcp_offset);

            if (tcp->syn) {
                size_t opts_offset = tcp_offset + sizeof(struct tcphdr);
                uint8_t *opts = result.data_out.data() + opts_offset;
                if (opts[0] == 2 && opts[1] == 4) {
                    uint16_t clamped_mss = (opts[2] << 8) | opts[3];
                    EXPECT_LE(clamped_mss, (uint16_t)TACHYON_TARGET_MSS)
                        << "MSS should be clamped to " << TACHYON_TARGET_MSS;
                }
            }
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * Packet Structure Validation
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(XdpTest, GhostHeaderLayout) {
    /* Verify ghost header field offsets */
    struct tachyon_ghost_hdr hdr = {};
    hdr.quic_flags = 0x42;
    hdr.pad[0] = 0x01;
    hdr.pad[1] = 0x02;
    hdr.pad[2] = 0x03;
    hdr.session_id = htonl(1);
    hdr.seq = htobe64(0x1234567890ABCDEFULL);
    hdr.nonce_salt = htonl(0xDEADBEEF);

    auto *raw = reinterpret_cast<uint8_t *>(&hdr);
    EXPECT_EQ(raw[0], 0x42); /* quic_flags at offset 0 */
    EXPECT_EQ(raw[1], 0x01); /* pad[0] at offset 1 */
    EXPECT_EQ(raw[2], 0x02); /* pad[1] at offset 2 */
    EXPECT_EQ(raw[3], 0x03); /* pad[2] at offset 3 */

    /* session_id at offset 4 (network byte order) */
    uint32_t sid;
    memcpy(&sid, raw + 4, 4);
    EXPECT_EQ(ntohl(sid), 1u);

    /* seq at offset 8 */
    uint64_t seq;
    memcpy(&seq, raw + 8, 8);
    EXPECT_EQ(be64toh(seq), 0x1234567890ABCDEFULL);

    /* nonce_salt at offset 16 */
    uint32_t salt;
    memcpy(&salt, raw + 16, 4);
    EXPECT_EQ(ntohl(salt), 0xDEADBEEFu);

    /* Total size = 20 */
    EXPECT_EQ(sizeof(hdr), 20u);
}
