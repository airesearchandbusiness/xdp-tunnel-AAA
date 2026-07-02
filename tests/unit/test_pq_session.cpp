/* SPDX-License-Identifier: MIT */
/*
 * Two-peer integration tests for the post-quantum session-establishment layer
 * (tachyon::pqsession). These drive the full hybrid handshake — cookie gate,
 * wire framing, key agreement, PSK binding, and tamper/impersonation/DoS
 * rejection — in two ways:
 *
 *   1. In-process: Client and Server exchange byte buffers directly.
 *   2. End-to-end: the same buffers are pushed across a real AF_INET loopback
 *      UDP socketpair, proving the on-wire packet sizes round-trip intact.
 *
 * The KEM-dependent paths need a real ML-KEM backend; they skip cleanly on a
 * stub build (no OpenSSL>=3.5 / liboqs). Framing, cookie, and state-machine
 * assertions run regardless.
 */
#include <gtest/gtest.h>

#include "pq_session.h"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

/* From crypto.cpp; forward-declared to keep this TU free of the loader's
 * BPF-pulling umbrella header. */
bool generate_x25519_keypair(uint8_t *priv_out, uint8_t *pub_out);
bool generate_cookie(const uint8_t *secret, uint32_t client_ip, uint64_t nonce, uint64_t window,
                     uint8_t *out_cookie);
void init_crypto_globals();

class PqCryptoEnvironment : public ::testing::Environment {
  public:
    void SetUp() override { init_crypto_globals(); }
};
const ::testing::Environment *const kPqSessEnv =
    ::testing::AddGlobalTestEnvironment(new PqCryptoEnvironment);

namespace pqs = tachyon::pqsession;
namespace pqhs = tachyon::pqhs;

#define REQUIRE_PQ_BACKEND()                                                                       \
    do {                                                                                           \
        if (!pqs::available())                                                                     \
            GTEST_SKIP() << "no post-quantum KEM backend in this build";                           \
    } while (0)

namespace {

struct Peer {
    uint8_t priv[32];
    uint8_t pub[32];
};

Peer make_peer() {
    Peer p{};
    EXPECT_TRUE(generate_x25519_keypair(p.priv, p.pub));
    return p;
}

pqhs::StaticIdentity id_of(const Peer &me, const Peer &other) {
    pqhs::StaticIdentity id{};
    std::memcpy(id.priv, me.priv, 32);
    std::memcpy(id.my_pub, me.pub, 32);
    std::memcpy(id.peer_pub, other.pub, 32);
    return id;
}

constexpr uint32_t kSession = 0xA1B2C3D4;
constexpr uint32_t kSrcIp = 0x0100007F; /* 127.0.0.1, network order */
constexpr uint64_t kNonce = 0x1122334455667788ULL;
constexpr uint64_t kWindow = 0x0000000000ABCDEFULL;

/* Mint a cookie exactly as the responder will recompute it. */
void mint_cookie(const uint8_t secret[32], uint8_t out[32]) {
    ASSERT_TRUE(generate_cookie(secret, kSrcIp, kNonce, kWindow, out));
}

/* Drive a complete handshake in-process. On success writes both peers' final
 * per-direction keys. */
bool run_session(const pqhs::StaticIdentity &cid, const pqhs::StaticIdentity &sid,
                 const uint8_t *cpsk, size_t cpsk_len, const uint8_t *spsk, size_t spsk_len,
                 uint8_t c_tx[32], uint8_t c_rx[32], uint8_t s_tx[32], uint8_t s_rx[32]) {
    uint8_t secret[32];
    std::memset(secret, 0x5A, sizeof(secret));
    uint8_t cookie[32];
    if (!generate_cookie(secret, kSrcIp, kNonce, kWindow, cookie))
        return false;

    pqs::Client cli(cid, kSession, cpsk, cpsk_len);
    pqs::Server srv(sid, kSession, spsk, spsk_len);

    std::vector<uint8_t> m_init, m_resp, m_conf;
    if (!cli.make_init(cookie, kNonce, m_init))
        return false;
    if (srv.on_init(m_init.data(), m_init.size(), secret, kSrcIp, kWindow, m_resp) != pqs::Step::OK)
        return false;
    if (cli.on_response(m_resp.data(), m_resp.size(), m_conf) != pqs::Step::COMPLETE)
        return false;
    if (srv.on_confirm(m_conf.data(), m_conf.size()) != pqs::Step::COMPLETE)
        return false;
    if (!cli.complete() || !srv.complete())
        return false;
    return cli.export_keys(c_tx, c_rx) && srv.export_keys(s_tx, s_rx);
}

} // namespace

TEST(PqSession, WireSizesAreFixed) {
    EXPECT_EQ(pqs::PQ_INIT_LEN, pqs::PQ_HDR_LEN + 8 + pqs::COOKIE_LEN + pqhs::MSG_INIT_LEN);
    EXPECT_EQ(pqs::PQ_RESPONSE_LEN, pqs::PQ_HDR_LEN + pqhs::MSG_RESPONSE_LEN);
    EXPECT_EQ(pqs::PQ_CONFIRM_LEN, pqs::PQ_HDR_LEN + pqhs::MSG_CONFIRM_LEN);
    /* Every handshake packet must fit a single datagram with room to spare. */
    EXPECT_LT(pqs::PQ_INIT_LEN, 4096u);
    EXPECT_LT(pqs::PQ_RESPONSE_LEN, 4096u);
}

TEST(PqSession, AvailabilityMatchesBackend) {
    EXPECT_EQ(pqs::available(), tachyon::hkex::hybrid_available());
}

TEST(PqSession, DowngradeProtectionPolicy) {
    /* Hybrid mode refuses the classical key-exchange messages... */
    EXPECT_FALSE(pqs::handshake_flag_allowed(pqs::PKT_CLASSICAL_AUTH, true));
    EXPECT_FALSE(pqs::handshake_flag_allowed(pqs::PKT_CLASSICAL_FINISH, true));
    /* ...but allows the PQ messages. */
    EXPECT_TRUE(pqs::handshake_flag_allowed(pqs::PKT_PQ_INIT, true));
    EXPECT_TRUE(pqs::handshake_flag_allowed(pqs::PKT_PQ_RESPONSE, true));
    EXPECT_TRUE(pqs::handshake_flag_allowed(pqs::PKT_PQ_CONFIRM, true));

    /* Classical mode is the mirror image: PQ messages refused, AUTH/FINISH ok. */
    EXPECT_FALSE(pqs::handshake_flag_allowed(pqs::PKT_PQ_INIT, false));
    EXPECT_FALSE(pqs::handshake_flag_allowed(pqs::PKT_PQ_RESPONSE, false));
    EXPECT_FALSE(pqs::handshake_flag_allowed(pqs::PKT_PQ_CONFIRM, false));
    EXPECT_TRUE(pqs::handshake_flag_allowed(pqs::PKT_CLASSICAL_AUTH, false));
    EXPECT_TRUE(pqs::handshake_flag_allowed(pqs::PKT_CLASSICAL_FINISH, false));

    /* The shared cookie round, keepalives, and cipher-reneg are always allowed. */
    for (bool hybrid : {false, true}) {
        EXPECT_TRUE(pqs::handshake_flag_allowed(0xC0, hybrid)); /* INIT       */
        EXPECT_TRUE(pqs::handshake_flag_allowed(0xC1, hybrid)); /* COOKIE     */
        EXPECT_TRUE(pqs::handshake_flag_allowed(0xC4, hybrid)); /* KEEPALIVE  */
        EXPECT_TRUE(pqs::handshake_flag_allowed(0xC5, hybrid)); /* CIPHER_NEG */
        EXPECT_TRUE(pqs::handshake_flag_allowed(0xC6, hybrid)); /* CIPHER_ACK */
    }
}

TEST(PqSession, FullHandshakeAgreesOnKeys) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    const uint8_t psk[] = "shared-secret-psk";
    uint8_t c_tx[32], c_rx[32], s_tx[32], s_rx[32];
    ASSERT_TRUE(run_session(id_of(i, r), id_of(r, i), psk, sizeof(psk), psk, sizeof(psk), c_tx,
                            c_rx, s_tx, s_rx));

    /* Per-direction mirror: client send == server receive, and vice versa. */
    EXPECT_EQ(std::memcmp(c_tx, s_rx, 32), 0);
    EXPECT_EQ(std::memcmp(c_rx, s_tx, 32), 0);
    /* The two directions must use distinct keys. */
    EXPECT_NE(std::memcmp(c_tx, c_rx, 32), 0);
}

TEST(PqSession, EmptyPskStillAgrees) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    uint8_t c_tx[32], c_rx[32], s_tx[32], s_rx[32];
    ASSERT_TRUE(
        run_session(id_of(i, r), id_of(r, i), nullptr, 0, nullptr, 0, c_tx, c_rx, s_tx, s_rx));
    EXPECT_EQ(std::memcmp(c_tx, s_rx, 32), 0);
    EXPECT_EQ(std::memcmp(c_rx, s_tx, 32), 0);
}

TEST(PqSession, DifferentPskDerivesDifferentKeys) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    const uint8_t psk1[] = "psk-one";
    const uint8_t psk2[] = "psk-two";

    uint8_t a_tx[32], a_rx[32], b_tx[32], b_rx[32];
    ASSERT_TRUE(run_session(id_of(i, r), id_of(r, i), psk1, sizeof(psk1), psk1, sizeof(psk1), a_tx,
                            a_rx, b_tx, b_rx));
    uint8_t c_tx[32], c_rx[32], d_tx[32], d_rx[32];
    ASSERT_TRUE(run_session(id_of(i, r), id_of(r, i), psk2, sizeof(psk2), psk2, sizeof(psk2), c_tx,
                            c_rx, d_tx, d_rx));
    /* Same identities, different PSK -> different session keys. */
    EXPECT_NE(std::memcmp(a_tx, c_tx, 32), 0);
}

TEST(PqSession, MismatchedPskBreaksAgreement) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    const uint8_t psk1[] = "client-psk";
    const uint8_t psk2[] = "server-psk";

    /* The pqhs handshake still completes (it authenticates via static-static DH,
     * not the PSK), but the PSK fold makes the final keys disagree, so the
     * datapath will never come up — exactly the classical behaviour. */
    uint8_t c_tx[32], c_rx[32], s_tx[32], s_rx[32];
    ASSERT_TRUE(run_session(id_of(i, r), id_of(r, i), psk1, sizeof(psk1), psk2, sizeof(psk2), c_tx,
                            c_rx, s_tx, s_rx));
    EXPECT_NE(std::memcmp(c_tx, s_rx, 32), 0);
    EXPECT_NE(std::memcmp(c_rx, s_tx, 32), 0);
}

TEST(PqSession, BadCookieIsRejectedBeforeKemWork) {
    /* The cookie is validated before any KEM decapsulation, so this exercises
     * the anti-DoS gate even on a stub build: a hand-built PQ_INIT with a
     * corrupt cookie is rejected without touching the (absent) backend. */
    Peer i = make_peer(), r = make_peer();
    uint8_t secret[32];
    std::memset(secret, 0x33, sizeof(secret));
    uint8_t cookie[32];
    mint_cookie(secret, cookie);
    cookie[7] ^= 0x80; /* corrupt the cookie */

    std::vector<uint8_t> pkt(pqs::PQ_INIT_LEN, 0);
    pkt[0] = pqs::PKT_PQ_INIT;
    uint32_t be = htonl(kSession);
    std::memcpy(pkt.data() + 4, &be, 4);
    std::memcpy(pkt.data() + pqs::PQ_HDR_LEN, &kNonce, 8);
    std::memcpy(pkt.data() + pqs::PQ_HDR_LEN + 8, cookie, 32);

    pqs::Server srv(id_of(r, i), kSession, nullptr, 0);
    std::vector<uint8_t> resp;
    EXPECT_EQ(srv.on_init(pkt.data(), pkt.size(), secret, kSrcIp, kWindow, resp),
              pqs::Step::DOS_REJECT);
    EXPECT_FALSE(srv.complete());
}

TEST(PqSession, PreviousWindowCookieAccepted) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    uint8_t secret[32];
    std::memset(secret, 0x44, sizeof(secret));
    /* Cookie minted for window-1; responder a minute later must still accept. */
    uint8_t cookie[32];
    ASSERT_TRUE(generate_cookie(secret, kSrcIp, kNonce, kWindow - 1, cookie));

    pqs::Client cli(id_of(i, r), kSession, nullptr, 0);
    pqs::Server srv(id_of(r, i), kSession, nullptr, 0);

    std::vector<uint8_t> m_init, m_resp;
    ASSERT_TRUE(cli.make_init(cookie, kNonce, m_init));
    EXPECT_EQ(srv.on_init(m_init.data(), m_init.size(), secret, kSrcIp, kWindow, m_resp),
              pqs::Step::OK);
}

TEST(PqSession, TamperedResponseFailsAuthentication) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    uint8_t secret[32];
    std::memset(secret, 0x5A, sizeof(secret));
    uint8_t cookie[32];
    mint_cookie(secret, cookie);

    pqs::Client cli(id_of(i, r), kSession, nullptr, 0);
    pqs::Server srv(id_of(r, i), kSession, nullptr, 0);

    std::vector<uint8_t> m_init, m_resp, m_conf;
    ASSERT_TRUE(cli.make_init(cookie, kNonce, m_init));
    ASSERT_EQ(srv.on_init(m_init.data(), m_init.size(), secret, kSrcIp, kWindow, m_resp),
              pqs::Step::OK);

    /* Flip a byte inside the KEM ciphertext (after the hdr + pqhs hdr + nonce). */
    m_resp[pqs::PQ_HDR_LEN + pqhs::HDR_LEN + pqhs::NONCE_LEN + 5] ^= 0x40;
    pqs::Step st = cli.on_response(m_resp.data(), m_resp.size(), m_conf);
    EXPECT_TRUE(st == pqs::Step::AUTH_FAIL || st == pqs::Step::CRYPTO_ERROR);
    EXPECT_FALSE(cli.complete());
}

TEST(PqSession, ImpersonatedPeerFailsAuthentication) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer(), attacker = make_peer();
    uint8_t secret[32];
    std::memset(secret, 0x5A, sizeof(secret));
    uint8_t cookie[32];
    mint_cookie(secret, cookie);

    /* Server believes the peer is `attacker`, so its static-static DH differs. */
    pqs::Client cli(id_of(i, r), kSession, nullptr, 0);
    pqs::Server srv(id_of(r, attacker), kSession, nullptr, 0);

    std::vector<uint8_t> m_init, m_resp, m_conf;
    ASSERT_TRUE(cli.make_init(cookie, kNonce, m_init));
    ASSERT_EQ(srv.on_init(m_init.data(), m_init.size(), secret, kSrcIp, kWindow, m_resp),
              pqs::Step::OK);
    EXPECT_EQ(cli.on_response(m_resp.data(), m_resp.size(), m_conf), pqs::Step::AUTH_FAIL);
    EXPECT_FALSE(cli.complete());
}

TEST(PqSession, MalformedAndWrongSessionRejected) {
    Peer i = make_peer(), r = make_peer();
    pqs::Server srv(id_of(r, i), kSession, nullptr, 0);
    uint8_t secret[32];
    std::memset(secret, 0x01, sizeof(secret));
    std::vector<uint8_t> out;

    /* Too short. */
    std::vector<uint8_t> short_msg(10, 0);
    EXPECT_EQ(srv.on_init(short_msg.data(), short_msg.size(), secret, kSrcIp, kWindow, out),
              pqs::Step::BAD_MESSAGE);

    /* Right length, wrong session id -> silently ignored (not penalized). */
    std::vector<uint8_t> wrong_sess(pqs::PQ_INIT_LEN, 0);
    wrong_sess[0] = pqs::PKT_PQ_INIT;
    uint32_t be = htonl(kSession ^ 0xFFFF);
    std::memcpy(wrong_sess.data() + 4, &be, 4);
    EXPECT_EQ(srv.on_init(wrong_sess.data(), wrong_sess.size(), secret, kSrcIp, kWindow, out),
              pqs::Step::IGNORE);
}

TEST(PqSession, OutOfOrderCallsRejected) {
    Peer i = make_peer(), r = make_peer();
    pqs::Client cli(id_of(i, r), kSession, nullptr, 0);
    pqs::Server srv(id_of(r, i), kSession, nullptr, 0);

    /* on_response before make_init. */
    std::vector<uint8_t> dummy(pqs::PQ_RESPONSE_LEN, 0), out;
    EXPECT_EQ(cli.on_response(dummy.data(), dummy.size(), out), pqs::Step::STATE_ERROR);

    /* on_confirm before on_init. */
    std::vector<uint8_t> dummy2(pqs::PQ_CONFIRM_LEN, 0);
    EXPECT_EQ(srv.on_confirm(dummy2.data(), dummy2.size()), pqs::Step::STATE_ERROR);

    /* export before completion. */
    uint8_t tx[32], rx[32];
    EXPECT_FALSE(cli.export_keys(tx, rx));
    EXPECT_FALSE(srv.export_keys(tx, rx));
}

/* ── End-to-end over a real loopback UDP socketpair ─────────────────────────
 * Proves the framed packets (≈1.3 kB) traverse a genuine datagram socket
 * intact and the two peers agree on keys driven only by what came off the
 * wire. The handshake is strictly lock-step, so no threads are needed. */
TEST(PqSession, EndToEndOverUdpSocketpair) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    const uint8_t psk[] = "wire-psk";

    int cs = ::socket(AF_INET, SOCK_DGRAM, 0);
    int ss = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(cs, 0);
    ASSERT_GE(ss, 0);

    auto bind_loopback = [](int fd, sockaddr_in &out) {
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        ASSERT_EQ(::bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)), 0);
        socklen_t l = sizeof(out);
        ASSERT_EQ(::getsockname(fd, reinterpret_cast<sockaddr *>(&out), &l), 0);
    };
    sockaddr_in caddr{}, saddr{};
    bind_loopback(cs, caddr);
    bind_loopback(ss, saddr);
    ASSERT_EQ(::connect(cs, reinterpret_cast<sockaddr *>(&saddr), sizeof(saddr)), 0);
    ASSERT_EQ(::connect(ss, reinterpret_cast<sockaddr *>(&caddr), sizeof(caddr)), 0);

    timeval tv{2, 0};
    ::setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(ss, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t secret[32];
    std::memset(secret, 0x77, sizeof(secret));
    uint8_t cookie[32];
    mint_cookie(secret, cookie);

    pqs::Client cli(id_of(i, r), kSession, psk, sizeof(psk));
    pqs::Server srv(id_of(r, i), kSession, psk, sizeof(psk));

    auto send_all = [](int fd, const std::vector<uint8_t> &b) {
        return ::send(fd, b.data(), b.size(), 0) == static_cast<ssize_t>(b.size());
    };
    uint8_t rxbuf[4096];

    std::vector<uint8_t> m_init, m_resp, m_conf;
    ASSERT_TRUE(cli.make_init(cookie, kNonce, m_init));
    ASSERT_TRUE(send_all(cs, m_init));

    ssize_t n = ::recv(ss, rxbuf, sizeof(rxbuf), 0);
    ASSERT_EQ(n, static_cast<ssize_t>(pqs::PQ_INIT_LEN));
    ASSERT_EQ(srv.on_init(rxbuf, n, secret, kSrcIp, kWindow, m_resp), pqs::Step::OK);
    ASSERT_TRUE(send_all(ss, m_resp));

    n = ::recv(cs, rxbuf, sizeof(rxbuf), 0);
    ASSERT_EQ(n, static_cast<ssize_t>(pqs::PQ_RESPONSE_LEN));
    ASSERT_EQ(cli.on_response(rxbuf, n, m_conf), pqs::Step::COMPLETE);
    ASSERT_TRUE(send_all(cs, m_conf));

    n = ::recv(ss, rxbuf, sizeof(rxbuf), 0);
    ASSERT_EQ(n, static_cast<ssize_t>(pqs::PQ_CONFIRM_LEN));
    ASSERT_EQ(srv.on_confirm(rxbuf, n), pqs::Step::COMPLETE);

    uint8_t c_tx[32], c_rx[32], s_tx[32], s_rx[32];
    ASSERT_TRUE(cli.export_keys(c_tx, c_rx));
    ASSERT_TRUE(srv.export_keys(s_tx, s_rx));
    EXPECT_EQ(std::memcmp(c_tx, s_rx, 32), 0);
    EXPECT_EQ(std::memcmp(c_rx, s_tx, 32), 0);

    ::close(cs);
    ::close(ss);
}
