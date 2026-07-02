/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Fuzz Test - Post-Quantum Handshake Message Parsers
 *
 * libFuzzer harness for the untrusted-input attack surface added by the hybrid
 * PQ handshake: the wire-message parsers in tachyon::pqsession (Server::on_init
 * / on_confirm, Client::on_response) and the underlying tachyon::pqhs state
 * machine (Responder::process_init / process_confirm, Initiator::process_
 * response). Every one of these consumes bytes straight off the network, so the
 * property under test is: no arrangement of hostile input causes a crash, a
 * buffer over-read, or undefined behaviour — the length checks, header parsing,
 * and offset arithmetic must stay memory-safe regardless of the KEM backend.
 *
 * With no ML-KEM backend linked the KEM steps fail closed early, so the harness
 * exercises the framing/cookie/offset logic; with a real backend (OpenSSL >=
 * 3.5) it drives the full decapsulation/transcript path too.
 *
 * Build:
 *   cmake -B build -S tests -DBUILD_FUZZ_TESTS=ON -DCMAKE_CXX_COMPILER=clang++
 *   cmake --build build --target fuzz_pq_handshake
 * Run:
 *   ./build/fuzz_pq_handshake -max_total_time=300
 */
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <vector>

#include "pq_session.h"

/* From crypto.cpp; forward-declared to avoid the BPF umbrella header. */
bool generate_x25519_keypair(uint8_t *priv_out, uint8_t *pub_out);
bool generate_cookie(const uint8_t *secret, uint32_t client_ip, uint64_t nonce, uint64_t window,
                     uint8_t *out_cookie);
void init_crypto_globals();

namespace pqs = tachyon::pqsession;
namespace pqhs = tachyon::pqhs;

namespace {

constexpr uint32_t kSession = 0xABCD1234;
constexpr uint32_t kSrcIp = 0x0100007F;
constexpr uint64_t kWindow = 0x1234;

bool g_ready = false;
pqhs::StaticIdentity g_resp_id; /* responder's view (peer = a fixed initiator) */
uint8_t g_cookie_secret[32];

void ensure_init() {
    if (g_ready)
        return;
    init_crypto_globals();
    uint8_t rpriv[32], rpub[32], ppriv[32], ppub[32];
    generate_x25519_keypair(rpriv, rpub);
    generate_x25519_keypair(ppriv, ppub);
    std::memcpy(g_resp_id.priv, rpriv, 32);
    std::memcpy(g_resp_id.my_pub, rpub, 32);
    std::memcpy(g_resp_id.peer_pub, ppub, 32);
    std::memset(g_cookie_secret, 0xA5, sizeof(g_cookie_secret));
    g_ready = true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ensure_init();
    if (size < 1)
        return 0;

    const uint8_t selector = data[0];
    std::vector<uint8_t> pkt(data + 1, data + size); /* mutable working copy */

    switch (selector % 5) {
    case 0: {
        /* Raw PQ_INIT: framing, length tolerance, cookie gate, offset math. */
        pqs::Server srv(g_resp_id, kSession, nullptr, 0);
        std::vector<uint8_t> out;
        srv.on_init(pkt.data(), pkt.size(), g_cookie_secret, kSrcIp, kWindow, out);
        break;
    }
    case 1: {
        /* PQ_INIT with header + cookie repaired, to drive past the anti-DoS gate
         * into the KEM/transcript parser (fully reachable with a backend). */
        if (pkt.size() >= pqs::PQ_INIT_LEN) {
            pkt[0] = pqs::PKT_PQ_INIT;
            uint32_t sid_be = htonl(kSession);
            std::memcpy(pkt.data() + 4, &sid_be, 4);
            uint64_t nonce;
            std::memcpy(&nonce, pkt.data() + pqs::PQ_HDR_LEN, 8);
            uint8_t cookie[32];
            if (generate_cookie(g_cookie_secret, kSrcIp, nonce, kWindow, cookie))
                std::memcpy(pkt.data() + pqs::PQ_HDR_LEN + 8, cookie, 32);
        }
        pqs::Server srv(g_resp_id, kSession, nullptr, 0);
        std::vector<uint8_t> out;
        srv.on_init(pkt.data(), pkt.size(), g_cookie_secret, kSrcIp, kWindow, out);
        break;
    }
    case 2: {
        /* Session-layer confirm parser. */
        pqs::Server srv(g_resp_id, kSession, nullptr, 0);
        srv.on_confirm(pkt.data(), pkt.size());
        break;
    }
    case 3: {
        /* Bare pqhs INIT parser: version/type/length checks + transcript hashing
         * over the buffer + encapsulation entry. */
        pqhs::Responder r(g_resp_id);
        std::vector<uint8_t> out;
        r.process_init(pkt.data(), pkt.size(), out);
        break;
    }
    case 4: {
        /* Initiator RESPONSE parser. create_init needs a backend; without one it
         * no-ops and process_response returns STATE_ERROR, still exercising the
         * length/header validation on the hostile buffer. */
        pqhs::Initiator i(g_resp_id);
        std::vector<uint8_t> m1, out;
        i.create_init(m1);
        i.process_response(pkt.data(), pkt.size(), out);
        break;
    }
    }
    return 0;
}
