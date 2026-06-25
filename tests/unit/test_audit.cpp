/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>

#include "audit.h"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <openssl/evp.h>
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

// ---------------------------------------------------------------------------
// Helpers for the structured-format / hash-chain tests below.
// ---------------------------------------------------------------------------
namespace {

std::vector<std::string> split_lines(const std::string &s) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

// Extract the string value of a JSON key rendered as "key":"value" (with the
// escaping audit.cpp produces). Returns "" if absent. Sufficient for the values
// produced in these tests (no embedded escaped quotes).
std::string json_str_field(const std::string &line, const std::string &key) {
    std::string needle = "\"" + key + "\":\"";
    auto pos = line.find(needle);
    if (pos == std::string::npos)
        return std::string();
    pos += needle.size();
    auto end = line.find('"', pos);
    if (end == std::string::npos)
        return std::string();
    return line.substr(pos, end - pos);
}

// Extract the numeric value of a JSON key rendered as "key":<digits>.
std::string json_num_field(const std::string &line, const std::string &key) {
    std::string needle = "\"" + key + "\":";
    auto pos = line.find(needle);
    if (pos == std::string::npos)
        return std::string();
    pos += needle.size();
    auto end = pos;
    while (end < line.size() && (std::isdigit(static_cast<unsigned char>(line[end])) != 0))
        ++end;
    return line.substr(pos, end - pos);
}

std::string to_hex_bytes(const unsigned char *b, size_t n) {
    static const char *d = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(d[(b[i] >> 4) & 0xF]);
        out.push_back(d[b[i] & 0xF]);
    }
    return out;
}

bool hex_to_bytes(const std::string &hex, std::vector<unsigned char> &out) {
    if (hex.size() % 2 != 0)
        return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

// Reproduce audit.cpp's canonical serialisation for a record, from the field
// values as recovered from the emitted JSON line.
std::string canonical(const std::string &seq, const std::string &ts, const std::string &event,
                      const std::string &severity, const std::string &peer_ip,
                      const std::string &session_id, const std::string &outcome,
                      const std::string &details) {
    auto field = [](std::string &dst, const std::string &v) {
        dst += std::to_string(v.size());
        dst += ':';
        dst += v;
        dst += '|';
    };
    std::string c = "tachyon-audit-v1|";
    field(c, seq);
    field(c, ts);
    field(c, event);
    field(c, severity);
    field(c, peer_ip);
    field(c, session_id);
    field(c, outcome);
    field(c, details);
    return c;
}

// SHA256(prev_raw || canonical) -> hex, using the OpenSSL EVP interface.
std::string chain_hash(const std::vector<unsigned char> &prev, const std::string &canon) {
    std::vector<unsigned char> buf;
    buf.reserve(prev.size() + canon.size());
    buf.insert(buf.end(), prev.begin(), prev.end());
    buf.insert(buf.end(), canon.begin(), canon.end());
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    EXPECT_EQ(EVP_Digest(buf.data(), buf.size(), md, &mdlen, EVP_sha256(), nullptr), 1);
    return to_hex_bytes(md, mdlen);
}

const std::string kGenesis(64, '0');

} // namespace

TEST_F(AuditTest, JsonFormatEmitsWellFormedLines) {
    path_ = make_temp_path();
    ASSERT_TRUE(audit::init(path_, audit::AuditFormat::JSON));

    audit::EventInfo a{};
    a.event = audit::Event::HANDSHAKE_INIT;
    a.session_id = 4242;
    a.outcome = "success";
    a.details = "needs \"quote\" and \\slash and\nnewline";
    audit::emit(a);

    audit::EventInfo b{};
    b.event = audit::Event::AUTH_FAIL;
    struct in_addr addr;
    ASSERT_EQ(inet_pton(AF_INET, "198.51.100.7", &addr), 1);
    b.peer_ip = addr.s_addr;
    b.outcome = "bad-mac";
    audit::emit(b);

    std::string contents = read_file(path_);
    auto lines = split_lines(contents);
    ASSERT_EQ(lines.size(), 2u);

    for (const auto &line : lines) {
        EXPECT_EQ(line.front(), '{');
        EXPECT_EQ(line.back(), '}');
        EXPECT_NE(line.find("\"ts\":\""), std::string::npos);
        EXPECT_NE(line.find("\"event\":\""), std::string::npos);
        EXPECT_NE(line.find("\"severity\":"), std::string::npos);
        EXPECT_NE(line.find("\"seq\":"), std::string::npos);
        EXPECT_NE(line.find("\"prev_hash\":\""), std::string::npos);
        EXPECT_NE(line.find("\"hash\":\""), std::string::npos);
    }

    // First record's fields and escaping.
    EXPECT_NE(lines[0].find("\"event\":\"handshake_init\""), std::string::npos);
    EXPECT_NE(lines[0].find("\"session_id\":4242"), std::string::npos);
    EXPECT_NE(lines[0].find("\"seq\":1"), std::string::npos);
    // Special characters must be JSON-escaped, not literal.
    EXPECT_NE(lines[0].find("\\\"quote\\\""), std::string::npos);
    EXPECT_NE(lines[0].find("\\\\slash"), std::string::npos);
    EXPECT_NE(lines[0].find("and\\nnewline"), std::string::npos);
    EXPECT_EQ(lines[0].find('\t'), std::string::npos);

    // Second record carries the peer IP and an incremented seq.
    EXPECT_NE(lines[1].find("\"peer_ip\":\"198.51.100.7\""), std::string::npos);
    EXPECT_NE(lines[1].find("\"event\":\"auth_fail\""), std::string::npos);
    EXPECT_NE(lines[1].find("\"seq\":2"), std::string::npos);
}

TEST_F(AuditTest, CefFormatEmitsHeaderAndExtensions) {
    path_ = make_temp_path();
    ASSERT_TRUE(audit::init(path_, audit::AuditFormat::CEF));

    audit::EventInfo info{};
    info.event = audit::Event::REPLAY_DETECTED;
    struct in_addr addr;
    ASSERT_EQ(inet_pton(AF_INET, "203.0.113.9", &addr), 1);
    info.peer_ip = addr.s_addr;
    info.session_id = 777;
    info.outcome = "failure";
    info.details = "weird=value\\pair";
    audit::emit(info);

    std::string contents = read_file(path_);
    auto lines = split_lines(contents);
    ASSERT_EQ(lines.size(), 1u);
    const std::string &line = lines[0];

    EXPECT_EQ(line.rfind("CEF:0|Tachyon|tunnel|", 0), 0u);
    EXPECT_NE(line.find("|replay_detected|"), std::string::npos);
    // key=value extensions present.
    EXPECT_NE(line.find("rt="), std::string::npos);
    EXPECT_NE(line.find("src=203.0.113.9"), std::string::npos);
    EXPECT_NE(line.find("cs1Label=sessionId cs1=777"), std::string::npos);
    EXPECT_NE(line.find("outcome=failure"), std::string::npos);
    EXPECT_NE(line.find("cn1Label=seq cn1=1"), std::string::npos);
    EXPECT_NE(line.find("prevHash="), std::string::npos);
    EXPECT_NE(line.find("hash="), std::string::npos);
    EXPECT_NE(line.find(kGenesis), std::string::npos); // genesis prev_hash
    // '=' and '\' inside the details value must be CEF-escaped.
    EXPECT_NE(line.find("msg=weird\\=value\\\\pair"), std::string::npos);
}

TEST_F(AuditTest, HashChainIsContinuousAndTamperEvident) {
    path_ = make_temp_path();
    ASSERT_TRUE(audit::init(path_, audit::AuditFormat::JSON));

    constexpr int kN = 6;
    for (int i = 0; i < kN; ++i) {
        audit::EventInfo info{};
        info.event = audit::Event::HANDSHAKE_COMPLETE;
        info.session_id = static_cast<uint32_t>(1000 + i);
        info.outcome = "success";
        info.details = (i % 2 == 0) ? "even" : "odd";
        audit::emit(info);
    }

    std::string contents = read_file(path_);
    auto lines = split_lines(contents);
    ASSERT_EQ(lines.size(), static_cast<size_t>(kN));

    std::vector<std::string> prev_hashes(kN);
    std::vector<std::string> hashes(kN);
    for (int i = 0; i < kN; ++i) {
        prev_hashes[i] = json_str_field(lines[i], "prev_hash");
        hashes[i] = json_str_field(lines[i], "hash");
        ASSERT_EQ(prev_hashes[i].size(), 64u);
        ASSERT_EQ(hashes[i].size(), 64u);
    }

    // (1) Continuity: genesis at the head, then prev[i] == hash[i-1].
    EXPECT_EQ(prev_hashes[0], kGenesis);
    for (int i = 1; i < kN; ++i) {
        EXPECT_EQ(prev_hashes[i], hashes[i - 1]) << "chain break at record " << i;
    }
    // The library-exposed chain head must equal the last record's hash.
    EXPECT_EQ(audit::chain_head(), hashes[kN - 1]);

    // (2) Independently recompute the whole chain from the emitted fields and
    // confirm it matches what was written.
    std::vector<unsigned char> prev_raw;
    ASSERT_TRUE(hex_to_bytes(kGenesis, prev_raw));
    for (int i = 0; i < kN; ++i) {
        std::string canon =
            canonical(json_num_field(lines[i], "seq"), json_str_field(lines[i], "ts"),
                      json_str_field(lines[i], "event"), json_num_field(lines[i], "severity"),
                      json_str_field(lines[i], "peer_ip"), json_num_field(lines[i], "session_id"),
                      json_str_field(lines[i], "outcome"), json_str_field(lines[i], "details"));
        std::string recomputed = chain_hash(prev_raw, canon);
        EXPECT_EQ(recomputed, hashes[i]) << "recomputed hash mismatch at record " << i;
        ASSERT_TRUE(hex_to_bytes(hashes[i], prev_raw));
    }

    // (3) Tamper detection: mutate a middle record's content and show that the
    // recomputed hash no longer matches the stored one, which also breaks the
    // link expected by the following record.
    const int mid = kN / 2;
    std::vector<unsigned char> prev_for_mid;
    ASSERT_TRUE(hex_to_bytes(prev_hashes[mid], prev_for_mid));
    std::string tampered_canon =
        canonical(json_num_field(lines[mid], "seq"), json_str_field(lines[mid], "ts"),
                  json_str_field(lines[mid], "event"), json_num_field(lines[mid], "severity"),
                  json_str_field(lines[mid], "peer_ip"),
                  "999999", // attacker rewrites the session id
                  json_str_field(lines[mid], "outcome"), json_str_field(lines[mid], "details"));
    std::string tampered_hash = chain_hash(prev_for_mid, tampered_canon);
    EXPECT_NE(tampered_hash, hashes[mid]);
    // The next record still points at the original hash, so the chain no longer
    // verifies once the middle record is altered.
    EXPECT_NE(tampered_hash, prev_hashes[mid + 1]);
}

TEST_F(AuditTest, SetFormatOverridesDefault) {
    path_ = make_temp_path();
    ASSERT_TRUE(audit::init(path_)); // default TEXT
    audit::set_format(audit::AuditFormat::CEF);

    audit::EventInfo info{};
    info.event = audit::Event::SERVICE_START;
    info.outcome = "success";
    audit::emit(info);

    std::string contents = read_file(path_);
    EXPECT_EQ(contents.rfind("CEF:0|Tachyon|tunnel|", 0), 0u);
}

TEST_F(AuditTest, TextFormatRemainsBackwardCompatible) {
    path_ = make_temp_path();
    ASSERT_TRUE(audit::init(path_)); // default format == TEXT

    audit::EventInfo info{};
    info.event = audit::Event::HANDSHAKE_INIT;
    info.session_id = 12345;
    info.outcome = "success";
    info.details = "test-details";
    audit::emit(info);

    std::string contents = read_file(path_);
    EXPECT_NE(contents.find("\"event\":\"handshake_init\""), std::string::npos);
    EXPECT_NE(contents.find("\"session_id\":12345"), std::string::npos);
    EXPECT_NE(contents.find("\"outcome\":\"success\""), std::string::npos);
    EXPECT_NE(contents.find("\"details\":\"test-details\""), std::string::npos);
    EXPECT_NE(contents.find("\"ts\":\""), std::string::npos);
    // New chain fields are additive and present even in TEXT mode.
    EXPECT_NE(contents.find("\"seq\":1"), std::string::npos);
    EXPECT_NE(contents.find("\"prev_hash\":\"" + kGenesis + "\""), std::string::npos);
    EXPECT_NE(contents.find("\"hash\":\""), std::string::npos);
    EXPECT_EQ(contents.back(), '\n');
    EXPECT_EQ(std::count(contents.begin(), contents.end(), '\n'), 1);
}
