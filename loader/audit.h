/* SPDX-License-Identifier: MIT */
/*
 * Audit logging subsystem for the Tachyon XDP Tunnel.
 *
 * Provides a dedicated audit-trail facility (separate from the operational
 * logging in loader/log.h) intended for SIEM ingestion and compliance
 * (SOC2 / HIPAA / PCI-DSS) review. Each event is serialised as a single line
 * with an ISO 8601 UTC timestamp, optional peer-IP / session-id context, an
 * outcome and an optional free-form details field. The writer is thread-safe,
 * fsync()s every record for durability, and falls back to syslog (LOG_AUTH
 * facility) when no file path is configured or when a write to the configured
 * file fails.
 *
 * Records may be emitted in one of three formats (see AuditFormat): the
 * historical compact TEXT/JSON line, ArcSight CEF, or JSON Lines. Every record
 * additionally participates in a tamper-evident SHA-256 hash chain: each record
 * carries a monotonic sequence number, the hash of the previous record
 * (prev_hash) and its own hash, so that any post-hoc mutation, reordering or
 * deletion of records is detectable by recomputing the chain.
 */
#pragma once
#include <cstdint>
#include <string>

namespace tachyon::audit {

enum class Event : uint8_t {
    SERVICE_START,
    SERVICE_STOP,
    HANDSHAKE_INIT,
    HANDSHAKE_COMPLETE,
    HANDSHAKE_FAIL,
    AUTH_FAIL,
    COOKIE_INVALID,
    REPLAY_DETECTED,
    KEY_ROTATION,
    CONFIG_RELOAD,
    PEER_BLOCKED,
};

// Output rendering for emitted records.
//   TEXT - the historical compact single-line JSON object (default, unchanged).
//   JSON - JSON Lines: one compact JSON object per line, with chain fields.
//   CEF  - ArcSight Common Event Format header + key=value extensions.
enum class AuditFormat : uint8_t {
    TEXT,
    JSON,
    CEF,
};

struct EventInfo {
    Event event;
    uint32_t peer_ip = 0; // 0 = N/A; in network byte order
    uint32_t session_id = 0;
    const char *outcome = nullptr; // "success" | "failure" | reason string
    const char *details = nullptr; // Optional free-form
};

// Initialize audit subsystem. file_path empty → syslog only.
// The format argument selects the on-disk record encoding and defaults to the
// historical TEXT behaviour so existing callers are unaffected.
// Returns false if file cannot be opened.
bool init(const std::string &file_path, AuditFormat fmt = AuditFormat::TEXT);
void shutdown();

// Select the output format for subsequently emitted records. Thread-safe and
// may be called independently of init(); the default is AuditFormat::TEXT.
void set_format(AuditFormat fmt);

// Emit an event. Thread-safe. Always fsyncs for compliance.
void emit(const EventInfo &info);

const char *event_name(Event ev);

// Current head of the tamper-evident hash chain (lower-case hex SHA-256 of the
// most recently emitted record), or the all-zero genesis hash if no record has
// been emitted since the last init(). Thread-safe.
std::string chain_head();

} // namespace tachyon::audit
