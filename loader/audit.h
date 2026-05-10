/* SPDX-License-Identifier: MIT */
/*
 * Audit logging subsystem for the Tachyon XDP Tunnel.
 *
 * Provides a dedicated audit-trail facility (separate from the operational
 * logging in loader/log.h) intended for SIEM ingestion and compliance
 * (SOC2 / HIPAA / PCI-DSS) review. Each event is serialised as a single-line
 * JSON object with an ISO 8601 UTC timestamp, optional peer-IP / session-id
 * context, an outcome and an optional free-form details field. The writer is
 * thread-safe, fsync()s every record for durability, and falls back to syslog
 * (LOG_AUTH facility) when no file path is configured or when a write to the
 * configured file fails.
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

struct EventInfo {
    Event event;
    uint32_t peer_ip = 0; // 0 = N/A; in network byte order
    uint32_t session_id = 0;
    const char *outcome = nullptr; // "success" | "failure" | reason string
    const char *details = nullptr; // Optional free-form
};

// Initialize audit subsystem. file_path empty → syslog only.
// Returns false if file cannot be opened.
bool init(const std::string &file_path);
void shutdown();

// Emit an event. Thread-safe. Always fsyncs for compliance.
void emit(const EventInfo &info);

const char *event_name(Event ev);

} // namespace tachyon::audit
