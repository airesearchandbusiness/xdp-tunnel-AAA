/* SPDX-License-Identifier: MIT */
/*
 * Lightweight sd_notify(3) wrapper.
 *
 * Implements the systemd Type=notify protocol *without* linking against
 * libsystemd. Reads $NOTIFY_SOCKET at startup; if unset, every call is a
 * no-op (process is not running under systemd). On supported systems we
 * write directly to the unix datagram/abstract socket as documented in
 *   man sd_notify(3) — STATE=READY=1 / WATCHDOG=1 / STOPPING=1 / STATUS=...
 *
 * This avoids a hard dependency on libsystemd (which is GPL/LGPL, may not
 * be present in distroless containers, etc.) while still giving us
 * watchdog + readiness signalling in production.
 */
#pragma once

#include <string>

namespace tachyon::sd {

/* True if $NOTIFY_SOCKET is set and we successfully resolved it. After
 * init() returns false, all notify() calls are silent no-ops. */
bool init();

/* Send a single newline-terminated state message. Returns true if at least
 * one byte was successfully written (best-effort, no retry). */
bool notify(const char *state);

/* Convenience: composes "STATUS=<msg>" + "WATCHDOG=1" if requested. */
bool notify_status(const std::string &status, bool kick_watchdog = true);

/* Send STOPPING=1 + final STATUS, then close the socket. */
void shutdown();

/* True if init() succeeded. */
bool enabled();

} /* namespace tachyon::sd */
