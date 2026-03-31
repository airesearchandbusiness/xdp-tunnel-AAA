#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Tachyon Integration Test - Full Tunnel End-to-End
#
# Tests:
#   1. Tunnel establishment (handshake completion)
#   2. Data plane connectivity (ping through tunnel)
#   3. Statistics reporting (tachyon show)
#   4. Graceful shutdown and cleanup
#
# Usage: sudo ./test_tunnel_e2e.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

# ── Prerequisites ──
check_prerequisites

# ── Setup ──
log_info "=== Tachyon E2E Tunnel Test ==="
setup_namespaces
generate_configs

# ── Test 1: Tunnel Establishment ──
log_info "--- Test 1: Tunnel Establishment ---"
start_tunnels

if wait_for_handshake 30; then
    log_pass "Handshake completed successfully"
else
    # Check logs for diagnostic info
    log_fail "Handshake failed to complete"
    log_info "Log A (last 10 lines):"
    tail -10 "$TMP_DIR/log_a.txt" 2>/dev/null || true
    log_info "Log B (last 10 lines):"
    tail -10 "$TMP_DIR/log_b.txt" 2>/dev/null || true
fi

# ── Test 2: Data Plane Connectivity ──
log_info "--- Test 2: Data Plane Connectivity ---"

# Give the datapath a moment to stabilize
sleep 2

if ip netns exec "$NS_A" ping -c 3 -W 5 10.8.0.2 >/dev/null 2>&1; then
    log_pass "Ping A -> B through tunnel succeeded"
else
    log_fail "Ping A -> B through tunnel failed"
fi

if ip netns exec "$NS_B" ping -c 3 -W 5 10.8.0.1 >/dev/null 2>&1; then
    log_pass "Ping B -> A through tunnel succeeded"
else
    log_fail "Ping B -> A through tunnel failed"
fi

# ── Test 3: Statistics Reporting ──
log_info "--- Test 3: Statistics Reporting ---"

SHOW_A=$(ip netns exec "$NS_A" "$TACHYON_BIN" show "$CONF_A" 2>&1) || true
if echo "$SHOW_A" | grep -q "TX:"; then
    log_pass "tachyon show reports TX statistics"
else
    log_fail "tachyon show missing TX statistics"
fi

if echo "$SHOW_A" | grep -q "RX:"; then
    log_pass "tachyon show reports RX statistics"
else
    log_fail "tachyon show missing RX statistics"
fi

# ── Test 4: Graceful Shutdown ──
log_info "--- Test 4: Graceful Shutdown ---"
stop_tunnels

# Verify tunnel interfaces are cleaned up
if ! ip netns exec "$NS_A" ip link show t_node_a_in 2>/dev/null; then
    log_pass "Tunnel interface cleaned up in NS_A"
else
    log_fail "Tunnel interface still exists in NS_A"
fi

# Verify BPF pins are cleaned up
if [[ ! -d "/sys/fs/bpf/tachyon/node_a" ]]; then
    log_pass "BPF pins cleaned up"
else
    log_fail "BPF pins still exist"
fi

# ── Test 5: Log Content Validation ──
log_info "--- Test 5: Log Content Validation ---"

LOG_A=$(cat "$TMP_DIR/log_a.txt" 2>/dev/null || echo "")
LOG_B=$(cat "$TMP_DIR/log_b.txt" 2>/dev/null || echo "")

assert_contains "Log A contains AKE version" "$LOG_A" "AKE v"
assert_contains "Log A contains role assignment" "$LOG_A" "Role:"
assert_contains "Log B contains AKE version" "$LOG_B" "AKE v"
assert_contains "Log B contains role assignment" "$LOG_B" "Role:"

# One should be Initiator, one Responder
if echo "$LOG_A$LOG_B" | grep -q "Initiator" && echo "$LOG_A$LOG_B" | grep -q "Responder"; then
    log_pass "Both Initiator and Responder roles assigned"
else
    log_fail "Role assignment incomplete"
fi

# ── Summary ──
print_summary
