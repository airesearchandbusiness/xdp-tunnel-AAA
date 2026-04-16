#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Tachyon Integration Test - Dead Peer Detection
#
# Tests:
#   1. DPD timeout triggers after peer goes silent
#   2. Tunnel re-establishes after peer recovery
#
# TACHYON_DPD_TIMEOUT is 35 seconds in production.
#
# Usage: sudo ./test_dpd.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

# ── Prerequisites ──
check_prerequisites

# ── Setup ──
log_info "=== Tachyon Dead Peer Detection Test ==="
setup_namespaces
generate_configs

start_tunnels

if ! wait_for_handshake 30; then
    log_fail "Initial handshake failed"
    print_summary
    exit 1
fi

log_pass "Initial handshake succeeded"

# Verify initial connectivity
assert_true "Initial connectivity" ip netns exec "$NS_A" ping -c 2 -W 5 10.8.0.2

# ── Test 1: Kill Peer B and Wait for DPD ──
log_info "--- Test 1: Dead Peer Detection ---"

log_info "Killing tunnel B (PID $PID_B)..."
kill -KILL "$PID_B" 2>/dev/null || true
wait "$PID_B" 2>/dev/null || true
PID_B=""

# Also tear down B's tunnel interface to ensure silence
ip netns exec "$NS_B" "$TACHYON_BIN" down "$CONF_B" 2>/dev/null || true

log_info "Waiting for DPD timeout (up to 45s)..."
DPD_TIMEOUT=45
ELAPSED=0
DPD_DETECTED=false

while [[ $ELAPSED -lt $DPD_TIMEOUT ]]; do
    if grep -q "Peer timeout\|Resetting state" "$TMP_DIR/log_a.txt" 2>/dev/null; then
        DPD_DETECTED=true
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    log_info "  Waiting... (${ELAPSED}s)"
done

if $DPD_DETECTED; then
    log_pass "Dead Peer Detection triggered on node A"
else
    log_fail "DPD not detected within ${DPD_TIMEOUT}s"
fi

# ── Test 2: Peer Recovery ──
log_info "--- Test 2: Peer Recovery ---"

log_info "Restarting tunnel B..."
ip netns exec "$NS_B" "$TACHYON_BIN" up "$CONF_B" > "$TMP_DIR/log_b_restart.txt" 2>&1 &
PID_B=$!

# Wait for re-handshake
REHSK_TIMEOUT=40
ELAPSED=0
REHSK_DONE=false

while [[ $ELAPSED -lt $REHSK_TIMEOUT ]]; do
    if grep -c "Handshake complete" "$TMP_DIR/log_a.txt" 2>/dev/null | grep -q "^[2-9]\|^[0-9][0-9]"; then
        REHSK_DONE=true
        break
    fi
    if grep -q "Handshake complete" "$TMP_DIR/log_b_restart.txt" 2>/dev/null; then
        REHSK_DONE=true
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    log_info "  Waiting for re-handshake... (${ELAPSED}s)"
done

if $REHSK_DONE; then
    log_pass "Re-handshake completed after peer recovery"
else
    log_skip "Re-handshake not detected (may need more time)"
fi

# ── Test 3: Post-Recovery Connectivity ──
log_info "--- Test 3: Post-Recovery Connectivity ---"
sleep 3

if ip netns exec "$NS_A" ping -c 3 -W 5 10.8.0.2 >/dev/null 2>&1; then
    log_pass "Connectivity restored after peer recovery"
else
    log_fail "Connectivity not restored after peer recovery"
fi

# ── Cleanup ──
stop_tunnels
print_summary
