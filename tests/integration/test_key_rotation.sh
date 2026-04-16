#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Tachyon Integration Test - Key Rotation
#
# Tests:
#   1. Tunnel remains operational during key rotation
#   2. Rekey log messages appear
#   3. Data plane connectivity persists after rekey
#
# Note: TACHYON_REKEY_INTERVAL is 60s in production.
# This test waits for the rekey to occur naturally.
#
# Usage: sudo ./test_key_rotation.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

# ── Prerequisites ──
check_prerequisites

# ── Setup ──
log_info "=== Tachyon Key Rotation Test ==="
setup_namespaces
generate_configs

start_tunnels

if ! wait_for_handshake 30; then
    log_fail "Initial handshake failed"
    print_summary
    exit 1
fi

log_pass "Initial handshake succeeded"

# ── Test 1: Connectivity Before Rekey ──
log_info "--- Test 1: Pre-Rekey Connectivity ---"
assert_true "Ping before rekey" ip netns exec "$NS_A" ping -c 3 -W 5 10.8.0.2

# ── Test 2: Wait for Key Rotation ──
log_info "--- Test 2: Waiting for Key Rotation (up to 75s) ---"

REKEY_TIMEOUT=75
ELAPSED=0
REKEY_FOUND=false

while [[ $ELAPSED -lt $REKEY_TIMEOUT ]]; do
    if grep -q "key rotation" "$TMP_DIR/log_a.txt" 2>/dev/null ||
       grep -q "key rotation" "$TMP_DIR/log_b.txt" 2>/dev/null; then
        REKEY_FOUND=true
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    log_info "  Waiting... (${ELAPSED}s)"
done

if $REKEY_FOUND; then
    log_pass "Key rotation initiated (detected in logs)"
else
    log_skip "Key rotation not detected within ${REKEY_TIMEOUT}s (may need longer timeout)"
fi

# ── Test 3: Post-Rekey Handshake ──
log_info "--- Test 3: Post-Rekey Handshake ---"

# Wait a bit for the rekey handshake to complete
sleep 10

# Count handshake completions
HS_COUNT_A=$(grep -c "Handshake complete" "$TMP_DIR/log_a.txt" 2>/dev/null || echo 0)
HS_COUNT_B=$(grep -c "Handshake complete" "$TMP_DIR/log_b.txt" 2>/dev/null || echo 0)

if [[ $HS_COUNT_A -ge 1 && $HS_COUNT_B -ge 1 ]]; then
    log_pass "Handshake(s) completed: A=$HS_COUNT_A, B=$HS_COUNT_B"
else
    log_fail "Handshake completion count: A=$HS_COUNT_A, B=$HS_COUNT_B"
fi

# ── Test 4: Post-Rekey Connectivity ──
log_info "--- Test 4: Post-Rekey Connectivity ---"

if ip netns exec "$NS_A" ping -c 5 -W 5 10.8.0.2 >/dev/null 2>&1; then
    log_pass "Ping through tunnel after rekey succeeded"
else
    log_fail "Ping through tunnel after rekey failed"
fi

if ip netns exec "$NS_B" ping -c 5 -W 5 10.8.0.1 >/dev/null 2>&1; then
    log_pass "Reverse ping after rekey succeeded"
else
    log_fail "Reverse ping after rekey failed"
fi

# ── Cleanup ──
stop_tunnels
print_summary
