#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Tachyon Integration Test Library
#
# Shared functions for network namespace-based integration tests.
# Source this file from test scripts: source "$(dirname "$0")/lib.sh"
#
# Requirements: root, iproute2, tachyon binary, kernel module

set -euo pipefail

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Globals ──
TEST_UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$$")
TEST_UUID="${TEST_UUID:0:8}"
NS_A="tachyon_a_${TEST_UUID}"
NS_B="tachyon_b_${TEST_UUID}"
VETH_A="veth_a_${TEST_UUID:0:4}"
VETH_B="veth_b_${TEST_UUID:0:4}"
TMP_DIR=""
TACHYON_BIN=""
TEST_PASSED=0
TEST_FAILED=0
TEST_SKIPPED=0
PID_A=""
PID_B=""

# ── Logging ──
log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; TEST_PASSED=$((TEST_PASSED + 1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; TEST_FAILED=$((TEST_FAILED + 1)); }
log_skip()  { echo -e "${YELLOW}[SKIP]${NC}  $*"; TEST_SKIPPED=$((TEST_SKIPPED + 1)); }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

# ── Assertions ──
assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        log_pass "$desc"
    else
        log_fail "$desc (expected='$expected', actual='$actual')"
    fi
}

assert_true() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        log_pass "$desc"
    else
        log_fail "$desc (command failed: $*)"
    fi
}

assert_false() {
    local desc="$1"
    shift
    if ! "$@" >/dev/null 2>&1; then
        log_pass "$desc"
    else
        log_fail "$desc (command succeeded unexpectedly: $*)"
    fi
}

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if grep -q "$needle" <<< "$haystack"; then
        log_pass "$desc"
    else
        log_fail "$desc (string not found: '$needle')"
    fi
}

# ── Check Prerequisites ──
check_prerequisites() {
    if [[ $EUID -ne 0 ]]; then
        log_skip "Integration tests require root privileges"
        exit 0
    fi

    # Find tachyon binary
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local project_root="$script_dir/../.."

    if [[ -x "$project_root/loader/tachyon" ]]; then
        TACHYON_BIN="$project_root/loader/tachyon"
    elif command -v tachyon >/dev/null 2>&1; then
        TACHYON_BIN="$(command -v tachyon)"
    else
        log_skip "tachyon binary not found (build with 'make loader' first)"
        exit 0
    fi

    # Check kernel module
    if ! lsmod | grep -q "^mod " 2>/dev/null; then
        log_warn "Kernel module 'mod' not loaded, some tests may fail"
    fi

    log_info "Using tachyon binary: $TACHYON_BIN"
}

# ── Key Generation ──
generate_keypair() {
    local priv pub
    priv=$("$TACHYON_BIN" genkey)
    pub=$(echo "$priv" | "$TACHYON_BIN" pubkey)
    echo "$priv $pub"
}

# ── Network Namespace Setup ──
setup_namespaces() {
    log_info "Creating network namespaces: $NS_A, $NS_B"

    TMP_DIR=$(mktemp -d /tmp/tachyon_test_XXXXXX)

    # Create namespaces
    ip netns add "$NS_A"
    ip netns add "$NS_B"

    # Create veth pair connecting the namespaces
    ip link add "$VETH_A" type veth peer name "$VETH_B"
    ip link set "$VETH_A" netns "$NS_A"
    ip link set "$VETH_B" netns "$NS_B"

    # Configure physical IPs
    ip netns exec "$NS_A" ip addr add 192.168.100.1/24 dev "$VETH_A"
    ip netns exec "$NS_B" ip addr add 192.168.100.2/24 dev "$VETH_B"

    # Bring interfaces up
    ip netns exec "$NS_A" ip link set lo up
    ip netns exec "$NS_A" ip link set "$VETH_A" up
    ip netns exec "$NS_B" ip link set lo up
    ip netns exec "$NS_B" ip link set "$VETH_B" up

    # Get MAC addresses
    MAC_A=$(ip netns exec "$NS_A" cat /sys/class/net/"$VETH_A"/address)
    MAC_B=$(ip netns exec "$NS_B" cat /sys/class/net/"$VETH_B"/address)

    # Disable rp_filter in both namespaces
    ip netns exec "$NS_A" sysctl -qw net.ipv4.conf.all.rp_filter=0
    ip netns exec "$NS_B" sysctl -qw net.ipv4.conf.all.rp_filter=0

    # Verify connectivity
    if ip netns exec "$NS_A" ping -c 1 -W 2 192.168.100.2 >/dev/null 2>&1; then
        log_info "Namespace connectivity verified"
    else
        log_warn "Namespace connectivity check failed"
    fi
}

# ── Generate Config Files ──
generate_configs() {
    local key_a key_b pub_a pub_b

    read -r key_a pub_a <<< "$(generate_keypair)"
    read -r key_b pub_b <<< "$(generate_keypair)"

    CONF_A="$TMP_DIR/node_a.conf"
    CONF_B="$TMP_DIR/node_b.conf"

    cat > "$CONF_A" <<EOF
[Interface]
PrivateKey = $key_a
PeerPublicKey = $pub_b
ListenPort = 443
VirtualIP = 10.8.0.1/24
LocalPhysicalIP = 192.168.100.1
PhysicalInterface = $VETH_A
MimicryType = 1
EnableEncryption = true

[Peer]
EndpointIP = 192.168.100.2
EndpointMAC = $MAC_B
InnerIP = 10.8.0.2
EOF

    cat > "$CONF_B" <<EOF
[Interface]
PrivateKey = $key_b
PeerPublicKey = $pub_a
ListenPort = 443
VirtualIP = 10.8.0.2/24
LocalPhysicalIP = 192.168.100.2
PhysicalInterface = $VETH_B
MimicryType = 1
EnableEncryption = true

[Peer]
EndpointIP = 192.168.100.1
EndpointMAC = $MAC_A
InnerIP = 10.8.0.1
EOF

    log_info "Config files generated: $CONF_A, $CONF_B"
}

# ── Start Tunnel Instances ──
start_tunnels() {
    log_info "Starting tunnel in namespace $NS_A..."
    ip netns exec "$NS_A" "$TACHYON_BIN" up "$CONF_A" > "$TMP_DIR/log_a.txt" 2>&1 &
    PID_A=$!

    log_info "Starting tunnel in namespace $NS_B..."
    ip netns exec "$NS_B" "$TACHYON_BIN" up "$CONF_B" > "$TMP_DIR/log_b.txt" 2>&1 &
    PID_B=$!

    log_info "Tunnel PIDs: A=$PID_A, B=$PID_B"
}

# ── Wait for Handshake ──
wait_for_handshake() {
    local timeout="${1:-30}"
    local elapsed=0

    log_info "Waiting for handshake completion (timeout: ${timeout}s)..."

    while [[ $elapsed -lt $timeout ]]; do
        if grep -q "Handshake complete" "$TMP_DIR/log_a.txt" 2>/dev/null &&
           grep -q "Handshake complete" "$TMP_DIR/log_b.txt" 2>/dev/null; then
            log_info "Handshake completed in ${elapsed}s"
            return 0
        fi
        sleep 1
        ((elapsed++))
    done

    log_warn "Handshake did not complete within ${timeout}s"
    return 1
}

# ── Stop Tunnels ──
stop_tunnels() {
    log_info "Stopping tunnels..."

    if [[ -n "$PID_A" ]] && kill -0 "$PID_A" 2>/dev/null; then
        kill -TERM "$PID_A" 2>/dev/null || true
        wait "$PID_A" 2>/dev/null || true
    fi

    if [[ -n "$PID_B" ]] && kill -0 "$PID_B" 2>/dev/null; then
        kill -TERM "$PID_B" 2>/dev/null || true
        wait "$PID_B" 2>/dev/null || true
    fi

    # Clean up with tachyon down
    ip netns exec "$NS_A" "$TACHYON_BIN" down "$CONF_A" 2>/dev/null || true
    ip netns exec "$NS_B" "$TACHYON_BIN" down "$CONF_B" 2>/dev/null || true

    PID_A=""
    PID_B=""
}

# ── Cleanup ──
cleanup() {
    log_info "Cleaning up test resources..."

    stop_tunnels

    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip link del "$VETH_A" 2>/dev/null || true
    ip link del "$VETH_B" 2>/dev/null || true

    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}

# ── Test Summary ──
print_summary() {
    echo ""
    echo "════════════════════════════════════════"
    echo -e "  ${GREEN}Passed:${NC}  $TEST_PASSED"
    echo -e "  ${RED}Failed:${NC}  $TEST_FAILED"
    echo -e "  ${YELLOW}Skipped:${NC} $TEST_SKIPPED"
    echo "════════════════════════════════════════"

    if [[ $TEST_FAILED -gt 0 ]]; then
        echo -e "${RED}SOME TESTS FAILED${NC}"
        return 1
    else
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        return 0
    fi
}

# ── Register Cleanup ──
trap cleanup EXIT
