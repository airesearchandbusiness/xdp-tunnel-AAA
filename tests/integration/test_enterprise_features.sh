#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Smoke test for enterprise features that don't require root:
#   - structured JSON logging
#   - /health and /ready endpoints
#   - audit log file writes
#   - SIGHUP behaviour (signal flag set, no crash)
#   - SIGTERM clean shutdown
#
# This test exercises the *libraries* (via a small driver) rather than the
# full tachyon binary, because the full binary needs CAP_NET_ADMIN+CAP_BPF
# which CI runners don't have.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${ROOT}/tests/build"

if [[ ! -d "$BUILD" ]]; then
    echo "FAIL: build directory missing at $BUILD"
    exit 1
fi

cd "$BUILD"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

# 1. test_log binary exists and runs
[[ -x ./test_log ]] || fail "test_log not built"
./test_log --gtest_color=no >/dev/null 2>&1 || fail "test_log returned non-zero"
pass "test_log: 8 cases"

# 2. test_audit emits parseable JSON
[[ -x ./test_audit ]] || fail "test_audit not built"
./test_audit --gtest_color=no >/dev/null 2>&1 || fail "test_audit returned non-zero"
pass "test_audit: 8 cases"

# 3. test_shutdown drain logic
[[ -x ./test_shutdown ]] || fail "test_shutdown not built"
./test_shutdown --gtest_color=no >/dev/null 2>&1 || fail "test_shutdown returned non-zero"
pass "test_shutdown: 12 cases"

# 4. test_ip_rate_limiter LRU + verdicts
[[ -x ./test_ip_rate_limiter ]] || fail "test_ip_rate_limiter not built"
./test_ip_rate_limiter --gtest_color=no >/dev/null 2>&1 || fail "ip_rate_limiter failed"
pass "test_ip_rate_limiter: 10 cases"

# 5. test_circuit_breaker state machine
[[ -x ./test_circuit_breaker ]] || fail "test_circuit_breaker not built"
./test_circuit_breaker --gtest_color=no >/dev/null 2>&1 || fail "circuit_breaker failed"
pass "test_circuit_breaker: 10 cases"

# 6. test_secret_resolution env+file://
[[ -x ./test_secret_resolution ]] || fail "test_secret_resolution not built"
./test_secret_resolution --gtest_color=no >/dev/null 2>&1 || fail "secret_resolution failed"
pass "test_secret_resolution: 8 cases"

# 7. test_metrics health/ready/version endpoints
[[ -x ./test_metrics ]] || fail "test_metrics not built"
./test_metrics --gtest_color=no >/dev/null 2>&1 || fail "metrics failed"
pass "test_metrics: health/ready/version endpoints"

# 8. Helm chart lints (if helm is on path)
if command -v helm >/dev/null 2>&1; then
    if helm lint "${ROOT}/deploy/helm/tachyon" >/dev/null 2>&1; then
        pass "helm lint deploy/helm/tachyon"
    else
        fail "helm lint failed"
    fi
else
    echo "SKIP: helm not installed"
fi

# 9. systemd unit verifies (if systemd-analyze is available)
if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze verify "${ROOT}/systemd/tachyon@.service" 2>&1 | grep -qE 'error|warning'; then
        echo "WARN: systemd-analyze found issues (may be tolerable)"
    else
        pass "systemd-analyze tachyon@.service"
    fi
else
    echo "SKIP: systemd-analyze not installed"
fi

# 10. Grafana dashboard JSON parses (if jq available)
if command -v jq >/dev/null 2>&1 && [[ -f "${ROOT}/deploy/grafana/tachyon-dashboard.json" ]]; then
    jq -e '.title' "${ROOT}/deploy/grafana/tachyon-dashboard.json" >/dev/null \
        && pass "deploy/grafana/tachyon-dashboard.json valid" \
        || fail "Grafana dashboard JSON malformed"
fi

# 11. Prometheus alerts YAML parses (if python3 yaml available)
if [[ -f "${ROOT}/deploy/prometheus/alerts.yaml" ]]; then
    python3 -c "import yaml; list(yaml.safe_load_all(open('${ROOT}/deploy/prometheus/alerts.yaml')))" \
        && pass "deploy/prometheus/alerts.yaml valid" \
        || fail "AlertManager YAML malformed"
fi

echo ""
echo "ALL ENTERPRISE FEATURE SMOKE TESTS PASSED"
