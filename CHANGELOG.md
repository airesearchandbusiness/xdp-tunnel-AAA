# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — Enterprise Hardening

### Added — Observability
- **Structured JSON logging** (`loader/log.h`) with thread-local context fields
  (`session_id`, `peer_ip`, `event`), ISO 8601 timestamps with millisecond
  precision, syslog integration, and runtime level filtering.
- **Health & readiness endpoints** on the metrics HTTP server:
  - `GET /health` — liveness probe (200 OK if process is alive)
  - `GET /ready` — readiness probe (200 once a session key is established,
    503 otherwise)
  - `GET /version` — build metadata (version, protocol)
- **Audit logging subsystem** (`loader/audit.h`) with 11 named events
  (handshake_init, handshake_complete, handshake_fail, auth_fail,
  cookie_invalid, replay_detected, key_rotation, config_reload, peer_blocked,
  service_start, service_stop). Thread-safe append-only JSON file with fsync,
  falling back to `LOG_AUTH` syslog facility.

### Added — Security & Resilience
- **Per-IP handshake rate limiter** (`loader/ip_rate_limiter.h`) with LRU
  eviction (4096 default capacity). Three verdicts: `ALLOW`, `BACKOFF`
  (3+ failures, exponential), `BLOCK` (10+ failures within 60s window).
- **Circuit breaker** (`loader/circuit_breaker.h`) with `CLOSED → OPEN →
  HALF_OPEN` state machine. Default: 5 failures → open, 30s cooldown,
  exponential backoff capped at 60s.
- **Graceful shutdown drain** (`loader/shutdown.h`): SIGTERM/SIGINT initiate
  a configurable drain phase (default 5s, max 30s) so in-flight handshakes
  complete before the process exits.
- **Environment variable / `file://` URI overrides for secrets**:
  `TACHYON_PRIVATE_KEY`, `TACHYON_PEER_PUBLIC_KEY`, `TACHYON_PSK`. Captured
  values are immediately `unsetenv()`'d to clear from `/proc/PID/environ`.

### Added — Deployment
- **Production Docker image** (`docker/Dockerfile.prod`): multi-stage build
  with `gcr.io/distroless/cc-debian12:nonroot` runtime, OCI labels, non-root
  user.
- **Helm chart** (`deploy/helm/tachyon/`) for Kubernetes DaemonSet
  deployment with `hostNetwork: true`, BPF filesystem mount, secret-based
  key delivery, liveness/readiness probes, optional Prometheus
  ServiceMonitor.
- **Hardened systemd unit** (`systemd/tachyon@.service`): `Type=notify`,
  `WatchdogSec=30`, journal logging, resource limits (`MemoryMax=512M`,
  `CPUQuota=200%`, `TasksMax=64`), additional sandboxing.

### Added — Documentation
- `docs/OPERATIONS.md` — operational runbook (lifecycle, monitoring,
  troubleshooting, incident response).
- `docs/PERFORMANCE.md` — performance tuning guide (CPU affinity, NUMA,
  BPF buffer sizes, replay window, rate limit, hardware recommendations).
- `docs/MIGRATION_v4_to_v5.md` — upgrade path from v1.0 to v1.2.
- `docs/SECURITY_CONTROLS.md` — defence-in-depth catalogue.
- `docs/man/tachyon.1` — groff manpage covering commands, env vars, signals.
- `deploy/grafana/tachyon-dashboard.json` — Grafana dashboard for the
  Prometheus metrics.
- `deploy/prometheus/alerts.yaml` — AlertManager rules for handshake
  failures, replay drops, crypto errors, and process down.
- `scripts/tachyon.bash` and `scripts/_tachyon` — bash and zsh completion.

### Added — Tests
- 45 new unit tests across log, audit, shutdown, secret resolution,
  IP rate limiter, circuit breaker, and metrics health/version endpoints.
- 3 new Google Benchmark harnesses (`bench_log`, `bench_ip_rate_limiter`,
  `bench_circuit_breaker`).
- Pre-existing `bench_crypto` bug fixed (`TACHYON_AEAD_NONCE_LEN` →
  `TACHYON_AEAD_IV_LEN`).

### Changed
- `tests/unit/test_advanced.cpp` was orphaned during the v5 merge; it has
  been salvaged with 19 live-symbol tests (CipherSuite, PqKem, extended
  wire-format) re-registered in `tests/CMakeLists.txt`.
- `MetricsExporter::start(0)` now accepts an ephemeral port for tests.

### Fixed (inherited from main)
- CWE-323: control-plane AEAD nonce counter unification (keepalive vs
  decoy collision).
- QUIC header parser dead bounds check (CodeQL).
- `clang-format` violations across Phase 25 files (smart_obfs, xsk,
  bench_transport).
- `clang-tidy` cert-err34-c errors from `sscanf` in `hex2bin` and
  `parse_mac` (replaced with manual hex parsing).

## [1.1.0] — earlier

Initial v5 "Ghost-PQ" release.
