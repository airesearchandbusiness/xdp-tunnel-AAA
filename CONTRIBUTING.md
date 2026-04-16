# Contributing to Tachyon XDP Tunnel

Thank you for your interest in contributing to Tachyon.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/airesearchandbusiness/xdp-tunnel-AAA.git
cd xdp-tunnel-AAA

# Install build dependencies (Ubuntu/Debian)
sudo apt-get install -y \
    build-essential cmake \
    libssl-dev libelf-dev zlib1g-dev \
    clang llvm \
    linux-headers-$(uname -r) \
    shellcheck cppcheck clang-format \
    valgrind lcov

# Install pre-commit hooks (recommended)
pip install pre-commit
pre-commit install

# Build and run unit tests (no root required)
make test-unit

# Format code
make format

# Run linters
make lint
```

## Code Style

- **C/C++**: LLVM-based style enforced by `.clang-format` (4-space indent, 100-column limit, Linux braces)
- **Shell**: ShellCheck-clean (`set -euo pipefail`, no bashisms where avoidable)
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) with scopes: `fix(build)`, `feat(crypto)`, `test(unit)`, `docs`, `ci`, `refactor`, `security`

Run `make format` before committing to auto-format all source files.
Pre-commit hooks will enforce formatting automatically if installed.

## Testing Requirements

All changes must pass:

1. **Unit tests** (`make test-unit`) -- 186+ tests, no root required
2. **Lint checks** (`make lint`) -- clang-format, cppcheck, shellcheck
3. **CI pipeline** -- GitHub Actions runs 8 parallel checks automatically

### Full local test matrix

```bash
# Core (required before every PR)
make test-unit        # Unit tests (gtest, ~186 tests)
make format-check     # Dry-run format verification

# Memory safety (recommended)
make test-sanitize    # AddressSanitizer + UndefinedBehaviorSanitizer
make test-tsan        # ThreadSanitizer (data-race detection)
make test-valgrind    # Valgrind memcheck (requires valgrind)

# Coverage (optional)
make coverage         # HTML coverage report at build/coverage/html/

# Performance (optional)
make benchmark        # Google Benchmark crypto harnesses

# Privileged (requires root + kernel module)
make test-xdp         # XDP/BPF program tests
make test-integration # End-to-end tunnel tests
make test-all         # All test tiers
```

### CMake presets

For developers who prefer CMake directly over Makefile wrappers:

```bash
cd tests
cmake --preset ci-unit     && cmake --build --preset ci-unit
cmake --preset ci-sanitize && cmake --build --preset ci-sanitize
cmake --preset ci-tsan     && cmake --build --preset ci-tsan
cmake --preset ci-coverage && cmake --build --preset ci-coverage
cmake --preset ci-bench    && cmake --build --preset ci-bench
```

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes with clear, atomic commits
3. Ensure all tests pass locally
4. Open a pull request against `main`
5. Wait for CI checks to pass
6. Address any review feedback

## Architecture Notes

Before making significant changes, please review:

- `src/common.h` -- single source of truth for wire formats and protocol constants
- `loader/tachyon.h` -- userspace mirror structs must match common.h layout
- `kmod/mod.c` -- kernel module has its own copy of struct definitions

**Critical invariant**: Changes to wire-format structures in `common.h` must be mirrored in `loader/tachyon.h` (userspace) and `kmod/mod.c` (kernel). Layout mismatches cause silent data corruption.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting. Never commit real cryptographic keys, even in tests -- use deterministic test vectors.
