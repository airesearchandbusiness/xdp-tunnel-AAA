# Tachyon XDP Tunnel - Build System
#
# Targets:
#   all          Build kernel module, XDP object, and control plane
#   kmod         Build kernel crypto module only
#   xdp          Build XDP/eBPF object only
#   loader       Build control plane binary only
#   install      Install binary, config dir, systemd service
#   uninstall    Remove installed files
#   install-dkms Install kernel module via DKMS
#   remove-dkms  Remove DKMS module
#   test         Basic tunnel up/down test
#   clean        Remove build artifacts
#   purge        Full cleanup including BPF state and interfaces
#   help         Show this help

.PHONY: all kmod xdp loader clean install uninstall \
        install-dkms remove-dkms install-module remove-module \
        test test-unit test-xdp test-integration test-all \
        test-sanitize test-tsan test-valgrind benchmark \
        lint format format-check coverage \
        purge help

VERSION     ?= 1.1.0
KDIR        ?= /lib/modules/$(shell uname -r)/build
PWD         := $(shell pwd)
ARCH        ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Install paths
PREFIX      ?= /usr
BINDIR      ?= $(PREFIX)/bin
SYSCONFDIR  ?= /etc/tachyon
SYSTEMDDIR  ?= /etc/systemd/system

# Compiler flags
CXX         ?= g++
CXXFLAGS    := -O2 -Wall -Wextra -std=c++17 \
               -DTACHYON_VERSION=\"$(VERSION)\"
LDFLAGS     := -lbpf -lcrypto -lelf -lz

# Loader source files
LOADER_SRCS := loader/main.cpp loader/crypto.cpp loader/config.cpp \
               loader/network.cpp loader/tunnel.cpp
LOADER_BIN  := loader/tachyon

# ── Build Targets ──

all: kmod xdp loader

kmod:
	@echo "\n[1/3] Building Tachyon Kernel Module..."
	$(MAKE) -C $(KDIR) M=$(PWD)/kmod modules
	@echo "  -> kmod/mod.ko"

xdp:
	@echo "\n[2/3] Building XDP Core (eBPF)..."
	clang -O2 -g -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c src/xdp_core.c -o src/xdp_core.o
	@echo "  -> src/xdp_core.o"

loader:
	@echo "\n[3/3] Building Tachyon Control Plane..."
	$(CXX) $(CXXFLAGS) $(LOADER_SRCS) -o $(LOADER_BIN) $(LDFLAGS)
	@echo "  -> $(LOADER_BIN)"

# ── Installation ──

install: loader
	@echo "Installing Tachyon..."
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -m 755 $(LOADER_BIN) $(DESTDIR)$(BINDIR)/tachyon
	@if [ -d systemd ]; then \
		install -d $(DESTDIR)$(SYSTEMDDIR); \
		install -m 644 systemd/tachyon@.service $(DESTDIR)$(SYSTEMDDIR)/; \
		systemctl daemon-reload 2>/dev/null || true; \
	fi
	@echo "Install complete. Configs go in $(SYSCONFDIR)."

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/tachyon
	rm -f $(DESTDIR)$(SYSTEMDDIR)/tachyon@.service
	systemctl daemon-reload 2>/dev/null || true
	@echo "Uninstalled."

install-dkms:
	@echo "\nInstalling Tachyon Module via DKMS..."
	sudo dkms remove -m tachyon-crypto -v 1.0 --all 2>/dev/null || true
	sudo rm -rf /usr/src/tachyon-crypto-1.0
	sudo mkdir -p /usr/src/tachyon-crypto-1.0
	sudo cp -r kmod /usr/src/tachyon-crypto-1.0/
	sudo cp dkms.conf /usr/src/tachyon-crypto-1.0/
	cd /usr/src/tachyon-crypto-1.0 && sudo dkms add .
	sudo dkms build -m tachyon-crypto -v 1.0
	sudo dkms install -m tachyon-crypto -v 1.0
	sudo modprobe mod 2>/dev/null || sudo insmod /var/lib/dkms/tachyon-crypto/1.0/*/mod.ko 2>/dev/null || true
	@echo "DKMS installation complete."

remove-dkms:
	sudo modprobe -r mod 2>/dev/null || true
	sudo dkms remove -m tachyon-crypto -v 1.0 --all 2>/dev/null || true
	sudo rm -rf /usr/src/tachyon-crypto-1.0
	@echo "DKMS removal complete."

install-module:
	sudo insmod kmod/mod.ko
	@echo "Module loaded."

remove-module:
	sudo rmmod mod 2>/dev/null || true
	@echo "Module removed."

# ── Testing ──

test-unit:
	@echo "\n[TEST] Building and running unit tests..."
	@cmake -B build/tests -S tests \
		-DCMAKE_BUILD_TYPE=Debug \
		-DBUILD_XDP_TESTS=OFF \
		-DBUILD_FUZZ_TESTS=OFF \
		-G "Unix Makefiles" > /dev/null 2>&1
	@cmake --build build/tests -j$$(nproc) > /dev/null 2>&1
	@cd build/tests && ctest --output-on-failure --timeout 60
	@echo "[TEST] Unit tests complete."

test-sanitize:
	@echo "\n[TEST] Building with ASan+UBSan..."
	@cmake -B build/sanitize -S tests \
		-DCMAKE_BUILD_TYPE=Debug \
		-DENABLE_SANITIZE=ON \
		-DBUILD_XDP_TESTS=OFF \
		-DBUILD_FUZZ_TESTS=OFF \
		-G "Unix Makefiles" > /dev/null 2>&1
	@cmake --build build/sanitize -j$$(nproc) > /dev/null 2>&1
	@ASAN_OPTIONS=halt_on_error=1:detect_leaks=1 \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		cd build/sanitize && ctest --output-on-failure --timeout 120
	@echo "[TEST] Sanitizer tests complete."

test-tsan:
	@echo "\n[TEST] Building with ThreadSanitizer..."
	@cmake -B build/tsan -S tests \
		-DCMAKE_BUILD_TYPE=Debug \
		-DENABLE_TSAN=ON \
		-DBUILD_XDP_TESTS=OFF \
		-DBUILD_FUZZ_TESTS=OFF \
		-G "Unix Makefiles" > /dev/null 2>&1
	@cmake --build build/tsan -j$$(nproc) > /dev/null 2>&1
	@TSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		cd build/tsan && ctest --output-on-failure --timeout 120
	@echo "[TEST] TSan tests complete."

test-valgrind:
	@echo "\n[TEST] Building for valgrind (no instrumentation)..."
	@cmake -B build/valgrind -S tests \
		-DCMAKE_BUILD_TYPE=Debug \
		-DBUILD_XDP_TESTS=OFF \
		-DBUILD_FUZZ_TESTS=OFF \
		-G "Unix Makefiles" > /dev/null 2>&1
	@cmake --build build/valgrind -j$$(nproc) > /dev/null 2>&1
	@echo "\n[TEST] Running under valgrind memcheck..."
	@for t in test_config test_crypto test_nonce_cache test_utils test_protocol; do \
		echo "  -> $$t"; \
		valgrind --tool=memcheck --error-exitcode=1 \
			--leak-check=full --show-leak-kinds=definite,indirect \
			--track-origins=yes \
			--suppressions=tests/valgrind.supp \
			build/valgrind/$$t 2>&1 | tail -5 || exit 1; \
	done
	@echo "[TEST] Valgrind memcheck complete."

benchmark:
	@echo "\n[BENCH] Building crypto benchmarks..."
	@cmake -B build/bench -S tests \
		-DCMAKE_BUILD_TYPE=Release \
		-DBUILD_BENCHMARKS=ON \
		-DBUILD_XDP_TESTS=OFF \
		-DBUILD_FUZZ_TESTS=OFF \
		-G "Unix Makefiles" > /dev/null 2>&1
	@cmake --build build/bench --target bench_crypto -j$$(nproc) > /dev/null 2>&1
	@build/bench/bench_crypto --benchmark_repetitions=3 \
		--benchmark_report_aggregates_only=true
	@echo "[BENCH] Complete."

test: loader
	@echo "\nTesting Tachyon (integration)..."
	@test -f test.conf || { echo "Create test.conf first (see tun.conf.example)"; exit 1; }
	sudo -E ./$(LOADER_BIN) up test.conf
	sleep 2
	sudo -E ./$(LOADER_BIN) show test.conf
	sudo -E ./$(LOADER_BIN) down test.conf

format:
	@find src/ loader/ tests/ \( -name '*.c' -o -name '*.cpp' -o -name '*.h' \) \
		| xargs clang-format -i --style=file

format-check:
	@find src/ loader/ tests/ \( -name '*.c' -o -name '*.cpp' -o -name '*.h' \) \
		| xargs clang-format --dry-run --Werror --style=file

lint: format-check
	@echo "\n[LINT] Running shellcheck..."
	@find tests/ -name '*.sh' -exec shellcheck -x -S warning {} +
	@echo "\n[LINT] Running cppcheck..."
	@cppcheck \
		--enable=warning,performance,portability \
		--error-exitcode=1 \
		--suppress=missingInclude \
		--suppress=missingIncludeSystem \
		--inline-suppr \
		--std=c11 \
		src/ loader/
	@echo "\n[LINT] All checks passed."

coverage:
	@echo "\n[COV] Building with coverage instrumentation..."
	@cmake -B build/coverage -S tests \
		-DCMAKE_BUILD_TYPE=Debug \
		-DENABLE_COVERAGE=ON \
		-DBUILD_XDP_TESTS=OFF \
		-DBUILD_FUZZ_TESTS=OFF \
		-G "Unix Makefiles" > /dev/null 2>&1
	@cmake --build build/coverage -j$$(nproc) > /dev/null 2>&1
	@cd build/coverage && ctest --output-on-failure --timeout 60
	@echo "\n[COV] Collecting coverage data..."
	@lcov --capture --directory build/coverage \
		--output-file build/coverage/coverage.info \
		--ignore-errors mismatch 2>/dev/null
	@lcov --remove build/coverage/coverage.info \
		'/usr/*' '*/tests/*' '*/googletest/*' \
		--output-file build/coverage/coverage-filtered.info 2>/dev/null
	@genhtml build/coverage/coverage-filtered.info \
		--output-directory build/coverage/html \
		--title "Tachyon XDP Tunnel" \
		--legend --demangle-cpp 2>/dev/null
	@echo "\n[COV] HTML report: build/coverage/html/index.html"

test-xdp:
	@echo "\n[TEST] Running XDP/BPF tests (requires root + loaded XDP program)..."
	@sudo tests/xdp/run_xdp_tests.sh

test-integration:
	@echo "\n[TEST] Running integration tests (requires root)..."
	@sudo tests/integration/test_tunnel_e2e.sh
	@sudo tests/integration/test_key_rotation.sh
	@sudo tests/integration/test_dpd.sh

test-all: test-unit test-sanitize test-tsan test-valgrind test-xdp test-integration
	@echo "\n[TEST] All test tiers complete."

# ── Cleanup ──

clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD)/kmod clean 2>/dev/null || true
	rm -f src/xdp_core.o $(LOADER_BIN)
	rm -rf build/
	@echo "Clean complete."

purge: clean remove-dkms remove-module
	sudo rm -rf /sys/fs/bpf/tachyon
	sudo ip link del t_ghost_in 2>/dev/null || true
	sudo ip link del t_ghost_out 2>/dev/null || true
	@echo "Full purge complete."

# ── Help ──

help:
	@echo "Tachyon XDP Tunnel v$(VERSION)"
	@echo ""
	@echo "Build targets:"
	@echo "  all              Build everything (kmod + xdp + loader)"
	@echo "  kmod             Build kernel crypto module"
	@echo "  xdp              Build XDP/eBPF object"
	@echo "  loader           Build control plane binary"
	@echo ""
	@echo "Install targets:"
	@echo "  install          Install binary and systemd service"
	@echo "  uninstall        Remove installed files"
	@echo "  install-dkms     Install kernel module via DKMS"
	@echo "  remove-dkms      Remove DKMS module"
	@echo ""
	@echo "Testing:"
	@echo "  test             Run basic up/show/down smoke test"
	@echo "  test-unit        Build and run unit tests (no root)"
	@echo "  test-sanitize    Build and run with ASan+UBSan"
	@echo "  test-tsan        Build and run with ThreadSanitizer"
	@echo "  test-valgrind    Build and run under valgrind memcheck"
	@echo "  benchmark        Run Google Benchmark crypto harnesses"
	@echo "  test-xdp         Run XDP/BPF tests (requires root)"
	@echo "  test-integration Run integration tests (requires root)"
	@echo "  test-all         Run all test tiers"
	@echo ""
	@echo "Code quality:"
	@echo "  lint             Run all linters (clang-format, cppcheck, shellcheck)"
	@echo "  format           Auto-format all source files"
	@echo "  format-check     Dry-run format check (used by CI)"
	@echo "  coverage         Generate HTML coverage report"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean            Remove build artifacts"
	@echo "  purge            Full cleanup (artifacts + BPF state + interfaces)"
	@echo "  help             Show this help"
