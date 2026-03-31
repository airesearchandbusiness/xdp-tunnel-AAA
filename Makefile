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
        test purge help

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
CXXFLAGS    := -O2 -Wall -Wextra -Wpedantic -std=c++17 \
               -DTACHYON_VERSION=\"$(VERSION)\"
LDFLAGS     := -lbpf -lcrypto

# Loader source files
LOADER_SRCS := loader/main.cpp loader/crypto.cpp loader/config.cpp \
               loader/network.cpp loader/tunnel.cpp
LOADER_BIN  := loader/tachyon

# Test build flags (TACHYON_NO_BPF avoids libbpf dependency for unit tests)
TEST_CXXFLAGS := -O0 -g -Wall -Wextra -std=c++17 -I. \
                 -DTACHYON_VERSION=\"$(VERSION)\" -DTACHYON_NO_BPF
TEST_LDFLAGS  := -lcrypto
TEST_SRCS     := loader/crypto.cpp loader/config.cpp

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

test-unit: tests/test_crypto tests/test_config tests/test_utils tests/test_protocol
	@echo "\n Running Tachyon Unit Tests...\n"
	@./tests/test_crypto && ./tests/test_config && \
	 ./tests/test_utils && ./tests/test_protocol && \
	 echo "\n All tests passed." || (echo "\n Some tests FAILED." && exit 1)

tests/test_crypto: tests/test_crypto.cpp $(TEST_SRCS) loader/tachyon.h
	$(CXX) $(TEST_CXXFLAGS) tests/test_crypto.cpp $(TEST_SRCS) -o $@ $(TEST_LDFLAGS)

tests/test_config: tests/test_config.cpp $(TEST_SRCS) loader/tachyon.h
	$(CXX) $(TEST_CXXFLAGS) tests/test_config.cpp $(TEST_SRCS) -o $@ $(TEST_LDFLAGS)

tests/test_utils: tests/test_utils.cpp loader/tachyon.h
	$(CXX) $(TEST_CXXFLAGS) tests/test_utils.cpp -o $@ $(TEST_LDFLAGS)

tests/test_protocol: tests/test_protocol.cpp loader/tachyon.h src/common.h
	$(CXX) $(TEST_CXXFLAGS) tests/test_protocol.cpp -o $@ $(TEST_LDFLAGS)

test-sanitize: TEST_CXXFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
test-sanitize: TEST_LDFLAGS  += -fsanitize=address,undefined
test-sanitize: test-unit

test: loader
	@echo "\nTesting Tachyon (integration)..."
	@test -f test.conf || { echo "Create test.conf first (see tun.conf.example)"; exit 1; }
	sudo -E ./$(LOADER_BIN) up test.conf
	sleep 2
	sudo -E ./$(LOADER_BIN) show test.conf
	sudo -E ./$(LOADER_BIN) down test.conf

format:
	find loader/ tests/ -name '*.cpp' -o -name '*.h' | xargs clang-format -i

format-check:
	find loader/ tests/ -name '*.cpp' -o -name '*.h' | xargs clang-format --dry-run --Werror

# ── Cleanup ──

clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD)/kmod clean 2>/dev/null || true
	rm -f src/xdp_core.o $(LOADER_BIN)
	rm -f tests/test_crypto tests/test_config tests/test_utils tests/test_protocol
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
	@echo "  all            Build everything (kmod + xdp + loader)"
	@echo "  kmod           Build kernel crypto module"
	@echo "  xdp            Build XDP/eBPF object"
	@echo "  loader         Build control plane binary"
	@echo ""
	@echo "Install targets:"
	@echo "  install        Install binary and systemd service"
	@echo "  uninstall      Remove installed files"
	@echo "  install-dkms   Install kernel module via DKMS"
	@echo "  remove-dkms    Remove DKMS module"
	@echo ""
	@echo "Other:"
	@echo "  test           Run basic up/show/down test"
	@echo "  clean          Remove build artifacts"
	@echo "  purge          Full cleanup (artifacts + BPF state + interfaces)"
	@echo "  help           Show this help"
