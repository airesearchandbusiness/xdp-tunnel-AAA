.PHONY: all kmod xdp loader clean install-dkms remove-dkms

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: kmod xdp loader

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc/tachyon
SYSTEMDDIR ?= /etc/systemd/system

kmod:
	@echo "\n[1/3] Building Tachyon Kernel Module (Twin-Engine)..."
	$(MAKE) -C $(KDIR) M=$(PWD)/kmod modules
	@echo " Kernel Module built: kmod/mod.ko"

xdp:
	@echo "\n[2/3] Building XDP Core (eBPF Fast-Path)..."
	clang -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 \
		-I/usr/include/x86_64-linux-gnu \
		-c src/xdp_core.c -o src/xdp_core.o
	@echo " XDP object built: src/xdp_core.o"

loader:
	@echo "\n[3/3] Building Tachyon Control Plane (C++ Loader)..."
	g++ -O2 -Wall -std=c++17 loader/main.cpp -o loader/tachyon -lbpf -lcrypto
	@echo " Loader built: ./loader/tachyon"

install-dkms:
	@echo "\n Installing Tachyon Module via DKMS..."
	# پاکسازی قبلی
	sudo dkms remove -m tachyon-crypto -v 1.0 --all 2>/dev/null || true
	sudo rm -rf /usr/src/tachyon-crypto-1.0
	
	# کپی سورس
	sudo mkdir -p /usr/src/tachyon-crypto-1.0
	sudo cp -r kmod /usr/src/tachyon-crypto-1.0/
	sudo cp dkms.conf /usr/src/tachyon-crypto-1.0/
	
	# نصب DKMS
	cd /usr/src/tachyon-crypto-1.0 && sudo dkms add .
	sudo dkms build -m tachyon-crypto -v 1.0
	sudo dkms install -m tachyon-crypto -v 1.0
	
	# لود ماژول
	sudo modprobe mod 2>/dev/null || sudo modprobe tachyon-crypto 2>/dev/null || \
	sudo insmod /var/lib/dkms/tachyon-crypto/1.0/*/mod.ko
	
	@echo "\n DKMS installation complete."
	@echo " Module status:"
	lsmod | grep -E "mod|tachyon" || echo "Module not loaded"

remove-dkms:
	@echo "\n Removing Tachyon Module from DKMS..."
	sudo modprobe -r mod 2>/dev/null || true
	sudo modprobe -r tachyon-crypto 2>/dev/null || true
	sudo dkms remove -m tachyon-crypto -v 1.0 --all 2>/dev/null || true
	sudo rm -rf /usr/src/tachyon-crypto-1.0
	@echo " DKMS removal complete."

install-module:
	@echo "\n Installing module manually..."
	sudo insmod kmod/mod.ko
	@echo " Module installed"

remove-module:
	@echo "\n Removing module..."
	sudo rmmod mod.ko 2>/dev/null || true
	@echo " Module removed"

test: loader
	@echo "\n Testing Tachyon..."
	sudo -E ./loader/tachyon up test.conf || echo "Create test.conf first"
	sleep 2
	sudo -E ./loader/tachyon show test.conf
	sudo -E ./loader/tachyon down test.conf

clean:
	@echo "\n Cleaning up build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD)/kmod clean
	rm -f src/xdp_core.o loader/tachyon
	@echo " Clean complete"

install:
	@echo "Installing Tachyon..."
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -d $(DESTDIR)$(SYSTEMDDIR)
	install -m 755 tachyon $(DESTDIR)$(BINDIR)/tachyon
	install -m 644 systemd/tachyon@.service $(DESTDIR)$(SYSTEMDDIR)/tachyon@.service
	systemctl daemon-reload
	@echo "Install complete. Put your configs in $(SYSCONFDIR) and run: systemctl start tachyon@<configname>"

uninstall:
	@echo "Uninstalling Tachyon..."
	rm -f $(DESTDIR)$(BINDIR)/tachyon
	rm -f $(DESTDIR)$(SYSTEMDDIR)/tachyon@.service
	systemctl daemon-reload

purge: clean remove-dkms remove-module
	sudo rm -rf /sys/fs/bpf/tachyon
	sudo ip link del t_ghost_in 2>/dev/null || true
	sudo ip link del t_ghost_out 2>/dev/null || true
	@echo "\n Full purge complete"