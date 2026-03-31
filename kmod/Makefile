obj-m += mod.o

KBUILD_CFLAGS += -g -O2 -Wall -Werror -fno-omit-frame-pointer

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo cp mod.ko /lib/modules/$(shell uname -r)/extra/
	sudo depmod -a
