ifneq ($(KERNELRELEASE),)

# kbuild part of makefile
obj-m  := tcp_rocc_ccmatic.o

else
# normal makefile

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
endif
