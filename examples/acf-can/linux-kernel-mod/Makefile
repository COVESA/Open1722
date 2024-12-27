obj-$(CONFIG_ACF_CAN) += acfcan.o
acfcan-objs := acfcanmain.o 1722ethernet.o ../../../src/avtp/acf/Tscf.o ../../../src/avtp/acf/Ntscf.o ../../../src/avtp/acf/Can.o ../../../src/avtp/Utils.o ../../../src/avtp/CommonHeader.o
ccflags-y += -DLINUX_KERNEL1722=1
ccflags-y += -I $(src)/../../../include



all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)   modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)  clean