#/**************************************************************************
# *Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
# Copyright 2017 NXP
#
# Makefile config for the NSP Misc kernel driver module
#
#
CC      = $(CROSS_COMPILE)gcc
AR      = $(CROSS_COMPILE)ar
LD      = $(CROSS_COMPILE)ld

EXTRA_CFLAGS += -I$(ODP_PATH)/kern

obj-m += nsp_misc.o

all:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) clean


