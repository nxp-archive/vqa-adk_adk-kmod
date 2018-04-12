#
# Copyright 2017 NXP
#
SUBDIRS = nsp_misc

.PHONY: all clean install

all:
	@for sdir in $(SUBDIRS); do \
		$(MAKE) ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD)/$$sdir modules || exit 1; \
	done

clean:
	@for sdir in $(SUBDIRS); do \
		$(MAKE) -C $$sdir clean; \
	done

install:
	@for sdir in $(SUBDIRS); do \
		$(MAKE) -C $$sdir install || exit 1; \
	done
