#
# Copyright 2017 NXP
#
SUBDIRS = nsp_misc

.PHONY: subdirs $(SUBDIRS) all clean install

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ all

all: subdirs

clean:
	@for sdir in $(SUBDIRS); do \
		$(MAKE) -C $$sdir clean; \
	done

install:
	@for sdir in $(SUBDIRS); do \
		$(MAKE) -C $$sdir install || exit 1; \
	done
