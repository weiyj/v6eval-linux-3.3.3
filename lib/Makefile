SUBDIRS = Cm Pz pkt

.PHONY: all clean install
all clean install:
	@for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done

