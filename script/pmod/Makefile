SUBDIRS = IO-Tty IO-Stty Expect V6evalTool V6evalRemote V6evalCommon

.PHONY: all clean install
all clean install:
	@for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done

