SUBDIRS=pktbuf pktctl pktsend pktrecv checker autorun pktlint remotes dhgen dhcomp prfcomp ivcomp x509dec sigcomp file2hex indexgen

.PHONY: all clean install
all clean install:
	@for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
