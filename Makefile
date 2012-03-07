SUBDIRS = lib bin etc script include
export PREFIX = /usr/local/v6eval
DOCFILES=00README INSTALL CHANGELOG \
	 00README.v6eval INSTALL.v6eval CHANGELOG.v6eval \
	 COPYRIGHT

DIRS = $(PREFIX) $(PREFIX)/bin $(PREFIX)/man $(PREFIX)/doc
SECTIONS=       1

.PHONY: all clean ${SUBDIRS}
all clean:
	@for subdir in ${SUBDIRS}; do \
		$(MAKE) -C $$subdir $@; \
	done

.PHONY: install
install:
	@for subdir in ${DIRS}; do \
		install -d -o bin -g bin -m 755 $$subdir; \
	done
	@for i in ${SECTIONS}; do \
		install -d -o bin -g bin -m 755 ${PREFIX}/man/man$$i; \
	done
	install -c -o bin -g bin -m 444 ${DOCFILES} ${PREFIX}/doc
	@for subdir in ${SUBDIRS}; do \
		$(MAKE) -C $$subdir install; \
	done

