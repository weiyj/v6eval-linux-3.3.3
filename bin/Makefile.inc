Cm = ../../lib/Cm/
Pz = ../../lib/Pz/
pkt = ../../lib/pkt/
CFLAGS += -pipe -g -fno-strict-aliasing
CPPFLAGS += -I${Cm} -I${Pz} -I${pkt}
CXXFLAGS+= ${CFLAGS} -Woverloaded-virtual
LDFLAGS += -L${Cm} -L${Pz} -L${pkt}
LDLIBS	+= -lPkt -lPz -lCm -lcrypto

INSTALL	= /usr/bin/install -c

%: %.c
	$(CC) ${CPPFLAGS} ${CFLAGS} $^ ${LDFLAGS} ${LDLIBS} -o $@

%: %.cc
	$(CXX) ${CPPFLAGS} ${CXXFLAGS} $^ ${LDFLAGS} ${LDLIBS} -o $@

.PHONY: all
all: ${PROG}

${PROG}: ${SRCS} ${Cm}/libCm.a ${Pz}/libPz.a ${pkt}/libPkt.a

.PHONY: install
install: ${PROG}
	$(INSTALL) ${PROG} ${PREFIX}/bin/${PROG}

.PHONY: clean
clean:
	rm -f ${PROG}

