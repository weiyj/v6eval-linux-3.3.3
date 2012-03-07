LIBS = libPkt.a
YSRC = PzParse.y
OBJS = PzParse.o LxToken.o LxLexer.o RAFControl.o \
	PktAgent.o PktRecv.o PktClient.o PktServer.o StdAgent.o \
	BpfAgent.o Bpfilter.o Ringbuf.o RunEnv.o PktCtlClient.o \
	PktSndClient.o PktRcvClient.o PktBuf.o PktQueue.o bufStat.o

Cm = ../Cm
Pz = ../Pz

CFLAGS+=	-I. -I$(Cm) -I$(Pz) -DHAVE_BPF_HDRCMPLT -pipe -g
CXXFLAGS+=	${CFLAGS}

.PHONY: all
all:	${LIBS}

${LIBS}: ${OBJS}
	$(AR) r $@ $?

PzParse.cc: PzParse.y
	$(YACC) -d -o PzParse.cc PzParse.y
	@if [ -e "PzParse.cc.h" ]; \
		then mv PzParse.cc.h PzParse.h; \
	fi

.PHONY: install
install:

.PHONY: clean
clean:
	- rm -f ${LIBS} *.o PzParse.cc PzParse.h

