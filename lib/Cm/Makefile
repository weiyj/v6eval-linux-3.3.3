LIBS = libCm.a
OBJS =	CmTypes.o \
	BtObject.o BtArray.o BtList.o BtSet.o \
	CmQueue.o CmAgent.o CmMain.o CmSocket.o \
	CmFdSet.o CmFdMasks.o CmString.o PerfCollect.o \
	Timer.o CmDispatch.o CmReceiver.o timeval.o \
	CmToken.o CmMatch.o CmLexer.o

CFLAGS+=	-O0 -pipe -g -DYYDEBUG
CXXFLAGS+=	${CFLAGS}

.PHONY: all
all:	${LIBS}

${LIBS}: ${OBJS}
	$(AR) r $@ $?

.PHONY: install
install:

.PHONY: clean
clean:
	- rm -f ${LIBS} *.o

