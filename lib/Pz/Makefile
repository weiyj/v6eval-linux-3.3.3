LIBS = libPz.a
OBJS =	DmObject.o ItPosition.o McAH.o McARP.o McAlgorithm.o	\
	McDHCPv6.o McDNS.o McESP.o McEther.o McICMPv4.o		\
	McICMPv6.o McIGMP.o McIKE.o McIPv4.o McIPv6.o McInit.o	\
	McMLDv2.o McMobility.o McNoNext.o McNull.o McObject.o	\
	McRIPng.o McRR.o McSIP.o McSNMP.o McSub.o McTCP.o	\
	McUDP.o McVRRP.o MfAlgorithm.o MmChecksum.o MmData.o	\
	MmHeader.o MmObject.o MvArgCheck.o MvFunction.o		\
	PAlgorithm.o PControl.o PObject.o PcObject.o PlObject.o	\
	PrItem.o PvAction.o PvAutoItem.o PvIfName.o PvName.o	\
	PvObject.o PvOctets.o RObject.o WObject.o		\
	rijndael-alg-fst.o rijndael-api-fst.o camellia.o camellia-api.o

Cm = ../Cm
CFLAGS+=	-O0 -I$(Cm) -I. -pipe -g -DYYDEBUG
CXXFLAGS+=	${CFLAGS}

#CXXFLAGS=	-pipe -g -Wall -I./ -I$(Cm)
#CFLAGS=	-pipe -g -Wall -I./ -I$(Cm) -I/usr/local/include

VPATH = crypto/rijndael crypto/camellia

# <draft-ietf-nemo-basic-support-03.txt>, NEMO Basic Support
# CXXFLAGS+=	-DTBD_OPT_MH_MOB_NETWORK_PREF=6

# <draft-ietf-ipv6-router-selection-05.txt>,
#     Default Router Preferences and More-Specific Routes
# CXXFLAGS+=	-DTBD_OPT_ROUTE_INFO=200

# <draft-ietf-dhc-dhcpv6-opt-timeconfig-03.txt>,
#     Time Configuration Options for DHCPv6
# CXXFLAGS+=	-DTBD_OPT_NTP_SERVERS=27
# CXXFLAGS+=	-DTBD_OPT_TIME_ZONE=28

# RFC 1157,  SNMP
# RFC 1905,  Protocol Operations for SNMPv2
# CXXFLAGS+=   -DNOT_USE_SNMP

# RFC 3376, IGMPv3
# CXXFLAGS+=	-DNOT_USE_IGMPV3_QUERY

# RFC 3775, Mobility Support in IPv6
# CXXFLAGS+=	-DRR_DBG

# RFC 3315, DHCP for IPv6
# CXXFLAGS+=	-DDHCP_DBG

# RFC 3768, VRRP
# draft-ietf-vrrp-ipv6-spec-06.txt, VRRP for IPv6
# CXXFLAGS+=	-DVRRP_DBG

# RFC 2408, ISAKMP
# CXXFLAGS+=	-DISAKMP_DBG

# RFC 3566, AES-XCBC-MAC-96 Algorithm
# CXXFLAGS+=	-DAESXCBC_DBG

# RFC 3686, Using AES Counter Mode With IPsec ESP
# CXXFLAGS+=	-DAESCTR_DBG

# RFC 4303, IP Encapsulating Security Payload (ESP)
# 2.2.1. Extended (64-bit) Sequence Number
# CXXFLAGS+=	-DESN_DBG


.PHONY: all
all:	${LIBS}

${LIBS}: ${OBJS}
	$(AR) r $@ $?

.PHONY: install
install:

.PHONY: clean
clean:
	- rm -f ${LIBS} *.o

