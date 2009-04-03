/*
 * Copyright (C) 2006, 2007, 2008, 2009 Fujitsu Limited.
 * All rights reserved.
 *
 * Redistribution and use of this software in source and binary forms, with
 * or without modification, are permitted provided that the following
 * conditions and disclaimer are agreed and accepted by the user:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the names of the copyrighters, the name of the project which
 * is related to this software (hereinafter referred to as "project") nor
 * the names of the contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * 4. No merchantable use may be permitted without prior written
 * notification to the copyrighters. However, using this software for the
 * purpose of testing or evaluating any products including merchantable
 * products may be permitted without any notification to the copyrighters.
 *
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHTERS, THE PROJECT AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING
 * BUT NOT LIMITED THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE, ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHTERS, THE PROJECT OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT,STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 *    Author: Wei Yongjun <yjwei@cn.fujitsu.com>
 *
 */
#if !defined(__McSCTP_h__)
#define	__McSCTP_h__	1

#include "McSub.h"

//////////////////////////////////////////////////////////////////////////////
//	Upper SCTP	RFC2960

class McUpp_SCTP :public McUpper{
static	McUpp_SCTP*		instance_;
static	class McTopHdr_SCTP*	tophdr_;
	McUpp_SCTP(CSTR);
public:
virtual ~McUpp_SCTP();
static	McUpp_SCTP* create(CSTR key,CSTR tophdrkey);
static	McUpp_SCTP* instance(){return instance_;}
	int32_t headerType()const{return 0x84;}
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
virtual uint32_t length_for_reverse(RControl&,ItPosition& at,OCTBUF& buf) const;
virtual RObject* reverse(RControl& c,
		RObject* r_parent,ItPosition& at,OCTBUF& buf)const;
virtual bool generate(WControl& c,WObject* w_self,OCTBUF& buf)const;
};

class McTopHdr_SCTP :public McHeader{
friend	class McUpp_SCTP;
	McTopHdr_SCTP(CSTR);
virtual ~McTopHdr_SCTP();
static	McTopHdr_SCTP* create(CSTR);
	int32_t headerType()const{return TP_Upp_TCP;}
};

//////////////////////////////////////////////////////////////////////////////
const int32_t TP_CHUNK_DATA		= 0;
const int32_t TP_CHUNK_INIT		= 1;
const int32_t TP_CHUNK_INIT_ACK		= 2;
const int32_t TP_CHUNK_SACK		= 3;
const int32_t TP_CHUNK_HEARTBEAT	= 4;
const int32_t TP_CHUNK_HEARTBEAT_ACK	= 5;
const int32_t TP_CHUNK_ABORT		= 6;
const int32_t TP_CHUNK_SHUTDOWN		= 7;
const int32_t TP_CHUNK_SHUTDOWN_ACK	= 8;
const int32_t TP_CHUNK_ERROR		= 9;
const int32_t TP_CHUNK_COOKIE_ECHO	= 10;
const int32_t TP_CHUNK_COOKIE_ACK	= 11;
const int32_t TP_CHUNK_ECN_ECNE		= 12;
const int32_t TP_CHUNK_ECN_CWR		= 13;
const int32_t TP_CHUNK_SHUTDOWN_COMPLETE= 14;
const int32_t TP_CHUNK_AUTH		= 0x0F;
const int32_t TP_CHUNK_NR_SACK		= 0x10;
const int32_t TP_CHUNK_FWD_TSN		= 0xC0;
const int32_t TP_CHUNK_ASCONF		= 0xC1;
const int32_t TP_CHUNK_ASCONF_ACK	= 0x80;
const int32_t TP_CHUNK_PKTDROP		= 0x81;
const int32_t TP_CHUNK_STREAM_RESET	= 0x82;
const int32_t TP_CHUNK_PADDING		= 0x84;

class McChunk : public McOption{
protected:
	MmUint*	type_;
	void	type_member(MmUint* meta){type_=meta; member(meta);}
	MmUint*	length_;
	void	length_member(MmUint* meta){length_=meta; member(meta);}
	void	common_member();
	McChunk(CSTR);
public:
virtual	~McChunk();
static	void	create_chunks();
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
	uint32_t alignment_requirement() const;
virtual uint32_t length_for_reverse(RControl&,ItPosition& at,OCTBUF& buf) const;
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
//HardCording action method
	DEC_HCGENE(Length);
};

//any optionType Format (for unknown option type)
class McChunkAny :public McChunk{
	McChunkAny(CSTR);
public:
virtual	~McChunkAny();
static	McChunkAny* create(CSTR);
};

class McChunkInit :public McChunk{
	McChunkInit(CSTR);
public:
virtual	~McChunkInit();
static	McChunkInit* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_INIT;}
};

class McChunkInitAck :public McChunk{
	McChunkInitAck(CSTR);
public:
virtual	~McChunkInitAck();
static	McChunkInitAck* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_INIT_ACK;}
};

class McChunkSack :public McChunk{
protected:
	MmUint*	gap_;
	void	gap_member(MmUint* meta){gap_=meta; member(meta);}
	MmUint*	dup_;
	void	dup_member(MmUint* meta){dup_=meta; member(meta);}
	McChunkSack(CSTR);
public:
virtual	~McChunkSack();
static	McChunkSack* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_SACK;}
	DEC_HC_MLC(GAP);
	DEC_HC_MLC(DUP);
};

class McChunkHeartbeat :public McChunk{
	McChunkHeartbeat(CSTR);
public:
virtual	~McChunkHeartbeat();
static	McChunkHeartbeat* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_HEARTBEAT;}
};

class McChunkHeartbeatAck :public McChunk{
	McChunkHeartbeatAck(CSTR);
public:
virtual	~McChunkHeartbeatAck();
static	McChunkHeartbeatAck* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_HEARTBEAT_ACK;}
};

class McChunkData :public McChunk{
	McChunkData(CSTR);
public:
virtual	~McChunkData();
static	McChunkData* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_DATA;}
//HardCording action method
	DEC_HCGENE(Length);
};

class McChunkAbort :public McChunk{
	McChunkAbort(CSTR);
public:
virtual	~McChunkAbort();
static	McChunkAbort* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_ABORT;}
};

class McChunkShutdown :public McChunk{
	McChunkShutdown(CSTR);
public:
virtual	~McChunkShutdown();
static	McChunkShutdown* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_SHUTDOWN;}
};

class McChunkShutdownAck :public McChunk{
	McChunkShutdownAck(CSTR);
public:
virtual	~McChunkShutdownAck();
static	McChunkShutdownAck* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_SHUTDOWN_ACK;}
};

class McChunkError :public McChunk{
	McChunkError(CSTR);
public:
virtual	~McChunkError();
static	McChunkError* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_ERROR;}
};

class McChunkCookieEcho :public McChunk{
	McChunkCookieEcho(CSTR);
public:
virtual	~McChunkCookieEcho();
static	McChunkCookieEcho* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_COOKIE_ECHO;}
};

class McChunkCookieAck :public McChunk{
	McChunkCookieAck(CSTR);
public:
virtual	~McChunkCookieAck();
static	McChunkCookieAck* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_COOKIE_ACK;}
};

class McChunkCongestionExperiencedReport :public McChunk{
	McChunkCongestionExperiencedReport(CSTR);
public:
virtual	~McChunkCongestionExperiencedReport();
static	McChunkCongestionExperiencedReport* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_ECN_ECNE;}
};

class McChunkCongestionWindowReport :public McChunk{
	McChunkCongestionWindowReport(CSTR);
public:
virtual	~McChunkCongestionWindowReport();
static	McChunkCongestionWindowReport* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_ECN_CWR;}
};

class McChunkShutdownComplete :public McChunk{
	McChunkShutdownComplete(CSTR);
public:
virtual	~McChunkShutdownComplete();
static	McChunkShutdownComplete* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_SHUTDOWN_COMPLETE;}
};

class McAuthenticationChunk :public McChunk{
	McAuthenticationChunk(CSTR);
public:
virtual	~McAuthenticationChunk();
static	McAuthenticationChunk* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_AUTH;}
};

class McChunkNRSack :public McChunk{
protected:
	MmUint*	gap_;
	void	gap_member(MmUint* meta){gap_=meta; member(meta);}
	MmUint*	nrgap_;
	void	nrgap_member(MmUint* meta){nrgap_=meta; member(meta);}
	MmUint*	dup_;
	void	dup_member(MmUint* meta){dup_=meta; member(meta);}
	McChunkNRSack(CSTR);
public:
virtual	~McChunkNRSack();
static	McChunkNRSack* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_NR_SACK;}
	DEC_HC_MLC(GAP);
	DEC_HC_MLC(NRGAP);
	DEC_HC_MLC(DUP);
};

class McChunkForwardTSN :public McChunk{
	McChunkForwardTSN(CSTR);
public:
virtual	~McChunkForwardTSN();
static	McChunkForwardTSN* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_FWD_TSN;}
	DEC_HC_MLC(Stream);
	DEC_HC_MLC(Sequence);
};

class McChunkAddressConfigurationChange :public McChunk{
	McChunkAddressConfigurationChange(CSTR);
public:
virtual	~McChunkAddressConfigurationChange();
static	McChunkAddressConfigurationChange* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_ASCONF;}
};

class McAddressConfigurationAck :public McChunk{
	McAddressConfigurationAck(CSTR);
public:
virtual	~McAddressConfigurationAck();
static	McAddressConfigurationAck* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_ASCONF_ACK;}
};

class McChunkPacketDrop :public McChunk{
	McChunkPacketDrop(CSTR);
public:
virtual	~McChunkPacketDrop();
static	McChunkPacketDrop* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_PKTDROP;}
};

class McChunkStreamReset :public McChunk{
	McChunkStreamReset(CSTR);
public:
virtual	~McChunkStreamReset();
static	McChunkStreamReset* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_STREAM_RESET;}
};

class McChunkPadding :public McChunk{
	McChunkPadding(CSTR);
public:
virtual	~McChunkPadding();
static	McChunkPadding* create(CSTR);
	int32_t optionType()const{return TP_CHUNK_PADDING;}
};

//////////////////////////////////////////////////////////////////////////////
const int32_t TP_PARAM_HEARTBEAT_INFO	= 1;
const int32_t TP_PARAM_IPV4_ADDR	= 5;
const int32_t TP_PARAM_IPV6_ADDR	= 6;
const int32_t TP_PARAM_STALE_COOKIE	= 7;
const int32_t TP_PARAM_UNREG_PARAM	= 8;
const int32_t TP_PARAM_COOKIE_PRER	= 9;
const int32_t TP_PARAM_HOSTNAME_ADDR	= 11;
const int32_t TP_PARAM_SUPPORT_ADDR	= 12;
const int32_t TP_PARAM_ENC_CAPABLE	= 0x8000;
const int32_t TP_PARAM_RANDOM		= 0x8002;
const int32_t TP_PARAM_CHUNK_LIST	= 0x8003;
const int32_t TP_PARAM_HMAC_ALGO	= 0x8004;
const int32_t TP_PARAM_PADDING		= 0x8005;
const int32_t TP_PARAM_SUPP_EXTEN	= 0x8008;
const int32_t TP_PARAM_FORWARD_TSN	= 0xC000;
const int32_t TP_PARAM_ADD_IP_ADDRESS	= 0xC001;
const int32_t TP_PARAM_DEL_IP_ADDRESS	= 0xC002;
const int32_t TP_PARAM_ERR_INDICATION	= 0xC003;
const int32_t TP_PARAM_SET_PRIM_ADDR	= 0xC004;
const int32_t TP_PARAM_SUCC_INDICATION	= 0xC005;
const int32_t TP_PARAM_ADP_LAYER_INDT	= 0xC006;

const int32_t TP_PARAM_OSSN_RESET_REQUEST	= 0x000d;
const int32_t TP_PARAM_ISSN_RESET_REQUEST	= 0x000e;
const int32_t TP_PARAM_SSN_RESET_REQUEST	= 0x000f;
const int32_t TP_PARAM_STREAM_RESET_RESPONSE	= 0x0010;
const int32_t TP_PARAM_ADD_STREAMS		= 0x0011;

class McParameter : public McOption{
protected:
	MmUint*	type_;
	void	type_member(MmUint* meta){type_=meta; member(meta);}
	MmUint*	length_;
	void	length_member(MmUint* meta){length_=meta; member(meta);}
	void	common_member();
	McParameter(CSTR);
public:
virtual	~McParameter();
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
	uint32_t alignment_requirement() const;
virtual uint32_t length_for_reverse(RControl&,ItPosition& at,OCTBUF& buf) const;
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
//HardCording action method
	DEC_HCGENE(Length);
};

class McParamANY :public McParameter {
	McParamANY(CSTR);
public:
virtual	~McParamANY();
static	McParamANY* create(CSTR);
};

class McParamHeartbeatInfo :public McParameter{
	McParamHeartbeatInfo(CSTR);
public:
virtual	~McParamHeartbeatInfo();
static	McParamHeartbeatInfo* create(CSTR);
	int32_t optionType()const{return TP_PARAM_HEARTBEAT_INFO;}
};

class McParamIPv4Address :public McParameter{
	McParamIPv4Address(CSTR);
public:
virtual	~McParamIPv4Address();
static	McParamIPv4Address* create(CSTR);
	int32_t optionType()const{return TP_PARAM_IPV4_ADDR;}
};

class McParamIPv6Address :public McParameter{
	McParamIPv6Address(CSTR);
public:
virtual	~McParamIPv6Address();
static	McParamIPv6Address* create(CSTR);
	int32_t optionType()const{return TP_PARAM_IPV6_ADDR;}
};

class McParamStaleCookie :public McParameter{
	McParamStaleCookie(CSTR);
public:
virtual	~McParamStaleCookie();
static	McParamStaleCookie* create(CSTR);
	int32_t optionType()const{return TP_PARAM_STALE_COOKIE;}
};

class McParamUnrecognizedParameters :public McParameter{
	McParamUnrecognizedParameters(CSTR);
public:
virtual	~McParamUnrecognizedParameters();
static	McParamUnrecognizedParameters* create(CSTR);
	int32_t optionType()const{return TP_PARAM_UNREG_PARAM;}
};

class McParamHostNameAddress :public McParameter{
	McParamHostNameAddress(CSTR);
public:
virtual	~McParamHostNameAddress();
static	McParamHostNameAddress* create(CSTR);
	int32_t optionType()const{return TP_PARAM_HOSTNAME_ADDR;}
};

class McParamCookiePreservative :public McParameter{
	McParamCookiePreservative(CSTR);
public:
virtual	~McParamCookiePreservative();
static	McParamCookiePreservative* create(CSTR);
	int32_t optionType()const{return TP_PARAM_COOKIE_PRER;}
};

class McParamSupportAddress :public McParameter{
	McParamSupportAddress(CSTR);
public:
virtual	~McParamSupportAddress();
static	McParamSupportAddress* create(CSTR);
	int32_t optionType()const{return TP_PARAM_SUPPORT_ADDR;}
	DEC_HC_MLC(AddrType);
};

class McParamENCCapable :public McParameter{
	McParamENCCapable(CSTR);
public:
virtual	~McParamENCCapable();
static	McParamENCCapable* create(CSTR);
	int32_t optionType()const{return TP_PARAM_ENC_CAPABLE;}
};

class McParamForwardTSN :public McParameter{
	McParamForwardTSN(CSTR);
public:
virtual	~McParamForwardTSN();
static	McParamForwardTSN* create(CSTR);
	int32_t optionType()const{return TP_PARAM_FORWARD_TSN;}
};

class McParamAdaptationLayerIndication :public McParameter{
	McParamAdaptationLayerIndication(CSTR);
public:
virtual	~McParamAdaptationLayerIndication();
static	McParamAdaptationLayerIndication* create(CSTR);
	int32_t optionType()const{return TP_PARAM_ADP_LAYER_INDT;}
};

class McParamSetPrimaryAddress :public McParameter{
	McParamSetPrimaryAddress(CSTR);
public:
virtual	~McParamSetPrimaryAddress();
static	McParamSetPrimaryAddress* create(CSTR);
	int32_t optionType()const{return TP_PARAM_SET_PRIM_ADDR;}
};

class McParamSupportedExtensions :public McParameter{
	McParamSupportedExtensions(CSTR);
public:
virtual	~McParamSupportedExtensions();
static	McParamSupportedExtensions* create(CSTR);
	int32_t optionType()const{return TP_PARAM_SUPP_EXTEN;}
	DEC_HC_MLC(ChunkType);
};

class McParamAddIPAddress :public McParameter{
	McParamAddIPAddress(CSTR);
public:
virtual	~McParamAddIPAddress();
static	McParamAddIPAddress* create(CSTR);
	int32_t optionType()const{return TP_PARAM_ADD_IP_ADDRESS;}
};

class McParamDeleteIPAddress :public McParameter{
	McParamDeleteIPAddress(CSTR);
public:
virtual	~McParamDeleteIPAddress();
static	McParamDeleteIPAddress* create(CSTR);
	int32_t optionType()const{return TP_PARAM_DEL_IP_ADDRESS;}
};

class McParamErrorCauseIndication :public McParameter{
	McParamErrorCauseIndication(CSTR);
public:
virtual	~McParamErrorCauseIndication();
static	McParamErrorCauseIndication* create(CSTR);
	int32_t optionType()const{return TP_PARAM_ERR_INDICATION;}
};

class McParamSuccessIndication :public McParameter{
	McParamSuccessIndication(CSTR);
public:
virtual	~McParamSuccessIndication();
static	McParamSuccessIndication* create(CSTR);
	int32_t optionType()const{return TP_PARAM_SUCC_INDICATION;}
};

class McParamRandom :public McParameter{
	McParamRandom(CSTR);
public:
virtual	~McParamRandom();
static	McParamRandom* create(CSTR);
	int32_t optionType()const{return TP_PARAM_RANDOM;}
};

class McParamChunkList :public McParameter{
	McParamChunkList(CSTR);
public:
virtual	~McParamChunkList();
static	McParamChunkList* create(CSTR);
	int32_t optionType()const{return TP_PARAM_CHUNK_LIST;}
	DEC_HC_MLC(ChunkType);
};

class McParamRequestedHMACAlgorithm :public McParameter{
	McParamRequestedHMACAlgorithm(CSTR);
public:
virtual	~McParamRequestedHMACAlgorithm();
static	McParamRequestedHMACAlgorithm* create(CSTR);
	int32_t optionType()const{return TP_PARAM_HMAC_ALGO;}
	DEC_HC_MLC(Identifier);
};

class McParamPadding :public McParameter{
	McParamPadding(CSTR);
public:
virtual	~McParamPadding();
static	McParamPadding* create(CSTR);
	int32_t optionType()const{return TP_PARAM_PADDING;}
};

class McParamOutgoingSSNResetRequest :public McParameter{
	McParamOutgoingSSNResetRequest(CSTR);
public:
virtual	~McParamOutgoingSSNResetRequest();
static	McParamOutgoingSSNResetRequest* create(CSTR);
	int32_t optionType()const{return TP_PARAM_OSSN_RESET_REQUEST;}
	DEC_HC_MLC(StreamNumber);
};

class McParamIncomingSSNResetRequest :public McParameter{
	McParamIncomingSSNResetRequest(CSTR);
public:
virtual	~McParamIncomingSSNResetRequest();
static	McParamIncomingSSNResetRequest* create(CSTR);
	int32_t optionType()const{return TP_PARAM_ISSN_RESET_REQUEST;}
	DEC_HC_MLC(StreamNumber);
};

class McParamSSNResetRequest :public McParameter{
	McParamSSNResetRequest(CSTR);
public:
virtual	~McParamSSNResetRequest();
static	McParamSSNResetRequest* create(CSTR);
	int32_t optionType()const{return TP_PARAM_SSN_RESET_REQUEST;}
};

class McParamStreamResetResponse :public McParameter{
	McParamStreamResetResponse(CSTR);
public:
virtual	~McParamStreamResetResponse();
static	McParamStreamResetResponse* create(CSTR);
	int32_t optionType()const{return TP_PARAM_STREAM_RESET_RESPONSE;}
	DEC_HC_MLC(SendNextTSN);
	DEC_HC_MLC(RecvNextTSN);
};

class McParamAddStreams :public McParameter{
	McParamAddStreams(CSTR);
public:
virtual	~McParamAddStreams();
static	McParamAddStreams* create(CSTR);
	int32_t optionType()const{return TP_PARAM_ADD_STREAMS;}
};

//////////////////////////////////////////////////////////////////////////////
const int32_t TP_ERROR_INVALID_STREAM_INDNT	= 1;
const int32_t TP_ERROR_MISSING_MAND_PARAM	= 2;
const int32_t TP_ERROR_STALE_COOKIE_ERROR	= 3;
const int32_t TP_ERROR_OUT_OF_RESOURCE		= 4;
const int32_t TP_ERROR_UNRESOLV_ADDR		= 5;
const int32_t TP_ERROR_UNREG_CHUNK_TYPE		= 6;
const int32_t TP_ERROR_INVALID_MAND_PARAM	= 7;
const int32_t TP_ERROR_UNREG_PARAM		= 8;
const int32_t TP_ERROR_NO_USER_DATA		= 9;
const int32_t TP_ERROR_COOKIE_RECV_SHUTDOWN	= 10;
const int32_t TP_ERROR_RESTART_NEW_ADDRESS	= 11;
const int32_t TP_ERROR_USER_INITIATED_ABORT	= 12;
const int32_t TP_ERROR_PROTOCOL_VIOLATION	= 13;
const int32_t TP_ERROR_DEL_LAST_REMAIN_ADDR	= 0x00A0;
const int32_t TP_ERROR_REFUSED_RES_SHORTAGE	= 0x00A1;
const int32_t TP_ERROR_DEL_SOURCE_ADDR		= 0x00A2;
const int32_t TP_ERROR_ILLEGAL_ASCONF_ACK	= 0x00A3;
const int32_t TP_ERROR_NO_AUTHORIZATION		= 0x00A4;
const int32_t TP_ERROR_UNSUPPORTED_HMAC		= 0x0105;

class McErrorCause : public McOption{
protected:
	MmUint*	code_;
	void	code_member(MmUint* meta){code_=meta; member(meta);}
	MmUint*	length_;
	void	length_member(MmUint* meta){length_=meta; member(meta);}
	void	common_member();
	McErrorCause(CSTR);
public:
virtual	~McErrorCause();
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
	uint32_t alignment_requirement() const;
virtual uint32_t length_for_reverse(RControl&,ItPosition& at,OCTBUF& buf) const;
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
//HardCording action method
	DEC_HCGENE(Length);
};

class McErrorCauseANY :public McErrorCause {
	McErrorCauseANY(CSTR);
public:
virtual	~McErrorCauseANY();
static	McErrorCauseANY* create(CSTR);
};

class McErrorInvalidStreamIndentifier :public McErrorCause{
	McErrorInvalidStreamIndentifier(CSTR);
public:
virtual	~McErrorInvalidStreamIndentifier();
static	McErrorInvalidStreamIndentifier* create(CSTR);
	int32_t optionType()const{return TP_ERROR_INVALID_STREAM_INDNT;}
};

class McErrorMissingMandatoryParameter :public McErrorCause{
protected:
	MmUint*	num_;
	void	num_member(MmUint* meta){num_=meta; member(meta);}
	McErrorMissingMandatoryParameter(CSTR);
public:
virtual	~McErrorMissingMandatoryParameter();
static	McErrorMissingMandatoryParameter* create(CSTR);
	int32_t optionType()const{return TP_ERROR_MISSING_MAND_PARAM;}
	DEC_HC_MLC(NUM);
};

class McErrorStaleCookieError :public McErrorCause{
	McErrorStaleCookieError(CSTR);
public:
virtual	~McErrorStaleCookieError();
static	McErrorStaleCookieError* create(CSTR);
	int32_t optionType()const{return TP_ERROR_STALE_COOKIE_ERROR;}
};

class McErrorOutOfResource :public McErrorCause{
	McErrorOutOfResource(CSTR);
public:
virtual	~McErrorOutOfResource();
static	McErrorOutOfResource* create(CSTR);
	int32_t optionType()const{return TP_ERROR_OUT_OF_RESOURCE;}
};

class McErrorUnresolvableAddress :public McErrorCause{
	McErrorUnresolvableAddress(CSTR);
public:
virtual	~McErrorUnresolvableAddress();
static	McErrorUnresolvableAddress* create(CSTR);
	int32_t optionType()const{return TP_ERROR_UNRESOLV_ADDR;}
};

class McErrorUnrecognizedChunkType :public McErrorCause{
	McErrorUnrecognizedChunkType(CSTR);
public:
virtual	~McErrorUnrecognizedChunkType();
static	McErrorUnrecognizedChunkType* create(CSTR);
	int32_t optionType()const{return TP_ERROR_UNREG_CHUNK_TYPE;}
};

class McErrorInvalidMandatoryParameter :public McErrorCause{
	McErrorInvalidMandatoryParameter(CSTR);
public:
virtual	~McErrorInvalidMandatoryParameter();
static	McErrorInvalidMandatoryParameter* create(CSTR);
	int32_t optionType()const{return TP_ERROR_INVALID_MAND_PARAM;}
};

class McErrorUnrecognizedParameters :public McErrorCause{
	McErrorUnrecognizedParameters(CSTR);
public:
virtual	~McErrorUnrecognizedParameters();
static	McErrorUnrecognizedParameters* create(CSTR);
	int32_t optionType()const{return TP_ERROR_UNREG_PARAM;}
};

class McErrorNoUserData :public McErrorCause{
	McErrorNoUserData(CSTR);
public:
virtual	~McErrorNoUserData();
static	McErrorNoUserData* create(CSTR);
	int32_t optionType()const{return TP_ERROR_NO_USER_DATA;}
};

class McErrorCookieRecvShutdown :public McErrorCause{
	McErrorCookieRecvShutdown(CSTR);
public:
virtual	~McErrorCookieRecvShutdown();
static	McErrorCookieRecvShutdown* create(CSTR);
	int32_t optionType()const{return TP_ERROR_COOKIE_RECV_SHUTDOWN;}
};

class McErrorRestartWithNewAddresses :public McErrorCause{
	McErrorRestartWithNewAddresses(CSTR);
public:
virtual	~McErrorRestartWithNewAddresses();
static	McErrorRestartWithNewAddresses* create(CSTR);
	int32_t optionType()const{return TP_ERROR_RESTART_NEW_ADDRESS;}
};

class McErrorUserInitiatedAbort :public McErrorCause{
	McErrorUserInitiatedAbort(CSTR);
public:
virtual	~McErrorUserInitiatedAbort();
static	McErrorUserInitiatedAbort* create(CSTR);
	int32_t optionType()const{return TP_ERROR_USER_INITIATED_ABORT;}
};

class McErrorProtocolViolation :public McErrorCause{
	McErrorProtocolViolation(CSTR);
public:
virtual	~McErrorProtocolViolation();
static	McErrorProtocolViolation* create(CSTR);
	int32_t optionType()const{return TP_ERROR_PROTOCOL_VIOLATION;}
};

class McErrorDeleteLastRemainingIPAddress :public McErrorCause{
	McErrorDeleteLastRemainingIPAddress(CSTR);
public:
virtual	~McErrorDeleteLastRemainingIPAddress();
static	McErrorDeleteLastRemainingIPAddress* create(CSTR);
	int32_t optionType()const{return TP_ERROR_DEL_LAST_REMAIN_ADDR;}
};

class McErrorRefusedResourceShortage :public McErrorCause{
	McErrorRefusedResourceShortage(CSTR);
public:
virtual	~McErrorRefusedResourceShortage();
static	McErrorRefusedResourceShortage* create(CSTR);
	int32_t optionType()const{return TP_ERROR_REFUSED_RES_SHORTAGE;}
};

class McErrorDeleteSourceIPAddress :public McErrorCause{
	McErrorDeleteSourceIPAddress(CSTR);
public:
virtual	~McErrorDeleteSourceIPAddress();
static	McErrorDeleteSourceIPAddress* create(CSTR);
	int32_t optionType()const{return TP_ERROR_DEL_SOURCE_ADDR;}
};

class McErrorIllegalASCONFAck :public McErrorCause{
	McErrorIllegalASCONFAck(CSTR);
public:
virtual	~McErrorIllegalASCONFAck();
static	McErrorIllegalASCONFAck* create(CSTR);
	int32_t optionType()const{return TP_ERROR_ILLEGAL_ASCONF_ACK;}
};

class McErrorNoAuthorization :public McErrorCause{
	McErrorNoAuthorization(CSTR);
public:
virtual	~McErrorNoAuthorization();
static	McErrorNoAuthorization* create(CSTR);
	int32_t optionType()const{return TP_ERROR_NO_AUTHORIZATION;}
};

class McErrorUnsupportedHMACIdentifier :public McErrorCause{
	McErrorUnsupportedHMACIdentifier(CSTR);
public:
virtual	~McErrorUnsupportedHMACIdentifier();
static	McErrorUnsupportedHMACIdentifier* create(CSTR);
	int32_t optionType()const{return TP_ERROR_UNSUPPORTED_HMAC;}
};

#include "MmHeader.h"
//////////////////////////////////////////////////////////////////////////////
// chunk = xx (reference chunk(SCTP) on the McUpp_SCTP)
class MmChunk:public MmReference_More0 {
static	TypevsMcDict	dict_;  //chunkType(SCTP) vs McChunk_*
public:
	MmChunk(CSTR);
virtual	~MmChunk();
	int32_t token()const{return metaToken(tkn_option_ref_);}
	const TypevsMcDict* get_dict()const{return &dict_;}
static	void add(McChunk* mc);
static	void add_other(McChunk* mc);
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
virtual	uint32_t objectLength(const PObject* =0,const WObject* =0) const;
};

//////////////////////////////////////////////////////////////////////////////
// Param = xx (reference Param(SCTP Chunk) on the McChunk)
class MmParameter:public MmReference_More0 {
static	TypevsMcDict	dict_;
public:
	MmParameter(CSTR);
virtual	~MmParameter();
	int32_t token()const{return metaToken(tkn_option_ref_);}
	const TypevsMcDict* get_dict()const{return &dict_;}
static	void add(McParameter* mc);
static	void add_other(McParameter* mc);
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
};

//////////////////////////////////////////////////////////////////////////////
// Error = xx (reference Error(SCTP ERROR) on the McChunk)
class MmErrorCause:public MmReference_More0 {
static	TypevsMcDict	dict_;
public:
	MmErrorCause(CSTR);
virtual	~MmErrorCause();
	int32_t token()const{return metaToken(tkn_option_ref_);}
	const TypevsMcDict* get_dict()const{return &dict_;}
static	void add(McErrorCause* mc);
static	void add_other(McErrorCause* mc);
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
};

#endif
