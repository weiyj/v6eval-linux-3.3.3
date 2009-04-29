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
#include "McSCTP.h"
#include "MmSCTPChecksum.h"
#include "MmSCTPAuth.h"
#include "MmData.h"
#include "ItPosition.h"
#include "WObject.h"
#include "RObject.h"
#include "PControl.h"
#include "PvObject.h"
#include "PvOctets.h"

#include "PvAutoItem.h"
#include "PvAction.h"

#define UN(n)		PvNumber::unique(n)
#define MUST()		PvMUSTDEF::must()
#define	V6TN()		PvV6Addr::TN()
#define	V6NUT()		PvV6Addr::NUT()
#define EVALANY()	new PvANY()
#define EVALZERO()	new PvOctets(0, 0)
#define GENEHC(mc,cls,mem)	new PvHCgene(mc,(HCgenefunc)&cls::HCGENE(mem))
#define EVALHC(mc,cls,mem)	new PvHCeval(mc,(HCevalfunc)&cls::HCEVAL(mem))

#define DEF_EVALSKIP	true

#define DEF_ALIGNMENTT_SCTP	4
#define DEF_LENGTH_ELEM_SCTP	4

static inline uint32_t roundN(uint32_t num,uint32_t align) {
        return ((num + align - 1) / align) * align;
}

//////////////////////////////////////////////////////////////////////////////
#define SUPER	McUpper

McUpp_SCTP* McUpp_SCTP::instance_ = 0;
McTopHdr_SCTP* McUpp_SCTP::tophdr_ = 0;

McUpp_SCTP::McUpp_SCTP(CSTR key) : SUPER(key) {
	instance_ = this;
}

McUpp_SCTP::~McUpp_SCTP() {
	if(instance_ == this) instance_ = 0;
}

// COMPOSE/REVERSE
uint32_t McUpp_SCTP::length_for_reverse(
		RControl& c,ItPosition& at,OCTBUF& buf) const {
	return buf.remainLength(at.bytes());
}

RObject* McUpp_SCTP::reverse(RControl& c,
		RObject* r_parent,ItPosition& at,OCTBUF& buf) const {
	RObject* r_self = SUPER::reverse(c, r_parent, at, buf);
	if(!c.error()){
		Con_IPinfo* info = c.IPinfo();
		if(info)info->reverse_postUppChecksum(c, r_self);
	}
	return r_self;
}

bool McUpp_SCTP::generate(WControl& c,WObject* w_self,OCTBUF& buf) const {
	bool rtn = SUPER::generate(c, w_self, buf);
	if(!c.error()){
		Con_IPinfo* info = c.IPinfo();
		if(info) {
			info->generate_postSCTPAuth(c, buf, w_self);
			info->generate_postUppChecksum(c, buf, w_self);
		}
	}
	return rtn;
}

#undef SUPER

//----------------------------------------------------------------------------
#define SUPER	McHeader

McTopHdr_SCTP::McTopHdr_SCTP(CSTR key) : SUPER(key) {}
McTopHdr_SCTP::~McTopHdr_SCTP() {}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McOption

McChunk::McChunk(CSTR key):SUPER(key),type_(0),length_(0){}
McChunk::~McChunk(){}

// COMPOSE/REVERSE
uint32_t McChunk::length_for_reverse(RControl& c,
		ItPosition& at,OCTBUF& buf) const{
	if(!length_)return SUPER::length_for_reverse(c,at,buf);
	uint32_t length = length_->value(at,buf);
	length = (length == 0) ? 4 : length;
	if(buf.remainLength(at.bytes()) >= roundN(length, 4))
		length = roundN(length, 4);
	return length;
}

bool McChunk::HCGENE(Length)(WControl& cntr,WObject* wmem,OCTBUF& buf)const{
	WObject* wc = wmem->parent();	//chunk
	uint32_t reallen = wc->size().bytes();
	PvNumber def(reallen);
	return def.generate(cntr, wmem, buf);
}

bool McChunk::overwrite_DictType(
		RControl& c,ItPosition& at,OCTBUF& buf)const{
	if(c.DictType().finish())return false;	//Chunk DATA
	uint32_t limit = buf.remainLength(at.bytes());
	if(limit==0)return false;		//End of TCP Header
	//
	ItPosition tmpat=at;
	RObject* rtype = type_->reverse(c,0,tmpat,buf);
	if(!rtype)return false;			//Type field decode error
	//
	const PvNumber* pv = (const PvNumber*)rtype->pvalue();
	uint32_t typevalue = pv->value();
	c.DictType().type_Set(typevalue);	//self Type set
	delete rtype;
	return true;
}

uint32_t McChunk::alignment_requirement() const{
	return DEF_LENGTH_ELEM_SCTP;
}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McChunk

//----------------------------------------------------------------------------
McChunkAny::McChunkAny(CSTR key):SUPER(key){}
McChunkAny::~McChunkAny(){}

McChunkInit::McChunkInit(CSTR key):SUPER(key){}
McChunkInit::~McChunkInit(){}

McChunkInitAck::McChunkInitAck(CSTR key):SUPER(key){}
McChunkInitAck::~McChunkInitAck(){}

McChunkSack::McChunkSack(CSTR key):SUPER(key),gap_(0),dup_(0){}
McChunkSack::~McChunkSack(){}

uint32_t McChunkSack::HC_MLC(GAP)(const ItPosition &at, OCTBUF &buf) const {
	if(gap_)
		return(gap_->value(at, buf));
	else
		return(0);
}

uint32_t McChunkSack::HC_MLC(DUP)(const ItPosition &at, OCTBUF &buf) const {
	if(dup_)
		return(dup_->value(at, buf));
	else
		return(0);
}

McChunkHeartbeat::McChunkHeartbeat(CSTR key):SUPER(key){}
McChunkHeartbeat::~McChunkHeartbeat(){}

McChunkHeartbeatAck::McChunkHeartbeatAck(CSTR key):SUPER(key){}
McChunkHeartbeatAck::~McChunkHeartbeatAck(){}

McChunkData::McChunkData(CSTR key):SUPER(key){}
McChunkData::~McChunkData(){}

bool McChunkData::HCGENE(Length)(WControl& cntr,WObject* wmem,OCTBUF& buf)const{
	WObject* wc		= wmem->parent();	//chunk
	uint32_t reallen	= wc->size().bytes();
	PvNumber def(reallen);
	return def.generate(cntr, wmem, buf);
}

McChunkAbort::McChunkAbort(CSTR key):SUPER(key){}
McChunkAbort::~McChunkAbort(){}

McChunkShutdown::McChunkShutdown(CSTR key):SUPER(key){}
McChunkShutdown::~McChunkShutdown(){}

McChunkShutdownAck::McChunkShutdownAck(CSTR key):SUPER(key){}
McChunkShutdownAck::~McChunkShutdownAck(){}

McChunkError::McChunkError(CSTR key):SUPER(key){}
McChunkError::~McChunkError(){}

McChunkCookieEcho::McChunkCookieEcho(CSTR key):SUPER(key){}
McChunkCookieEcho::~McChunkCookieEcho(){}

McChunkCookieAck::McChunkCookieAck(CSTR key):SUPER(key){}
McChunkCookieAck::~McChunkCookieAck(){}

McChunkCongestionExperiencedReport::McChunkCongestionExperiencedReport(CSTR key):SUPER(key){}
McChunkCongestionExperiencedReport::~McChunkCongestionExperiencedReport(){}

McChunkCongestionWindowReport::McChunkCongestionWindowReport(CSTR key):SUPER(key){}
McChunkCongestionWindowReport::~McChunkCongestionWindowReport(){}

McChunkShutdownComplete::McChunkShutdownComplete(CSTR key):SUPER(key){}
McChunkShutdownComplete::~McChunkShutdownComplete(){}

McAuthenticationChunk::McAuthenticationChunk(CSTR key):SUPER(key){}
McAuthenticationChunk::~McAuthenticationChunk(){}

McChunkNRSack::McChunkNRSack(CSTR key):SUPER(key),gap_(0),nrgap_(0),dup_(0){}
McChunkNRSack::~McChunkNRSack(){}

McChunkForwardTSN::McChunkForwardTSN(CSTR key):SUPER(key){}
McChunkForwardTSN::~McChunkForwardTSN(){}

uint32_t McChunkForwardTSN::HC_MLC(Stream)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	if(length_) {
		len = length_->value(at,buf);
	}
	uint32_t count = (len - 8) / 4;
	return(count);
}

uint32_t McChunkForwardTSN::HC_MLC(Sequence)(const ItPosition &at, OCTBUF &buf) const {
	return(0);
}

McChunkAddressConfigurationChange::McChunkAddressConfigurationChange(CSTR key):SUPER(key){}
McChunkAddressConfigurationChange::~McChunkAddressConfigurationChange(){}

McAddressConfigurationAck::McAddressConfigurationAck(CSTR key):SUPER(key){}
McAddressConfigurationAck::~McAddressConfigurationAck(){}

McChunkPacketDrop::McChunkPacketDrop(CSTR key):SUPER(key){}
McChunkPacketDrop::~McChunkPacketDrop(){}

McChunkStreamReset::McChunkStreamReset(CSTR key):SUPER(key){}
McChunkStreamReset::~McChunkStreamReset(){}

McChunkPadding::McChunkPadding(CSTR key):SUPER(key){}
McChunkPadding::~McChunkPadding(){}

uint32_t McChunkNRSack::HC_MLC(GAP)(const ItPosition &at, OCTBUF &buf) const {
	if(gap_)
		return(gap_->value(at, buf));
	else
		return(0);
}

uint32_t McChunkNRSack::HC_MLC(NRGAP)(const ItPosition &at, OCTBUF &buf) const {
	if(nrgap_)
		return(nrgap_->value(at, buf));
	else
		return(0);
}

uint32_t McChunkNRSack::HC_MLC(DUP)(const ItPosition &at, OCTBUF &buf) const {
	if(dup_)
		return(dup_->value(at, buf));
	else
		return(0);
}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	MmReference_More0
MmChunk::MmChunk(CSTR key) : SUPER(key, true) {}
MmChunk::~MmChunk() {}
TypevsMcDict MmChunk::dict_;

void MmChunk::add(McChunk* mc) {
	dict_.add(mc->optionType(), mc);
}

void MmChunk::add_other(McChunk* mc) {
	dict_.add_other(mc);
}

// REVERSE
bool MmChunk::overwrite_DictType(RControl& c,ItPosition& at,OCTBUF& buf) const {
	McChunk* any = (McChunk*)dict_.find_other();
	return any->overwrite_DictType(c, at, buf);
}

uint32_t MmChunk::objectLength(const PObject* po, const WObject* w) const {
	uint32_t length = SUPER::objectLength(po,w);
	return roundN(length, 4);
}
#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McOption

McParameter::McParameter(CSTR key) : SUPER(key), type_(0), length_(0){}
McParameter::~McParameter(){}

// COMPOSE/REVERSE
uint32_t McParameter::length_for_reverse(RControl& c,
		ItPosition& at,OCTBUF& buf) const {
	if(!length_) return SUPER::length_for_reverse(c, at, buf);
	uint32_t valulen = length_->value(at,buf);
	valulen = (valulen == 0) ? 4 : valulen;
	if(buf.remainLength(at.bytes()) >= roundN(valulen, 4))
		valulen = roundN(valulen, 4);
	return valulen;
}

bool McParameter::HCGENE(Length)(WControl& cntr,WObject* wmem,OCTBUF& buf)const{
	WObject* wc = wmem->parent();	//chunk
	uint32_t reallen = wc->size().bytes();
	PvNumber def(reallen);
	return def.generate(cntr, wmem, buf);
}

bool McParameter::overwrite_DictType(
		RControl& c,ItPosition& at,OCTBUF& buf)const{
	if(c.DictType().finish())return false;	//Chunk DATA
	uint32_t limit = buf.remainLength(at.bytes());
	if(limit==0)return false;		//End of TCP Header
	//
	ItPosition tmpat=at;
	RObject* rtype = type_->reverse(c,0,tmpat,buf);
	if(!rtype)return false;			//Type field decode error
	//
	const PvNumber* pv = (const PvNumber*)rtype->pvalue();
	uint32_t typevalue = pv->value();
	c.DictType().type_Set(typevalue);	//self Type set
	delete rtype;
	return true;
}

uint32_t McParameter::alignment_requirement() const{
	return DEF_LENGTH_ELEM_SCTP;
}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McParameter

McParamANY::McParamANY(CSTR key):SUPER(key){}
McParamANY::~McParamANY(){}

McParamHeartbeatInfo::McParamHeartbeatInfo(CSTR key):SUPER(key){}
McParamHeartbeatInfo::~McParamHeartbeatInfo(){}

McParamIPv4Address::McParamIPv4Address(CSTR key):SUPER(key){}
McParamIPv4Address::~McParamIPv4Address(){}

McParamIPv6Address::McParamIPv6Address(CSTR key):SUPER(key){}
McParamIPv6Address::~McParamIPv6Address(){}

McParamStaleCookie::McParamStaleCookie(CSTR key):SUPER(key){}
McParamStaleCookie::~McParamStaleCookie(){}

McParamUnrecognizedParameters::McParamUnrecognizedParameters(CSTR key):SUPER(key){}
McParamUnrecognizedParameters::~McParamUnrecognizedParameters(){}

McParamHostNameAddress::McParamHostNameAddress(CSTR key):SUPER(key){}
McParamHostNameAddress::~McParamHostNameAddress(){}

McParamCookiePreservative::McParamCookiePreservative(CSTR key):SUPER(key){}
McParamCookiePreservative::~McParamCookiePreservative(){}

McParamSupportAddress::McParamSupportAddress(CSTR key):SUPER(key){}
McParamSupportAddress::~McParamSupportAddress(){}

uint32_t McParamSupportAddress::HC_MLC(AddrType)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	if(length_) {
		len = length_->value(at,buf);
	}
	uint32_t count = (len - 4) / 2;
	return(count);
}

McParamENCCapable::McParamENCCapable(CSTR key):SUPER(key){}
McParamENCCapable::~McParamENCCapable(){}

McParamForwardTSN::McParamForwardTSN(CSTR key):SUPER(key){}
McParamForwardTSN::~McParamForwardTSN(){}

McParamAdaptationLayerIndication::McParamAdaptationLayerIndication(CSTR key):SUPER(key){}
McParamAdaptationLayerIndication::~McParamAdaptationLayerIndication(){}

McParamSetPrimaryAddress::McParamSetPrimaryAddress(CSTR key):SUPER(key){}
McParamSetPrimaryAddress::~McParamSetPrimaryAddress(){}

McParamSupportedExtensions::McParamSupportedExtensions(CSTR key):SUPER(key){}
McParamSupportedExtensions::~McParamSupportedExtensions(){}

uint32_t McParamSupportedExtensions::HC_MLC(ChunkType)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	if(length_) {
		len = length_->value(at,buf);
	}
	return(len - 4);
}

McParamAddIPAddress::McParamAddIPAddress(CSTR key):SUPER(key){}
McParamAddIPAddress::~McParamAddIPAddress(){}

McParamDeleteIPAddress::McParamDeleteIPAddress(CSTR key):SUPER(key){}
McParamDeleteIPAddress::~McParamDeleteIPAddress(){}

McParamErrorCauseIndication::McParamErrorCauseIndication(CSTR key):SUPER(key){}
McParamErrorCauseIndication::~McParamErrorCauseIndication(){}

McParamSuccessIndication::McParamSuccessIndication(CSTR key):SUPER(key){}
McParamSuccessIndication::~McParamSuccessIndication(){}

McParamRandom::McParamRandom(CSTR key):SUPER(key){}
McParamRandom::~McParamRandom(){}

McParamChunkList::McParamChunkList(CSTR key):SUPER(key){}
McParamChunkList::~McParamChunkList(){}

uint32_t McParamChunkList::HC_MLC(ChunkType)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	if(length_) {
		len = length_->value(at,buf);
	}
	return(len - 4);
}

McParamRequestedHMACAlgorithm::McParamRequestedHMACAlgorithm(CSTR key):SUPER(key){}
McParamRequestedHMACAlgorithm::~McParamRequestedHMACAlgorithm(){}

uint32_t McParamRequestedHMACAlgorithm::HC_MLC(Identifier)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	if(length_) {
		len = length_->value(at,buf);
	}
	return((len - 4) / 2);
}

McParamPadding::McParamPadding(CSTR key):SUPER(key){}
McParamPadding::~McParamPadding(){}

McParamOutgoingSSNResetRequest::McParamOutgoingSSNResetRequest(CSTR key):SUPER(key){}
McParamOutgoingSSNResetRequest::~McParamOutgoingSSNResetRequest(){}

uint32_t McParamOutgoingSSNResetRequest::HC_MLC(StreamNumber)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	if(length_) {
		len = length_->value(at,buf);
	}
	return((len - 16) / 2);
}

McParamIncomingSSNResetRequest::McParamIncomingSSNResetRequest(CSTR key):SUPER(key){}
McParamIncomingSSNResetRequest::~McParamIncomingSSNResetRequest(){}

uint32_t McParamIncomingSSNResetRequest::HC_MLC(StreamNumber)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	if(length_) {
		len = length_->value(at,buf);
	}
	return((len - 8) / 2);
}

McParamSSNResetRequest::McParamSSNResetRequest(CSTR key):SUPER(key){}
McParamSSNResetRequest::~McParamSSNResetRequest(){}

McParamStreamResetResponse::McParamStreamResetResponse(CSTR key):SUPER(key){}
McParamStreamResetResponse::~McParamStreamResetResponse(){}

uint32_t McParamStreamResetResponse::HC_MLC(SendNextTSN)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	if(length_) {
		len = length_->value(at,buf);
	}
	return((len >= 16) ? 1 : 0);
}

uint32_t McParamStreamResetResponse::HC_MLC(RecvNextTSN)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	if(length_) {
		len = length_->value(at,buf);
	}
	return((len >= 20) ? 1 : 0);
}

McParamAddStreams::McParamAddStreams(CSTR key):SUPER(key){}
McParamAddStreams::~McParamAddStreams(){}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
MmParameter::MmParameter(CSTR key) : MmReference_More0(key, true) {}
MmParameter::~MmParameter() {}

TypevsMcDict MmParameter::dict_;

void MmParameter::add(McParameter* mc){
	dict_.add(mc->optionType(), mc);
}

void MmParameter::add_other(McParameter* mc) {
	dict_.add_other(mc);
}

// REVERSE
bool MmParameter::overwrite_DictType(
		RControl& c,ItPosition& at,OCTBUF& buf)const{
	McParameter* any = (McParameter*)dict_.find_other();
	return any->overwrite_DictType(c, at, buf);
}

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McOption

McErrorCause::McErrorCause(CSTR key) : SUPER(key), code_(0), length_(0){}
McErrorCause::~McErrorCause(){}

// COMPOSE/REVERSE
uint32_t McErrorCause::length_for_reverse(RControl& c,
		ItPosition& at,OCTBUF& buf) const {
	if(!length_) return SUPER::length_for_reverse(c, at, buf);
	uint32_t valulen = length_->value(at,buf);
	if(buf.remainLength(at.bytes()) >= roundN(valulen, 4))
		valulen = roundN(valulen, 4);
	return valulen;
}

bool McErrorCause::HCGENE(Length)(WControl& cntr,WObject* wmem,OCTBUF& buf)const{
	WObject* wc = wmem->parent();	//chunk
	uint32_t reallen = wc->size().bytes();
	PvNumber def(reallen);
	return def.generate(cntr, wmem, buf);
}

bool McErrorCause::overwrite_DictType(
		RControl& c,ItPosition& at,OCTBUF& buf)const{
	if(buf.remainLength(at.bytes())) {
		ItPosition tmpat=at;
		RObject* rcode = code_->reverse(c,0,tmpat,buf);
		if(!rcode)return false;			//Type field decode error

		const PvNumber* pv = (const PvNumber*)rcode->pvalue();
		uint32_t codevalue = pv->value();
		c.DictType().type_Set(codevalue);	//self Type set
		delete rcode;
		return true;
	}
	return false;
}

uint32_t McErrorCause::alignment_requirement() const{
	return DEF_LENGTH_ELEM_SCTP;
}

#undef SUPER

#define SUPER	McErrorCause

McErrorCauseANY::McErrorCauseANY(CSTR key):SUPER(key){}
McErrorCauseANY::~McErrorCauseANY(){}

McErrorInvalidStreamIndentifier::McErrorInvalidStreamIndentifier(CSTR key):SUPER(key){}
McErrorInvalidStreamIndentifier::~McErrorInvalidStreamIndentifier(){}

McErrorMissingMandatoryParameter::McErrorMissingMandatoryParameter(CSTR key):SUPER(key){}
McErrorMissingMandatoryParameter::~McErrorMissingMandatoryParameter(){}

uint32_t McErrorMissingMandatoryParameter::HC_MLC(NUM)(const ItPosition &at, OCTBUF &buf) const {
	if(num_)
		return(num_->value(at, buf));
	else
		return(0);
}

McErrorStaleCookieError::McErrorStaleCookieError(CSTR key):SUPER(key){}
McErrorStaleCookieError::~McErrorStaleCookieError(){}

McErrorOutOfResource::McErrorOutOfResource(CSTR key):SUPER(key){}
McErrorOutOfResource::~McErrorOutOfResource(){}

McErrorUnresolvableAddress::McErrorUnresolvableAddress(CSTR key):SUPER(key){}
McErrorUnresolvableAddress::~McErrorUnresolvableAddress(){}

McErrorUnrecognizedChunkType::McErrorUnrecognizedChunkType(CSTR key):SUPER(key){}
McErrorUnrecognizedChunkType::~McErrorUnrecognizedChunkType(){}

McErrorInvalidMandatoryParameter::McErrorInvalidMandatoryParameter(CSTR key):SUPER(key){}
McErrorInvalidMandatoryParameter::~McErrorInvalidMandatoryParameter(){}

McErrorUnrecognizedParameters::McErrorUnrecognizedParameters(CSTR key):SUPER(key){}
McErrorUnrecognizedParameters::~McErrorUnrecognizedParameters(){}

McErrorNoUserData::McErrorNoUserData(CSTR key):SUPER(key){}
McErrorNoUserData::~McErrorNoUserData(){}

McErrorCookieRecvShutdown::McErrorCookieRecvShutdown(CSTR key):SUPER(key){}
McErrorCookieRecvShutdown::~McErrorCookieRecvShutdown(){}

McErrorRestartWithNewAddresses::McErrorRestartWithNewAddresses(CSTR key):SUPER(key){}
McErrorRestartWithNewAddresses::~McErrorRestartWithNewAddresses(){}

McErrorUserInitiatedAbort::McErrorUserInitiatedAbort(CSTR key):SUPER(key){}
McErrorUserInitiatedAbort::~McErrorUserInitiatedAbort(){}

McErrorProtocolViolation::McErrorProtocolViolation(CSTR key):SUPER(key){}
McErrorProtocolViolation::~McErrorProtocolViolation(){}

McErrorDeleteLastRemainingIPAddress::McErrorDeleteLastRemainingIPAddress(CSTR key):SUPER(key){}
McErrorDeleteLastRemainingIPAddress::~McErrorDeleteLastRemainingIPAddress(){}

McErrorRefusedResourceShortage::McErrorRefusedResourceShortage(CSTR key):SUPER(key){}
McErrorRefusedResourceShortage::~McErrorRefusedResourceShortage(){}

McErrorDeleteSourceIPAddress::McErrorDeleteSourceIPAddress(CSTR key):SUPER(key){}
McErrorDeleteSourceIPAddress::~McErrorDeleteSourceIPAddress(){}

McErrorIllegalASCONFAck::McErrorIllegalASCONFAck(CSTR key):SUPER(key){}
McErrorIllegalASCONFAck::~McErrorIllegalASCONFAck(){}

McErrorNoAuthorization::McErrorNoAuthorization(CSTR key):SUPER(key){}
McErrorNoAuthorization::~McErrorNoAuthorization(){}

McErrorUnsupportedHMACIdentifier::McErrorUnsupportedHMACIdentifier(CSTR key):SUPER(key){}
McErrorUnsupportedHMACIdentifier::~McErrorUnsupportedHMACIdentifier(){}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
MmErrorCause::MmErrorCause(CSTR key) : MmReference_More0(key, true) {}
MmErrorCause::~MmErrorCause() {}

TypevsMcDict MmErrorCause::dict_;

void MmErrorCause::add(McErrorCause* mc){
	dict_.add(mc->optionType(), mc);
}

void MmErrorCause::add_other(McErrorCause* mc) {
	dict_.add_other(mc);
}

// REVERSE
bool MmErrorCause::overwrite_DictType(
		RControl& c,ItPosition& at,OCTBUF& buf)const{
	McErrorCause* any = (McErrorCause*)dict_.find_other();
	return any->overwrite_DictType(c, at, buf);
}

//////////////////////////////////////////////////////////////////////////////
McUpp_SCTP* McUpp_SCTP::create(CSTR key,CSTR tophdrkey){
	addCompound(tophdr_ = McTopHdr_SCTP::create(tophdrkey));
	McUpp_SCTP* mc = new McUpp_SCTP(key);

	mc->member(new MmTopHdr("header", tophdr_));
	mc->member(new MmChunk("chunk"));

	MmUpper_onIP::add(mc);
	return mc;
}

McTopHdr_SCTP* McTopHdr_SCTP::create(CSTR key){
	McTopHdr_SCTP* mc = new McTopHdr_SCTP(key);

	mc->member(new MmUint("SourcePort",	16, MUST(), MUST()));
	mc->member(new MmUint("DestinationPort",16, MUST(), MUST()));
	mc->member(new MmUint("VerificationTag",32, UN(0), UN(0)));
	mc->member(new MmSCTPChecksum("Checksum",	32));

	// no dict
	return mc;
}

//////////////////////////////////////////////////////////////////////////////
void McChunk::common_member(){
	int32_t type = optionType();
	type_member(new MmUint( "Type",	8, UN(type), UN(type)));
	member(new MmUint( "Flags",	8, UN(0), UN(0)));
	length_member(new MmUint( "Length", 16,
		GENEHC(this, McChunk, Length), EVALANY()));
}

McChunkAny* McChunkAny::create(CSTR key){
	McChunkAny* mc = new McChunkAny(key);

	mc->common_member();
	mc->member(new MmData("Data"));

	MmChunk::add_other(mc);
	return mc;
}

McChunkInit* McChunkInit::create(CSTR key){
	McChunkInit* mc = new McChunkInit(key);

	mc->common_member();
	mc->member(new MmUint("InitiateTag",	32, UN(0), UN(0)));
	mc->member(new MmUint("AdvRecvWindow",	32, UN(0), UN(0)));
	mc->member(new MmUint("NumOfOutbound",	16, UN(0), UN(0)));
	mc->member(new MmUint("NumOfInbound",	16, UN(0), UN(0)));
	mc->member(new MmUint("TSN",		32, UN(0), UN(0)));
	mc->member(new MmParameter("Param"));

	MmChunk::add(mc);
	return mc;
}

McChunkInitAck* McChunkInitAck::create(CSTR key){
	McChunkInitAck* mc = new McChunkInitAck(key);

	mc->common_member();
	mc->member(new MmUint("InitiateTag",	32, UN(0), UN(0)));
	mc->member(new MmUint("AdvRecvWindow",	32, UN(0), UN(0)));
	mc->member(new MmUint("NumOfOutbound",	16, UN(0), UN(0)));
	mc->member(new MmUint("NumOfInbound",	16, UN(0), UN(0)));
	mc->member(new MmUint("TSN",		32, UN(0), UN(0)));
	mc->member(new MmParameter("Param"));

	MmChunk::add(mc);
	return mc;
}

McChunkSack* McChunkSack::create(CSTR key){
	McChunkSack* mc = new McChunkSack(key);

	mc->common_member();
	mc->member(new MmUint("ACK",	32, UN(0), UN(0)));
	mc->member(new MmUint("AdvRecvWindow",	32, UN(0), UN(0)));
	mc->gap_member(new MmUint("NumOfGapAck",	16, UN(0), UN(0)));
	mc->dup_member(new MmUint("NumOfDupTSN",	16, UN(0), UN(0)));
	mc->member(
		new MmMultipleTwo(
			new MmUint("GapAckBlockStart", 16, MUST(), MUST()),
			new MmUint("GapAckBlockEnd", 16, MUST(), MUST()),
			(METH_HC_MLC)&McChunkSack::HC_MLC(GAP)
		)
	);
	mc->member(
		new MmMultiple(
			new MmUint("DupTSN", 32, MUST(), MUST()),
			(METH_HC_MLC)&McChunkSack::HC_MLC(DUP)
		)
	);

	MmChunk::add(mc);
	return mc;
}

McChunkHeartbeat* McChunkHeartbeat::create(CSTR key){
	McChunkHeartbeat* mc = new McChunkHeartbeat(key);

	mc->common_member();
	mc->member(new MmParameter("Information"));

	MmChunk::add(mc);
	return mc;
}

McChunkHeartbeatAck* McChunkHeartbeatAck::create(CSTR key){
	McChunkHeartbeatAck* mc = new McChunkHeartbeatAck(key);

	mc->common_member();
	mc->member(new MmParameter("Information"));

	MmChunk::add(mc);
	return mc;
}

McChunkData* McChunkData::create(CSTR key){
	McChunkData* mc = new McChunkData(key);

	int32_t type = mc->optionType();
	mc->type_member(new MmUint("Type", 	8, UN(type), UN(type)));
	mc->member(new MmUint("Reserved",	4, UN(0), UN(0)));
	mc->member(new MmUint("IFlag",		1, UN(0), UN(0)));
	mc->member(new MmUint("UFlag", 		1, UN(0), UN(0)));
	mc->member(new MmUint("BFlag", 		1, UN(1), UN(1)));
	mc->member(new MmUint("EFlag", 		1, UN(1), UN(1)));
	mc->length_member(new MmUint("Length", 	16,
		GENEHC(mc, McChunkData, Length), EVALANY()));
	mc->member(new MmUint("TSN", 		32, UN(0), UN(0)));
	mc->member(new MmUint("Identifier", 	16, UN(0), UN(0)));
	mc->member(new MmUint("SequenceNumber",	16, UN(0), UN(0)));
	mc->member(new MmUint("Protocol",	32, UN(0), UN(0)));
	mc->member(new MmPayload("payload"));

	MmChunk::add(mc);
	return mc;
}

McChunkAbort* McChunkAbort::create(CSTR key){
	McChunkAbort* mc = new McChunkAbort(key);

	int32_t type = mc->optionType();
	mc->type_member(new MmUint("Type",	8, UN(type), UN(type)));
	mc->member(new MmUint("Reserved",	7, UN(0), UN(0)));
	mc->member(new MmUint("TFlag",		1, UN(0), UN(0)));
	mc->length_member(new MmUint("Length",	16, GENEHC(mc, McChunk, Length), EVALANY()));
	mc->member(new MmErrorCause("Error"));

	MmChunk::add(mc);
	return mc;
}

McChunkShutdown* McChunkShutdown::create(CSTR key){
	McChunkShutdown* mc = new McChunkShutdown(key);

	mc->common_member();
	mc->member(new MmUint("TSN",	32, UN(0), UN(0)));

	MmChunk::add(mc);
	return mc;
}

McChunkShutdownAck* McChunkShutdownAck::create(CSTR key){
	McChunkShutdownAck* mc = new McChunkShutdownAck(key);

	mc->common_member();

	MmChunk::add(mc);
	return mc;
}

McChunkError* McChunkError::create(CSTR key){
	McChunkError* mc = new McChunkError(key);

	mc->common_member();
	mc->member(new MmErrorCause("Error"));

	MmChunk::add(mc);
	return mc;
}

McChunkCookieEcho* McChunkCookieEcho::create(CSTR key){
	McChunkCookieEcho* mc = new McChunkCookieEcho(key);

	mc->common_member();
	mc->member(new MmVarOctets("Cookie"));

	MmChunk::add(mc);
	return mc;
}

McChunkCookieAck* McChunkCookieAck::create(CSTR key){
	McChunkCookieAck* mc = new McChunkCookieAck(key);

	mc->common_member();

	MmChunk::add(mc);
	return mc;
}

McChunkCongestionExperiencedReport* McChunkCongestionExperiencedReport::create(CSTR key){
	McChunkCongestionExperiencedReport* mc = new McChunkCongestionExperiencedReport(key);

	mc->common_member();
	mc->member(new MmUint("LowestTSNNumber", 32, UN(0), UN(0)));

	MmChunk::add(mc);
	return mc;
}

McChunkCongestionWindowReport* McChunkCongestionWindowReport::create(CSTR key){
	McChunkCongestionWindowReport* mc = new McChunkCongestionWindowReport(key);

	mc->common_member();
	mc->member(new MmUint("LowestTSNNumber", 32, UN(0), UN(0)));

	MmChunk::add(mc);
	return mc;
}

McChunkShutdownComplete* McChunkShutdownComplete::create(CSTR key){
	McChunkShutdownComplete* mc = new McChunkShutdownComplete(key);

	int32_t type = mc->optionType();
	mc->type_member(new MmUint("Type",	8, UN(type), UN(type)));
	mc->member(new MmUint("Reserved",	7, UN(0), UN(0)));
	mc->member(new MmUint("TFlag",		1, UN(0), UN(0)));
	mc->length_member(new MmUint("Length",	16, GENEHC(mc, McChunk, Length), EVALANY()));

	MmChunk::add(mc);
	return mc;
}

McAuthenticationChunk* McAuthenticationChunk::create(CSTR key){
	McAuthenticationChunk* mc = new McAuthenticationChunk(key);

	mc->common_member();
	mc->member(new MmUint("SharedKeyIdentifier", 16, UN(0), UN(0)));
	mc->member(new MmUint("HMACIdentifier", 16, UN(0), UN(0)));
	mc->member(new MmSCTPAuth("HMAC"));

	MmChunk::add(mc);
	return mc;
}

McChunkNRSack* McChunkNRSack::create(CSTR key){
	McChunkNRSack* mc = new McChunkNRSack(key);
	int32_t type = mc->optionType();

	mc->type_member(new MmUint("Type",	8, UN(type), UN(type)));
	mc->member(new MmUint("Reserved",	6, UN(0), UN(0)));
	mc->member(new MmUint("AFlag",		1, UN(0), UN(0)));
	mc->member(new MmUint("Reserved",	1, UN(0), UN(0)));
	mc->length_member(new MmUint("Length",	16, GENEHC(mc, McChunk, Length), EVALANY()));

	mc->member(new MmUint("ACK",	32, UN(0), UN(0)));
	mc->member(new MmUint("AdvRecvWindow",	32, UN(0), UN(0)));
	mc->gap_member(new MmUint("NumOfGapAck",	16, UN(0), UN(0)));
	mc->nrgap_member(new MmUint("NumOfNRGapAck",	16, UN(0), UN(0)));
	mc->dup_member(new MmUint("NumOfDupTSN",	16, UN(0), UN(0)));
	mc->dup_member(new MmUint("Reserved",		16, UN(0), UN(0)));
	mc->member(
		new MmMultipleTwo(
			new MmUint("GapAckBlockStart", 16, MUST(), MUST()),
			new MmUint("GapAckBlockEnd", 16, MUST(), MUST()),
			(METH_HC_MLC)&McChunkSack::HC_MLC(GAP)
		)
	);
	mc->member(
		new MmMultipleTwo(
			new MmUint("NRGapAckBlockStart", 16, MUST(), MUST()),
			new MmUint("NRGapAckBlockEnd", 16, MUST(), MUST()),
			(METH_HC_MLC)&McChunkSack::HC_MLC(GAP)
		)
	);
	mc->member(
		new MmMultiple(
			new MmUint("DupTSN", 32, MUST(), MUST()),
			(METH_HC_MLC)&McChunkSack::HC_MLC(DUP)
		)
	);

	MmChunk::add(mc);
	return mc;
}

McChunkForwardTSN* McChunkForwardTSN::create(CSTR key){
	McChunkForwardTSN* mc = new McChunkForwardTSN(key);

	mc->common_member();
	mc->member(new MmUint("NewTSN",	32, UN(0), UN(0)));
	mc->member(
		new MmMultipleTwo(
			new MmUint("Stream", 16, MUST(), MUST()),
			new MmUint("StreamSequence", 16, MUST(), MUST()),
			(METH_HC_MLC)&McChunkForwardTSN::HC_MLC(Stream)
		)
	);

	MmChunk::add(mc);
	return mc;
}

McChunkAddressConfigurationChange* McChunkAddressConfigurationChange::create(CSTR key){
	McChunkAddressConfigurationChange* mc = new McChunkAddressConfigurationChange(key);

	mc->common_member();
	mc->member(new MmUint("SerialNumber",	32, UN(0), UN(0)));
	mc->member(new MmParameter("Param"));

	MmChunk::add(mc);
	return mc;
}

McAddressConfigurationAck* McAddressConfigurationAck::create(CSTR key){
	McAddressConfigurationAck* mc = new McAddressConfigurationAck(key);

	mc->common_member();
	mc->member(new MmUint("SerialNumber",	32, UN(0), UN(0)));
	mc->member(new MmParameter("Param"));

	MmChunk::add(mc);
	return mc;
}

McChunkPacketDrop* McChunkPacketDrop::create(CSTR key){
	McChunkPacketDrop* mc = new McChunkPacketDrop(key);
	int32_t type = mc->optionType();

	mc->type_member(new MmUint("Type",	8, UN(type), UN(type)));
	mc->member(new MmUint("Reserved",	4, UN(0), UN(0)));
	mc->member(new MmUint("CFlag",		1, UN(0), UN(0)));
	mc->member(new MmUint("TFlag",		1, UN(0), UN(0)));
	mc->member(new MmUint("BFlag",		1, UN(0), UN(0)));
	mc->member(new MmUint("MFlag",		1, UN(0), UN(0)));
	mc->length_member(new MmUint("Length",	16, GENEHC(mc, McChunk, Length), EVALANY()));

	mc->member(new MmUint("LinkBandwidth",	32, UN(0), UN(0)));
	mc->member(new MmUint("SizeOfData",	32, UN(0), UN(0)));
	mc->member(new MmUint("TruncatedLength",16, UN(0), UN(0)));
	mc->member(new MmUint("Reserved",	16, UN(0), UN(0)));
	mc->member(new MmData("DroppedPacket"));

	MmChunk::add(mc);
	return mc;
}

McChunkStreamReset* McChunkStreamReset::create(CSTR key){
	McChunkStreamReset* mc = new McChunkStreamReset(key);

	mc->common_member();
	mc->member(new MmParameter("Param"));

	MmChunk::add(mc);
	return mc;
}

McChunkPadding* McChunkPadding::create(CSTR key){
	McChunkPadding* mc = new McChunkPadding(key);

	mc->common_member();
	mc->member(new MmData("Padding"));

	MmChunk::add(mc);
	return mc;
}

//////////////////////////////////////////////////////////////////////////////
void McParameter::common_member(){
	int32_t type = optionType();
	type_member(new MmUint( "Type",		16, UN(type),UN(type)));
	length_member(new MmUint( "Length", 	16, GENEHC(this,McParameter,Length), EVALANY()));
}

McParamANY* McParamANY::create(CSTR key){
	McParamANY* mc = new McParamANY(key);

	mc->common_member();
	mc->member(new MmData("Data"));

	MmParameter::add_other(mc);
	return mc;
}

McParamHeartbeatInfo* McParamHeartbeatInfo::create(CSTR key){
	McParamHeartbeatInfo* mc = new McParamHeartbeatInfo(key);

	mc->common_member();
	mc->member(new MmData("Data"));

	MmParameter::add(mc);
	return mc;
}

McParamIPv4Address* McParamIPv4Address::create(CSTR key){
	McParamIPv4Address* mc = new McParamIPv4Address(key);
	mc->common_member();
	mc->member(new MmV4Addr("Address", MUST(),MUST()));

	MmParameter::add(mc);
	return mc;
}

McParamIPv6Address* McParamIPv6Address::create(CSTR key){
	McParamIPv6Address* mc = new McParamIPv6Address(key);

	mc->common_member();
	mc->member(new MmV6Addr( "Address", V6TN(), V6NUT()));

	MmParameter::add(mc);
	return mc;
}

McParamStaleCookie* McParamStaleCookie::create(CSTR key){
	McParamStaleCookie* mc = new McParamStaleCookie(key);

	mc->common_member();
	mc->member(new MmVarOctets("Cookie"));

	MmParameter::add(mc);
	return mc;
}

McParamUnrecognizedParameters* McParamUnrecognizedParameters::create(CSTR key){
	McParamUnrecognizedParameters* mc = new McParamUnrecognizedParameters(key);

	mc->common_member();
	mc->member(new MmParameter("Parameters"));

	MmParameter::add(mc);
	return mc;
}

McParamHostNameAddress* McParamHostNameAddress::create(CSTR key){
	McParamHostNameAddress* mc = new McParamHostNameAddress(key);
	mc->common_member();
	mc->member(new MmAsciiString("HostName", 0, EVALZERO()));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmParameter::add(mc);
	return mc;
}

McParamCookiePreservative* McParamCookiePreservative::create(CSTR key){
	McParamCookiePreservative* mc = new McParamCookiePreservative(key);

	mc->common_member();
	mc->member(new MmUint("CookieLife", 32, UN(0), UN(0)));

	MmParameter::add(mc);
	return mc;
}

McParamSupportAddress* McParamSupportAddress::create(CSTR key){
	McParamSupportAddress* mc = new McParamSupportAddress(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("AddrType", 16, MUST(), MUST()),
			(METH_HC_MLC)&McParamSupportAddress::HC_MLC(AddrType)
		)
	);
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmParameter::add(mc);
	return mc;
}

McParamENCCapable* McParamENCCapable::create(CSTR key){
	McParamENCCapable* mc = new McParamENCCapable(key);

	mc->common_member();

	MmParameter::add(mc);
	return mc;
}

McParamForwardTSN* McParamForwardTSN::create(CSTR key){
	McParamForwardTSN* mc = new McParamForwardTSN(key);

	mc->common_member();

	MmParameter::add(mc);
	return mc;
}

McParamAdaptationLayerIndication* McParamAdaptationLayerIndication::create(CSTR key){
	McParamAdaptationLayerIndication* mc = new McParamAdaptationLayerIndication(key);

	mc->common_member();
	mc->member(new MmUint("Indication", 32, UN(0), UN(0)));

	MmParameter::add(mc);
	return mc;
}

McParamSetPrimaryAddress* McParamSetPrimaryAddress::create(CSTR key){
	McParamSetPrimaryAddress* mc = new McParamSetPrimaryAddress(key);

	mc->common_member();
	mc->member(new MmUint("RequestID", 32, UN(0), UN(0)));
	mc->member(new MmParameter("Address"));

	MmParameter::add(mc);
	return mc;
}

McParamSupportedExtensions* McParamSupportedExtensions::create(CSTR key){
	McParamSupportedExtensions* mc = new McParamSupportedExtensions(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("ChunkType", 8, MUST(), MUST()),
			(METH_HC_MLC)&McParamSupportedExtensions::HC_MLC(ChunkType)
		)
	);
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmParameter::add(mc);
	return mc;
}

McParamAddIPAddress* McParamAddIPAddress::create(CSTR key){
	McParamAddIPAddress* mc = new McParamAddIPAddress(key);

	mc->common_member();
	mc->member(new MmUint("RequestID", 32, UN(0), UN(0)));
	mc->member(new MmParameter("Address"));

	MmParameter::add(mc);
	return mc;
}

McParamDeleteIPAddress* McParamDeleteIPAddress::create(CSTR key){
	McParamDeleteIPAddress* mc = new McParamDeleteIPAddress(key);

	mc->common_member();
	mc->member(new MmUint("RequestID", 32, UN(0), UN(0)));
	mc->member(new MmParameter("Address"));

	MmParameter::add(mc);
	return mc;
}

McParamErrorCauseIndication* McParamErrorCauseIndication::create(CSTR key){
	McParamErrorCauseIndication* mc = new McParamErrorCauseIndication(key);

	mc->common_member();
	mc->member(new MmUint("RequestID", 32, UN(0), UN(0)));
	mc->member(new MmErrorCause("Error"));

	MmParameter::add(mc);
	return mc;
}

McParamSuccessIndication* McParamSuccessIndication::create(CSTR key){
	McParamSuccessIndication* mc = new McParamSuccessIndication(key);

	mc->common_member();
	mc->member(new MmUint("RequestID", 32, UN(0), UN(0)));

	MmParameter::add(mc);
	return mc;
}

McParamRandom* McParamRandom::create(CSTR key){
	McParamRandom* mc = new McParamRandom(key);

	mc->common_member();
	mc->member(new MmVarOctets("RandomNumber"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmParameter::add(mc);
	return mc;
}

McParamChunkList* McParamChunkList::create(CSTR key){
	McParamChunkList* mc = new McParamChunkList(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("ChunkType", 8, MUST(), MUST()),
			(METH_HC_MLC)&McParamChunkList::HC_MLC(ChunkType)
		)
	);
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmParameter::add(mc);
	return mc;
}

McParamRequestedHMACAlgorithm* McParamRequestedHMACAlgorithm::create(CSTR key){
	McParamRequestedHMACAlgorithm* mc = new McParamRequestedHMACAlgorithm(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("HMACIdentifier", 16, MUST(), MUST()),
			(METH_HC_MLC)&McParamRequestedHMACAlgorithm::HC_MLC(Identifier)
		)
	);
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmParameter::add(mc);
	return mc;
}

McParamPadding* McParamPadding::create(CSTR key){
	McParamPadding* mc = new McParamPadding(key);

	mc->common_member();
	mc->member(new MmData("Padding"));

	MmParameter::add(mc);
	return mc;
}

McParamOutgoingSSNResetRequest* McParamOutgoingSSNResetRequest::create(CSTR key){
	McParamOutgoingSSNResetRequest* mc = new McParamOutgoingSSNResetRequest(key);

	mc->common_member();
	mc->member(new MmUint("RequestSequenceNumber", 32, UN(0), UN(0)));
	mc->member(new MmUint("ResponseSequenceNumber", 32, UN(0), UN(0)));
	mc->member(new MmUint("SendersLastAssignedTSN", 32, UN(0), UN(0)));
	mc->member(
		new MmMultiple(
			new MmUint("StreamNumber", 16, MUST(), MUST()),
			(METH_HC_MLC)&McParamOutgoingSSNResetRequest::HC_MLC(StreamNumber)
		)
	);
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmParameter::add(mc);
	return mc;
}

McParamIncomingSSNResetRequest* McParamIncomingSSNResetRequest::create(CSTR key){
	McParamIncomingSSNResetRequest* mc = new McParamIncomingSSNResetRequest(key);

	mc->common_member();
	mc->member(new MmUint("RequestSequenceNumber", 32, UN(0), UN(0)));
	mc->member(
		new MmMultiple(
			new MmUint("StreamNumber", 16, MUST(), MUST()),
			(METH_HC_MLC)&McParamIncomingSSNResetRequest::HC_MLC(StreamNumber)
		)
	);
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmParameter::add(mc);
	return mc;
}

McParamSSNResetRequest* McParamSSNResetRequest::create(CSTR key){
	McParamSSNResetRequest* mc = new McParamSSNResetRequest(key);

	mc->common_member();
	mc->member(new MmUint("RequestSequenceNumber", 32, UN(0), UN(0)));

	MmParameter::add(mc);
	return mc;
}

McParamStreamResetResponse* McParamStreamResetResponse::create(CSTR key){
	McParamStreamResetResponse* mc = new McParamStreamResetResponse(key);

	mc->common_member();
	mc->member(new MmUint("ResponseSequenceNumber", 32, UN(0), UN(0)));
	mc->member(new MmUint("Result", 32, UN(0), UN(0)));
	mc->member(
		new MmMultiple(
			new MmUint("SendNextTSN", 32, MUST(), MUST()),
			(METH_HC_MLC)&McParamStreamResetResponse::HC_MLC(SendNextTSN)
		)
	);
	mc->member(
		new MmMultiple(
			new MmUint("RecvNextTSN", 32, MUST(), MUST()),
			(METH_HC_MLC)&McParamStreamResetResponse::HC_MLC(RecvNextTSN)
		)
	);

	MmParameter::add(mc);
	return mc;
}

McParamAddStreams* McParamAddStreams::create(CSTR key){
	McParamAddStreams* mc = new McParamAddStreams(key);

	mc->common_member();
	mc->member(new MmUint("RequestSequenceNumber", 32, UN(0), UN(0)));
	mc->member(new MmUint("NumberOfNewStreams", 16, UN(0), UN(0)));
	mc->member(new MmUint("Reserved", 16, UN(0), UN(0)));

	MmParameter::add(mc);
	return mc;
}

//////////////////////////////////////////////////////////////////////////////
void McErrorCause::common_member(){
	int32_t code = optionType();
	code_member(new MmUint( "Code",		16, UN(code),UN(code)));
	length_member(new MmUint( "Length", 	16, GENEHC(this,McErrorCause,Length), EVALANY()));
}

McErrorCauseANY* McErrorCauseANY::create(CSTR key){
	McErrorCauseANY* mc = new McErrorCauseANY(key);

	mc->common_member();
	mc->member(new MmData("Data"));

	MmErrorCause::add_other(mc);
	return mc;
}

McErrorInvalidStreamIndentifier* McErrorInvalidStreamIndentifier::create(CSTR key){
	McErrorInvalidStreamIndentifier* mc = new McErrorInvalidStreamIndentifier(key);

	mc->common_member();
	mc->member(new MmUint("Identifier", 	16, UN(0), UN(0)));
	mc->member(new MmUint("Reserved", 		16, UN(0), UN(0)));

	MmErrorCause::add(mc);
	return mc;
}

McErrorMissingMandatoryParameter* McErrorMissingMandatoryParameter::create(CSTR key){
	McErrorMissingMandatoryParameter* mc = new McErrorMissingMandatoryParameter(key);

	mc->common_member();
	mc->num_member(new MmUint("NumOfMissingParam", 	32, UN(0), UN(0)));
	mc->member(
		new MmMultiple(
			new MmUint("ParamType", 16, MUST(), MUST()),
			(METH_HC_MLC)&McErrorMissingMandatoryParameter::HC_MLC(NUM)
		)
	);
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmErrorCause::add(mc);
	return mc;
}

McErrorStaleCookieError* McErrorStaleCookieError::create(CSTR key){
	McErrorStaleCookieError* mc = new McErrorStaleCookieError(key);

	mc->common_member();
	mc->member(new MmUint("Staleness", 	32, UN(0), UN(0)));

	MmErrorCause::add(mc);
	return mc;
}

McErrorOutOfResource* McErrorOutOfResource::create(CSTR key){
	McErrorOutOfResource* mc = new McErrorOutOfResource(key);

	mc->common_member();

	MmErrorCause::add(mc);
	return mc;
}

McErrorUnresolvableAddress* McErrorUnresolvableAddress::create(CSTR key){
	McErrorUnresolvableAddress* mc = new McErrorUnresolvableAddress(key);

	mc->common_member();
	mc->member(new MmParameter("Address"));

	MmErrorCause::add(mc);
	return mc;
}

McErrorUnrecognizedChunkType* McErrorUnrecognizedChunkType::create(CSTR key){
	McErrorUnrecognizedChunkType* mc = new McErrorUnrecognizedChunkType(key);

	mc->common_member();
	mc->member(new MmData("Chunk"));

	MmErrorCause::add(mc);
	return mc;
}

McErrorInvalidMandatoryParameter* McErrorInvalidMandatoryParameter::create(CSTR key){
	McErrorInvalidMandatoryParameter* mc = new McErrorInvalidMandatoryParameter(key);

	mc->common_member();

	MmErrorCause::add(mc);
	return mc;
}

McErrorUnrecognizedParameters* McErrorUnrecognizedParameters::create(CSTR key){
	McErrorUnrecognizedParameters* mc = new McErrorUnrecognizedParameters(key);

	mc->common_member();
	mc->member(new MmParameter("Parameters"));

	MmErrorCause::add(mc);
	return mc;
}

McErrorNoUserData* McErrorNoUserData::create(CSTR key){
	McErrorNoUserData* mc = new McErrorNoUserData(key);

	mc->common_member();
	mc->member(new MmUint("TSN", 	32, UN(0), UN(0)));

	MmErrorCause::add(mc);
	return mc;
}

McErrorCookieRecvShutdown* McErrorCookieRecvShutdown::create(CSTR key){
	McErrorCookieRecvShutdown* mc = new McErrorCookieRecvShutdown(key);

	mc->common_member();

	MmErrorCause::add(mc);
	return mc;
}

McErrorRestartWithNewAddresses* McErrorRestartWithNewAddresses::create(CSTR key){
	McErrorRestartWithNewAddresses* mc = new McErrorRestartWithNewAddresses(key);

	mc->common_member();
	mc->member(new MmParameter("NewAddress"));

	MmErrorCause::add(mc);
	return mc;
}

McErrorUserInitiatedAbort* McErrorUserInitiatedAbort::create(CSTR key){
	McErrorUserInitiatedAbort* mc = new McErrorUserInitiatedAbort(key);

	mc->common_member();
	mc->member(new MmData("Reason"));

	MmErrorCause::add(mc);
	return mc;
}

McErrorProtocolViolation* McErrorProtocolViolation::create(CSTR key){
	McErrorProtocolViolation* mc = new McErrorProtocolViolation(key);

	mc->common_member();
	mc->member(new MmData("Information"));

	MmErrorCause::add(mc);
	return mc;
}

McErrorDeleteLastRemainingIPAddress* McErrorDeleteLastRemainingIPAddress::create(CSTR key){
	McErrorDeleteLastRemainingIPAddress* mc = new McErrorDeleteLastRemainingIPAddress(key);

	mc->common_member();
	mc->member(new MmParameter("Information"));

	MmErrorCause::add(mc);
	return mc;
}

McErrorRefusedResourceShortage* McErrorRefusedResourceShortage::create(CSTR key){
	McErrorRefusedResourceShortage* mc = new McErrorRefusedResourceShortage(key);

	mc->common_member();
	mc->member(new MmParameter("Information"));

	MmErrorCause::add(mc);
	return mc;
}

McErrorDeleteSourceIPAddress* McErrorDeleteSourceIPAddress::create(CSTR key){
	McErrorDeleteSourceIPAddress* mc = new McErrorDeleteSourceIPAddress(key);

	mc->common_member();
	mc->member(new MmParameter("Information"));

	MmErrorCause::add(mc);
	return mc;
}

McErrorIllegalASCONFAck* McErrorIllegalASCONFAck::create(CSTR key){
	McErrorIllegalASCONFAck* mc = new McErrorIllegalASCONFAck(key);

	mc->common_member();

	MmErrorCause::add(mc);
	return mc;
}

McErrorNoAuthorization* McErrorNoAuthorization::create(CSTR key){
	McErrorNoAuthorization* mc = new McErrorNoAuthorization(key);

	mc->common_member();
	mc->member(new MmParameter("Information"));

	MmErrorCause::add(mc);
	return mc;
}

McErrorUnsupportedHMACIdentifier* McErrorUnsupportedHMACIdentifier::create(CSTR key){
	McErrorUnsupportedHMACIdentifier* mc = new McErrorUnsupportedHMACIdentifier(key);

	mc->common_member();
	mc->member(new MmUint("HMACIdentifier", 16, UN(0), UN(0)));
	mc->member(new MmUint("Padding", 	16, UN(0), UN(0)));

	MmErrorCause::add(mc);
	return mc;
}
