/*
 * Copyright (C) 2008, 2009 Fujitsu Limited.
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
#include <arpa/inet.h>
#include "McDCCP.h"
#include "MmChecksum.h"
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

#define DEF_ALIGNMENTT_DCCP	4
#define DEF_LENGTH_ELEM_DCCP	4

static inline uint32_t roundN(uint32_t num,uint32_t align) {
        return ((num + align - 1) / align) * align;
}

//////////////////////////////////////////////////////////////////////////////
#define SUPER	McUpper

McUpp_DCCP* McUpp_DCCP::instance_ = 0;
McTopHdr_DCCP* McUpp_DCCP::tophdr_ = 0;

McUpp_DCCP::McUpp_DCCP(CSTR key) : SUPER(key) {
	instance_ = this;
}

McUpp_DCCP::~McUpp_DCCP() {
	if(instance_ == this) instance_ = 0;
}

// COMPOSE/REVERSE
uint32_t McUpp_DCCP::length_for_reverse(
		RControl& c,ItPosition& at,OCTBUF& buf) const {
	return buf.remainLength(at.bytes());
}

RObject* McUpp_DCCP::reverse(RControl& c,
		RObject* r_parent,ItPosition& at,OCTBUF& buf) const {
	RObject* r_self = SUPER::reverse(c, r_parent, at, buf);
	OCTBUF *basebuf = (OCTBUF *)r_self->pvalue();
	uint8_t doff = *(uint8_t *)((unsigned char *)basebuf->buffer() +  4);
	uint8_t cocsv = *(uint8_t *)((unsigned char *)basebuf->buffer() +  5);
	if(!c.error()){
		Con_IPinfo* info = c.IPinfo();
		if (cocsv > 0) {
			if(info)info->reverse_postUppChecksumWithLiteLength(c, r_self, (doff + cocsv - 1) * 4);
		} else {
			if(info)info->reverse_postUppChecksum(c, r_self);
		}
	}
	return r_self;
}

bool McUpp_DCCP::generate(WControl& c,WObject* w_self,OCTBUF& buf) const {
	bool rtn = SUPER::generate(c, w_self, buf);
	OCTBUF *basebuf = (OCTBUF *)w_self->pvalue();
	uint8_t doff = *(uint8_t *)((unsigned char *)basebuf->buffer() +  4);
	uint8_t cocsv = *(uint8_t *)((unsigned char *)basebuf->buffer() +  5);
	if(!c.error()){
		Con_IPinfo* info = c.IPinfo();
		if (cocsv > 0) {
			if(info)info->generate_postUppChecksumWithLiteLength(c, buf, w_self, (doff + cocsv - 1) * 4);
		} else {
			if(info)info->generate_postUppChecksum(c, buf, w_self);
		}
	}
	return rtn;
}

#undef SUPER

//----------------------------------------------------------------------------
#define SUPER	McHeader

McTopHdr_DCCP::McTopHdr_DCCP(CSTR key) : SUPER(key) {}
McTopHdr_DCCP::~McTopHdr_DCCP() {}

bool McTopHdr_DCCP::HCGENE(DataOff)(WControl& cntr,WObject* wmem,OCTBUF& buf)const{
	WObject* wc = wmem->parent();
	uint32_t reallen = wc->size().bytes();
	if (wc->nextSister()) {
		reallen += wc->nextSister()->size().bytes();
	}
	reallen = (reallen + 3) / 4;
	PvNumber def(reallen);
	return def.generate(cntr, wmem, buf);
}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McHeader

McDCCPacket::McDCCPacket(CSTR key):SUPER(key),type_(0),xflag_(0){}
McDCCPacket::~McDCCPacket(){}

// COMPOSE/REVERSE
uint32_t McDCCPacket::length_for_reverse(RControl& c,
		ItPosition& at,OCTBUF& buf) const{
        unsigned char *off = (unsigned char *)buf.buffer() + at.bytes() - 4;
        uint8_t length = *(uint8_t *)off;
	length = 4 * (length - 2);
	if(buf.remainLength(at.bytes()) < length)
		length = buf.remainLength(at.bytes());
	return length;
}

bool McDCCPacket::overwrite_DictType(
		RControl& c,ItPosition& at,OCTBUF& buf)const{
        uint8_t type = *((uint8_t *)buf.buffer() + at.bytes());
        type = type & 0x3F;
        c.DictType().type_Set(type);
	return true;
}

uint32_t McDCCPacket::alignment_requirement() const{
	return DEF_ALIGNMENTT_DCCP;
}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McDCCPacket
McDCCPAny::McDCCPAny(CSTR key):SUPER(key){}
McDCCPAny::~McDCCPAny(){}

McDCCPRequest::McDCCPRequest(CSTR key):SUPER(key){}
McDCCPRequest::~McDCCPRequest(){}

McDCCPRequestShort::McDCCPRequestShort(CSTR key):SUPER(key){}
McDCCPRequestShort::~McDCCPRequestShort(){}

McDCCPResponse::McDCCPResponse(CSTR key):SUPER(key){}
McDCCPResponse::~McDCCPResponse(){}

McDCCPResponseShort::McDCCPResponseShort(CSTR key):SUPER(key){}
McDCCPResponseShort::~McDCCPResponseShort(){}

McDCCPData::McDCCPData(CSTR key):SUPER(key){}
McDCCPData::~McDCCPData(){}

McDCCPDataShort::McDCCPDataShort(CSTR key):SUPER(key){}
McDCCPDataShort::~McDCCPDataShort(){}

McDCCPAck::McDCCPAck(CSTR key):SUPER(key){}
McDCCPAck::~McDCCPAck(){}

McDCCPAckShort::McDCCPAckShort(CSTR key):SUPER(key){}
McDCCPAckShort::~McDCCPAckShort(){}

McDCCPDataAck::McDCCPDataAck(CSTR key):SUPER(key){}
McDCCPDataAck::~McDCCPDataAck(){}

McDCCPDataAckShort::McDCCPDataAckShort(CSTR key):SUPER(key){}
McDCCPDataAckShort::~McDCCPDataAckShort(){}

McDCCPCloseReq::McDCCPCloseReq(CSTR key):SUPER(key){}
McDCCPCloseReq::~McDCCPCloseReq(){}

McDCCPCloseReqShort::McDCCPCloseReqShort(CSTR key):SUPER(key){}
McDCCPCloseReqShort::~McDCCPCloseReqShort(){}

McDCCPClose::McDCCPClose(CSTR key):SUPER(key){}
McDCCPClose::~McDCCPClose(){}

McDCCPCloseShort::McDCCPCloseShort(CSTR key):SUPER(key){}
McDCCPCloseShort::~McDCCPCloseShort(){}

McDCCPReset::McDCCPReset(CSTR key):SUPER(key){}
McDCCPReset::~McDCCPReset(){}

McDCCPResetShort::McDCCPResetShort(CSTR key):SUPER(key){}
McDCCPResetShort::~McDCCPResetShort(){}

McDCCPSync::McDCCPSync(CSTR key):SUPER(key){}
McDCCPSync::~McDCCPSync(){}

McDCCPSyncShort::McDCCPSyncShort(CSTR key):SUPER(key){}
McDCCPSyncShort::~McDCCPSyncShort(){}

McDCCPSyncAck::McDCCPSyncAck(CSTR key):SUPER(key){}
McDCCPSyncAck::~McDCCPSyncAck(){}

McDCCPSyncAckShort::McDCCPSyncAckShort(CSTR key):SUPER(key){}
McDCCPSyncAckShort::~McDCCPSyncAckShort(){}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McOption
McOpt_DCCP::McOpt_DCCP(CSTR key):SUPER(key),type_(0),length_(0){}
McOpt_DCCP::~McOpt_DCCP(){}

// COMPOSE/REVERSE
uint32_t McOpt_DCCP::length_for_reverse(RControl& c,
		ItPosition& at,OCTBUF& buf) const{
	if(!length_)return SUPER::length_for_reverse(c,at,buf);
	uint32_t valulen	= length_->value(at,buf);
	uint32_t length		= (valulen > 1) ? valulen : 2;
	return length;
}

bool McOpt_DCCP::HCGENE(Length)(WControl& cntr,WObject* wmem,OCTBUF& buf)const{
	WObject* wc		= wmem->parent();	//Opt_DCCP
	uint32_t reallen	= wc->size().bytes();
	uint32_t valulen	= reallen;
	PvNumber def(valulen);
	return def.generate(cntr,wmem,buf);
}

bool McOpt_DCCP::overwrite_DictType(
		RControl& c,ItPosition& at,OCTBUF& buf)const{
	if(c.DictType().finish())return false;	//End of OptionList
	uint32_t limit = buf.remainLength(at.bytes());
	if(limit==0)return false;		//End of DCCP Header
	//
	ItPosition tmpat=at;
	RObject* rtype = type_->reverse(c,0,tmpat,buf);
	if(!rtype)return false;			//Type field decode error
	//
	const PvNumber* pv = (const PvNumber*)rtype->pvalue();
	uint32_t typevalue = pv->value();
	if (typevalue >= TP_DCCP_OPT_MIN_RESERVED && typevalue <= TP_DCCP_OPT_MAX_RESERVED)
		typevalue = TP_DCCP_OPT_MAX_RESERVED;
	c.DictType().type_Set(typevalue);	//self Type set
	delete rtype;
	return true;
}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McOpt_DCCP
McOpt_DCCP_ANY::McOpt_DCCP_ANY(CSTR key):SUPER(key){}
McOpt_DCCP_ANY::~McOpt_DCCP_ANY(){}

McOpt_DCCP_Reserved::McOpt_DCCP_Reserved(CSTR key):SUPER(key){}
McOpt_DCCP_Reserved::~McOpt_DCCP_Reserved(){}

McOpt_DCCP_Padding::McOpt_DCCP_Padding(CSTR key):SUPER(key){}
McOpt_DCCP_Padding::~McOpt_DCCP_Padding(){}

McOpt_DCCP_Mandatory::McOpt_DCCP_Mandatory(CSTR key):SUPER(key){}
McOpt_DCCP_Mandatory::~McOpt_DCCP_Mandatory(){}

McOpt_DCCP_ChangeL::McOpt_DCCP_ChangeL(CSTR key):SUPER(key){}
McOpt_DCCP_ChangeL::~McOpt_DCCP_ChangeL(){}

McOpt_DCCP_ConfirmL::McOpt_DCCP_ConfirmL(CSTR key):SUPER(key){}
McOpt_DCCP_ConfirmL::~McOpt_DCCP_ConfirmL(){}

McOpt_DCCP_ChangeR::McOpt_DCCP_ChangeR(CSTR key):SUPER(key){}
McOpt_DCCP_ChangeR::~McOpt_DCCP_ChangeR(){}

McOpt_DCCP_ConfirmR::McOpt_DCCP_ConfirmR(CSTR key):SUPER(key){}
McOpt_DCCP_ConfirmR::~McOpt_DCCP_ConfirmR(){}

McOpt_DCCP_InitCookie::McOpt_DCCP_InitCookie(CSTR key):SUPER(key){}
McOpt_DCCP_InitCookie::~McOpt_DCCP_InitCookie(){}

McOpt_DCCP_NDPCount::McOpt_DCCP_NDPCount(CSTR key):SUPER(key){}
McOpt_DCCP_NDPCount::~McOpt_DCCP_NDPCount(){}

McOpt_DCCP_AckVector0::McOpt_DCCP_AckVector0(CSTR key):SUPER(key){}
McOpt_DCCP_AckVector0::~McOpt_DCCP_AckVector0(){}

uint32_t McOpt_DCCP_AckVector0::HC_MLC(Vector)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 2;
	return(count);
}

McOpt_DCCP_AckVector1::McOpt_DCCP_AckVector1(CSTR key):SUPER(key){}
McOpt_DCCP_AckVector1::~McOpt_DCCP_AckVector1(){}

uint32_t McOpt_DCCP_AckVector1::HC_MLC(Vector)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 2;
	return(count);
}

McOpt_DCCP_Timestamp::McOpt_DCCP_Timestamp(CSTR key):SUPER(key){}
McOpt_DCCP_Timestamp::~McOpt_DCCP_Timestamp(){}

McOpt_DCCP_TimestampEcho::McOpt_DCCP_TimestampEcho(CSTR key):SUPER(key){}
McOpt_DCCP_TimestampEcho::~McOpt_DCCP_TimestampEcho(){}

uint32_t McOpt_DCCP_TimestampEcho::HC_MLC(ElapsedTime)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	return(len >= 10) ? 1 : 0;
}

uint32_t McOpt_DCCP_TimestampEcho::HC_MLC(ElapsedTimeShort)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	return(len == 8) ? 1 : 0;
}

McOpt_DCCP_ElapsedTime::McOpt_DCCP_ElapsedTime(CSTR key):SUPER(key){}
McOpt_DCCP_ElapsedTime::~McOpt_DCCP_ElapsedTime(){}

uint32_t McOpt_DCCP_ElapsedTime::HC_MLC(ElapsedTime)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	return(len >= 6) ? 1 : 0;
}

uint32_t McOpt_DCCP_ElapsedTime::HC_MLC(ElapsedTimeShort)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	return(len == 4) ? 1 : 0;
}

McOpt_DCCP_DataChecksum::McOpt_DCCP_DataChecksum(CSTR key):SUPER(key){}
McOpt_DCCP_DataChecksum::~McOpt_DCCP_DataChecksum(){}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McOption
McFeature::McFeature(CSTR key):SUPER(key),type_(0){}
McFeature::~McFeature(){}

// COMPOSE/REVERSE
uint32_t McFeature::length_for_reverse(RControl& c,
		ItPosition& at,OCTBUF& buf) const{
	return buf.remainLength(at.bytes());
}

bool McFeature::overwrite_DictType(
		RControl& c,ItPosition& at,OCTBUF& buf)const{
	uint32_t limit = buf.remainLength(at.bytes());
	if(limit==0)return false;		//End of DCCP Header
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

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	McFeature

McFeature_ANY::McFeature_ANY(CSTR key):SUPER(key){}
McFeature_ANY::~McFeature_ANY(){}

McFeature_CCID::McFeature_CCID(CSTR key):SUPER(key){}
McFeature_CCID::~McFeature_CCID(){}

uint32_t McFeature_CCID::HC_MLC(Value)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 1;
	return(count);
}

McFeature_ShortSeq::McFeature_ShortSeq(CSTR key):SUPER(key){}
McFeature_ShortSeq::~McFeature_ShortSeq(){}

uint32_t McFeature_ShortSeq::HC_MLC(Value)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 1;
	return(count);
}

McFeature_SeqWin::McFeature_SeqWin(CSTR key):SUPER(key){}
McFeature_SeqWin::~McFeature_SeqWin(){}

uint32_t McFeature_SeqWin::HC_MLC(Value)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 1;
	return(count);
}

McFeature_ENCIncapable::McFeature_ENCIncapable(CSTR key):SUPER(key){}
McFeature_ENCIncapable::~McFeature_ENCIncapable(){}

uint32_t McFeature_ENCIncapable::HC_MLC(Value)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 1;
	return(count);
}

McFeature_AckRatio::McFeature_AckRatio(CSTR key):SUPER(key){}
McFeature_AckRatio::~McFeature_AckRatio(){}

uint32_t McFeature_AckRatio::HC_MLC(Value)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = (len - 1) / 2;
	return(count);
}

McFeature_SendAckVector::McFeature_SendAckVector(CSTR key):SUPER(key){}
McFeature_SendAckVector::~McFeature_SendAckVector(){}

uint32_t McFeature_SendAckVector::HC_MLC(Value)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 1;
	return(count);
}

McFeature_SendNDPCount::McFeature_SendNDPCount(CSTR key):SUPER(key){}
McFeature_SendNDPCount::~McFeature_SendNDPCount(){}

uint32_t McFeature_SendNDPCount::HC_MLC(Value)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 1;
	return(count);
}

McFeature_MinCsumCover::McFeature_MinCsumCover(CSTR key):SUPER(key){}
McFeature_MinCsumCover::~McFeature_MinCsumCover(){}

uint32_t McFeature_MinCsumCover::HC_MLC(Value)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 1;
	return(count);
}

McFeature_DataChecksum::McFeature_DataChecksum(CSTR key):SUPER(key){}
McFeature_DataChecksum::~McFeature_DataChecksum(){}

uint32_t McFeature_DataChecksum::HC_MLC(Value)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 1;
	return(count);
}

McFeature_SendLevRate::McFeature_SendLevRate(CSTR key):SUPER(key){}
McFeature_SendLevRate::~McFeature_SendLevRate(){}

uint32_t McFeature_SendLevRate::HC_MLC(Value)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t len = buf.remainLength(at.bytes());
	uint32_t count = len - 1;
	return(count);
}

#undef SUPER

///////////////////////////////////////////////////////////////////////////////
#define SUPER	MmReference_Must1
MmDCCPacket::MmDCCPacket(CSTR key) : SUPER(key, true) {}
MmDCCPacket::~MmDCCPacket() {}
TypevsMcDict MmDCCPacket::dict_;

void MmDCCPacket::add(McDCCPacket* mc, int xflag) {
	dict_.add(mc->optionType() << 1 | xflag, mc);
}

void MmDCCPacket::add_other(McDCCPacket* mc) {
	dict_.add_other(mc);
}

// REVERSE
bool MmDCCPacket::overwrite_DictType(RControl& c,ItPosition& at,OCTBUF& buf) const {
	McDCCPacket* any = (McDCCPacket*)dict_.find_other();
	return any->overwrite_DictType(c, at, buf);
}

uint32_t MmDCCPacket::objectLength(const PObject* po, const WObject* w) const {
	uint32_t length = SUPER::objectLength(po,w);
	return roundN(length, 4);
}
#undef SUPER

///////////////////////////////////////////////////////////////////////////////
MmOption_onDCCP::MmOption_onDCCP(CSTR key):MmReference_More0(key,true) {}
MmOption_onDCCP::~MmOption_onDCCP() {}

void MmOption_onDCCP::add(McOpt_DCCP* mc){
	dict_.add(mc->optionType(),mc);}
void MmOption_onDCCP::add_other(McOpt_DCCP* mc){dict_.add_other(mc);}
TypevsMcDict MmOption_onDCCP::dict_;

// REVERSE
bool MmOption_onDCCP::overwrite_DictType(
		RControl& c,ItPosition& at,OCTBUF& buf)const{
	McOpt_DCCP* any = (McOpt_DCCP*)dict_.find_other();
	return any->overwrite_DictType(c,at,buf);
}

///////////////////////////////////////////////////////////////////////////////
MmFeature::MmFeature(CSTR key):MmReference_More0(key,true) {}
MmFeature::~MmFeature() {}

void MmFeature::add(McFeature* mc) {
	dict_.add(mc->optionType(), mc);
}

void MmFeature::add_other(McFeature* mc) {
	dict_.add_other(mc);
}

TypevsMcDict MmFeature::dict_;

// REVERSE
bool MmFeature::overwrite_DictType(
		RControl& c,ItPosition& at,OCTBUF& buf)const{
	McFeature* any = (McFeature*)dict_.find_other();
	return any->overwrite_DictType(c,at,buf);
}

//////////////////////////////////////////////////////////////////////////////
McUpp_DCCP* McUpp_DCCP::create(CSTR key,CSTR tophdrkey){
	addCompound(tophdr_ = McTopHdr_DCCP::create(tophdrkey));
	McUpp_DCCP* mc = new McUpp_DCCP(key);

	mc->member(new MmTopHdr("header", tophdr_));
	//exthdr
	mc->member(new MmDCCPacket("exthdr"));
	mc->member(new MmPayload("payload"));

	MmUpper_onIP::add(mc);
	return mc;
}

McTopHdr_DCCP* McTopHdr_DCCP::create(CSTR key){
	McTopHdr_DCCP* mc = new McTopHdr_DCCP(key);

	mc->member(new MmUint("SourcePort",	16, MUST(), MUST()));
	mc->member(new MmUint("DestinationPort",16, MUST(), MUST()));
//	mc->member(new MmUint("DataOffset",	8, UN(4), UN(4)));
	mc->member(new MmUint( "DataOffset", 8,
		GENEHC(mc, McTopHdr_DCCP, DataOff), EVALANY()));
	mc->member(new MmUint("CCVal",		4, UN(0), UN(0)));
	mc->member(new MmUint("CsCov",		4, UN(0), UN(0)));
	mc->member(new MmUppChecksum("Checksum",16));

	return mc;
}

//////////////////////////////////////////////////////////////////////////////
void McDCCPacket::common_member(){
	int32_t type = optionType();

	member(new MmUint("Reserved",	3, UN(0), UN(0)));
	type_member(new MmUint("Type",	4, UN(type), UN(type)));
	xflag_member(new MmUint("XFlag",1, UN(1), UN(1)));
	member(new MmUint("Reserved",	8, UN(0), UN(0)));
	member(new MmUint("Sequence",	48, UN(0), UN(0)));
}

void McDCCPacket::common_member_ack(){
	int32_t type = optionType();

	member(new MmUint("Reserved",	3, UN(0), UN(0)));
	type_member(new MmUint("Type",	4, UN(type), UN(type)));
	xflag_member(new MmUint("XFlag",1, UN(1), UN(1)));
	member(new MmUint("Reserved",	8, UN(0), UN(0)));
	member(new MmUint("Sequence",	48, UN(0), UN(0)));
	member(new MmUint("Reserved",	16, UN(0), UN(0)));
	member(new MmUint("Acknowledgement",	48, UN(0), UN(0)));
}

void McDCCPacket::common_member_short(){
	int32_t type = optionType();

	member(new MmUint("Reserved",	3, UN(0), UN(0)));
	type_member(new MmUint( "Type",	4, UN(type), UN(type)));
	xflag_member(new MmUint("XFlag",1, UN(0), UN(0)));
	member(new MmUint("Sequence",	24, UN(0), UN(0)));
}

void McDCCPacket::common_member_ack_short(){
	int32_t type = optionType();

	member(new MmUint("Reserved",	3, UN(0), UN(0)));
	type_member(new MmUint( "Type",	4, UN(type), UN(type)));
	xflag_member(new MmUint("XFlag",1, UN(0), UN(0)));
	member(new MmUint("Sequence",	24, UN(0), UN(0)));
	member(new MmUint("Reserved",	8, UN(0), UN(0)));
	member(new MmUint("Acknowledgement",	24, UN(0), UN(0)));
}

McDCCPAny* McDCCPAny::create(CSTR key){
	McDCCPAny* mc = new McDCCPAny(key);

	mc->common_member();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add_other(mc);
	return mc;
}

McDCCPRequest* McDCCPRequest::create(CSTR key){
	McDCCPRequest* mc = new McDCCPRequest(key);

	mc->common_member();
	mc->member(new MmUint("Service",	32, UN(0), UN(0)));
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 1);
	return mc;
}

McDCCPRequestShort* McDCCPRequestShort::create(CSTR key){
	McDCCPRequestShort* mc = new McDCCPRequestShort(key);

	mc->common_member_short();
	mc->member(new MmUint("Service",	32, UN(0), UN(0)));
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 0);
	return mc;
}

McDCCPResponse* McDCCPResponse::create(CSTR key){
	McDCCPResponse* mc = new McDCCPResponse(key);

	mc->common_member_ack();
	mc->member(new MmUint("Service",	32, UN(0), UN(0)));
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 1);
	return mc;
}

McDCCPResponseShort* McDCCPResponseShort::create(CSTR key){
	McDCCPResponseShort* mc = new McDCCPResponseShort(key);

	mc->common_member_ack_short();
	mc->member(new MmUint("Service",	32, UN(0), UN(0)));
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 0);
	return mc;
}

McDCCPData* McDCCPData::create(CSTR key){
	McDCCPData* mc = new McDCCPData(key);

	mc->common_member();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 1);
	return mc;
}

McDCCPDataShort* McDCCPDataShort::create(CSTR key){
	McDCCPDataShort* mc = new McDCCPDataShort(key);

	mc->common_member_short();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 0);
	return mc;
}

McDCCPAck* McDCCPAck::create(CSTR key){
	McDCCPAck* mc = new McDCCPAck(key);

	mc->common_member_ack();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 1);
	return mc;
}

McDCCPAckShort* McDCCPAckShort::create(CSTR key){
	McDCCPAckShort* mc = new McDCCPAckShort(key);

	mc->common_member_ack_short();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 0);
	return mc;
}

McDCCPDataAck* McDCCPDataAck::create(CSTR key){
	McDCCPDataAck* mc = new McDCCPDataAck(key);

	mc->common_member_ack();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 1);
	return mc;
}

McDCCPDataAckShort* McDCCPDataAckShort::create(CSTR key){
	McDCCPDataAckShort* mc = new McDCCPDataAckShort(key);

	mc->common_member_ack_short();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 0);
	return mc;
}

McDCCPCloseReq* McDCCPCloseReq::create(CSTR key){
	McDCCPCloseReq* mc = new McDCCPCloseReq(key);

	mc->common_member_ack();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 1);
	return mc;
}

McDCCPCloseReqShort* McDCCPCloseReqShort::create(CSTR key){
	McDCCPCloseReqShort* mc = new McDCCPCloseReqShort(key);

	mc->common_member_ack_short();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 0);
	return mc;
}

McDCCPClose* McDCCPClose::create(CSTR key){
	McDCCPClose* mc = new McDCCPClose(key);

	mc->common_member_ack();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 1);
	return mc;
}

McDCCPCloseShort* McDCCPCloseShort::create(CSTR key){
	McDCCPCloseShort* mc = new McDCCPCloseShort(key);

	mc->common_member_ack_short();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 0);
	return mc;
}

McDCCPReset* McDCCPReset::create(CSTR key){
	McDCCPReset* mc = new McDCCPReset(key);

	mc->common_member_ack();
	mc->member(new MmUint("ResetCode",	8, UN(0), UN(0)));
	mc->member(new MmUint("Data1",		8, UN(0), UN(0)));
	mc->member(new MmUint("Data2",		8, UN(0), UN(0)));
	mc->member(new MmUint("Data3",		8, UN(0), UN(0)));
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 1);
	return mc;
}

McDCCPResetShort* McDCCPResetShort::create(CSTR key){
	McDCCPResetShort* mc = new McDCCPResetShort(key);

	mc->common_member_ack_short();
	mc->member(new MmUint("ResetCode",	8, UN(0), UN(0)));
	mc->member(new MmUint("Data1",		8, UN(0), UN(0)));
	mc->member(new MmUint("Data2",		8, UN(0), UN(0)));
	mc->member(new MmUint("Data3",		8, UN(0), UN(0)));
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 0);
	return mc;
}

McDCCPSync* McDCCPSync::create(CSTR key){
	McDCCPSync* mc = new McDCCPSync(key);

	mc->common_member_ack();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 1);
	return mc;
}

McDCCPSyncShort* McDCCPSyncShort::create(CSTR key){
	McDCCPSyncShort* mc = new McDCCPSyncShort(key);

	mc->common_member_ack_short();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 0);
	return mc;
}

McDCCPSyncAck* McDCCPSyncAck::create(CSTR key){
	McDCCPSyncAck* mc = new McDCCPSyncAck(key);

	mc->common_member_ack();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 1);
	return mc;
}

McDCCPSyncAckShort* McDCCPSyncAckShort::create(CSTR key){
	McDCCPSyncAckShort* mc = new McDCCPSyncAckShort(key);

	mc->common_member_ack_short();
	mc->member(new MmOption_onDCCP("Option"));
	mc->member(new MmData("Padding", DEF_EVALSKIP));

	MmDCCPacket::add(mc, 0);
	return mc;
}

//////////////////////////////////////////////////////////////////////////////
void McOpt_DCCP::common_member(){
	int32_t type = optionType();

	type_member(new MmUint("Type",		8, UN(type), UN(type)));
	length_member(new MmUint( "Length",	8,
			GENEHC(this, McOpt_DCCP,Length), EVALANY()));
}

McOpt_DCCP_ANY* McOpt_DCCP_ANY::create(CSTR key){
	McOpt_DCCP_ANY* mc = new McOpt_DCCP_ANY(key);

	mc->common_member();
	mc->member( new MmData( "Data" ) );

	MmOption_onDCCP::add_other(mc);
	return mc;
}

McOpt_DCCP_Reserved* McOpt_DCCP_Reserved::create(CSTR key){
	McOpt_DCCP_Reserved* mc = new McOpt_DCCP_Reserved(key);
        int32_t type = mc->optionType();

        mc->type_member(new MmUint("Type", 8, UN(type), UN(type)));

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_Padding* McOpt_DCCP_Padding::create(CSTR key){
	McOpt_DCCP_Padding* mc = new McOpt_DCCP_Padding(key);
        int32_t type = mc->optionType();

        mc->type_member(new MmUint("Type", 8, UN(type), UN(type)));

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_Mandatory* McOpt_DCCP_Mandatory::create(CSTR key){
	McOpt_DCCP_Mandatory* mc = new McOpt_DCCP_Mandatory(key);
        int32_t type = mc->optionType();

        mc->type_member(new MmUint("Type", 8, UN(type), UN(type)));

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_ChangeL* McOpt_DCCP_ChangeL::create(CSTR key){
	McOpt_DCCP_ChangeL* mc = new McOpt_DCCP_ChangeL(key);

        mc->common_member();
	mc->member(new MmFeature("Feature"));

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_ConfirmL* McOpt_DCCP_ConfirmL::create(CSTR key){
	McOpt_DCCP_ConfirmL* mc = new McOpt_DCCP_ConfirmL(key);

        mc->common_member();
	mc->member(new MmFeature("Feature"));

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_ChangeR* McOpt_DCCP_ChangeR::create(CSTR key){
	McOpt_DCCP_ChangeR* mc = new McOpt_DCCP_ChangeR(key);

        mc->common_member();
	mc->member(new MmFeature("Feature"));

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_ConfirmR* McOpt_DCCP_ConfirmR::create(CSTR key){
	McOpt_DCCP_ConfirmR* mc = new McOpt_DCCP_ConfirmR(key);

        mc->common_member();
	mc->member(new MmFeature("Feature"));

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_InitCookie* McOpt_DCCP_InitCookie::create(CSTR key){
	McOpt_DCCP_InitCookie* mc = new McOpt_DCCP_InitCookie(key);

        mc->common_member();
	mc->member(new MmData("Cookie"));

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_NDPCount* McOpt_DCCP_NDPCount::create(CSTR key){
	McOpt_DCCP_NDPCount* mc = new McOpt_DCCP_NDPCount(key);

        mc->common_member();
	mc->member(new MmData("Count"));

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_AckVector0* McOpt_DCCP_AckVector0::create(CSTR key){
	McOpt_DCCP_AckVector0* mc = new McOpt_DCCP_AckVector0(key);

        mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Vector", 8, MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DCCP_AckVector0::HC_MLC(Vector)
		)
	);

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_AckVector1* McOpt_DCCP_AckVector1::create(CSTR key){
	McOpt_DCCP_AckVector1* mc = new McOpt_DCCP_AckVector1(key);

        mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Vector", 8, MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DCCP_AckVector1::HC_MLC(Vector)
		)
	);

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_Timestamp* McOpt_DCCP_Timestamp::create(CSTR key){
	McOpt_DCCP_Timestamp* mc = new McOpt_DCCP_Timestamp(key);

        mc->common_member();
        mc->member(new MmUint("Timestamp", 32, UN(0), UN(0)));

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_TimestampEcho* McOpt_DCCP_TimestampEcho::create(CSTR key){
	McOpt_DCCP_TimestampEcho* mc = new McOpt_DCCP_TimestampEcho(key);

	mc->common_member();
	mc->member(new MmUint("TimestampEcho", 32, UN(0), UN(0)));
	mc->member(
		new MmMultiple(
			new MmUint("ElapsedTime", 32, MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DCCP_TimestampEcho::HC_MLC(ElapsedTime)
		)
	);
	mc->member(
		new MmMultiple(
			new MmUint("ElapsedTimeShort", 16, MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DCCP_TimestampEcho::HC_MLC(ElapsedTimeShort)
		)
	);

	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_ElapsedTime* McOpt_DCCP_ElapsedTime::create(CSTR key){
	McOpt_DCCP_ElapsedTime* mc = new McOpt_DCCP_ElapsedTime(key);

        mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("ElapsedTime", 32, MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DCCP_ElapsedTime::HC_MLC(ElapsedTime)
		)
	);
	mc->member(
		new MmMultiple(
			new MmUint("ElapsedTimeShort", 16, MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DCCP_ElapsedTime::HC_MLC(ElapsedTimeShort)
		)
	);
	MmOption_onDCCP::add(mc);
	return mc;
}

McOpt_DCCP_DataChecksum* McOpt_DCCP_DataChecksum::create(CSTR key){
	McOpt_DCCP_DataChecksum* mc = new McOpt_DCCP_DataChecksum(key);

        mc->common_member();
        mc->member(new MmUint("Checksum", 32, UN(0), UN(0)));

	MmOption_onDCCP::add(mc);
	return mc;
}

//////////////////////////////////////////////////////////////////////////////
void McFeature::common_member(){
	int32_t type = optionType();

	type_member(new MmUint("Type",		8, UN(type), UN(type)));
}

McFeature_ANY* McFeature_ANY::create(CSTR key) {
	McFeature_ANY* mc = new McFeature_ANY(key);

	mc->common_member();
	mc->member(new MmData("Data"));

	MmFeature::add_other(mc);
	return mc;
}

McFeature_CCID* McFeature_CCID::create(CSTR key) {
	McFeature_CCID* mc = new McFeature_CCID(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Value", 8, MUST(), MUST()),
			(METH_HC_MLC)&McFeature_CCID::HC_MLC(Value)
		)
	);

	MmFeature::add(mc);
	return mc;
}

McFeature_ShortSeq* McFeature_ShortSeq::create(CSTR key) {
	McFeature_ShortSeq* mc = new McFeature_ShortSeq(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Value", 8, MUST(), MUST()),
			(METH_HC_MLC)&McFeature_ShortSeq::HC_MLC(Value)
		)
	);

	MmFeature::add(mc);
	return mc;
}

McFeature_SeqWin* McFeature_SeqWin::create(CSTR key) {
	McFeature_SeqWin* mc = new McFeature_SeqWin(key);

	mc->common_member();
        mc->member(new MmUint("Value", 48, UN(0), UN(0)));

	MmFeature::add(mc);
	return mc;
}

McFeature_ENCIncapable* McFeature_ENCIncapable::create(CSTR key) {
	McFeature_ENCIncapable* mc = new McFeature_ENCIncapable(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Value", 8, MUST(), MUST()),
			(METH_HC_MLC)&McFeature_ENCIncapable::HC_MLC(Value)
		)
	);

	MmFeature::add(mc);
	return mc;
}

McFeature_AckRatio* McFeature_AckRatio::create(CSTR key) {
	McFeature_AckRatio* mc = new McFeature_AckRatio(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Value", 16, MUST(), MUST()),
			(METH_HC_MLC)&McFeature_AckRatio::HC_MLC(Value)
		)
	);

	MmFeature::add(mc);
	return mc;
}

McFeature_SendAckVector* McFeature_SendAckVector::create(CSTR key) {
	McFeature_SendAckVector* mc = new McFeature_SendAckVector(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Value", 8, MUST(), MUST()),
			(METH_HC_MLC)&McFeature_SendAckVector::HC_MLC(Value)
		)
	);

	MmFeature::add(mc);
	return mc;
}

McFeature_SendNDPCount* McFeature_SendNDPCount::create(CSTR key) {
	McFeature_SendNDPCount* mc = new McFeature_SendNDPCount(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Value", 8, MUST(), MUST()),
			(METH_HC_MLC)&McFeature_SendNDPCount::HC_MLC(Value)
		)
	);

	MmFeature::add(mc);
	return mc;
}

McFeature_MinCsumCover* McFeature_MinCsumCover::create(CSTR key) {
	McFeature_MinCsumCover* mc = new McFeature_MinCsumCover(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Value", 8, MUST(), MUST()),
			(METH_HC_MLC)&McFeature_MinCsumCover::HC_MLC(Value)
		)
	);

	MmFeature::add(mc);
	return mc;
}

McFeature_DataChecksum* McFeature_DataChecksum::create(CSTR key) {
	McFeature_DataChecksum* mc = new McFeature_DataChecksum(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Value", 8, MUST(), MUST()),
			(METH_HC_MLC)&McFeature_DataChecksum::HC_MLC(Value)
		)
	);

	MmFeature::add(mc);
	return mc;
}

McFeature_SendLevRate* McFeature_SendLevRate::create(CSTR key) {
	McFeature_SendLevRate* mc = new McFeature_SendLevRate(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("Value", 8, MUST(), MUST()),
			(METH_HC_MLC)&McFeature_SendLevRate::HC_MLC(Value)
		)
	);

	MmFeature::add(mc);
	return mc;
}

