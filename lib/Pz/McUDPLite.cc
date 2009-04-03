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
#include "McUDP.h"
#include "McUDPLite.h"
#include "MmHeader.h"
#include "MmChecksum.h"
#include "ItPosition.h"
#include "WObject.h"
#include "RObject.h"
#include "PControl.h"
#include "PvObject.h"
#include "PvOctets.h"
#include "PvAutoItem.h"
#include "PvAction.h"

#include <arpa/inet.h>

#define UN(n)		PvNumber::unique(n)
#define MUST()		PvMUSTDEF::must()
#define EVALANY()	new PvANY()
#define GENEHC(mc,cls,mem)	new PvHCgene(mc,(HCgenefunc)&cls::HCGENE(mem))
#define EVALHC(mc,cls,mem)	new PvHCeval(mc,(HCevalfunc)&cls::HCEVAL(mem))

#define DEF_OPTCHKSUM    true

//////////////////////////////////////////////////////////////////////////////
#define SUPER	McUpper
McUpp_UDPLite* McUpp_UDPLite::instance_=0;
McTopHdr_UDPLite* McUpp_UDPLite::tophdr_=0;
McUpp_UDPLite::McUpp_UDPLite(CSTR key):SUPER(key) {instance_=this;}
McUpp_UDPLite::~McUpp_UDPLite(){if(instance_==this)instance_=0;}

// COMPOSE/REVERSE
uint32_t McUpp_UDPLite::length_for_reverse(
		RControl& c,ItPosition& at,OCTBUF& buf) const{
	return buf.remainLength(at.bytes());
}

RObject* McUpp_UDPLite::reverse(RControl& c,
		RObject* r_parent,ItPosition& at,OCTBUF& buf)const{
	RObject* r_self = SUPER::reverse(c,r_parent,at,buf);
	uint16_t cscov = tophdr_->CsCov_for_reverse(c, at, buf);
	if(!c.error()){
		Con_IPinfo* info = c.IPinfo();
		if (cscov >= 8) {
			if(info)info->reverse_postUppChecksumWithLiteLength(c, r_self, cscov);
		} else {
			if(info)info->reverse_postUppChecksum(c, r_self);
		}
	}
	return r_self;
}

bool McUpp_UDPLite::generate(WControl& c,WObject* w_self,OCTBUF& buf) const {
	bool rtn = SUPER::generate(c,w_self,buf);
	OCTBUF *basebuf = (OCTBUF *)w_self->pvalue();
	uint16_t cscov = ntohs(*(uint16_t *)((unsigned char *)basebuf->buffer() +  4));
	if(!c.error()){
		Con_IPinfo* info = c.IPinfo();
		if (cscov >= 8) {
			if(info)info->generate_postUppChecksumWithLiteLength(c, buf, w_self, cscov);
		} else {
			if(info)info->generate_postUppChecksum(c, buf, w_self);
		}
	}
	return rtn;
}
#undef SUPER

//----------------------------------------------------------------------------
#define SUPER	McHeader
McTopHdr_UDPLite::McTopHdr_UDPLite(CSTR key):SUPER(key), SrcPort_meta_(0), DstPort_meta_(0), CsCov_meta_(0) {
	PrtObjs_ = new PrtObjs();
}

McTopHdr_UDPLite::~McTopHdr_UDPLite(){}

// COMPOSE/REVERSE
uint16_t McTopHdr_UDPLite::CsCov_for_reverse(
			RControl& c,ItPosition& at,OCTBUF& buf) const{
	if(!CsCov_meta_) return 0;
	uint16_t cscov = CsCov_meta_->value(at,buf);
	return cscov;
}

RObject *McTopHdr_UDPLite::reverse(RControl &c, RObject *r_parent, ItPosition &at, OCTBUF &buf) const {
	RObject *r_self = SUPER::reverse(c, r_parent, at, buf);

	if(r_self) {
		upperProto_set_Object(r_self);
	}

	return(r_self);
}

void McTopHdr_UDPLite::upperProto_set_Object(RObject *r_self) const {
	if((!r_self) || (!SrcPort_meta_) || (!DstPort_meta_) || (!PrtObjs_)) {
		return;
	}

        RObject *src = (RObject *)r_self->corresponding(SrcPort_meta_);
        RObject *dst = (RObject *)r_self->corresponding(DstPort_meta_);

	if(src){
		set_srcobj(src);
	}

	if(dst) {
		set_dstobj(dst);
	}

	return;
}

bool McTopHdr_UDPLite::HCGENE(SourcePort)(WControl &cntr, WObject *wmem, OCTBUF &buf) const {
	int32_t val = get_next_protocolPort(wmem);

	if(val == -1) {
		return(false);
	}

	PvNumber def(val);
	return(def.generate(cntr, wmem, buf));
}

PObject *McTopHdr_UDPLite::HCEVAL(SourcePort)(WObject *wmem) const {
	int32_t val = get_next_protocolPort(wmem);

	return(new PvNumber(val));
}

bool McTopHdr_UDPLite::HCGENE(DestinationPort)(WControl &cntr, WObject *wmem, OCTBUF &buf) const {
	int32_t val = get_next_protocolPort(wmem);

	if(val == -1) {
		return(false);
	}

	PvNumber def(val);
	return(def.generate(cntr, wmem, buf));
}

PObject *McTopHdr_UDPLite::HCEVAL(DestinationPort)(WObject *wmem) const {
	int32_t val = get_next_protocolPort(wmem);

	return(new PvNumber(val));
}
#undef SUPER

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
McUpp_UDPLite *McUpp_UDPLite::create(CSTR key, CSTR tophdrkey) {
	addCompound(tophdr_ = McTopHdr_UDPLite::create(tophdrkey));
	McUpp_UDPLite *mc = new McUpp_UDPLite(key);

	mc->member(new MmTopHdr("header", tophdr_));
	mc->member(new MmUpper_onUpper("payload", tophdr_));

	// dict
	MmUpper_onIP::add(mc);	// Packet_IP::upper=

	return(mc);
}

McTopHdr_UDPLite *McTopHdr_UDPLite::create(CSTR key) {
	McTopHdr_UDPLite *mc = new McTopHdr_UDPLite(key);

	mc->SrcPort_member(
		new MmUint(
			"SourcePort",
			16,
			GENEHC(mc, McTopHdr_UDPLite, SourcePort),
			EVALHC(mc, McTopHdr_UDPLite, SourcePort)
		)
	);
	mc->DstPort_member(
		new MmUint(
			"DestinationPort",
			16,
			GENEHC(mc, McTopHdr_UDPLite, DestinationPort),
			EVALHC(mc, McTopHdr_UDPLite, DestinationPort)
		)
	);
	mc->CsCov_member(new MmUint("CsCov", 16, UN(0), EVALANY()));
	mc->member(new MmUppChecksum("Checksum", 16, DEF_OPTCHKSUM));

	// no dict
	return(mc);
}
