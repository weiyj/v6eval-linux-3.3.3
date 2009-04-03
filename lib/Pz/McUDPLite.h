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
#if !defined(__McUDPLite_h__)
#define	__McUDPLite_h__	1

#include "McSub.h"

//////////////////////////////////////////////////////////////////////////////
//	Upper UDP
#define TP_Upp_UDPLite		136

class McUpp_UDPLite : public McUpper{
static	McUpp_UDPLite*		instance_;
static	class McTopHdr_UDPLite*	tophdr_;
	McUpp_UDPLite(CSTR);
public:
virtual ~McUpp_UDPLite();
static	McUpp_UDPLite* create(CSTR key,CSTR tophdrkey);
static	McUpp_UDPLite* instance(){return instance_;}
	int32_t headerType()const{return TP_Upp_UDPLite;}
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
virtual uint32_t length_for_reverse(RControl&,ItPosition& at,OCTBUF& buf) const;
virtual RObject* reverse(RControl& c,
		RObject* r_parent,ItPosition& at,OCTBUF& buf)const;
virtual bool generate(WControl& c,WObject* w_self,OCTBUF& buf)const;
};

////////////////////////////////////////////////////////////////
class PrtObjs;

class McTopHdr_UDPLite :public McHeader{
friend	class McUpp_UDPLite;
	MmUint *SrcPort_meta_;
	MmUint *DstPort_meta_;
	MmUint*	CsCov_meta_;
	PrtObjs *PrtObjs_;

	void SrcPort_member(MmUint *meta) {
		SrcPort_meta_ = meta;
		member(meta);
	}

	void DstPort_member(MmUint *meta) {
		DstPort_meta_ = meta;
		member(meta);
	}

	void CsCov_member(MmUint* meta){
		CsCov_meta_=meta;
		member(meta);
	}

	void set_srcobj(RObject *obj) const {
		if(PrtObjs_) {
			PrtObjs_->set_src(obj);
		}
	}

	void set_dstobj(RObject *obj) const {
		if(PrtObjs_) {
			PrtObjs_->set_dst(obj);
		}
	}

	McTopHdr_UDPLite(CSTR);
virtual ~McTopHdr_UDPLite();
static	McTopHdr_UDPLite* create(CSTR);
	int32_t headerType()const{return TP_Upp_UDPLite;}
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
virtual uint16_t CsCov_for_reverse(RControl&,ItPosition&,OCTBUF&) const;
//HardCording action method

	public:
		virtual RObject *reverse(RControl &, RObject *, ItPosition &, OCTBUF &) const;
		void upperProto_set_Object(RObject *) const;
		const RObject *get_srcobj() const;
		const RObject *get_dstobj() const;
		DEC_HCGENE(SourcePort);
		DEC_HCEVAL(SourcePort);
		DEC_HCGENE(DestinationPort);
		DEC_HCEVAL(DestinationPort);
};

inline const RObject *McTopHdr_UDPLite::get_srcobj() const {
	if(!PrtObjs_) {
		return(0);
	}

	return(PrtObjs_->get_src());
}

inline const RObject *McTopHdr_UDPLite::get_dstobj() const {
	if(!PrtObjs_) {
		return(0);
	}

	return(PrtObjs_->get_dst());
}
//////////////////////////////////////////////////////////////////////////////
#endif
