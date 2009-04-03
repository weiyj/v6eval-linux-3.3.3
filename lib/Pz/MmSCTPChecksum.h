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
#if !defined(__MmSCTPChecksum_h__)
#define __MmSCTPChecksum_h__

#include "MmObject.h"
#include "RObject.h"
#include "WObject.h"

///////////////////////////////////////////////////////////////////////////////

class MmSCTPChecksum : public MmUint{
public:
	MmSCTPChecksum(CSTR s,uint16_t w,const ICVoverwriter* ow=0);
virtual ~MmSCTPChecksum();
public:
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
virtual RObject* reverseRm(RControl&,RObject* r_parent,
		const ItPosition& at,const ItPosition& size,PvObject* pv)const;
virtual WObject* composeWm(WControl& c,WObject* w_parent,
		const PObject* po)const;
virtual	RObject* reverse(RControl&,RObject* r_parent,
		ItPosition& at,OCTBUF& buf)const;
virtual bool geneAuto(WControl& c,WObject* w_self,OCTBUF& buf)const;
//
virtual void add_post(Con_IPinfo* info,TObject* self)const;
};

///////////////////////////////////////////////////////////////////////////////
class RmSCTPChecksum : public RmObject{
	PvObject*	calc_pvalue_;
public:
	RmSCTPChecksum(RObject* r_parent,const MObject* m,
		const ItPosition& offset,const ItPosition& size,PvObject* pv);
virtual	~RmSCTPChecksum();
	void set_calc_pvalue(PvObject* calc);
	PvObject* calc_pvalue()const{return calc_pvalue_;}
virtual void post_reverse(Con_IPinfo& info,RControl&,RObject* base);
virtual void printName(uint32_t t,CSTR cls) const ;
virtual void logSelf(uint32_t t,CSTR cls) const ;
};

///////////////////////////////////////////////////////////////////////////////
class WmSCTPChecksum : public WmObject{
public:
	WmSCTPChecksum(WObject* p,const MObject* m,const PObject* po);
virtual ~WmSCTPChecksum();
virtual void post_generate(Con_IPinfo&,WControl&,OCTBUF& buf,WObject* from);
virtual bool doEvaluate(WControl& c,RObject& r);
};

#endif
