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

#if !defined(__MmSCTPAuth_h__)
#define __MmSCTPAuth_h__

#include "MmObject.h"
#include "RObject.h"
#include "WObject.h"
#include "PvOctets.h"
#include "MvFunction.h"

///////////////////////////////////////////////////////////////////////////////
class MmSCTPAuth : public MmObject {
	bool	evalskip_;
public:
	MmSCTPAuth(CSTR, bool evalskip=false);
virtual ~MmSCTPAuth();
	int32_t token() const;
public:
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
virtual bool encodeOctets(WControl&, const ItPosition&, OCTBUF&, const PvOctets&)const;
virtual uint32_t objectLength(const PObject*, const WObject* =0) const;
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
virtual WObject* compose(WControl&,WObject* w_parent,const PObject* pl)const;
virtual RObject* reverse(RControl&,RObject* r_parent,ItPosition&,OCTBUF&) const;
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
virtual void composeList(WControl&, WObject* w_parent, const PObjectList& pls)const;
virtual uint32_t length_for_reverse(RControl&,ItPosition& at,OCTBUF& buf)const;
//virtual PvObject *reversePv(RControl &, const ItPosition &, const ItPosition &, const OCTBUF &) const;
virtual RObject* reverseRm(RControl &, RObject *, const ItPosition &, const ItPosition &, PvObject *) const;
virtual WObject* composeWm(WControl &, WObject *, const PObject *) const;
virtual bool generate(WControl &, WObject *, OCTBUF &) const;
virtual bool disused() const {return evalskip_;}
};

////////////////////////////////////////////////////////////////
class PfSCTPAuth: public PvFunction {
private:
	const MfSCTPAuth *meta_;
	OCTSTR context_;
public:
	PfSCTPAuth(const MfSCTPAuth *, CSTR, int);
	virtual ~PfSCTPAuth();
	const MfSCTPAuth *metaClass() const;
	virtual const MObject *meta() const;
	void init();
	void update(const OCTBUF &);
	PvOctets *result();
};

inline const MfSCTPAuth *PfSCTPAuth::metaClass() const {
	return (meta_);
}

///////////////////////////////////////////////////////////////////////////////
class WmSCTPAuth : public WmObject {
public:
	WmSCTPAuth(WObject* p, const MObject* m, const PObject* po);
virtual ~WmSCTPAuth();
virtual void post_generate(Con_IPinfo&, WControl&, OCTBUF& buf, WObject* from);
virtual bool doEvaluate(WControl& c, RObject& r);
};

#endif
