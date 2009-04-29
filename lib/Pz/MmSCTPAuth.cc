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
#include "MmSCTPAuth.h"
#include "PControl.h"
#include "RObject.h"
#include "WObject.h"
#include "PvObject.h"
#include "PvOctets.h"
#include "CmMain.h"
#include <stdio.h>
#include <string.h>

//////////////////////////////////////////////////////////////////////////////
MmSCTPAuth::MmSCTPAuth(CSTR key, bool evalskip):MmObject(key), evalskip_(evalskip){}
MmSCTPAuth::~MmSCTPAuth() {}

int32_t MmSCTPAuth::token() const{
	return metaToken(tkn_data_);
}

uint32_t MmSCTPAuth::objectLength(const PObject* o, const WObject* w) const {
	return o != 0 ? o->objectLength(w) : 0;
}

bool MmSCTPAuth::encodeOctets(WControl&, const ItPosition& at,
				OCTBUF& dst, const PvOctets& elm) const {
	dst.encode(at, elm);
	return true;
}

uint32_t MmSCTPAuth::length_for_reverse(
		RControl&, ItPosition& at, OCTBUF& buf) const {
	return buf.remainLength(at.bytes());
}

RObject* MmSCTPAuth::reverse(RControl& c,
		RObject* r_parent, ItPosition& at, OCTBUF& buf) const {
	const MObject* m_parent = r_parent ? r_parent->meta() : 0;
	uint32_t length = length_for_reverse(c,at,buf);
	if(evalskip_ && !length)
		return 0;	//useless reverse
	ItPosition size(length, 0);
	if(!check_decode_limit(m_parent, at, buf, size)){
		c.set_error(1);
		return 0;
	}
	PvObject* pv = buf.substr(at.bytes(), length);
	RObject* r_self = reverseRm(c, r_parent, at, size, pv);
	at += size;
	return r_self;
}

void MmSCTPAuth::composeList(WControl& c,
		WObject* w_parent, const PObjectList& pls) const {
	const PObject* pl =
		pls.reverseMatching(this, (PObjectEqFunc)&PObject::isEqualMeta);
	pl ? pl->selfCompose(c, w_parent) : compose(c, w_parent, 0);
}

WObject* MmSCTPAuth::compose(WControl& c,
		WObject* w_parent, const PObject* pl) const {
	const TypevsMcDict* keep = c.dict();
	c.dict_set(0);
	WObject* wm = composeWm(c, w_parent, pl);
	c.dict_set(keep);
	return wm;
}

WObject* MmSCTPAuth::composeWm(WControl&,
		WObject* w_parent, const PObject* pl)const{
	return new WmSCTPAuth(w_parent, this, pl);
}

RObject* MmSCTPAuth::reverseRm(RControl&,RObject* r_parent,
		const ItPosition& at,const ItPosition& size,PvObject* pv)const {
	return new RmObject(r_parent, this, at, size, pv);
}

bool MmSCTPAuth::generate(WControl& c,WObject* w_self,OCTBUF& buf) const {
	bool rtn = MmObject::generate(c, w_self, buf);
	if(!c.error()) {
		Con_IPinfo *info = c.IPinfo();
		const PObject* pl = w_self->object();
		if(info && pl->rvalue() && !strcmp("sctpauth", pl->rvalue()->metaString())) {
			info->postSCTPAuth(w_self);
		}
	}

        return(rtn);
}

////////////////////////////////////////////////////////////////
PfSCTPAuth::PfSCTPAuth(const MfSCTPAuth *a, CSTR b, int c): PvFunction(a, b, c), meta_(a), context_(0) {}
PfSCTPAuth::~PfSCTPAuth() {};

const MObject *PfSCTPAuth::meta() const {
	return(metaClass());
}

void PfSCTPAuth::init() {
	const MfSCTPAuth *m = metaClass();

	if (m)
		context_ = m->init(context_, args());
}

void PfSCTPAuth::update(const OCTBUF &s) {
	const MfSCTPAuth *m = metaClass();

	if (m)
		m->update(context_, args(), s);
}

PvOctets *PfSCTPAuth::result() {
	const MfSCTPAuth *m = metaClass();

	if (m)
		return m->result(context_, args());
}

///////////////////////////////////////////////////////////////////////////////

#define SUPER	WmObject
WmSCTPAuth::WmSCTPAuth(WObject* p, const MObject* m, const PObject* po) : SUPER(p, m, po) {}
WmSCTPAuth::~WmSCTPAuth() {}

void WmSCTPAuth::post_generate(Con_IPinfo& info, WControl& c, OCTBUF& buf,
		WObject* base) {
	const OCTBUF *basebuf = (const OCTBUF *)base->pvalue();
	PfSCTPAuth *pf_auth = (PfSCTPAuth *)(object()->rvalue());
	WObject *w_auth = (WObject *)info.postSCTPAuth();
	uint32_t length, offset;
	OCTBUF *calc = 0;

	if(!w_auth || !pf_auth)
		return;

	offset = w_auth->offset().bytes() - base->offset().bytes() - 8;
	length = base->size().bytes() - offset;

	OCTBUF hmacbuf(length, (OCTSTR)basebuf->string() + offset, true);

	if(pf_auth) {
		pf_auth->init();
		pf_auth->update(hmacbuf);
		calc = pf_auth->result();
	}

	if(calc) {
		set_rgenerate(calc);
		SUPER::generate(c, buf);
	}
}

bool WmSCTPAuth::doEvaluate(WControl& c,RObject& r) {
	RmObject& rm = (RmObject &)r;
	const PvObject* ro = rm.pvalue();
	const PvObject* eo = revaluate();
	if (!eo) eo = ro;
	return valueEvaluate(c, ro, eo);
}

#undef SUPER
