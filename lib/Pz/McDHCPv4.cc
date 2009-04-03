/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009 Fujitsu Limited.
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
#include "McSub.h"
#include "MmHeader.h"
#include "MmData.h"
#include "ItPosition.h"
#include "WObject.h"
#include "RObject.h"
#include "PControl.h"
#include "PvObject.h"
#include "PvOctets.h"
#include "McDHCPv4.h"
#include <stdio.h>
#include <string.h>

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

#if 0
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef dbg
#define dbg(file, fmt, args...) \
{ \
FILE *stream = fopen(file, "a"); \
if(stream) { \
fprintf(stream, "dbg[%d]: %s: %d: " fmt, getpid(), __FILE__, __LINE__, ##args); \
fclose(stream); \
} \
}
#endif
#else
#define dbg(file, fmt, args...)
#endif

////////////////////////////////////////////////////////////////
#define SUPER McHeader
McUdp_DHCPv4_ONE* McUdp_DHCPv4_ONE::instance_ = 0;

McUdp_DHCPv4_ONE* McUdp_DHCPv4_ONE::instance() {
	if(!instance_) {
		instance_ = new McUdp_DHCPv4_ONE("DHCPv4");
	}

	return(instance_);
}

McUdp_DHCPv4_ONE::McUdp_DHCPv4_ONE(CSTR key): SUPER(key) {
	member(new MmHeader_onDHCPv4("header"));

	MmUpper_onUpper::add(this);
}

McUdp_DHCPv4_ONE::~McUdp_DHCPv4_ONE() {}

bool McUdp_DHCPv4_ONE::containsMc(const MObject *mc) const {
	bool rtn = SUPER::containsMc(mc);

	return(rtn ? rtn : members_[0]->containsMc(mc));
}

uint32_t McUdp_DHCPv4_ONE::length_for_reverse(RControl &, ItPosition &at, OCTBUF &buf) const {
	return(buf.remainLength(at.bytes()));
}

RObject *McUdp_DHCPv4_ONE::reverse(RControl &c, RObject *r_parent, ItPosition &at, OCTBUF &buf) const {
	return(members_[0]->reverse(c, r_parent, at, buf));
}
#undef SUPER

////////////////////////////////////////////////////////////////
#define SUPER   McHeader
McUdp_DHCPv4::McUdp_DHCPv4(CSTR key): SUPER(key), type_(0) {
	McUdp_DHCPv4_ONE::instance();
}

McUdp_DHCPv4::~McUdp_DHCPv4() {}

int32_t McUdp_DHCPv4::token() const {
	return(metaToken(tkn_upper_));
}

uint32_t McUdp_DHCPv4::length_for_reverse(RControl &, ItPosition &at, OCTBUF &buf) const {
	return(buf.remainLength(at.bytes()));
}

bool McUdp_DHCPv4::overwrite_DictType(RControl &c, ItPosition &at, OCTBUF &buf) const {
	if(buf.remainLength(at.bytes())) {
		ItPosition tmpat = at;
		RObject *rtype = type_->reverse(c, 0, tmpat, buf);

		if(!rtype) {
			return(false);
		}

		const PvNumber *pv = (const PvNumber *)rtype->pvalue();

		uint32_t typevalue = pv->value();

		c.DictType().type_Set(typevalue);

		delete(rtype);

		return(true);
	}

	return(false);
}

bool McUdp_DHCPv4::HCGENE(Type)(WControl &cntr, WObject *wmem, OCTBUF &buf) const {
	int32_t val = get_dhcpv4Type(wmem);
	if(val < 0) {
		return(false);
	}

	PvNumber def(val);
	return(def.generate(cntr, wmem, buf));
}

PObject *McUdp_DHCPv4::HCEVAL(Type)(WObject *wmem) const {
	int32_t val = get_dhcpv4Type(wmem);
	return(new PvNumber(val));
}

int32_t McUdp_DHCPv4::get_dhcpv4Type(WObject *wmem) const {
	WObject *wc = wmem->parent();
	int32_t rtn = wc ? wc->meta()->dhcpv4Type() : -1;

	if(rtn < 0) {
		wmem->mustDefine(0);
	}

	return(rtn);
}

RObject *McUdp_DHCPv4::reverse(RControl &c, RObject *r_parent, ItPosition &at, OCTBUF &buf) const {
	return SUPER::reverse(c,r_parent,at,buf);
}

bool McUdp_DHCPv4::generate(WControl &c, WObject *w_self, OCTBUF &buf) const {
	return SUPER::generate(c, w_self, buf);
}

#undef SUPER

////////////////////////////////////////////////////////////////
McUdp_DHCPv4_ANY::McUdp_DHCPv4_ANY(CSTR key): McUdp_DHCPv4(key) {}
McUdp_DHCPv4_ANY::~McUdp_DHCPv4_ANY() {}

////////////////////////////////////////////////////////////////
McUdp_DHCPv4_BootRequest::McUdp_DHCPv4_BootRequest(CSTR key): McUdp_DHCPv4(key) {}
McUdp_DHCPv4_BootRequest::~McUdp_DHCPv4_BootRequest() {}

////////////////////////////////////////////////////////////////
McUdp_DHCPv4_BootReply::McUdp_DHCPv4_BootReply(CSTR key): McUdp_DHCPv4(key) {}
McUdp_DHCPv4_BootReply::~McUdp_DHCPv4_BootReply() {}

////////////////////////////////////////////////////////////////
MmHeader_onDHCPv4::MmHeader_onDHCPv4(CSTR key): MmReference_Less1(key, true) {}

MmHeader_onDHCPv4::~MmHeader_onDHCPv4() {}

void MmHeader_onDHCPv4::add(McUdp_DHCPv4 *mc) {
	dict_.add(mc->dhcpv4Type(), mc);
}

void MmHeader_onDHCPv4::add_other(McUdp_DHCPv4 *mc) {
	dict_.add_other(mc);
}

TypevsMcDict MmHeader_onDHCPv4::dict_;

bool MmHeader_onDHCPv4::overwrite_DictType(RControl &c, ItPosition &at, OCTBUF &buf) const {
	if(buf.remainLength(at.bytes())) {
		McUdp_DHCPv4 *any = (McUdp_DHCPv4 *)dict_.find_other();
		return(any->overwrite_DictType(c, at, buf));
	}

	return(false);
}

////////////////////////////////////////////////////////////////
MmOption_onDHCPv4::MmOption_onDHCPv4(CSTR key): MmReference_More0(key, true) {}
MmOption_onDHCPv4::~MmOption_onDHCPv4() {}

void MmOption_onDHCPv4::add(McOpt_DHCPv4 *mc) {
	dict_.add(mc->optionCode(), mc);
}

void MmOption_onDHCPv4::add_other(McOpt_DHCPv4 *mc) {
	dict_.add_other(mc);
}

TypevsMcDict MmOption_onDHCPv4::dict_;

bool MmOption_onDHCPv4::overwrite_DictType(RControl &c, ItPosition &at, OCTBUF &buf) const {
	if(buf.remainLength(at.bytes())) {
		McOpt_DHCPv4 *any = (McOpt_DHCPv4 *)dict_.find_other();

		return(any->overwrite_DictType(c, at, buf));
	}

	return(false);
}

////////////////////////////////////////////////////////////////
#define DEF_LENGTH_OFFSET_OptDHCPv4	2

McOpt_DHCPv4::McOpt_DHCPv4(CSTR key): McOption(key), code_(0), length_(0) {}
McOpt_DHCPv4::~McOpt_DHCPv4() {}

uint32_t McOpt_DHCPv4::length_for_reverse(RControl &c, ItPosition &at, OCTBUF &buf) const {
	if(!length_) {
		return(McOption::length_for_reverse(c, at, buf));
	}

	uint32_t valulen = length_->value(at, buf);
	uint32_t length = valulen + DEF_LENGTH_OFFSET_OptDHCPv4;

	return(length);
}

bool McOpt_DHCPv4::overwrite_DictType(RControl &c, ItPosition &at, OCTBUF &buf) const {
	if(buf.remainLength(at.bytes())) {
		ItPosition tmpat = at;

		RObject *rcode = code_->reverse(c, 0, tmpat,buf);
		if(!rcode) {
			return(false);
		}

		const PvNumber *pv = (const PvNumber *)rcode->pvalue();
		uint32_t codevalue = pv->value();
		c.DictType().type_Set(codevalue);

		delete(rcode);

		return(true);
	}

	return(false);
}

bool McOpt_DHCPv4::HCGENE(Length)(WControl &cntr, WObject *wmem, OCTBUF &buf) const {
	WObject *wc = wmem->parent();

	uint32_t reallen = wc->size().bytes();
	uint32_t valulen = reallen - DEF_LENGTH_OFFSET_OptDHCPv4;

	PvNumber def(valulen);

	return(def.generate(cntr, wmem, buf));
}
#undef DEF_LENGTH_OFFSET_OptDHCPv4

bool McOpt_DHCPv4::HCGENE(Code)(WControl &cntr, WObject *wmem, OCTBUF &buf) const {
	int32_t val = get_optionCode(wmem);
	if(val < 0) {
		return(false);
	}

	PvNumber def(val);
	return(def.generate(cntr, wmem, buf));
}

PObject *McOpt_DHCPv4::HCEVAL(Code)(WObject *wmem) const {
	int32_t val = get_optionCode(wmem);
	return(new PvNumber(val));
}

int32_t McOpt_DHCPv4::get_optionCode(WObject *wmem) const {
	WObject *wc = wmem->parent();
	int32_t rtn = wc ? wc->meta()->optionCode() : -1;

	if(rtn < 0) {
		wmem->mustDefine(0);
	}

	return(rtn);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_ANY::McOpt_DHCPv4_ANY(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_ANY::~McOpt_DHCPv4_ANY() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_Pad::McOpt_DHCPv4_Pad(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_Pad::~McOpt_DHCPv4_Pad() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_End::McOpt_DHCPv4_End(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_End::~McOpt_DHCPv4_End() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_SubnetMask::McOpt_DHCPv4_SubnetMask(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_SubnetMask::~McOpt_DHCPv4_SubnetMask() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_TimeOffset::McOpt_DHCPv4_TimeOffset(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_TimeOffset::~McOpt_DHCPv4_TimeOffset() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_Router::McOpt_DHCPv4_Router(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_Router::~McOpt_DHCPv4_Router() {}

uint32_t McOpt_DHCPv4_Router::HC_MLC(Address)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t count = (buf.remainLength(at.bytes()) - 2) / 4;

	return(count);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_TimeServer::McOpt_DHCPv4_TimeServer(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_TimeServer::~McOpt_DHCPv4_TimeServer() {}

uint32_t McOpt_DHCPv4_TimeServer::HC_MLC(Address)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t count = (buf.remainLength(at.bytes()) - 2) / 4;

	return(count);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_NameServer::McOpt_DHCPv4_NameServer(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_NameServer::~McOpt_DHCPv4_NameServer() {}

uint32_t McOpt_DHCPv4_NameServer::HC_MLC(Address)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t count = (buf.remainLength(at.bytes()) - 2) / 4;

	return(count);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_DomainNameServer::McOpt_DHCPv4_DomainNameServer(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_DomainNameServer::~McOpt_DHCPv4_DomainNameServer() {}

uint32_t McOpt_DHCPv4_DomainNameServer::HC_MLC(Address)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t count = (buf.remainLength(at.bytes()) - 2) / 4;

	return(count);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_LogServer::McOpt_DHCPv4_LogServer(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_LogServer::~McOpt_DHCPv4_LogServer() {}

uint32_t McOpt_DHCPv4_LogServer::HC_MLC(Address)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t count = (buf.remainLength(at.bytes()) - 2) / 4;

	return(count);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_CookieServer::McOpt_DHCPv4_CookieServer(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_CookieServer::~McOpt_DHCPv4_CookieServer() {}

uint32_t McOpt_DHCPv4_CookieServer::HC_MLC(Address)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t count = (buf.remainLength(at.bytes()) - 2) / 4;

	return(count);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_LPRServer::McOpt_DHCPv4_LPRServer(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_LPRServer::~McOpt_DHCPv4_LPRServer() {}

uint32_t McOpt_DHCPv4_LPRServer::HC_MLC(Address)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t count = (buf.remainLength(at.bytes()) - 2) / 4;

	return(count);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_ImpressServer::McOpt_DHCPv4_ImpressServer(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_ImpressServer::~McOpt_DHCPv4_ImpressServer() {}

uint32_t McOpt_DHCPv4_ImpressServer::HC_MLC(Address)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t count = (buf.remainLength(at.bytes()) - 2) / 4;

	return(count);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_ResourceLocationServer::McOpt_DHCPv4_ResourceLocationServer(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_ResourceLocationServer::~McOpt_DHCPv4_ResourceLocationServer() {}

uint32_t McOpt_DHCPv4_ResourceLocationServer::HC_MLC(Address)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t count = (buf.remainLength(at.bytes()) - 2) / 4;

	return(count);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_HostName::McOpt_DHCPv4_HostName(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_HostName::~McOpt_DHCPv4_HostName() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_BootFileSize::McOpt_DHCPv4_BootFileSize(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_BootFileSize::~McOpt_DHCPv4_BootFileSize() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_MeritDumpFile::McOpt_DHCPv4_MeritDumpFile(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_MeritDumpFile::~McOpt_DHCPv4_MeritDumpFile() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_DomainName::McOpt_DHCPv4_DomainName(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_DomainName::~McOpt_DHCPv4_DomainName() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_SwapServer::McOpt_DHCPv4_SwapServer(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_SwapServer::~McOpt_DHCPv4_SwapServer() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_RootPath::McOpt_DHCPv4_RootPath(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_RootPath::~McOpt_DHCPv4_RootPath() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_ExtensionsPath::McOpt_DHCPv4_ExtensionsPath(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_ExtensionsPath::~McOpt_DHCPv4_ExtensionsPath() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_NISDomainName::McOpt_DHCPv4_NISDomainName(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_NISDomainName::~McOpt_DHCPv4_NISDomainName() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_RequestedIPAddress::McOpt_DHCPv4_RequestedIPAddress(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_RequestedIPAddress::~McOpt_DHCPv4_RequestedIPAddress() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_IPAddressLeaseTime::McOpt_DHCPv4_IPAddressLeaseTime(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_IPAddressLeaseTime::~McOpt_DHCPv4_IPAddressLeaseTime() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_OptionOverload::McOpt_DHCPv4_OptionOverload(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_OptionOverload::~McOpt_DHCPv4_OptionOverload() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_TFTPServerName::McOpt_DHCPv4_TFTPServerName(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_TFTPServerName::~McOpt_DHCPv4_TFTPServerName() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_BootfileName::McOpt_DHCPv4_BootfileName(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_BootfileName::~McOpt_DHCPv4_BootfileName() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_MessageType::McOpt_DHCPv4_MessageType(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_MessageType::~McOpt_DHCPv4_MessageType() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_SID::McOpt_DHCPv4_SID(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_SID::~McOpt_DHCPv4_SID() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_ParameterRequestList::McOpt_DHCPv4_ParameterRequestList(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_ParameterRequestList::~McOpt_DHCPv4_ParameterRequestList() {}

uint32_t McOpt_DHCPv4_ParameterRequestList::HC_MLC(OptionCode)(const ItPosition &at, OCTBUF &buf) const {
	uint32_t count = buf.remainLength(at.bytes()) - 2;

	return(count);
}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_Message::McOpt_DHCPv4_Message(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_Message::~McOpt_DHCPv4_Message() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_MaxMessageSize::McOpt_DHCPv4_MaxMessageSize(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_MaxMessageSize::~McOpt_DHCPv4_MaxMessageSize() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_RenewalTimeValue::McOpt_DHCPv4_RenewalTimeValue(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_RenewalTimeValue::~McOpt_DHCPv4_RenewalTimeValue() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_RebindingTimeValue::McOpt_DHCPv4_RebindingTimeValue(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_RebindingTimeValue::~McOpt_DHCPv4_RebindingTimeValue() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_VendorClass::McOpt_DHCPv4_VendorClass(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_VendorClass::~McOpt_DHCPv4_VendorClass() {}

////////////////////////////////////////////////////////////////
McOpt_DHCPv4_CID::McOpt_DHCPv4_CID(CSTR key): McOpt_DHCPv4(key) {}
McOpt_DHCPv4_CID::~McOpt_DHCPv4_CID() {}

////////////////////////////////////////////////////////////////
MmDHCPv4String::MmDHCPv4String(CSTR s, uint32_t l, const PObject *g, const PObject *e): MmOctets(s, l, g, e, 0, 0) {}
MmDHCPv4String::~MmDHCPv4String() {}

PvObject *MmDHCPv4String::reversePv(RControl &, const ItPosition &at, const ItPosition &size, const OCTBUF &buf) const {
	uint32_t offset = at.bytes();
	uint32_t length = size.bytes();
	return(new PvDHCPv4String(length, (OCTSTR)buf.string(offset)));
}

////////////////////////////////////////////////////////////////
PvDHCPv4String::PvDHCPv4String(): PvOctets() {}
PvDHCPv4String::PvDHCPv4String(uint32_t l, OCTSTR o, bool b): PvOctets(l, o, b) {}
PvDHCPv4String::~PvDHCPv4String() {}

PvObject *PvDHCPv4String::shallowCopy() const {
	return(new PvDHCPv4String(length(), (OCTSTR)string()));
}

void PvDHCPv4String::log(uint32_t t) const {
	dump("\nlog:  ");
}

void PvDHCPv4String::print() const {
	dump();
}

void PvDHCPv4String::dump(CSTR tag) const {
	int i, i9 = length();
	COCTSTR s = string();

	if(s[0] == '\0') {
		printf("NULL");
		return;
	}

	printf("ascii(");
	for(i = 0; i < i9; i++) {
		if(s[i] == '\0') {
			break;
		}
		printf("%.01s", &s[i]);
	}
	printf(")");
}

////////////////////////////////////////////////////////////////
MmDHCPv4VarString::MmDHCPv4VarString(CSTR s, const PObject *g, const PObject *e): MmVarOctets(s, g, e, 0, 0) {}
MmDHCPv4VarString::~MmDHCPv4VarString() {}

PvObject *MmDHCPv4VarString::reversePv(RControl &, const ItPosition &at, const ItPosition &size, const OCTBUF &buf) const {
	uint32_t offset = at.bytes();
	uint32_t length = size.bytes();
	return(new PvDHCPv4VarString(length, (OCTSTR)buf.string(offset)));
}

////////////////////////////////////////////////////////////////
PvDHCPv4VarString::PvDHCPv4VarString(): PvOctets() {}
PvDHCPv4VarString::PvDHCPv4VarString(uint32_t l, OCTSTR o, bool b): PvOctets(l, o, b) {}
PvDHCPv4VarString::~PvDHCPv4VarString() {}

PvObject *PvDHCPv4VarString::shallowCopy() const {
	return(new PvDHCPv4String(length(), (OCTSTR)string()));
}

void PvDHCPv4VarString::log(uint32_t t) const {
	dump("\nlog:  ");
}

void PvDHCPv4VarString::print() const {
	dump();
}

void PvDHCPv4VarString::dump(CSTR tag) const {
	int i, i9 = length();
	COCTSTR s = string();

	if(s[0] == '\0') {
		printf("NULL");
		return;
	}

	printf("ascii(");
	for(i = 0; i < i9; i++)
		printf("%.01s", &s[i]);
	printf(")");
}

////////////////////////////////////////////////////////////////
MmDHCPv4HWAddr::MmDHCPv4HWAddr(CSTR s, const PObject *g, const PObject *e): MmOctets(s, 16, g, e, 0, 0) {}
MmDHCPv4HWAddr::~MmDHCPv4HWAddr() {}

PvObject *MmDHCPv4HWAddr::reversePv(RControl &, const ItPosition &at, const ItPosition &size, const OCTBUF &buf) const {
	uint32_t offset = at.bytes();
	uint32_t length = size.bytes();
	return(new PvDHCPv4HWAddr(length, (OCTSTR)buf.string(offset)));
}

////////////////////////////////////////////////////////////////
PvDHCPv4HWAddr::PvDHCPv4HWAddr(): PvOctets() {}
PvDHCPv4HWAddr::PvDHCPv4HWAddr(uint32_t l, OCTSTR o, bool b): PvOctets(l, o, b) {}
PvDHCPv4HWAddr::~PvDHCPv4HWAddr() {}

PvObject *PvDHCPv4HWAddr::shallowCopy() const {
	return(new PvDHCPv4HWAddr(length(), (OCTSTR)string()));
}

void PvDHCPv4HWAddr::log(uint32_t t) const {
	dump("\nlog:  ");
}

void PvDHCPv4HWAddr::print() const {
	dump();
}

void PvDHCPv4HWAddr::dump(CSTR tag) const {
	int i, i9 = length();
	COCTSTR s = string();

	for(i = 0; i < i9; i++) {
		if(i != 0) {
			printf(":");
		}

		printf("%02x", s[i]&0xff);
	}
}

////////////////////////////////////////////////////////////////
MmDHCPv4MessageType::MmDHCPv4MessageType(CSTR s, uint16_t n, const PObject* g,
	const PObject* e): MmUint(s, n, g, e, 0, 0) {}

MmDHCPv4MessageType::~MmDHCPv4MessageType() {}

PvObject *MmDHCPv4MessageType::reversePv(RControl &, const ItPosition &at, const ItPosition &size, const OCTBUF &buf) const {
	uint32_t val = decode(at,buf);
	return(new PvDHCPv4MessageType(val));
}

////////////////////////////////////////////////////////////////
PvDHCPv4MessageType::PvDHCPv4MessageType(): PvNumber() {}
PvDHCPv4MessageType::PvDHCPv4MessageType(int32_t x): PvNumber(x) {}
PvDHCPv4MessageType::~PvDHCPv4MessageType() {}

void PvDHCPv4MessageType::print() const {
	printf("%u", ((uint32_t)value() & 0xff));
	switch(value() & 0xff) {
		case 1: printf(" (DHCPDISCOVER)"); break;
		case 2: printf(" (DHCPOFFER)"); break;
		case 3: printf(" (DHCPREQUEST)"); break;
		case 4: printf(" (DHCPDECLINE)"); break;
		case 5: printf(" (DHCPACK)"); break;
		case 6: printf(" (DHCPNAK)"); break;
		case 7: printf(" (DHCPRELEASE)"); break;
		case 8: printf(" (INFORM)"); break;
		/* Unknown */
		default: printf(" (Unknown Message Type)"); break;
	}
}

//
// DHCPv4
//
////////////////////////////////////////////////////////////////

void McUdp_DHCPv4::common_member() {
	type_member(new MmUint("OpCode", 8, GENEHC(this, McUdp_DHCPv4, Type), EVALHC(this, McUdp_DHCPv4, Type)));
}

McUdp_DHCPv4_ANY *McUdp_DHCPv4_ANY::create(CSTR key) {
	McUdp_DHCPv4_ANY *mc = new McUdp_DHCPv4_ANY(key);

	mc->common_member();

	mc->member(new MmData("data"));

	MmHeader_onDHCPv4::add_other(mc);

	return(mc);
}

#define MAGIC_COOKIE 0x63825363

McUdp_DHCPv4_BootRequest *McUdp_DHCPv4_BootRequest::create(CSTR key) {
	McUdp_DHCPv4_BootRequest *mc = new McUdp_DHCPv4_BootRequest(key);

	mc->common_member();

	mc->member(new MmUint("HardwareType", 8, UN(1), UN(1)));
	mc->member(new MmUint("HardwareAddressLength", 8, UN(6), UN(6)));
	mc->member(new MmUint("Hops", 8, UN(0), UN(0)));
	mc->member(new MmUint("TransactionID", 32, UN(0), UN(0)));
	mc->member(new MmUint("Seconds", 16, UN(0), UN(0)));
	mc->member(new MmUint("Flags", 16, UN(0), UN(0)));
	mc->member(new MmV4Addr("ClientIPAddress", UN(0), UN(0)));
	mc->member(new MmV4Addr("YourIPAddress", UN(0), UN(0)));
	mc->member(new MmV4Addr("ServerIPAddress", UN(0), UN(0)));
	mc->member(new MmV4Addr("RelayIPAddress", UN(0), UN(0)));
	mc->member(new MmDHCPv4HWAddr("ClientEthernetAddress", UN(0), UN(0)));
	mc->member(new MmDHCPv4String("ServerHostName", 64, UN(0), UN(0)));
	mc->member(new MmDHCPv4String("BootFileName", 128, UN(0), UN(0)));
	mc->member(new MmUint("MagicCookie", 32, UN(MAGIC_COOKIE), UN(MAGIC_COOKIE)));

	mc->member(new MmOption_onDHCPv4("option"));

	MmHeader_onDHCPv4::add(mc);

	return(mc);
}

McUdp_DHCPv4_BootReply *McUdp_DHCPv4_BootReply::create(CSTR key) {
	McUdp_DHCPv4_BootReply *mc = new McUdp_DHCPv4_BootReply(key);

	mc->common_member();

	mc->member(new MmUint("HardwareType", 8, UN(1), UN(1)));
	mc->member(new MmUint("HardwareAddressLength", 8, UN(6), UN(6)));
	mc->member(new MmUint("Hops", 8, UN(0), UN(0)));
	mc->member(new MmUint("TransactionID", 32, UN(0), UN(0)));
	mc->member(new MmUint("Seconds", 16, UN(0), UN(0)));
	mc->member(new MmUint("Flags", 16, UN(0), UN(0)));
	mc->member(new MmV4Addr("ClientIPAddress", UN(0), UN(0)));
	mc->member(new MmV4Addr("YourIPAddress", UN(0), UN(0)));
	mc->member(new MmV4Addr("ServerIPAddress", UN(0), UN(0)));
	mc->member(new MmV4Addr("RelayIPAddress", UN(0), UN(0)));
	mc->member(new MmDHCPv4HWAddr("ClientEthernetAddress", UN(0), UN(0)));
	mc->member(new MmDHCPv4String("ServerHostName", 64, UN(0), UN(0)));
	mc->member(new MmDHCPv4String("BootFileName", 128, UN(0), UN(0)));
	mc->member(new MmUint("MagicCookie", 32, UN(MAGIC_COOKIE), UN(MAGIC_COOKIE)));

	mc->member(new MmOption_onDHCPv4("option"));

	MmHeader_onDHCPv4::add(mc);

	return(mc);
}

//
// DHCP options
//
////////////////////////////////////////////////////////////////

void McOpt_DHCPv4::common_member() {
	code_member(new MmUint("Code", 8, GENEHC(this, McOpt_DHCPv4, Code), EVALHC(this, McOpt_DHCPv4, Code)));
	length_member(new MmUint("Len", 8, GENEHC(this, McOpt_DHCPv4, Length), EVALANY()));
}

McOpt_DHCPv4_ANY *McOpt_DHCPv4_ANY::create(CSTR key) {
	McOpt_DHCPv4_ANY *mc = new McOpt_DHCPv4_ANY(key);

	mc->common_member();
	mc->member(new MmData("data"));

	MmOption_onDHCPv4::add_other(mc);

	return(mc);
}

//
// Pad Option
//
////////////////////////////////

McOpt_DHCPv4_Pad *McOpt_DHCPv4_Pad::create(CSTR key) {
	McOpt_DHCPv4_Pad *mc = new McOpt_DHCPv4_Pad(key);

	mc->code_member(new MmUint("Code", 8, GENEHC(mc, McOpt_DHCPv4, Code), EVALHC(mc, McOpt_DHCPv4, Code)));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// End Option
//
////////////////////////////////

McOpt_DHCPv4_End *McOpt_DHCPv4_End::create(CSTR key) {
	McOpt_DHCPv4_End *mc = new McOpt_DHCPv4_End(key);

	mc->code_member(new MmUint("Code", 8, GENEHC(mc, McOpt_DHCPv4, Code), EVALHC(mc, McOpt_DHCPv4, Code)));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Subnet Mask Option
//
////////////////////////////////

McOpt_DHCPv4_SubnetMask *McOpt_DHCPv4_SubnetMask::create(CSTR key) {
	McOpt_DHCPv4_SubnetMask *mc = new McOpt_DHCPv4_SubnetMask(key);

	mc->common_member();
	mc->member(new MmV4Addr("SubnetMask", UN(0), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Time Offset Option
//
////////////////////////////////
McOpt_DHCPv4_TimeOffset *McOpt_DHCPv4_TimeOffset::create(CSTR key) {
	McOpt_DHCPv4_TimeOffset *mc = new McOpt_DHCPv4_TimeOffset(key);

	mc->common_member();
	mc->member(new MmUint("TimeOffset", 32,  UN(0), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Router Option
//
////////////////////////////////

McOpt_DHCPv4_Router *McOpt_DHCPv4_Router::create(CSTR key) {
	McOpt_DHCPv4_Router *mc = new McOpt_DHCPv4_Router(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmV4Addr("Address", MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DHCPv4_Router::HC_MLC(Address)
		)
	);

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Time Server Option
//
////////////////////////////////

McOpt_DHCPv4_TimeServer *McOpt_DHCPv4_TimeServer::create(CSTR key) {
	McOpt_DHCPv4_TimeServer *mc = new McOpt_DHCPv4_TimeServer(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmV4Addr("Address", MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DHCPv4_TimeServer::HC_MLC(Address)
		)
	);

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Name Server Option
//
////////////////////////////////

McOpt_DHCPv4_NameServer *McOpt_DHCPv4_NameServer::create(CSTR key) {
	McOpt_DHCPv4_NameServer *mc = new McOpt_DHCPv4_NameServer(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmV4Addr("Address", MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DHCPv4_NameServer::HC_MLC(Address)
		)
	);

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Domain Name Server Option
//
////////////////////////////////

McOpt_DHCPv4_DomainNameServer *McOpt_DHCPv4_DomainNameServer::create(CSTR key) {
	McOpt_DHCPv4_DomainNameServer *mc = new McOpt_DHCPv4_DomainNameServer(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmV4Addr("Address", MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DHCPv4_DomainNameServer::HC_MLC(Address)
		)
	);

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Log Server Option
//
////////////////////////////////

McOpt_DHCPv4_LogServer *McOpt_DHCPv4_LogServer::create(CSTR key) {
	McOpt_DHCPv4_LogServer *mc = new McOpt_DHCPv4_LogServer(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmV4Addr("Address", MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DHCPv4_LogServer::HC_MLC(Address)
		)
	);

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Cookie Server Option
//
////////////////////////////////

McOpt_DHCPv4_CookieServer *McOpt_DHCPv4_CookieServer::create(CSTR key) {
	McOpt_DHCPv4_CookieServer *mc = new McOpt_DHCPv4_CookieServer(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmV4Addr("Address", MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DHCPv4_CookieServer::HC_MLC(Address)
		)
	);

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// LPR Server Option
//
////////////////////////////////

McOpt_DHCPv4_LPRServer *McOpt_DHCPv4_LPRServer::create(CSTR key) {
	McOpt_DHCPv4_LPRServer *mc = new McOpt_DHCPv4_LPRServer(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmV4Addr("Address", MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DHCPv4_LPRServer::HC_MLC(Address)
		)
	);

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Impress Server Option
//
////////////////////////////////

McOpt_DHCPv4_ImpressServer *McOpt_DHCPv4_ImpressServer::create(CSTR key) {
	McOpt_DHCPv4_ImpressServer *mc = new McOpt_DHCPv4_ImpressServer(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmV4Addr("Address", MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DHCPv4_ImpressServer::HC_MLC(Address)
		)
	);

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Resource Location Server Option
//
////////////////////////////////

McOpt_DHCPv4_ResourceLocationServer *McOpt_DHCPv4_ResourceLocationServer::create(CSTR key) {
	McOpt_DHCPv4_ResourceLocationServer *mc = new McOpt_DHCPv4_ResourceLocationServer(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmV4Addr("Address", MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DHCPv4_ResourceLocationServer::HC_MLC(Address)
		)
	);

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Host Name Option
//
////////////////////////////////

McOpt_DHCPv4_HostName *McOpt_DHCPv4_HostName::create(CSTR key) {
	McOpt_DHCPv4_HostName *mc = new McOpt_DHCPv4_HostName(key);

	mc->common_member();
	mc->member(new MmDHCPv4VarString("HostName", MUST(), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Boot File Size Option
//
////////////////////////////////

McOpt_DHCPv4_BootFileSize *McOpt_DHCPv4_BootFileSize::create(CSTR key) {
	McOpt_DHCPv4_BootFileSize *mc = new McOpt_DHCPv4_BootFileSize(key);

	mc->common_member();
	mc->member(new MmUint("FileSize", 16, UN(0), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Merit Dump File Option
//
////////////////////////////////

McOpt_DHCPv4_MeritDumpFile *McOpt_DHCPv4_MeritDumpFile::create(CSTR key) {
	McOpt_DHCPv4_MeritDumpFile *mc = new McOpt_DHCPv4_MeritDumpFile(key);

	mc->common_member();
	mc->member(new MmDHCPv4VarString("DumpFilePathname", MUST(), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Domain Name Option
//
////////////////////////////////

McOpt_DHCPv4_DomainName *McOpt_DHCPv4_DomainName::create(CSTR key) {
	McOpt_DHCPv4_DomainName *mc = new McOpt_DHCPv4_DomainName(key);

	mc->common_member();
	mc->member(new MmDHCPv4VarString("DomainName", MUST(), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Swap Server Option
//
////////////////////////////////

McOpt_DHCPv4_SwapServer *McOpt_DHCPv4_SwapServer::create(CSTR key) {
	McOpt_DHCPv4_SwapServer *mc = new McOpt_DHCPv4_SwapServer(key);

	mc->common_member();
	mc->member(new MmV4Addr("SwapServerAddress", UN(0), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Root Path Option
//
////////////////////////////////

McOpt_DHCPv4_RootPath *McOpt_DHCPv4_RootPath::create(CSTR key) {
	McOpt_DHCPv4_RootPath *mc = new McOpt_DHCPv4_RootPath(key);

	mc->common_member();
	mc->member(new MmDHCPv4VarString("RootPath", MUST(), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Extensions Path Option
//
////////////////////////////////

McOpt_DHCPv4_ExtensionsPath *McOpt_DHCPv4_ExtensionsPath::create(CSTR key) {
	McOpt_DHCPv4_ExtensionsPath *mc = new McOpt_DHCPv4_ExtensionsPath(key);

	mc->common_member();
	mc->member(new MmDHCPv4VarString("ExtensionsPath", MUST(), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

McOpt_DHCPv4_NISDomainName *McOpt_DHCPv4_NISDomainName::create(CSTR key) {
	McOpt_DHCPv4_NISDomainName *mc = new McOpt_DHCPv4_NISDomainName(key);

	mc->common_member();
	mc->member(new MmDHCPv4VarString("NISDomainName", MUST(), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Requested IP Address Option
//
////////////////////////////////

McOpt_DHCPv4_RequestedIPAddress *McOpt_DHCPv4_RequestedIPAddress::create(CSTR key) {
	McOpt_DHCPv4_RequestedIPAddress *mc = new McOpt_DHCPv4_RequestedIPAddress(key);

	mc->common_member();
	mc->member(new MmV4Addr("Address", UN(0), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// IP Address Lease Time Option
//
////////////////////////////////

McOpt_DHCPv4_IPAddressLeaseTime *McOpt_DHCPv4_IPAddressLeaseTime::create(CSTR key) {
	McOpt_DHCPv4_IPAddressLeaseTime *mc = new McOpt_DHCPv4_IPAddressLeaseTime(key);

	mc->common_member();
	mc->member(new MmUint("LeaseTime", 32, UN(0), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Option Overload Option
//
////////////////////////////////

McOpt_DHCPv4_OptionOverload *McOpt_DHCPv4_OptionOverload::create(CSTR key) {
	McOpt_DHCPv4_OptionOverload *mc = new McOpt_DHCPv4_OptionOverload(key);

	mc->common_member();
	mc->member(new MmUint("Value", 8, UN(1), UN(1)));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// TFTP Server Name Option
//
////////////////////////////////

McOpt_DHCPv4_TFTPServerName *McOpt_DHCPv4_TFTPServerName::create(CSTR key) {
	McOpt_DHCPv4_TFTPServerName *mc = new McOpt_DHCPv4_TFTPServerName(key);

	mc->common_member();
	mc->member(new MmDHCPv4VarString("TFTPServer", MUST(), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Bootfile Name Option
//
////////////////////////////////

McOpt_DHCPv4_BootfileName *McOpt_DHCPv4_BootfileName::create(CSTR key) {
	McOpt_DHCPv4_BootfileName *mc = new McOpt_DHCPv4_BootfileName(key);

	mc->common_member();
	mc->member(new MmDHCPv4VarString("BootfileName", MUST(), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// DHCP Message Type Option
//
////////////////////////////////

McOpt_DHCPv4_MessageType *McOpt_DHCPv4_MessageType::create(CSTR key) {
	McOpt_DHCPv4_MessageType *mc = new McOpt_DHCPv4_MessageType(key);

	mc->common_member();
	mc->member(new MmDHCPv4MessageType("Type", 8, UN(1), UN(1)));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Server Identifier Option
//
////////////////////////////////

McOpt_DHCPv4_SID *McOpt_DHCPv4_SID::create(CSTR key) {
	McOpt_DHCPv4_SID *mc = new McOpt_DHCPv4_SID(key);

	mc->common_member();
	mc->member(new MmV4Addr("Address", UN(0), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Parameter Request List Option
//
////////////////////////////////

McOpt_DHCPv4_ParameterRequestList *McOpt_DHCPv4_ParameterRequestList::create(CSTR key) {
	McOpt_DHCPv4_ParameterRequestList *mc = new McOpt_DHCPv4_ParameterRequestList(key);

	mc->common_member();
	mc->member(
		new MmMultiple(
			new MmUint("OptionCode", 8, MUST(), MUST()),
			(METH_HC_MLC)&McOpt_DHCPv4_ParameterRequestList::HC_MLC(OptionCode)
		)
	);

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Message Option
//
////////////////////////////////

McOpt_DHCPv4_Message *McOpt_DHCPv4_Message::create(CSTR key) {
	McOpt_DHCPv4_Message *mc = new McOpt_DHCPv4_Message(key);

	mc->common_member();
	mc->member(new MmDHCPv4VarString("Text", MUST(), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Maximum DHCP Message Size Option
//
////////////////////////////////

McOpt_DHCPv4_MaxMessageSize *McOpt_DHCPv4_MaxMessageSize::create(CSTR key) {
	McOpt_DHCPv4_MaxMessageSize *mc = new McOpt_DHCPv4_MaxMessageSize(key);

	mc->common_member();
	mc->member(new MmUint("Length", 8, UN(0), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Renewal (T1) Time Value Option
//
////////////////////////////////

McOpt_DHCPv4_RenewalTimeValue *McOpt_DHCPv4_RenewalTimeValue::create(CSTR key) {
	McOpt_DHCPv4_RenewalTimeValue *mc = new McOpt_DHCPv4_RenewalTimeValue(key);

	mc->common_member();
	mc->member(new MmUint("T1Interval", 32, UN(0), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Rebinding (T2) Time Value Option
//
////////////////////////////////

McOpt_DHCPv4_RebindingTimeValue *McOpt_DHCPv4_RebindingTimeValue::create(CSTR key) {
	McOpt_DHCPv4_RebindingTimeValue *mc = new McOpt_DHCPv4_RebindingTimeValue(key);

	mc->common_member();
	mc->member(new MmUint("T2Interval", 32, UN(0), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Vendor Class Identifier Option
//
////////////////////////////////

McOpt_DHCPv4_VendorClass *McOpt_DHCPv4_VendorClass::create(CSTR key) {
	McOpt_DHCPv4_VendorClass *mc = new McOpt_DHCPv4_VendorClass(key);

	mc->common_member();
	mc->member(new MmDHCPv4VarString("VendorClass", MUST(), EVALANY()));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}

//
// Client Identifier Option
//
////////////////////////////////

McOpt_DHCPv4_CID *McOpt_DHCPv4_CID::create(CSTR key) {
	McOpt_DHCPv4_CID *mc = new McOpt_DHCPv4_CID(key);

	mc->common_member();
	mc->member(new MmUint("Type", 8, UN(1), EVALANY()));
	mc->member(new MmData("ClientIdentifier"));

	MmOption_onDHCPv4::add(mc);

	return(mc);
}
