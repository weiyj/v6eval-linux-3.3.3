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
#if !defined(__McDHCPv4_h__)
#define __McDHCPv4_h__	1

#include "PvOctets.h"

// DHCPv4 Message op code
const int32_t TP_DHCPv4_BootRequest	= 1;
const int32_t TP_DHCPv4_BootReply	= 2;

// DHCPv4 Options
const int32_t TP_Opt_DHCPv4_PAD			= 0;
const int32_t TP_Opt_DHCPv4_END			= 255;
const int32_t TP_Opt_DHCPv4_SubnetMask		= 1;
const int32_t TP_Opt_DHCPv4_TimeOffset		= 2;
const int32_t TP_Opt_DHCPv4_Router		= 3;
const int32_t TP_Opt_DHCPv4_TimeServer		= 4;
const int32_t TP_Opt_DHCPv4_NameServer		= 5;
const int32_t TP_Opt_DHCPv4_DomainNameServer	= 6;
const int32_t TP_Opt_DHCPv4_LogServer		= 7;
const int32_t TP_Opt_DHCPv4_CookieServer	= 8;
const int32_t TP_Opt_DHCPv4_LPRServer		= 9;
const int32_t TP_Opt_DHCPv4_ImpressServer	= 10;
const int32_t TP_Opt_DHCPv4_ResourceLocationServer = 11;
const int32_t TP_Opt_DHCPv4_HostName		= 12;
const int32_t TP_Opt_DHCPv4_BootFileSize	= 13;
const int32_t TP_Opt_DHCPv4_MeritDumpFile	= 14;
const int32_t TP_Opt_DHCPv4_DomainName		= 15;
const int32_t TP_Opt_DHCPv4_SwapServer		= 16;
const int32_t TP_Opt_DHCPv4_RootPath		= 17;
const int32_t TP_Opt_DHCPv4_ExtensionsPath	= 18;
const int32_t TP_Opt_DHCPv4_NISDomainName	= 18;

// DHCPv4 Extensions
const int32_t TP_Opt_DHCPv4_RequestedIPAddress	= 50;
const int32_t TP_Opt_DHCPv4_IPAddressLeaseTime	= 51;
const int32_t TP_Opt_DHCPv4_OptionOverload	= 52;
const int32_t TP_Opt_DHCPv4_TFTPServerName	= 66;
const int32_t TP_Opt_DHCPv4_BootfileName	= 67;
const int32_t TP_Opt_DHCPv4_MessageType		= 53;
const int32_t TP_Opt_DHCPv4_SID			= 54;
const int32_t TP_Opt_DHCPv4_ParameterRequestList= 55;
const int32_t TP_Opt_DHCPv4_Message		= 56;
const int32_t TP_Opt_DHCPv4_MaxMessageSize	= 57;
const int32_t TP_Opt_DHCPv4_RenewalTimeValue	= 58;
const int32_t TP_Opt_DHCPv4_RebindingTimeValue	= 59;
const int32_t TP_Opt_DHCPv4_VendorClass		= 60;
const int32_t TP_Opt_DHCPv4_CID			= 61;

////////////////////////////////////////////////////////////////
class McUdp_DHCPv4_ONE: public McHeader {
private:
	static McUdp_DHCPv4_ONE *instance_;
	McUdp_DHCPv4_ONE(CSTR);
public:
	virtual ~McUdp_DHCPv4_ONE();
	static McUdp_DHCPv4_ONE *instance();

	int32_t upperPort() const {
		return(TP_Udp_DHCPv4_SV);
	}

	bool containsMc(const MObject *mc) const;

	virtual uint32_t length_for_reverse(RControl &, ItPosition &, OCTBUF &) const;
	virtual RObject *reverse(RControl &, RObject *, ItPosition &, OCTBUF &) const;
};

////////////////////////////////////////////////////////////////
class McUdp_DHCPv4: public McHeader {
protected:
	MmUint* type_;

	void type_member(MmUint* meta){
		type_ = meta;
		member(meta);
	}

	void common_member();
	McUdp_DHCPv4(CSTR);
public:
	const MmUint *get_type() const {
		return(type_);
	}

	virtual ~McUdp_DHCPv4();
	virtual int32_t token() const;

	int32_t upperPort() const {
		return(TP_Udp_DHCPv4_SV);
	}

	virtual uint32_t length_for_reverse(RControl &, ItPosition &, OCTBUF &) const;
	bool overwrite_DictType(RControl &, ItPosition &, OCTBUF &) const;

	DEC_HCGENE(Type);
	DEC_HCEVAL(Type);
	int32_t get_dhcpv4Type(WObject *) const;
	virtual RObject *reverse(RControl &, RObject *, ItPosition &, OCTBUF &) const;
	virtual bool generate(WControl &, WObject *, OCTBUF &) const;
};

////////////////////////////////////////////////////////////////
class McUdp_DHCPv4_ANY: public McUdp_DHCPv4 {
public:
	McUdp_DHCPv4_ANY(CSTR);
	virtual ~McUdp_DHCPv4_ANY();
	static McUdp_DHCPv4_ANY *create(CSTR);
};

////////////////////////////////////////////////////////////////
class McUdp_DHCPv4_BootRequest: public McUdp_DHCPv4 {
public:
	McUdp_DHCPv4_BootRequest(CSTR);
	virtual ~McUdp_DHCPv4_BootRequest();
	static McUdp_DHCPv4_BootRequest *create(CSTR);

	int32_t dhcpv4Type() const {
		return(TP_DHCPv4_BootRequest);
	}

	int32_t upperPort() const {
		return(TP_Udp_DHCPv4_CL);
	}
};

////////////////////////////////////////////////////////////////
class McUdp_DHCPv4_BootReply: public McUdp_DHCPv4 {
public:
	McUdp_DHCPv4_BootReply(CSTR);
	virtual ~McUdp_DHCPv4_BootReply();
	static McUdp_DHCPv4_BootReply *create(CSTR);

	int32_t dhcpv4Type() const {
		return(TP_DHCPv4_BootReply);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4: public McOption {
protected:
	MmUint *code_;

	void code_member(MmUint *meta) {
		code_ = meta;
		member(meta);
	}

	MmUint *length_;

	void length_member(MmUint *meta) {
		length_ = meta;
		member(meta);
	}

	void common_member();
	McOpt_DHCPv4(CSTR);
public:
	virtual ~McOpt_DHCPv4();

	virtual uint32_t length_for_reverse(RControl &, ItPosition &, OCTBUF &) const;
	bool overwrite_DictType(RControl &, ItPosition &, OCTBUF &) const;
	DEC_HCGENE(Length);

	DEC_HCGENE(Code);
	DEC_HCEVAL(Code);
	int32_t get_optionCode(WObject *) const;
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_ANY: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_ANY(CSTR);
	virtual ~McOpt_DHCPv4_ANY();
	static McOpt_DHCPv4_ANY *create(CSTR);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_Pad: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_Pad(CSTR);
	virtual ~McOpt_DHCPv4_Pad();
	static McOpt_DHCPv4_Pad *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_PAD);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_End: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_End(CSTR);
	virtual ~McOpt_DHCPv4_End();
	static McOpt_DHCPv4_End *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_END);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_SubnetMask: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_SubnetMask(CSTR);
	virtual ~McOpt_DHCPv4_SubnetMask();
	static McOpt_DHCPv4_SubnetMask *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_SubnetMask);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_TimeOffset: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_TimeOffset(CSTR);
	virtual ~McOpt_DHCPv4_TimeOffset();
	static McOpt_DHCPv4_TimeOffset *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_TimeOffset);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_Router: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_Router(CSTR);
	virtual ~McOpt_DHCPv4_Router();
	static McOpt_DHCPv4_Router *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_Router);
	}
	DEC_HC_MLC(Address);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_TimeServer: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_TimeServer(CSTR);
	virtual ~McOpt_DHCPv4_TimeServer();
	static McOpt_DHCPv4_TimeServer *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_TimeServer);
	}
	DEC_HC_MLC(Address);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_NameServer: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_NameServer(CSTR);
	virtual ~McOpt_DHCPv4_NameServer();
	static McOpt_DHCPv4_NameServer *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_NameServer);
	}
	DEC_HC_MLC(Address);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_DomainNameServer: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_DomainNameServer(CSTR);
	virtual ~McOpt_DHCPv4_DomainNameServer();
	static McOpt_DHCPv4_DomainNameServer *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_DomainNameServer);
	}
	DEC_HC_MLC(Address);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_LogServer: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_LogServer(CSTR);
	virtual ~McOpt_DHCPv4_LogServer();
	static McOpt_DHCPv4_LogServer *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_LogServer);
	}
	DEC_HC_MLC(Address);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_CookieServer: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_CookieServer(CSTR);
	virtual ~McOpt_DHCPv4_CookieServer();
	static McOpt_DHCPv4_CookieServer *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_CookieServer);
	}
	DEC_HC_MLC(Address);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_LPRServer: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_LPRServer(CSTR);
	virtual ~McOpt_DHCPv4_LPRServer();
	static McOpt_DHCPv4_LPRServer *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_LPRServer);
	}
	DEC_HC_MLC(Address);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_ImpressServer: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_ImpressServer(CSTR);
	virtual ~McOpt_DHCPv4_ImpressServer();
	static McOpt_DHCPv4_ImpressServer *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_ImpressServer);
	}
	DEC_HC_MLC(Address);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_ResourceLocationServer: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_ResourceLocationServer(CSTR);
	virtual ~McOpt_DHCPv4_ResourceLocationServer();
	static McOpt_DHCPv4_ResourceLocationServer *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_ResourceLocationServer);
	}
	DEC_HC_MLC(Address);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_HostName: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_HostName(CSTR);
	virtual ~McOpt_DHCPv4_HostName();
	static McOpt_DHCPv4_HostName *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_HostName);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_BootFileSize: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_BootFileSize(CSTR);
	virtual ~McOpt_DHCPv4_BootFileSize();
	static McOpt_DHCPv4_BootFileSize *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_BootFileSize);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_MeritDumpFile: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_MeritDumpFile(CSTR);
	virtual ~McOpt_DHCPv4_MeritDumpFile();
	static McOpt_DHCPv4_MeritDumpFile *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_MeritDumpFile);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_DomainName: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_DomainName(CSTR);
	virtual ~McOpt_DHCPv4_DomainName();
	static McOpt_DHCPv4_DomainName *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_DomainName);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_SwapServer: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_SwapServer(CSTR);
	virtual ~McOpt_DHCPv4_SwapServer();
	static McOpt_DHCPv4_SwapServer *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_SwapServer);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_RootPath: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_RootPath(CSTR);
	virtual ~McOpt_DHCPv4_RootPath();
	static McOpt_DHCPv4_RootPath *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_RootPath);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_ExtensionsPath: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_ExtensionsPath(CSTR);
	virtual ~McOpt_DHCPv4_ExtensionsPath();
	static McOpt_DHCPv4_ExtensionsPath *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_ExtensionsPath);
	}
};

class McOpt_DHCPv4_NISDomainName: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_NISDomainName(CSTR);
	virtual ~McOpt_DHCPv4_NISDomainName();
	static McOpt_DHCPv4_NISDomainName *create(CSTR);
	int32_t optionCode() const {
		return (TP_Opt_DHCPv4_NISDomainName);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_RequestedIPAddress: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_RequestedIPAddress(CSTR);
	virtual ~McOpt_DHCPv4_RequestedIPAddress();
	static McOpt_DHCPv4_RequestedIPAddress *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_RequestedIPAddress);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_IPAddressLeaseTime: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_IPAddressLeaseTime(CSTR);
	virtual ~McOpt_DHCPv4_IPAddressLeaseTime();
	static McOpt_DHCPv4_IPAddressLeaseTime *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_IPAddressLeaseTime);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_OptionOverload: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_OptionOverload(CSTR);
	virtual ~McOpt_DHCPv4_OptionOverload();
	static McOpt_DHCPv4_OptionOverload *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_OptionOverload);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_TFTPServerName: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_TFTPServerName(CSTR);
	virtual ~McOpt_DHCPv4_TFTPServerName();
	static McOpt_DHCPv4_TFTPServerName *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_TFTPServerName);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_BootfileName: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_BootfileName(CSTR);
	virtual ~McOpt_DHCPv4_BootfileName();
	static McOpt_DHCPv4_BootfileName *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_BootfileName);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_MessageType: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_MessageType(CSTR);
	virtual ~McOpt_DHCPv4_MessageType();
	static McOpt_DHCPv4_MessageType *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_MessageType);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_SID: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_SID(CSTR);
	virtual ~McOpt_DHCPv4_SID();
	static McOpt_DHCPv4_SID *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_SID);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_ParameterRequestList: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_ParameterRequestList(CSTR);
	virtual ~McOpt_DHCPv4_ParameterRequestList();
	static McOpt_DHCPv4_ParameterRequestList *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_ParameterRequestList);
	}
	DEC_HC_MLC(OptionCode);
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_Message: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_Message(CSTR);
	virtual ~McOpt_DHCPv4_Message();
	static McOpt_DHCPv4_Message *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_Message);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_MaxMessageSize: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_MaxMessageSize(CSTR);
	virtual ~McOpt_DHCPv4_MaxMessageSize();
	static McOpt_DHCPv4_MaxMessageSize *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_MaxMessageSize);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_RenewalTimeValue: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_RenewalTimeValue(CSTR);
	virtual ~McOpt_DHCPv4_RenewalTimeValue();
	static McOpt_DHCPv4_RenewalTimeValue *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_RenewalTimeValue);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_RebindingTimeValue: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_RebindingTimeValue(CSTR);
	virtual ~McOpt_DHCPv4_RebindingTimeValue();
	static McOpt_DHCPv4_RebindingTimeValue *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_RebindingTimeValue);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_VendorClass: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_VendorClass(CSTR);
	virtual ~McOpt_DHCPv4_VendorClass();
	static McOpt_DHCPv4_VendorClass *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_VendorClass);
	}
};

////////////////////////////////////////////////////////////////
class McOpt_DHCPv4_CID: public McOpt_DHCPv4 {
public:
	McOpt_DHCPv4_CID(CSTR);
	virtual ~McOpt_DHCPv4_CID();
	static McOpt_DHCPv4_CID *create(CSTR);
	int32_t optionCode() const {
		return(TP_Opt_DHCPv4_CID);
	}
};

////////////////////////////////////////////////////////////////
class MmHeader_onDHCPv4: public MmReference_Less1 {
	static TypevsMcDict dict_;

public:
	MmHeader_onDHCPv4(CSTR);
	virtual ~MmHeader_onDHCPv4();

	int32_t token() const {
		return(metaToken(tkn_payload_ref_));
	}

	const TypevsMcDict *get_dict() const {
		return(&dict_);
	}

	static void add(McUdp_DHCPv4 *mc);
	static void add_other(McUdp_DHCPv4 *mc);

	bool overwrite_DictType(RControl &, ItPosition &, OCTBUF &) const;
};

////////////////////////////////////////////////////////////////
class MmOption_onDHCPv4: public MmReference_More0 {
	static TypevsMcDict dict_;

public:
	MmOption_onDHCPv4(CSTR);
	virtual ~MmOption_onDHCPv4();

	int32_t token() const {
		return(metaToken(tkn_option_ref_));
	}

	const TypevsMcDict *get_dict() const {
		return(&dict_);
	}

	static void add(McOpt_DHCPv4 *mc);
	static void add_other(McOpt_DHCPv4 *mc);
	bool overwrite_DictType(RControl &, ItPosition &, OCTBUF &) const;
};

////////////////////////////////////////////////////////////////
class MmDHCPv4String: public MmOctets {
public:
	MmDHCPv4String(CSTR, uint32_t, const PObject *, const PObject *);
	virtual ~MmDHCPv4String();
	virtual PvObject *reversePv(RControl &, const ItPosition &,
		const ItPosition &, const OCTBUF &) const;
};

////////////////////////////////////////////////////////////////
class MmDHCPv4VarString: public MmVarOctets {
public:
	MmDHCPv4VarString(CSTR, const PObject *, const PObject *);
	virtual ~MmDHCPv4VarString();
	virtual PvObject *reversePv(RControl &, const ItPosition &,
		const ItPosition &, const OCTBUF &) const;
};

////////////////////////////////////////////////////////////////
class MmDHCPv4HWAddr: public MmOctets {
public:
	MmDHCPv4HWAddr(CSTR, const PObject *, const PObject *);
	virtual ~MmDHCPv4HWAddr();
	virtual PvObject *reversePv(RControl &, const ItPosition &,
		const ItPosition &, const OCTBUF &) const;
};

////////////////////////////////////////////////////////////////
class MmDHCPv4MessageType: public MmUint {
public:
	MmDHCPv4MessageType(CSTR, uint16_t, const PObject* =0, const PObject* =0);
	virtual ~MmDHCPv4MessageType();
	virtual PvObject *reversePv(RControl&,
		const ItPosition& at,const ItPosition& size,const OCTBUF&)const;
};

////////////////////////////////////////////////////////////////
class PvDHCPv4String: public PvOctets {
public:
	PvDHCPv4String();
	PvDHCPv4String(uint32_t, OCTSTR = 0, bool = false);
	virtual ~PvDHCPv4String();
	virtual PvObject *shallowCopy() const;
	virtual void print() const;
	virtual void log(uint32_t=0) const;
	virtual void dump(CSTR = 0) const;
};

////////////////////////////////////////////////////////////////
class PvDHCPv4VarString: public PvOctets {
public:
	PvDHCPv4VarString();
	PvDHCPv4VarString(uint32_t, OCTSTR = 0, bool = false);
	virtual ~PvDHCPv4VarString();
	virtual PvObject *shallowCopy() const;
	virtual void print() const;
	virtual void log(uint32_t=0) const;
	virtual void dump(CSTR = 0) const;
};

////////////////////////////////////////////////////////////////
class PvDHCPv4HWAddr: public PvOctets {
public:
	PvDHCPv4HWAddr();
	PvDHCPv4HWAddr(uint32_t, OCTSTR = 0, bool = false);
	virtual ~PvDHCPv4HWAddr();
	virtual PvObject *shallowCopy() const;
	virtual void print() const;
	virtual void log(uint32_t=0) const;
	virtual void dump(CSTR = 0) const;
};

////////////////////////////////////////////////////////////////
class PvDHCPv4MessageType: public PvNumber {
public:
	PvDHCPv4MessageType();
	PvDHCPv4MessageType(int32_t);
	virtual ~PvDHCPv4MessageType();
	virtual void print() const;
};

#endif
