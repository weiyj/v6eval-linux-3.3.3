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
#if !defined(__McDCCP_h__)
#define	__McDCCP_h__	1

#include "McSub.h"

//////////////////////////////////////////////////////////////////////////////
//	Upper SCTP	RFC2960

class McUpp_DCCP : public McUpper {
static	McUpp_DCCP*		instance_;
static	class McTopHdr_DCCP*	tophdr_;
	McUpp_DCCP(CSTR);
public:
virtual ~McUpp_DCCP();
static	McUpp_DCCP* create(CSTR key,CSTR tophdrkey);
static	McUpp_DCCP* instance(){return instance_;}
	int32_t headerType()const{return 33;}
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
virtual uint32_t length_for_reverse(RControl&,ItPosition& at,OCTBUF& buf) const;
virtual RObject* reverse(RControl& c,
		RObject* r_parent,ItPosition& at,OCTBUF& buf)const;
virtual bool generate(WControl& c,WObject* w_self,OCTBUF& buf)const;
};

class McTopHdr_DCCP : public McHeader {
friend	class McUpp_DCCP;
//	MmUint*	dataoff_;
//	MmUint*	cscov_;
//	void	dataoff_member(MmUint* meta){dataoff_=meta; member(meta);}
//	void	cscov_member(MmUint* meta){cscov_=meta; member(meta);}
	McTopHdr_DCCP(CSTR);
virtual ~McTopHdr_DCCP();
static	McTopHdr_DCCP* create(CSTR);
	int32_t headerType()const{return TP_Upp_TCP;}
	DEC_HCGENE(DataOff);
};

//////////////////////////////////////////////////////////////////////////////
const int32_t TP_DCCP_REQUEST		= 0;
const int32_t TP_DCCP_RESPONSE		= 1;
const int32_t TP_DCCP_DATA		= 2;
const int32_t TP_DCCP_ACK		= 3;
const int32_t TP_DCCP_DATAACK		= 4;
const int32_t TP_DCCP_CLOSEREQ		= 5;
const int32_t TP_DCCP_CLOSE		= 6;
const int32_t TP_DCCP_RESET		= 7;
const int32_t TP_DCCP_SYNC		= 8;
const int32_t TP_DCCP_SYNCACK		= 9;

class McDCCPacket : public McHeader {
protected:
	MmUint*	type_;
	void	type_member(MmUint* meta){type_=meta; member(meta);}
	MmUint*	xflag_;
	void	xflag_member(MmUint* meta){xflag_=meta; member(meta);}
	void	common_member_short();
	void	common_member_ack_short();
	void	common_member();
	void	common_member_ack();
	McDCCPacket(CSTR);
public:
virtual	~McDCCPacket();
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
	uint32_t alignment_requirement() const;
virtual uint32_t length_for_reverse(RControl&,ItPosition& at,OCTBUF& buf) const;
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
//HardCording action method
};

class McDCCPAny : public McDCCPacket {
	McDCCPAny(CSTR);
public:
virtual	~McDCCPAny();
static	McDCCPAny* create(CSTR);
};

class McDCCPRequest : public McDCCPacket {
	McDCCPRequest(CSTR);
public:
virtual	~McDCCPRequest();
static	McDCCPRequest* create(CSTR);
	int32_t optionType() const {return TP_DCCP_REQUEST;}
};

class McDCCPRequestShort : public McDCCPacket {
	McDCCPRequestShort(CSTR);
public:
virtual	~McDCCPRequestShort();
static	McDCCPRequestShort* create(CSTR);
	int32_t optionType() const {return TP_DCCP_REQUEST;}
};

class McDCCPResponse : public McDCCPacket {
	McDCCPResponse(CSTR);
public:
virtual	~McDCCPResponse();
static	McDCCPResponse* create(CSTR);
	int32_t optionType() const {return TP_DCCP_RESPONSE;}
};

class McDCCPResponseShort : public McDCCPacket {
	McDCCPResponseShort(CSTR);
public:
virtual	~McDCCPResponseShort();
static	McDCCPResponseShort* create(CSTR);
	int32_t optionType() const {return TP_DCCP_RESPONSE;}
};

class McDCCPData : public McDCCPacket {
	McDCCPData(CSTR);
public:
virtual	~McDCCPData();
static	McDCCPData* create(CSTR);
	int32_t optionType() const {return TP_DCCP_DATA;}
};

class McDCCPDataShort : public McDCCPacket {
	McDCCPDataShort(CSTR);
public:
virtual	~McDCCPDataShort();
static	McDCCPDataShort* create(CSTR);
	int32_t optionType() const {return TP_DCCP_DATA;}
};

class McDCCPAck : public McDCCPacket {
	McDCCPAck(CSTR);
public:
virtual	~McDCCPAck();
static	McDCCPAck* create(CSTR);
	int32_t optionType() const {return TP_DCCP_ACK;}
};

class McDCCPAckShort : public McDCCPacket {
	McDCCPAckShort(CSTR);
public:
virtual	~McDCCPAckShort();
static	McDCCPAckShort* create(CSTR);
	int32_t optionType() const {return TP_DCCP_ACK;}
};

class McDCCPDataAck : public McDCCPacket {
	McDCCPDataAck(CSTR);
public:
virtual	~McDCCPDataAck();
static	McDCCPDataAck* create(CSTR);
	int32_t optionType() const {return TP_DCCP_DATAACK;}
};

class McDCCPDataAckShort : public McDCCPacket {
	McDCCPDataAckShort(CSTR);
public:
virtual	~McDCCPDataAckShort();
static	McDCCPDataAckShort* create(CSTR);
	int32_t optionType() const {return TP_DCCP_DATAACK;}
};

class McDCCPCloseReq : public McDCCPacket {
	McDCCPCloseReq(CSTR);
public:
virtual	~McDCCPCloseReq();
static	McDCCPCloseReq* create(CSTR);
	int32_t optionType() const {return TP_DCCP_CLOSEREQ;}
};

class McDCCPCloseReqShort : public McDCCPacket {
	McDCCPCloseReqShort(CSTR);
public:
virtual	~McDCCPCloseReqShort();
static	McDCCPCloseReqShort* create(CSTR);
	int32_t optionType() const {return TP_DCCP_CLOSEREQ;}
};

class McDCCPClose : public McDCCPacket {
	McDCCPClose(CSTR);
public:
virtual	~McDCCPClose();
static	McDCCPClose* create(CSTR);
	int32_t optionType() const {return TP_DCCP_CLOSE;}
};

class McDCCPCloseShort : public McDCCPacket {
	McDCCPCloseShort(CSTR);
public:
virtual	~McDCCPCloseShort();
static	McDCCPCloseShort* create(CSTR);
	int32_t optionType() const {return TP_DCCP_CLOSE;}
};

class McDCCPReset :public McDCCPacket {
	McDCCPReset(CSTR);
public:
virtual	~McDCCPReset();
static	McDCCPReset* create(CSTR);
	int32_t optionType() const {return TP_DCCP_RESET;}
};

class McDCCPResetShort : public McDCCPacket {
	McDCCPResetShort(CSTR);
public:
virtual	~McDCCPResetShort();
static	McDCCPResetShort* create(CSTR);
	int32_t optionType() const {return TP_DCCP_RESET;}
};

class McDCCPSync : public McDCCPacket {
	McDCCPSync(CSTR);
public:
virtual	~McDCCPSync();
static	McDCCPSync* create(CSTR);
	int32_t optionType() const {return TP_DCCP_SYNC;}
};

class McDCCPSyncShort : public McDCCPacket {
	McDCCPSyncShort(CSTR);
public:
virtual	~McDCCPSyncShort();
static	McDCCPSyncShort* create(CSTR);
	int32_t optionType() const {return TP_DCCP_SYNC;}
};

class McDCCPSyncAck : public McDCCPacket {
	McDCCPSyncAck(CSTR);
public:
virtual	~McDCCPSyncAck();
static	McDCCPSyncAck* create(CSTR);
	int32_t optionType() const {return TP_DCCP_SYNCACK;}
};

class McDCCPSyncAckShort : public McDCCPacket {
	McDCCPSyncAckShort(CSTR);
public:
virtual	~McDCCPSyncAckShort();
static	McDCCPSyncAckShort* create(CSTR);
	int32_t optionType() const {return TP_DCCP_SYNCACK;}
};

//////////////////////////////////////////////////////////////////////////////
const int32_t TP_DCCP_OPT_PADDING	= 0;
const int32_t TP_DCCP_OPT_MANDATORY	= 1;
const int32_t TP_DCCP_OPT_SLOW_RECV	= 2;
const int32_t TP_DCCP_OPT_MIN_RESERVED	= 3;
const int32_t TP_DCCP_OPT_MAX_RESERVED	= 31;
const int32_t TP_DCCP_OPT_CHANGE_L	= 32;
const int32_t TP_DCCP_OPT_CONFIRM_L	= 33;
const int32_t TP_DCCP_OPT_CHANGE_R	= 34;
const int32_t TP_DCCP_OPT_CONFIRM_R	= 35;
const int32_t TP_DCCP_OPT_INIT_COOKIE	= 36;
const int32_t TP_DCCP_OPT_NDP_COUNT	= 37;
const int32_t TP_DCCP_OPT_ACK_VECTOR0	= 38;
const int32_t TP_DCCP_OPT_ACK_VECTOR1	= 39;
const int32_t TP_DCCP_OPT_DATA_DROPPED	= 40;
const int32_t TP_DCCP_OPT_TIMESTAMP	= 41;
const int32_t TP_DCCP_OPT_TIMESTAMP_ECHO= 42;
const int32_t TP_DCCP_OPT_ELAPSED_TIME	= 43;
const int32_t TP_DCCP_OPT_DATA_CHECKSUM	= 44;

class McOpt_DCCP : public McOption {
protected:
	MmUint*	type_;
	void	type_member(MmUint* meta){type_=meta; member(meta);}
	MmUint*	length_;
	void	length_member(MmUint* meta){length_=meta; member(meta);}
	void	common_member();
	McOpt_DCCP(CSTR);
public:
virtual	~McOpt_DCCP();
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
virtual uint32_t length_for_reverse(RControl&,ItPosition& at,OCTBUF& buf) const;
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
//HardCording action method
	DEC_HCGENE(Length);
};

class McOpt_DCCP_ANY : public McOpt_DCCP {
	McOpt_DCCP_ANY(CSTR);
public:
virtual	~McOpt_DCCP_ANY();
static	McOpt_DCCP_ANY* create(CSTR);
};

class McOpt_DCCP_Reserved : public McOpt_DCCP {
	McOpt_DCCP_Reserved(CSTR);
public:
virtual	~McOpt_DCCP_Reserved();
static	McOpt_DCCP_Reserved* create(CSTR);
	int32_t optionType() const{return TP_DCCP_OPT_MAX_RESERVED;}
};

class McOpt_DCCP_Padding : public McOpt_DCCP {
	McOpt_DCCP_Padding(CSTR);
public:
virtual	~McOpt_DCCP_Padding();
static	McOpt_DCCP_Padding* create(CSTR);
	int32_t optionType() const{return TP_DCCP_OPT_PADDING;}
virtual	bool disused() const {return true;}      //disuse evaluate
};

class McOpt_DCCP_Mandatory : public McOpt_DCCP {
	McOpt_DCCP_Mandatory(CSTR);
public:
virtual	~McOpt_DCCP_Mandatory();
static	McOpt_DCCP_Mandatory* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_MANDATORY;}
};

class McOpt_DCCP_ChangeL : public McOpt_DCCP {
	McOpt_DCCP_ChangeL(CSTR);
public:
virtual	~McOpt_DCCP_ChangeL();
static	McOpt_DCCP_ChangeL* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_CHANGE_L;}
};

class McOpt_DCCP_ConfirmL : public McOpt_DCCP {
	McOpt_DCCP_ConfirmL(CSTR);
public:
virtual	~McOpt_DCCP_ConfirmL();
static	McOpt_DCCP_ConfirmL* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_CONFIRM_L;}
};

class McOpt_DCCP_ChangeR : public McOpt_DCCP {
	McOpt_DCCP_ChangeR(CSTR);
public:
virtual	~McOpt_DCCP_ChangeR();
static	McOpt_DCCP_ChangeR* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_CHANGE_R;}
};

class McOpt_DCCP_ConfirmR : public McOpt_DCCP {
	McOpt_DCCP_ConfirmR(CSTR);
public:
virtual	~McOpt_DCCP_ConfirmR();
static	McOpt_DCCP_ConfirmR* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_CONFIRM_R;}
};

class McOpt_DCCP_InitCookie : public McOpt_DCCP {
	McOpt_DCCP_InitCookie(CSTR);
public:
virtual	~McOpt_DCCP_InitCookie();
static	McOpt_DCCP_InitCookie* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_INIT_COOKIE;}
};

class McOpt_DCCP_NDPCount : public McOpt_DCCP {
	McOpt_DCCP_NDPCount(CSTR);
public:
virtual	~McOpt_DCCP_NDPCount();
static	McOpt_DCCP_NDPCount* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_NDP_COUNT;}
};

class McOpt_DCCP_AckVector0 : public McOpt_DCCP {
	McOpt_DCCP_AckVector0(CSTR);
public:
virtual	~McOpt_DCCP_AckVector0();
static	McOpt_DCCP_AckVector0* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_ACK_VECTOR0;}
	DEC_HC_MLC(Vector);
};

class McOpt_DCCP_AckVector1 : public McOpt_DCCP {
	McOpt_DCCP_AckVector1(CSTR);
public:
virtual	~McOpt_DCCP_AckVector1();
static	McOpt_DCCP_AckVector1* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_ACK_VECTOR1;}
	DEC_HC_MLC(Vector);
};

class McOpt_DCCP_Timestamp : public McOpt_DCCP {
	McOpt_DCCP_Timestamp(CSTR);
public:
virtual	~McOpt_DCCP_Timestamp();
static	McOpt_DCCP_Timestamp* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_TIMESTAMP;}
};

class McOpt_DCCP_TimestampEcho : public McOpt_DCCP {
	McOpt_DCCP_TimestampEcho(CSTR);
public:
virtual	~McOpt_DCCP_TimestampEcho();
static	McOpt_DCCP_TimestampEcho* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_TIMESTAMP_ECHO;}
	DEC_HC_MLC(ElapsedTime);
	DEC_HC_MLC(ElapsedTimeShort);
};

class McOpt_DCCP_ElapsedTime : public McOpt_DCCP {
	McOpt_DCCP_ElapsedTime(CSTR);
public:
virtual	~McOpt_DCCP_ElapsedTime();
static	McOpt_DCCP_ElapsedTime* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_ELAPSED_TIME;}
	DEC_HC_MLC(ElapsedTime);
	DEC_HC_MLC(ElapsedTimeShort);
};

class McOpt_DCCP_DataChecksum : public McOpt_DCCP {
	McOpt_DCCP_DataChecksum(CSTR);
public:
virtual	~McOpt_DCCP_DataChecksum();
static	McOpt_DCCP_DataChecksum* create(CSTR);
	int32_t optionType() const {return TP_DCCP_OPT_DATA_CHECKSUM;}
};

//////////////////////////////////////////////////////////////////////////////
const int32_t TP_DCCP_FT_CCID		= 1;
const int32_t TP_DCCP_FT_SHORT_SEQ	= 2;
const int32_t TP_DCCP_FT_SEQ_WIN	= 3;
const int32_t TP_DCCP_FT_ENC_INCAPABLE	= 4;
const int32_t TP_DCCP_FT_ACK_RATIO	= 5;
const int32_t TP_DCCP_FT_SEND_ACK_VECTOR= 6;
const int32_t TP_DCCP_FT_SEND_NDP_COUNT	= 7;
const int32_t TP_DCCP_FT_MIN_CHKSUM_COV	= 8;
const int32_t TP_DCCP_FT_CHK_DATA_CHKSUM= 9;
const int32_t TP_DCCP_FT_SEND_LEV_RATE	= 192;

class McFeature : public McOption {
protected:
	MmUint*	type_;
	void	type_member(MmUint* meta){type_=meta; member(meta);}
	void	common_member();
	McFeature(CSTR);
public:
virtual	~McFeature();
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
virtual uint32_t length_for_reverse(RControl&,ItPosition& at,OCTBUF& buf) const;
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
};

class McFeature_ANY : public McFeature {
	McFeature_ANY(CSTR);
public:
virtual	~McFeature_ANY();
static	McFeature_ANY* create(CSTR);
};

class McFeature_CCID : public McFeature {
	McFeature_CCID(CSTR);
public:
virtual	~McFeature_CCID();
static	McFeature_CCID* create(CSTR);
	int32_t optionType() const {return TP_DCCP_FT_CCID;}
	DEC_HC_MLC(Value);
};

class McFeature_ShortSeq : public McFeature {
	McFeature_ShortSeq(CSTR);
public:
virtual	~McFeature_ShortSeq();
static	McFeature_ShortSeq* create(CSTR);
	int32_t optionType() const {return TP_DCCP_FT_SHORT_SEQ;}
	DEC_HC_MLC(Value);
};

class McFeature_SeqWin : public McFeature {
	McFeature_SeqWin(CSTR);
public:
virtual	~McFeature_SeqWin();
static	McFeature_SeqWin* create(CSTR);
	int32_t optionType() const {return TP_DCCP_FT_SEQ_WIN;}
	DEC_HC_MLC(Value);
};

class McFeature_ENCIncapable : public McFeature {
	McFeature_ENCIncapable(CSTR);
public:
virtual	~McFeature_ENCIncapable();
static	McFeature_ENCIncapable* create(CSTR);
	int32_t optionType() const {return TP_DCCP_FT_ENC_INCAPABLE;}
	DEC_HC_MLC(Value);
};

class McFeature_AckRatio : public McFeature {
	McFeature_AckRatio(CSTR);
public:
virtual	~McFeature_AckRatio();
static	McFeature_AckRatio* create(CSTR);
	int32_t optionType() const {return TP_DCCP_FT_ACK_RATIO;}
	DEC_HC_MLC(Value);
};

class McFeature_SendAckVector : public McFeature {
	McFeature_SendAckVector(CSTR);
public:
virtual	~McFeature_SendAckVector();
static	McFeature_SendAckVector* create(CSTR);
	int32_t optionType() const {return TP_DCCP_FT_SEND_ACK_VECTOR;}
	DEC_HC_MLC(Value);
};

class McFeature_SendNDPCount : public McFeature {
	McFeature_SendNDPCount(CSTR);
public:
virtual	~McFeature_SendNDPCount();
static	McFeature_SendNDPCount* create(CSTR);
	int32_t optionType() const {return TP_DCCP_FT_SEND_NDP_COUNT;}
	DEC_HC_MLC(Value);
};

class McFeature_MinCsumCover : public McFeature {
	McFeature_MinCsumCover(CSTR);
public:
virtual	~McFeature_MinCsumCover();
static	McFeature_MinCsumCover* create(CSTR);
	int32_t optionType() const {return TP_DCCP_FT_MIN_CHKSUM_COV;}
	DEC_HC_MLC(Value);
};

class McFeature_DataChecksum : public McFeature {
	McFeature_DataChecksum(CSTR);
public:
virtual	~McFeature_DataChecksum();
static	McFeature_DataChecksum* create(CSTR);
	int32_t optionType() const {return TP_DCCP_FT_CHK_DATA_CHKSUM;}
	DEC_HC_MLC(Value);
};

class McFeature_SendLevRate : public McFeature {
	McFeature_SendLevRate(CSTR);
public:
virtual	~McFeature_SendLevRate();
static	McFeature_SendLevRate* create(CSTR);
	int32_t optionType() const {return TP_DCCP_FT_SEND_LEV_RATE;}
	DEC_HC_MLC(Value);
};

#include "MmHeader.h"
//////////////////////////////////////////////////////////////////////////////
class MmDCCPacket : public MmReference_Must1 {
static	TypevsMcDict	dict_;
public:
	MmDCCPacket(CSTR);
virtual	~MmDCCPacket();
	int32_t token()const{return metaToken(tkn_option_ref_);}
	const TypevsMcDict* get_dict()const{return &dict_;}
static	void add(McDCCPacket* mc, int xflag);
static	void add_other(McDCCPacket* mc);
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
virtual	uint32_t objectLength(const PObject* =0,const WObject* =0) const;
};

//////////////////////////////////////////////////////////////////////////////
// Option = xx (reference option(DCCP) on the McDCCPacket)
class MmOption_onDCCP : public MmReference_More0 {
static	TypevsMcDict	dict_;
public:
	MmOption_onDCCP(CSTR);
virtual	~MmOption_onDCCP();
	int32_t token()const{return metaToken(tkn_option_ref_);}
	const TypevsMcDict* get_dict()const{return &dict_;}
static	void add(McOpt_DCCP* mc);
static	void add_other(McOpt_DCCP* mc);
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
};

//////////////////////////////////////////////////////////////////////////////
// Feature = xx (reference option(DCCP) on the McDCCPacket)
class MmFeature : public MmReference_More0 {
static	TypevsMcDict	dict_;
public:
	MmFeature(CSTR);
virtual	~MmFeature();
	int32_t token()const{return metaToken(tkn_option_ref_);}
	const TypevsMcDict* get_dict()const{return &dict_;}
static	void add(McFeature* mc);
static	void add_other(McFeature* mc);
// COMPOSE/REVERSE INTERFACE --------------------------------------------------
	bool overwrite_DictType(RControl&,ItPosition& at,OCTBUF& buf) const;
};

#endif
