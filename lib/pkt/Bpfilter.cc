/*
 * Copyright (C) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011
 * Yokogawa Electric Corporation, YDC Corporation,
 * IPA (Information-technology Promotion Agency, Japan).
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
 * $TAHI: v6eval/lib/pkt/Bpfilter.cc,v 1.17 2005/07/21 01:53:22 akisada Exp $
 */
#include "Bpfilter.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#if defined(__linux__)
#include "bpf.h"
#else
#include <net/bpf.h>
#endif
#include <net/if.h>

#if defined(__linux__)
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif
#include <netinet/in.h>
#endif

#include <sys/types.h>
#include "debug.h"

Bpfilter::Bpfilter(CSTR n):fd_(-1),bufsize_(0) {
#if !defined(__linux__)
	int i, fd=-1;
	char dev[32];
	struct ifreq ifr;
	for(i=0;;i++) {
		snprintf(dev,sizeof(dev),"/dev/bpf%d",i);
		fd=::open(dev,O_RDWR);
		if(fd<0) {
			if(errno==EBUSY) continue;
			else {perror("err:open");}}
		break;}
	if(fd<0) return;

	bufsize_=BPF_MAXBUFSIZE;
	if(ioctl(fd,BIOCSBLEN,(caddr_t)&bufsize_)<0){
		perror("err:ioctl(BIOCSBLEN)");
		::close(fd);
		return;}

#ifdef HAVE_BPF_HDRCMPLT
	uint32_t flag = 1;
	if(ioctl(fd,BIOCSHDRCMPLT,&flag)<0){
		perror("err:ioctl(BIOCSHDRCMPLT)");
		::close(fd);
		return;}
#endif

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name,n);
	if(ioctl(fd,BIOCSETIF,(caddr_t)&ifr)<0) {
		perror("err:ioctl(BIOCSETIF)");
		::close(fd);
		return;}
	if(ioctl(fd,BIOCGBLEN,(caddr_t)&bufsize_)<0){
		perror("err:ioctl(BIOCGBLEN)");
		::close(fd);
		return;}
	fd_=fd;}
#else
	int i, fd=-1;
	char dev[32];
	struct sockaddr_ll sll;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(fd<0) {
		perror("err:open");
		return;}
	memset(&sll, 0xff, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	ifindex_ = if_nametoindex(n);
	if(ifindex_<0) {
		perror("err:if_nametoindex()");
		return;}
	sll.sll_ifindex = ifindex_;
	int rc = bind(fd, (struct sockaddr *)&sll, sizeof(sll));
	if(rc<0) {
		perror("err:bind");
		return;}
	bufsize_=BPF_MAXBUFSIZE;
	fd_=fd;}
#endif

int Bpfilter::setfilter(struct bpf_program *filter) const {
#if !defined(__linux__)
	int fd=fileDesc();
	if(fd<0) return -1;
	int rc = ioctl(fd,BIOCSETF,filter);
	if(rc<0){perror("err:ioctl(BIOCSETF)");}
	return rc;
#else
	/* xxx: For Linux, "filter ipv6" in tn.def is NOT supported */
	return 0;
#endif
}

int Bpfilter::promiscuous() const {
	int fd=fileDesc();
	if(fd<0) return -1;
#if !defined(__linux__)
	int rc=ioctl(fd,BIOCPROMISC,NULL);
	if(rc<0) {perror("err:ioctl(BIOCPROMISC)");}
	return rc;}
#else
	struct ifreq ifr;
	int rc=ioctl(fd,SIOCGIFFLAGS,&ifr);
	if(rc<0) {perror("err:ioctl(SIOCGIFFLAGS)");}
	ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
	rc=ioctl(fd,SIOCSIFFLAGS,&ifr);
	if(rc<0) {perror("err:ioctl(SIOCSIFFLAGS)");}
	return 0;}
#endif

int Bpfilter::flush() const {
	int fd=fileDesc();
	if(fd<0) return -1;
#if !defined(__linux__)
	int rc=ioctl(fd,BIOCFLUSH,NULL);
	if(rc<0) {perror("err:ioctl(BIOCFLUSH)");}
	return rc;}
#else
	unsigned char buf[2048];
	int i=0;
	do {
		fd_set fds;
		struct timeval t;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		memset(&t, 0, sizeof(t));
		i = select(FD_SETSIZE, &fds, NULL, NULL, &t);
		if (i > 0)
			recv(fd, buf, i, 0);
	} while (i);
	return 0;}
#endif

int Bpfilter::immediate(uint32_t n) const {
#if !defined(__linux__)
	int fd=fileDesc();
	if(fd<0) return -1;
	int rc=ioctl(fd,BIOCIMMEDIATE,&n);
	if(rc<0) {perror("err:ioctl(BIOCIMMEDIATE)");}
	return rc;}
#else
	/* xxx: For Linux, tahi works only in immediate=true mode */
	return 0;}
#endif

int Bpfilter::statistics(uint32_t& recv,uint32_t& drop) const {
	struct bpf_stat stat;
	int fd=fileDesc();
	recv=0; drop=0;
	if(fd<0) return -1;
#if !defined(__linux__)
	int rc=ioctl(fd,BIOCGSTATS,(caddr_t)&stat);
	if(rc<0) {perror("err:ioctl(BIOCGSTATS)");}
	else {recv=stat.bs_recv; drop=stat.bs_drop;}
	return rc;}
#else
	/* xxx: Linux cannot get per-socket statistics */
	return 0;}
#endif

int Bpfilter::receive(caddr_t p) const {
	int fd=fileDesc();
	if(fd<0) return -1;
	uint32_t l=bufferSize();
#if !defined(__linux__)
#ifdef VCLEAR_DBG
xdbg("/tmp/vclear_dbg.txt", "Bpfilter", "l: %d\n", l);
#endif	// VCLEAR_DBG
	int rc=::read(fd,p,l);
#ifdef VCLEAR_DBG
xdbg("/tmp/vclear_dbg.txt", "Bpfilter", "l: %d, rc: %d\n", l, rc);
#endif	// VCLEAR_DBG
	if(rc<0) {perror("err:read");}
	return rc;}
#else
#define SIZEOF_BPF_HDR 18
	int rc =recv(fd, (p+SIZEOF_BPF_HDR), (l-SIZEOF_BPF_HDR), 0);
	gettimeofday( &((struct bpf_hdr *)p)->bh_tstamp, 0) ;
	((struct bpf_hdr *)p)->bh_caplen = rc;
	((struct bpf_hdr *)p)->bh_datalen =rc + SIZEOF_BPF_HDR;
	((struct bpf_hdr *)p)->bh_hdrlen = SIZEOF_BPF_HDR;
	if(rc<0) {
		perror("err:recv");
		return rc;}
	return (rc+SIZEOF_BPF_HDR);}
#undef SIZEOF_BPF_HDR
#endif

int
Bpfilter::nonblock_receive(caddr_t p) const
{
	int rc = 0;
	int fd = fileDesc();

	if(fd<0) {
		return(-1);
	}

	uint32_t l = bufferSize();

#ifdef VCLEAR_DBG
xdbg("/tmp/vclear_dbg.txt", "Bpfilter", "l: %d\n", l);
#endif	// VCLEAR_DBG

	int nfds = fd + 1;
	fd_set readfds;
	struct timeval timeout;

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);

	timeout.tv_sec	= 0;
	timeout.tv_usec	= 0;

	rc = ::select(nfds, &readfds, NULL, NULL, &timeout);
	if(rc < 0) {
		perror("err:select");
	}

#ifdef VCLEAR_DBG
xdbg("/tmp/vclear_dbg.txt", "Bpfilter", "l: %d, rc: %d\n", l, rc);
#endif	// VCLEAR_DBG

	if(rc && FD_ISSET(fd, &readfds)) {
		FD_CLR(fd, &readfds);

		rc = ::read(fd, p, l);

#ifdef VCLEAR_DBG
xdbg("/tmp/vclear_dbg.txt", "Bpfilter", "l: %d, rc: %d\n", l, rc);
#endif	// VCLEAR_DBG

		if(rc < 0) {
			perror("err:read");
		}
	}

	return(rc);
}

int Bpfilter::send(caddr_t p, uint32_t l) const {
	int fd=fileDesc();
	if(fd<0) return -1;
	if(l>bufferSize()){perror("err:send packet too long");return -1;};
#if !defined(__linux__)
#ifdef VCLEAR_DBG
xdbg("/tmp/vclear_dbg.txt", "Bpfilter", "l: %d\n", l);
#endif	// VCLEAR_DBG
	int rc=::write(fd,p,l);
#ifdef VCLEAR_DBG
xdbg("/tmp/vclear_dbg.txt", "Bpfilter", "l: %d, rc: %d\n", l, rc);
#endif	// VCLEAR_DBG
#else
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_ifindex = ifindex_;
	int rc = sendto(fd, p, l, 0, (struct sockaddr *)&sll, sizeof(sll));
#endif
	if(rc<0) {perror("err:write");}
	return rc;}

uint32_t Bpfilter::getDLT() const {
	int fd=fileDesc();
	if(fd<0) return 0xffff; /* xxx */
#if !defined(__linux__)
	uint32_t dlt;
	int rc=ioctl(fd,BIOCGDLT,&dlt);
	if(rc<0) {perror("err:ioctl(BIOCGSTATS)");}
	return dlt;}
#else
	/* Linux assumes ethernet */
	return DLT_EN10MB;}
#endif

