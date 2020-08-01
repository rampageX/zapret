#define _GNU_SOURCE
#include "darkmagic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

uint32_t net32_add(uint32_t netorder_value, uint32_t cpuorder_increment)
{
	return htonl(ntohl(netorder_value)+cpuorder_increment);
}

uint8_t *tcp_find_option(struct tcphdr *tcp, uint8_t kind)
{
	uint8_t *t = (uint8_t*)(tcp+1);
	uint8_t *end = (uint8_t*)tcp + (tcp->doff<<2);
	while(t<end)
	{
		switch(*t)
		{
			case 0: // end
				return NULL;
			case 1: // noop
				t++;
				break;
			default: // kind,len,data
				if ((t+1)>=end || t[1]<2 || (t+t[1])>end)
					return NULL;
				if (*t==kind)
					return t;
				t+=t[1];
				break;
		}
	}
	return NULL;
}
uint32_t *tcp_find_timestamps(struct tcphdr *tcp)
{
	uint8_t *t = tcp_find_option(tcp,8);
	return (t && t[1]==10) ? (uint32_t*)(t+2) : NULL;
}

static void fill_tcphdr(struct tcphdr *tcp, uint8_t tcp_flags, uint32_t seq, uint32_t ack_seq, uint8_t fooling, uint16_t nsport, uint16_t ndport, uint16_t nwsize, uint32_t *timestamps)
{
	char *tcpopt = (char*)(tcp+1);
	uint8_t t=0;

	memset(tcp,0,sizeof(*tcp));
	tcp->source     = nsport;
	tcp->dest       = ndport;
	if (fooling & TCP_FOOL_BADSEQ)
	{
		tcp->seq        = net32_add(seq,0x80000000);
		tcp->ack_seq    = net32_add(ack_seq,0x80000000);
	}
	else
	{
		tcp->seq        = seq;
		tcp->ack_seq    = ack_seq;
	}
	tcp->doff       = 5;
	*((uint8_t*)tcp+13)= tcp_flags;
	tcp->window     = nwsize;
	if (fooling & TCP_FOOL_MD5SIG)
	{
		tcpopt[0] = 19; // kind
		tcpopt[1] = 18; // len
		*(uint32_t*)(tcpopt+2)=random();
		*(uint32_t*)(tcpopt+6)=random();
		*(uint32_t*)(tcpopt+10)=random();
		*(uint32_t*)(tcpopt+14)=random();
		t=18;
	}
	if (timestamps || (fooling & TCP_FOOL_TS))
	{
		tcpopt[t] = 8; // kind
		tcpopt[t+1] = 10; // len
		// forge only TSecr if orig timestamp is present
		*(uint32_t*)(tcpopt+t+2) = timestamps ? timestamps[0] : -1;
		*(uint32_t*)(tcpopt+t+6) = (timestamps && !(fooling & TCP_FOOL_TS)) ? timestamps[1] : -1;
		t+=10;
	}
	while (t&3) tcpopt[t++]=1; // noop
	tcp->doff += t>>2;
}
static uint16_t tcpopt_len(uint8_t fooling, uint32_t *timestamps)
{
	uint16_t t=0;
	if (fooling & TCP_FOOL_MD5SIG) t=18;
	if ((fooling & TCP_FOOL_TS) || timestamps) t+=10;
	return (t+3)&~3;
}

static int rawsend_sock4=-1, rawsend_sock6=-1;
static void rawsend_clean_sock(int *sock)
{
	if (sock && *sock!=-1)
	{
		close(*sock);
		*sock=-1;
	}
}
void rawsend_cleanup()
{
	rawsend_clean_sock(&rawsend_sock4);
	rawsend_clean_sock(&rawsend_sock6);
}
static int *rawsend_family_sock(int family)
{
	switch(family)
	{
		case AF_INET: return &rawsend_sock4;
		case AF_INET6: return &rawsend_sock6;
		default: return NULL;
	}
}
static int rawsend_socket(int family,uint32_t fwmark)
{
	int *sock = rawsend_family_sock(family);
	if (!sock) return -1;
	
	if (*sock==-1)
	{
		int yes=1,pri=6;
		*sock = socket(family, SOCK_RAW, IPPROTO_RAW);
		if (*sock==-1)
			perror("rawsend: socket()");
		else if (setsockopt(*sock, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) == -1)
		{
			perror("rawsend: setsockopt(SO_MARK)");
			rawsend_clean_sock(sock);
		}
		else if (setsockopt(*sock, SOL_SOCKET, SO_PRIORITY, &pri, sizeof(pri)) == -1)
		{
			perror("rawsend: setsockopt(SO_PRIORITY)");
			rawsend_clean_sock(sock);
		}
	}
	return *sock;
}
bool rawsend(struct sockaddr* dst,uint32_t fwmark,const void *data,size_t len)
{
	int sock=rawsend_socket(dst->sa_family,fwmark);
	if (sock==-1) return false;

	int salen = dst->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	struct sockaddr_storage dst2;
	memcpy(&dst2,dst,salen);
	if (dst->sa_family==AF_INET6)
		((struct sockaddr_in6 *)&dst2)->sin6_port = 0; // or will be EINVAL

	int bytes = sendto(sock, data, len, 0, (struct sockaddr*)&dst2, salen);
	if (bytes==-1)
	{
		perror("rawsend: sendto");
		return false;
	}
	return true;
}
bool prepare_tcp_segment4(
	const struct sockaddr_in *src, const struct sockaddr_in *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	const void *data, uint16_t len,
	char *buf, size_t *buflen)
{
	uint16_t tcpoptlen = tcpopt_len(fooling,timestamps);
	uint16_t pktlen = sizeof(struct iphdr) + sizeof(struct tcphdr) + tcpoptlen  + len;
	if (pktlen>*buflen)
	{
		fprintf(stderr,"prepare_tcp_segment : packet len cannot exceed %zu\n",*buflen);
		return false;
	}

	struct iphdr *ip = (struct iphdr*) buf;
	struct tcphdr *tcp = (struct tcphdr*) (ip+1);

	ip->frag_off = 0;
	ip->version = 4;
	ip->ihl = 5;
	ip->tot_len = htons(pktlen);
	ip->id = 0;
	ip->ttl = ttl;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = src->sin_addr.s_addr;
	ip->daddr = dst->sin_addr.s_addr;

	fill_tcphdr(tcp,tcp_flags,seq,ack_seq,fooling,src->sin_port,dst->sin_port,wsize,timestamps);

	memcpy((char*)tcp+sizeof(struct tcphdr)+tcpoptlen,data,len);
	tcp4_fix_checksum(tcp,sizeof(struct tcphdr)+tcpoptlen+len,ip->saddr,ip->daddr);
	if (fooling & TCP_FOOL_BADSUM) tcp->check^=0xBEAF;

	*buflen = pktlen;
	return true;
}


bool prepare_tcp_segment6(
	const struct sockaddr_in6 *src, const struct sockaddr_in6 *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	const void *data, uint16_t len,
	char *buf, size_t *buflen)
{
	uint16_t tcpoptlen = tcpopt_len(fooling,timestamps);
	uint16_t payloadlen = sizeof(struct tcphdr) + tcpoptlen + len;
	uint16_t pktlen = sizeof(struct ip6_hdr) + payloadlen;
	if (pktlen>*buflen)
	{
		fprintf(stderr,"prepare_tcp_segment : packet len cannot exceed %zu\n",*buflen);
		return false;
	}

	struct ip6_hdr *ip6 = (struct ip6_hdr*) buf;
	struct tcphdr *tcp = (struct tcphdr*) (ip6+1);

	ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
	ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(payloadlen);
	ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
	ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;
	ip6->ip6_src = src->sin6_addr;
	ip6->ip6_dst = dst->sin6_addr;

	fill_tcphdr(tcp,tcp_flags,seq,ack_seq,fooling,src->sin6_port,dst->sin6_port,wsize,timestamps);

	memcpy((char*)tcp+sizeof(struct tcphdr)+tcpoptlen,data,len);
	tcp6_fix_checksum(tcp,sizeof(struct tcphdr)+tcpoptlen+len,&ip6->ip6_src,&ip6->ip6_dst);
	if (fooling & TCP_FOOL_BADSUM) tcp->check^=0xBEAF;

	*buflen = pktlen;
	return true;
}

bool prepare_tcp_segment(
	const struct sockaddr *src, const struct sockaddr *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	const void *data, uint16_t len,
	char *buf, size_t *buflen)
{
	return (src->sa_family==AF_INET && dst->sa_family==AF_INET) ?
		prepare_tcp_segment4((struct sockaddr_in *)src,(struct sockaddr_in *)dst,tcp_flags,seq,ack_seq,wsize,timestamps,ttl,fooling,data,len,buf,buflen) :
		(src->sa_family==AF_INET6 && dst->sa_family==AF_INET6) ?
		prepare_tcp_segment6((struct sockaddr_in6 *)src,(struct sockaddr_in6 *)dst,tcp_flags,seq,ack_seq,wsize,timestamps,ttl,fooling,data,len,buf,buflen) :
		false;
}


void extract_endpoints(const struct iphdr *iphdr,const struct ip6_hdr *ip6hdr,const struct tcphdr *tcphdr, struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
	if (iphdr)
	{
		struct sockaddr_in *si = (struct sockaddr_in*)dst;
		si->sin_family = AF_INET;
		si->sin_port = tcphdr ? tcphdr->dest : 0;
		si->sin_addr.s_addr = iphdr->daddr;

		si = (struct sockaddr_in*)src;
		si->sin_family = AF_INET;
		si->sin_port = tcphdr ? tcphdr->source : 0;
		si->sin_addr.s_addr = iphdr->saddr;
	}
	else if (ip6hdr)
	{
		struct sockaddr_in6 *si = (struct sockaddr_in6*)dst;
		si->sin6_family = AF_INET6;
		si->sin6_port = tcphdr ? tcphdr->dest : 0;
		si->sin6_addr = ip6hdr->ip6_dst;
		si->sin6_flowinfo = 0;
		si->sin6_scope_id = 0;

		si = (struct sockaddr_in6*)src;
		si->sin6_family = AF_INET6;
		si->sin6_port = tcphdr ? tcphdr->source : 0;
		si->sin6_addr = ip6hdr->ip6_src;
		si->sin6_flowinfo = 0;
		si->sin6_scope_id = 0;
	}
}

static const char *proto_name(uint8_t proto)
{
	switch(proto)
	{
		case IPPROTO_TCP:
			return "tcp";
		case IPPROTO_UDP:
			return "udp";
		case IPPROTO_ICMP:
			return "icmp";
		case IPPROTO_IGMP:
			return "igmp";
		case IPPROTO_ESP:
			return "esp";
		case IPPROTO_AH:
			return "ah";
		case IPPROTO_IPV6:
			return "6in4";
		case IPPROTO_SCTP:
			return "sctp";
		default:
			return NULL;
	}
}
static void str_proto_name(char *s, size_t s_len, uint8_t proto)
{
	const char *name = proto_name(proto);
	if (name)
		snprintf(s,s_len,"%s",name);
	else
		snprintf(s,s_len,"%u",proto);
}

static void str_srcdst_ip(char *s, size_t s_len, const void *saddr,const void *daddr)
{
	char s_ip[16],d_ip[16];
	*s_ip=*d_ip=0;
	inet_ntop(AF_INET, saddr, s_ip, sizeof(s_ip));
	inet_ntop(AF_INET, daddr, d_ip, sizeof(d_ip));
	snprintf(s,s_len,"%s => %s",s_ip,d_ip);
}
static void str_iphdr(char *s, size_t s_len, const struct iphdr *iphdr)
{
	char ss[64],s_proto[16];
	str_srcdst_ip(ss,sizeof(ss),&iphdr->saddr,&iphdr->daddr);
	str_proto_name(s_proto,sizeof(s_proto),iphdr->protocol);
	snprintf(s,s_len,"%s proto=%s",ss,s_proto);
}
void print_iphdr(const struct iphdr *iphdr)
{
	char s[64];
	str_iphdr(s,sizeof(s),iphdr);
	printf("%s",s);
}
static void str_srcdst_ip6(char *s, size_t s_len, const void *saddr,const void *daddr)
{
	char s_ip[40],d_ip[40];
	*s_ip=*d_ip=0;
	inet_ntop(AF_INET6, saddr, s_ip, sizeof(s_ip));
	inet_ntop(AF_INET6, daddr, d_ip, sizeof(d_ip));
	snprintf(s,s_len,"%s => %s",s_ip,d_ip);
}
static void str_ip6hdr(char *s, size_t s_len, const struct ip6_hdr *ip6hdr, uint8_t proto)
{
	char ss[128],s_proto[16];
	str_srcdst_ip6(ss,sizeof(ss),&ip6hdr->ip6_src,&ip6hdr->ip6_dst);
	str_proto_name(s_proto,sizeof(s_proto),proto);
	snprintf(s,s_len,"%s proto=%s",ss,s_proto);
}
void print_ip6hdr(const struct ip6_hdr *ip6hdr, uint8_t proto)
{
	char s[128];
	str_ip6hdr(s,sizeof(s),ip6hdr,proto);
	printf("%s",s);
}

static void str_tcphdr(char *s, size_t s_len, const struct tcphdr *tcphdr)
{
	char flags[7],*f=flags;
	if (tcphdr->syn) *f++='S';
	if (tcphdr->ack) *f++='A';
	if (tcphdr->rst) *f++='R';
	if (tcphdr->fin) *f++='F';
	if (tcphdr->psh) *f++='P';
	if (tcphdr->urg) *f++='U';
	*f=0;
	snprintf(s,s_len,"sport=%u dport=%u flags=%s seq=%u ack_seq=%u",htons(tcphdr->source),htons(tcphdr->dest),flags,htonl(tcphdr->seq),htonl(tcphdr->ack_seq));
}
void print_tcphdr(const struct tcphdr *tcphdr)
{
	char s[80];
	str_tcphdr(s,sizeof(s),tcphdr);
	printf("%s",s);
}
