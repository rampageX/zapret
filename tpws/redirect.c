#include "redirect.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "params.h"
#include "helpers.h"

//#if !defined(USE_PF) && (defined(__OpenBSD__) || defined(__APPLE__))
#if !defined(USE_PF) && defined(__OpenBSD__)
 #define USE_PF 1
#endif

#ifdef __linux__
 #include <linux/netfilter_ipv4.h>
 #ifndef IP6T_SO_ORIGINAL_DST
  #define IP6T_SO_ORIGINAL_DST 80
 #endif
#endif
#ifdef USE_PF
 #include <net/if.h>
 #include <net/pfvar.h>
#endif



#if defined(USE_PF)
static int redirector_fd=-1;

void redir_close()
{
	if (redirector_fd!=-1)
	{
		close(redirector_fd);
		redirector_fd = -1;
		DBGPRINT("closed redirector");
	}
}
static bool redir_open_private(const char *fname, int flags)
{
	redir_close();
	redirector_fd = open(fname, flags);
	if (redirector_fd < 0)
	{
		perror("redir_openv_private: ");
		return false;
	}
	DBGPRINT("opened redirector %s",fname);
	return true;
}
bool redir_init()
{
	return redir_open_private("/dev/pf", O_RDONLY);
}

static bool destination_from_pf(const struct sockaddr *accept_sa, struct sockaddr_storage *orig_dst)
{
	struct pfioc_natlook nl;

	if (redirector_fd==-1) return false;

	if (accept_sa->sa_family!=orig_dst->ss_family)
	{
		DBGPRINT("accept_sa and orig_dst sa_family mismatch : %d %d", accept_sa->sa_family, orig_dst->ss_family);
		return false;
	}
 
	memset(&nl, 0, sizeof(nl));
	nl.proto           = IPPROTO_TCP;
	nl.direction       = PF_OUT;
	switch(orig_dst->ss_family)
	{
	case AF_INET:
		{
		struct sockaddr_in *sin = (struct sockaddr_in *)orig_dst;
		nl.af              = AF_INET;
		nl.saddr.v4.s_addr = ((struct sockaddr_in*)accept_sa)->sin_addr.s_addr;
		nl.sport           = ((struct sockaddr_in*)accept_sa)->sin_port;
		nl.daddr.v4.s_addr = sin->sin_addr.s_addr;
		nl.dport           = sin->sin_port;
		}
		break;
	case AF_INET6:
		{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)orig_dst;
		nl.af = AF_INET6;
		nl.saddr.v6 = ((struct sockaddr_in6*)accept_sa)->sin6_addr;
		nl.sport = ((struct sockaddr_in6*)accept_sa)->sin6_port;
		nl.daddr.v6 = sin6->sin6_addr;
		nl.dport = sin6->sin6_port;
		}
		break;
	default:
		DBGPRINT("destination_from_pf : unexpected address family %d",orig_dst->ss_family);
		return false;
	}

	if (ioctl(redirector_fd, DIOCNATLOOK, &nl) < 0)
	{
		DBGPRINT("ioctl(DIOCNATLOOK) failed: %s",strerror(errno));
		return false;
	}
	DBGPRINT("destination_from_pf : got orig dest addr from pf");

	switch(nl.af)
	{
	case AF_INET:
		orig_dst->ss_family = nl.af;
		((struct sockaddr_in*)orig_dst)->sin_port = nl.rdport;
		((struct sockaddr_in*)orig_dst)->sin_addr = nl.rdaddr.v4;
		break;
	case AF_INET6:
		orig_dst->ss_family = nl.af;
		((struct sockaddr_in6*)orig_dst)->sin6_port = nl.rdport;
		((struct sockaddr_in6*)orig_dst)->sin6_addr = nl.rdaddr.v6;
		break;
	default:
		DBGPRINT("destination_from_pf : DIOCNATLOOK returned unexpected address family %d",nl.af);
		return false;
	}

	return true;
}


#else

bool redir_init() {return true;}
void redir_close() {};

#endif



//Store the original destination address in orig_dst
bool get_dest_addr(int sockfd, const struct sockaddr *accept_sa, struct sockaddr_storage *orig_dst)
{
	char orig_dst_str[INET6_ADDRSTRLEN];
	socklen_t addrlen = sizeof(*orig_dst);
	int r;

	memset(orig_dst, 0, addrlen);

	//For UDP transparent proxying:
	//Set IP_RECVORIGDSTADDR socket option for getting the original 
	//destination of a datagram

#ifdef __linux__
	// DNAT
	r=getsockopt(sockfd, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr*) orig_dst, &addrlen);
	if (r<0)
		r = getsockopt(sockfd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, (struct sockaddr*) orig_dst, &addrlen);
	if (r<0)
	{
		DBGPRINT("both SO_ORIGINAL_DST and IP6T_SO_ORIGINAL_DST failed !");
#endif
		// TPROXY : socket is bound to original destination
		r=getsockname(sockfd, (struct sockaddr*) orig_dst, &addrlen);
		if (r<0)
		{
			perror("getsockname: ");
			return false;
		}
#ifdef USE_PF
		if (!destination_from_pf(accept_sa, orig_dst))
			DBGPRINT("pf filter destination_from_pf failed");
#endif
#ifdef __linux__
	}
#endif
	if (saconvmapped(orig_dst))
		DBGPRINT("Original destination : converted ipv6 mapped address to ipv4");

	if (params.debug)
	{
		if (orig_dst->ss_family == AF_INET)
		{
			inet_ntop(AF_INET, &(((struct sockaddr_in*) orig_dst)->sin_addr), orig_dst_str, INET_ADDRSTRLEN);
			VPRINT("Original destination for socket fd=%d : %s:%d", sockfd,orig_dst_str, htons(((struct sockaddr_in*) orig_dst)->sin_port))
		}
		else if (orig_dst->ss_family == AF_INET6)
		{
			inet_ntop(AF_INET6,&(((struct sockaddr_in6*) orig_dst)->sin6_addr), orig_dst_str, INET6_ADDRSTRLEN);
			VPRINT("Original destination for socket fd=%d : [%s]:%d", sockfd,orig_dst_str, htons(((struct sockaddr_in6*) orig_dst)->sin6_port))
		}
	}
	return true;
}
