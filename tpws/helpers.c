#define _GNU_SOURCE

#include "helpers.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>

char *strncasestr(const char *s,const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0')
	{
		len = strlen(find);
		do
		{
			do
			{
				if (slen-- < 1 || (sc = *s++) == '\0') return NULL;
			} while (toupper(c) != toupper(sc));
			if (len > slen)	return NULL;
		} while (strncasecmp(s, find, len) != 0);
		s--;
	}
	return (char *)s;
}

void print_sockaddr(const struct sockaddr *sa)
{
	char str[64];
	switch (sa->sa_family)
	{
	case AF_INET:
		if (inet_ntop(sa->sa_family, &((struct sockaddr_in*)sa)->sin_addr, str, sizeof(str)))
			printf("%s:%d", str, ntohs(((struct sockaddr_in*)sa)->sin_port));
		break;
	case AF_INET6:
		if (inet_ntop(sa->sa_family, &((struct sockaddr_in6*)sa)->sin6_addr, str, sizeof(str)))
			printf("%s:%d", str, ntohs(((struct sockaddr_in6*)sa)->sin6_port));
		break;
	default:
		printf("UNKNOWN_FAMILY_%d", sa->sa_family);
	}
}


bool saismapped(const struct sockaddr_in6 *sa)
{
	// ::ffff:1.2.3.4
	return !memcmp(sa->sin6_addr.s6_addr,"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff",12);
}
bool samappedcmp(const struct sockaddr_in *sa1,const struct sockaddr_in6 *sa2)
{
	return saismapped(sa2) && !memcmp(sa2->sin6_addr.s6_addr+12,&sa1->sin_addr.s_addr,4);
}
bool sacmp(const struct sockaddr *sa1,const struct sockaddr *sa2)
{
	return sa1->sa_family==AF_INET && sa2->sa_family==AF_INET && !memcmp(&((struct sockaddr_in*)sa1)->sin_addr,&((struct sockaddr_in*)sa2)->sin_addr,sizeof(struct in_addr)) ||
		sa1->sa_family==AF_INET6 && sa2->sa_family==AF_INET6 && !memcmp(&((struct sockaddr_in6*)sa1)->sin6_addr,&((struct sockaddr_in6*)sa2)->sin6_addr,sizeof(struct in6_addr)) ||
		sa1->sa_family==AF_INET && sa2->sa_family==AF_INET6 && samappedcmp((struct sockaddr_in*)sa1,(struct sockaddr_in6*)sa2) ||
		sa1->sa_family==AF_INET6 && sa2->sa_family==AF_INET && samappedcmp((struct sockaddr_in*)sa2,(struct sockaddr_in6*)sa1);
}
uint16_t saport(const struct sockaddr *sa)
{
	return htons(sa->sa_family==AF_INET ? ((struct sockaddr_in*)sa)->sin_port :
		     sa->sa_family==AF_INET6 ? ((struct sockaddr_in6*)sa)->sin6_port : 0);
}
bool saconvmapped(struct sockaddr_storage *a)
{
	if ((a->ss_family == AF_INET6) && saismapped((struct sockaddr_in6*)a))
	{
		uint32_t ip4 = *(uint32_t*)(((struct sockaddr_in6*)a)->sin6_addr.s6_addr+12);
		uint16_t port = ((struct sockaddr_in6*)a)->sin6_port;
		a->ss_family = AF_INET;
		((struct sockaddr_in*)a)->sin_addr.s_addr = ip4;
		((struct sockaddr_in*)a)->sin_port = port;
		return true;
	}
	return false;
}
