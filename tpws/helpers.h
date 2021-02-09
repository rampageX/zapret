#pragma once

#include <arpa/inet.h>
#include <stddef.h>
#include <netinet/in.h>

void print_sockaddr(const struct sockaddr *sa);
char *strncasestr(const char *s,const char *find, size_t slen);
