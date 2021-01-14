#pragma once

#include <arpa/inet.h>
#include <stddef.h>
#include <stdbool.h>

void print_sockaddr(const struct sockaddr *sa);
char *strncasestr(const char *s,const char *find, size_t slen);
bool load_file(const char *filename,void *buffer,size_t *buffer_size);
bool load_file_nonempty(const char *filename,void *buffer,size_t *buffer_size);
