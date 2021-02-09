#pragma once

#include <sys/types.h>
#include <stdbool.h>

#ifdef __linux__

#include <sys/capability.h>

bool setpcap(uint64_t caps);
int getmaxcap();
bool dropcaps();
#endif

bool droproot(uid_t uid, gid_t gid);
void daemonize();
bool writepid(const char *filename);
