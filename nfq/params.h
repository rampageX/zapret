#pragma once

#include "params.h"
#include "strpool.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#define Q_RCVBUF	(128*1024)	// in bytes
#define Q_MAXLEN	1024		// in packets

struct params_s
{
	bool debug;
	int wsize;
	int qnum;
	bool hostcase, hostnospace, domcase;
	char hostspell[4];
	enum dpi_desync_mode desync_mode,desync_mode2;
	bool desync_retrans,desync_skip_nosni,desync_any_proto;
	int desync_repeats,desync_split_pos;
	uint8_t desync_ttl;
	uint8_t desync_tcp_fooling_mode;
	uint32_t desync_fwmark;
	char hostfile[256];
	strpool *hostlist;
	uint8_t fake_http[1460],fake_tls[1460];
	size_t fake_http_size,fake_tls_size;
};

extern struct params_s params;

#define DLOG(format, ...) {if (params.debug) printf(format, ##__VA_ARGS__);}
