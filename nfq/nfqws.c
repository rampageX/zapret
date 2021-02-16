#define _GNU_SOURCE

#include "nfqws.h"
#include "sec.h"
#include "desync.h"
#include "helpers.h"
#include "checksum.h"
#include "params.h"
#include "protocol.h"
#include "hostlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __linux__
#include <libnetfilter_queue/libnetfilter_queue.h>
#define NF_DROP 0
#define NF_ACCEPT 1
#endif

#ifndef IPPROTO_DIVERT
#define IPPROTO_DIVERT 258
#endif


struct params_s params;


static bool bHup = false;
static void onhup(int sig)
{
	printf("HUP received !\n");
	if (params.hostlist)
		printf("Will reload hostlist on next request\n");
	bHup = true;
}
// should be called in normal execution
static void dohup()
{
	if (bHup)
	{
		if (params.hostlist)
		{
			if (!LoadHostList(&params.hostlist, params.hostfile))
			{
				// what will we do without hostlist ?? sure, gonna die
				exit(1);
			}
		}
		bHup = false;
	}
}



static void tcp_rewrite_winsize(struct tcphdr *tcp, uint16_t winsize)
{
	uint16_t winsize_old;
	winsize_old = htons(tcp->th_win); // << scale_factor;
	tcp->th_win = htons(winsize);
	DLOG("Window size change %u => %u\n", winsize_old, winsize)
}

// data/len points to data payload
static bool modify_tcp_packet(uint8_t *data, size_t len, struct tcphdr *tcphdr)
{
	if (tcp_synack_segment(tcphdr) && params.wsize)
	{
		tcp_rewrite_winsize(tcphdr, (uint16_t)params.wsize);
		return true;
	}
	return false;
}



#ifdef __linux__
static packet_process_result processPacketData(uint8_t *data_pkt, size_t len_pkt, uint32_t *mark)
#else
static packet_process_result processPacketData(uint8_t *data_pkt, size_t len_pkt)
#endif
{
	struct ip *ip = NULL;
	struct ip6_hdr *ip6hdr = NULL;
	struct tcphdr *tcphdr = NULL;
	size_t len = len_pkt, len_tcp;
	uint8_t *data = data_pkt;
	packet_process_result res = pass, res2;
	uint8_t proto;

#ifdef __linux__
	if (*mark & params.desync_fwmark)
	{
		DLOG("ignoring generated packet\n")
		return res;
	}
#endif

	if (proto_check_ipv4(data, len))
	{
		ip = (struct ip *) data;
		proto = ip->ip_p;
		proto_skip_ipv4(&data, &len);
		if (params.debug)
		{
			printf("IP4: ");
			print_ip(ip);
		}
	}
	else if (proto_check_ipv6(data, len))
	{
		ip6hdr = (struct ip6_hdr *) data;
		proto_skip_ipv6(&data, &len, &proto);
		if (params.debug)
		{
			printf("IP6: ");
			print_ip6hdr(ip6hdr, proto);
		}
	}
	else
	{
		// not ipv6 and not ipv4
		return res;
	}

	if (proto==IPPROTO_TCP && proto_check_tcp(data, len))
	{
		tcphdr = (struct tcphdr *) data;
		len_tcp = len;
		proto_skip_tcp(&data, &len);

		if (params.debug)
		{
			printf(" ");
			print_tcphdr(tcphdr);
			printf("\n");
		}

		if (len) { DLOG("TCP: ") hexdump_limited_dlog(data, len, 32); DLOG("\n") }

		if (modify_tcp_packet(data, len, tcphdr))
			res = modify;

		res2 = dpi_desync_packet(data_pkt, len_pkt, ip, ip6hdr, tcphdr, len_tcp, data, len);
		res = (res2==pass && res==modify) ? modify : res2;
		// in my FreeBSD divert tests only ipv4 packets were reinjected with correct checksum
		// ipv6 packets were with incorrect checksum
#ifdef __FreeBSD__
		// FreeBSD tend to pass ipv6 frames with wrong checksum
		if (res==modify || ip6hdr)
#else
		if (res==modify)
#endif
			tcp_fix_checksum(tcphdr,len_tcp,ip,ip6hdr);
	}
	else
	{
		if (params.debug) printf("\n");
	}

	return res;
}


#ifdef __linux__
static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *cookie)
{
	int id;
	size_t len;
	struct nfqnl_msg_packet_hdr *ph;
	uint8_t *data;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ph ? ntohl(ph->packet_id) : 0;

	uint32_t mark = nfq_get_nfmark(nfa);
	len = nfq_get_payload(nfa, &data);
	DLOG("packet: id=%d len=%zu\n", id, len)
	if (len >= 0)
	{
		switch (processPacketData(data, len, &mark))
		{
		case modify: 
			DLOG("packet: id=%d pass modified\n", id);
			return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, len, data);
		case drop:
			DLOG("packet: id=%d drop\n", id);
			return nfq_set_verdict2(qh, id, NF_DROP, mark, 0, NULL);
		}
	}
	DLOG("packet: id=%d pass unmodified\n", id);
	return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
}
static int nfq_main()
{
	struct nfq_handle *h = NULL;
	struct nfq_q_handle *qh = NULL;
	int fd,rv;
	uint8_t buf[16384] __attribute__((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		goto exiterr;
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		goto exiterr;
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		goto exiterr;
	}

	printf("binding this socket to queue '%u'\n", params.qnum);
	qh = nfq_create_queue(h, params.qnum, &nfq_cb, &params);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		goto exiterr;
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		goto exiterr;
	}
	if (nfq_set_queue_maxlen(qh, Q_MAXLEN) < 0) {
		fprintf(stderr, "can't set queue maxlen\n");
		goto exiterr;
	}
	// accept packets if they cant be handled
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN , NFQA_CFG_F_FAIL_OPEN))
	{
		fprintf(stderr, "can't set queue flags. errno=%d\n", errno);
		// dot not fail. not supported on old linuxes <3.6 
	}

	if (!droproot(params.uid, params.gid)) goto exiterr;
	printf("Running as UID=%u GID=%u\n", getuid(), getgid());

	signal(SIGHUP, onhup);

	desync_init();

	fd = nfq_fd(h);

	// increase socket buffer size. on slow systems reloading hostlist can take a while.
	// if too many unhandled packets are received its possible to get "no buffer space available" error
	if (!set_socket_buffers(fd,Q_RCVBUF/2,Q_SNDBUF/2))
		goto exiterr;
	do
	{
		while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
		{
			dohup();
			int r = nfq_handle_packet(h, buf, rv);
			if (r) fprintf(stderr, "nfq_handle_packet error %d\n", r);
		}
		fprintf(stderr, "recv: errno %d\n",errno);
		perror("recv");
		// do not fail on ENOBUFS
	} while(errno==ENOBUFS);

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);
	return 0;

exiterr:
	if (qh) nfq_destroy_queue(qh);
	if (h) nfq_close(h);
	return 1;
}

#elif defined(BSD)

static int dvt_main()
{
	uint8_t buf[16384] __attribute__((aligned));
	struct sockaddr_storage sa_from;
	int fd[2] = {-1,-1}; // 4,6
	int i,r,res=1,fdct=1,fdmax;
	unsigned int id=0;
	socklen_t socklen;
	ssize_t rd,wr;
	packet_process_result ppr;
	struct timeval timeout={1,0};
	fd_set fdset;

	{
		struct sockaddr_in bp4;
		bp4.sin_family = AF_INET;
		bp4.sin_port = htons(params.port);
		bp4.sin_addr.s_addr = INADDR_ANY;
	
		printf("creating divert4 socket\n");
		fd[0] = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
		if (fd[0] == -1) {
				perror("socket (DIVERT4): ");
			goto exiterr;
		}
		printf("binding divert4 socket\n");
		if (bind(fd[0], (struct sockaddr*)&bp4, sizeof(bp4)) < 0)
		{
			perror("bind (DIVERT4): ");
			goto exiterr;
		}
		if (!set_socket_buffers(fd[0],Q_RCVBUF,Q_SNDBUF))
			goto exiterr;
	}


#ifdef __OpenBSD__
	{
		// in OpenBSD must use separate divert sockets for ipv4 and ipv6
		struct sockaddr_in6 bp6;
		memset(&bp6,0,sizeof(bp6));
		bp6.sin6_family = AF_INET6;
		bp6.sin6_port = htons(params.port);
	
		printf("creating divert6 socket\n");
		fd[1] = socket(AF_INET6, SOCK_RAW, IPPROTO_DIVERT);
		if (fd[1] == -1) {
			perror("socket (DIVERT6): ");
			goto exiterr;
		}
		printf("binding divert6 socket\n");
		if (bind(fd[1], (struct sockaddr*)&bp6, sizeof(bp6)) < 0)
		{
			perror("bind (DIVERT6): ");
			goto exiterr;
		}
		fdct++;
		if (!set_socket_buffers(fd[1],Q_RCVBUF,Q_SNDBUF))
			goto exiterr;
	}
#endif
	fdmax = (fd[0]>fd[1] ? fd[0] : fd[1]) + 1;

	printf("initializing raw sockets with sockarg 0x%08X (%u)\n", params.desync_fwmark, params.desync_fwmark);
	if (!rawsend_preinit(params.desync_fwmark))
		goto exiterr;

	if (!droproot(params.uid, params.gid)) goto exiterr;
	printf("Running as UID=%u GID=%u\n", getuid(), getgid());

	signal(SIGHUP, onhup);

	desync_init();

	for(;;)
	{
		FD_ZERO(&fdset);
		for(i=0;i<fdct;i++) FD_SET(fd[i], &fdset);
		r = select(fdmax,&fdset,NULL,NULL,&timeout);
		if (r==-1)
		{
			if (errno==EINTR)
			{
				// a signal received
				dohup();
				continue;
			}
			perror("select: ");
			goto exiterr;
		}
		for(i=0;i<fdct;i++)
		{
			if (FD_ISSET(fd[i], &fdset))
			{
				socklen = sizeof(sa_from);
				rd = recvfrom(fd[i], buf, sizeof(buf), 0, (struct sockaddr*)&sa_from, &socklen);
				if (rd<0)
				{
					perror("recvfrom: ");
					goto exiterr;
				}
				else if (rd>0)
				{
					DLOG("packet: id=%u len=%zd\n", id, rd)
					ppr = processPacketData(buf, rd);
					switch (ppr)
					{
					case pass:
					case modify:
						DLOG(ppr==pass ? "packet: id=%u reinject unmodified\n" : "packet: id=%u reinject modified\n", id);
						wr = sendto(fd[i], buf, rd, 0, (struct sockaddr*)&sa_from, socklen);
						if (wr<0)
							perror("reinject sendto: ");
						else if (wr!=rd)
							fprintf(stderr,"reinject sendto: not all data was reinjected. received %zd, sent %zd\n", rd, wr);
						break;
					default:
						DLOG("packet: id=%u drop\n", id);
					}
					id++;
				}
				else
				{
					DLOG("unexpected zero size recvfrom\n")
				}
			}
		}
	}

	res=0;
exiterr:
	if (fd[0]!=-1) close(fd[0]);
	if (fd[1]!=-1) close(fd[1]);
	return res;
}

#endif



static void exithelp()
{
	printf(
		" --debug=0|1\n"
#ifdef __linux__
		" --qnum=<nfqueue_number>\n"
#elif defined(BSD)
		" --port=<port>\t\t\t\t; divert port\n"
#endif
		" --daemon\t\t\t\t; daemonize\n"
		" --pidfile=<filename>\t\t\t; write pid to file\n"
		" --user=<username>\t\t\t; drop root privs\n"
		" --uid=uid[:gid]\t\t\t; drop root privs\n"
		" --wsize=<window_size>\t\t\t; set window size. 0 = do not modify. OBSOLETE !\n"
		" --hostcase\t\t\t\t; change Host: => host:\n"
		" --hostspell\t\t\t\t; exact spelling of \"Host\" header. must be 4 chars. default is \"host\"\n"
		" --hostnospace\t\t\t\t; remove space after Host: and add it to User-Agent: to preserve packet size\n"
		" --domcase\t\t\t\t; mix domain case : Host: TeSt.cOm\n"
		" --dpi-desync=<mode>[,<mode2>]\t\t; try to desync dpi state. modes : fake rst rstack disorder disorder2 split split2\n"
#ifdef __linux__
		" --dpi-desync-fwmark=<int|0xHEX>\t; override fwmark for desync packet. default = 0x%08X (%u)\n"
#elif defined(SO_USER_COOKIE)
		" --dpi-desync-sockarg=<int|0xHEX>\t; override sockarg (SO_USER_COOKIE) for desync packet. default = 0x%08X (%u)\n"
#endif
		" --dpi-desync-ttl=<int>\t\t\t; set ttl for desync packet\n"
		" --dpi-desync-fooling=<mode>[,<mode>]\t; can use multiple comma separated values. modes : none md5sig ts badseq badsum\n"
		" --dpi-desync-retrans=0|1\t\t; 0(default)=reinject original data packet after fake  1=drop original data packet to force its retransmission\n"
		" --dpi-desync-repeats=<N>\t\t; send every desync packet N times\n"
		" --dpi-desync-skip-nosni=0|1\t\t; 1(default)=do not act on ClientHello without SNI (ESNI ?)\n"
		" --dpi-desync-split-pos=<1..%u>\t; (for disorder only) split TCP packet at specified position\n"
		" --dpi-desync-any-protocol=0|1\t\t; 0(default)=desync only http and tls  1=desync any nonempty data packet\n"
		" --dpi-desync-fake-http=<filename>\t; file containing fake http request\n"
		" --dpi-desync-fake-tls=<filename>\t; file containing fake TLS ClientHello (for https)\n"
		" --hostlist=<filename>\t\t\t; apply dpi desync only to the listed hosts (one host per line, subdomains auto apply)\n",
#if defined(__linux__) || defined(SO_USER_COOKIE)
		DPI_DESYNC_FWMARK_DEFAULT,DPI_DESYNC_FWMARK_DEFAULT,
#endif
		DPI_DESYNC_MAX_FAKE_LEN
	);
	exit(1);
}

static void cleanup_params()
{
	if (params.hostlist)
	{
		StrPoolDestroy(&params.hostlist);
		params.hostlist = NULL;
	}
}
static void exithelp_clean()
{
	cleanup_params();
	exithelp();
}
static void exit_clean(int code)
{
	cleanup_params();
	exit(code);
}

int main(int argc, char **argv)
{
	int result, v;
	int option_index = 0;
	bool daemon = false;
	char pidfile[256];

	srandom(time(NULL));

	memset(&params, 0, sizeof(params));
	memcpy(params.hostspell, "host", 4); // default hostspell
	*pidfile = 0;

	params.desync_fwmark = DPI_DESYNC_FWMARK_DEFAULT;
	params.desync_skip_nosni = true;
	params.desync_split_pos = 3;
	params.desync_repeats = 1;
	params.fake_tls_size = sizeof(fake_tls_clienthello_default);
	memcpy(params.fake_tls,fake_tls_clienthello_default,params.fake_tls_size);
	params.fake_http_size = strlen(fake_http_request_default);
	memcpy(params.fake_http,fake_http_request_default,params.fake_http_size);
	params.uid = params.gid = 0x7FFFFFFF; // default uid:gid

	const struct option long_options[] = {
		{"debug",optional_argument,0,0},	// optidx=0
#ifdef __linux__
		{"qnum",required_argument,0,0},		// optidx=1
#elif defined(BSD)
		{"port",required_argument,0,0},		// optidx=1
#else
		{"disabled_argument_1",no_argument,0,0},// optidx=1
#endif
		{"daemon",no_argument,0,0},		// optidx=2
		{"pidfile",required_argument,0,0},	// optidx=3
		{"user",required_argument,0,0 },	// optidx=4
		{"uid",required_argument,0,0 },		// optidx=5
		{"wsize",required_argument,0,0},	// optidx=6
		{"hostcase",no_argument,0,0},		// optidx=7
		{"hostspell",required_argument,0,0},	// optidx=8
		{"hostnospace",no_argument,0,0},	// optidx=9
		{"domcase",no_argument,0,0 },		// optidx=10
		{"dpi-desync",required_argument,0,0},		// optidx=11
#ifdef __linux__
		{"dpi-desync-fwmark",required_argument,0,0},	// optidx=12
#elif defined(SO_USER_COOKIE)
		{"dpi-desync-sockarg",required_argument,0,0},	// optidx=12
#else
		{"disabled_argument_2",no_argument,0,0},	// optidx=12
#endif
		{"dpi-desync-ttl",required_argument,0,0},	// optidx=13
		{"dpi-desync-fooling",required_argument,0,0},	// optidx=14
		{"dpi-desync-retrans",optional_argument,0,0},	// optidx=15
		{"dpi-desync-repeats",required_argument,0,0},	// optidx=16
		{"dpi-desync-skip-nosni",optional_argument,0,0},// optidx=17
		{"dpi-desync-split-pos",required_argument,0,0},// optidx=18
		{"dpi-desync-any-protocol",optional_argument,0,0},// optidx=19
		{"dpi-desync-fake-http",required_argument,0,0},// optidx=20
		{"dpi-desync-fake-tls",required_argument,0,0},// optidx=21
		{"hostlist",required_argument,0,0},		// optidx=22
		{NULL,0,NULL,0}
	};
	if (argc < 2) exithelp();
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case 0: /* debug */
			params.debug = !optarg || atoi(optarg);
			break;
		case 1: /* qnum or port */
#ifdef __linux__
			params.qnum = atoi(optarg);
			if (params.qnum < 0 || params.qnum>65535)
			{
				fprintf(stderr, "bad qnum\n");
				exit_clean(1);
			}
#elif defined(BSD)
			{
				int i = atoi(optarg);
				if (i <= 0 || i > 65535)
				{
					fprintf(stderr, "bad port number\n");
					exit_clean(1);
				}
				params.port = (uint16_t)i;
			}
#endif
			break;
		case 2: /* daemon */
			daemon = true;
			break;
		case 3: /* pidfile */
			strncpy(pidfile, optarg, sizeof(pidfile));
			pidfile[sizeof(pidfile) - 1] = '\0';
			break;
		case 4: /* user */
		{
			struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				fprintf(stderr, "non-existent username supplied\n");
				exit_clean(1);
			}
			params.uid = pwd->pw_uid;
			params.gid = pwd->pw_gid;
			break;
		}
		case 5: /* uid */
			params.gid = 0x7FFFFFFF; // default gid. drop gid=0
			if (!sscanf(optarg, "%u:%u", &params.uid, &params.gid))
			{
				fprintf(stderr, "--uid should be : uid[:gid]\n");
				exit_clean(1);
			}
			break;
		case 6: /* wsize */
			params.wsize = atoi(optarg);
			if (params.wsize < 0 || params.wsize>65535)
			{
				fprintf(stderr, "bad wsize\n");
				exit_clean(1);
			}
			break;
		case 7: /* hostcase */
			params.hostcase = true;
			break;
		case 8: /* hostspell */
			if (strlen(optarg) != 4)
			{
				fprintf(stderr, "hostspell must be exactly 4 chars long\n");
				exit_clean(1);
			}
			params.hostcase = true;
			memcpy(params.hostspell, optarg, 4);
			break;
		case 9: /* hostnospace */
			params.hostnospace = true;
			break;
		case 10: /* domcase */
			params.domcase = true;
			break;
		case 11: /* dpi-desync */
			{
				char *mode2;
				mode2 = optarg ? strchr(optarg,',') : NULL;
				if (mode2) *mode2++=0;

				params.desync_mode = desync_mode_from_string(optarg);
				params.desync_mode2 = desync_mode_from_string(mode2);
				if (params.desync_mode==DESYNC_NONE || params.desync_mode==DESYNC_INVALID || params.desync_mode2==DESYNC_INVALID)
				{
					fprintf(stderr, "invalid dpi-desync mode\n");
					exit_clean(1);
				}
				if (params.desync_mode2 && !(desync_valid_first_stage(params.desync_mode) && desync_valid_second_stage(params.desync_mode2)))
				{
					fprintf(stderr, "invalid desync combo : %s+%s\n", optarg,mode2);
					exit_clean(1);
				}
			}
			break;
		case 12: /* dpi-desync-fwmark/dpi-desync-sockarg */
#if defined(__linux__) || defined(SO_USER_COOKIE)
			params.desync_fwmark = 0;
			if (!sscanf(optarg, "0x%X", &params.desync_fwmark)) sscanf(optarg, "%u", &params.desync_fwmark);
			if (!params.desync_fwmark)
			{
				fprintf(stderr, "fwmark/sockarg should be decimal or 0xHEX and should not be zero\n");
				exit_clean(1);
			}
#else
			fprintf(stderr, "fmwark/sockarg not supported in this OS\n");
			exit_clean(1);
#endif
			break;
		case 13: /* dpi-desync-ttl */
			params.desync_ttl = (uint8_t)atoi(optarg);
			break;
		case 14: /* dpi-desync-fooling */
			{
				char *e,*p = optarg;
				while (p)
				{
					e = strchr(p,',');
					if (e) *e++=0;
					if (!strcmp(p,"md5sig"))
						params.desync_tcp_fooling_mode |= TCP_FOOL_MD5SIG;
					else if (!strcmp(p,"ts"))
						params.desync_tcp_fooling_mode |= TCP_FOOL_TS;
					else if (!strcmp(p,"badsum"))
					{
						#ifdef __OpenBSD__
						printf("\nWARNING !!! OpenBSD may forcibly recompute tcp checksums !!! In this case badsum fooling will not work.\nYou should check tcp checksum correctness in tcpdump manually before using badsum.\n\n");
						#endif
						params.desync_tcp_fooling_mode |= TCP_FOOL_BADSUM;
					}
					else if (!strcmp(p,"badseq"))
						params.desync_tcp_fooling_mode |= TCP_FOOL_BADSEQ;
					else if (strcmp(p,"none"))
					{
						fprintf(stderr, "dpi-desync-fooling allowed values : none,md5sig,ts,badseq,badsum\n");
						exit_clean(1);
					}
					p = e;
				}
			}
			break;
		case 15: /* dpi-desync-retrans */
			params.desync_retrans = !optarg || atoi(optarg);
			break;
		case 16: /* dpi-desync-repeats */
			params.desync_repeats = atoi(optarg);
			if (params.desync_repeats<=0 || params.desync_repeats>20)
			{
				fprintf(stderr, "dpi-desync-repeats must be within 1..20\n");
				exit_clean(1);
			}
			break;
		case 17: /* dpi-desync-skip-nosni */
			params.desync_skip_nosni = !optarg || atoi(optarg);
			break;
		case 18: /* dpi-desync-split-pos */
			params.desync_split_pos = atoi(optarg);
			if (params.desync_split_pos<1 || params.desync_split_pos>DPI_DESYNC_MAX_FAKE_LEN)
			{
				fprintf(stderr, "dpi-desync-split-pos must be within 1..%u range\n",DPI_DESYNC_MAX_FAKE_LEN);
				exit_clean(1);
			}
			break;
		case 19: /* dpi-desync-any-protocol */
			params.desync_any_proto = !optarg || atoi(optarg);
			break;
		case 20: /* dpi-desync-fake-http */
			params.fake_http_size = sizeof(params.fake_http);
			if (!load_file_nonempty(optarg,params.fake_http,&params.fake_http_size))
			{
				fprintf(stderr, "could not read %s\n",optarg);
				exit_clean(1);
			}
			break;
		case 21: /* dpi-desync-fake-tls */
			params.fake_tls_size = sizeof(params.fake_tls);
			if (!load_file_nonempty(optarg,params.fake_tls,&params.fake_tls_size))
			{
				fprintf(stderr, "could not read %s\n",optarg);
				exit_clean(1);
			}
			break;
		case 22: /* hostlist */
			if (!LoadHostList(&params.hostlist, optarg))
				exit_clean(1);
			strncpy(params.hostfile,optarg,sizeof(params.hostfile));
			params.hostfile[sizeof(params.hostfile)-1]='\0';
			break;
		}
	}
#ifdef BSD
	if (!params.port)
	{
		fprintf(stderr, "Need port number\n");
		exit_clean(1);
	}
#endif

	if (daemon) daemonize();

	if (*pidfile && !writepid(pidfile))
	{
		fprintf(stderr, "could not write pidfile\n");
		goto exiterr;
	}

#ifdef __linux__
	result = nfq_main();
#elif defined(BSD)
	result = dvt_main();
#else
	#error unsupported OS
#endif
ex:
	rawsend_cleanup();
	cleanup_params();
	return result;
exiterr:
	result = 1;
	goto ex;
}
