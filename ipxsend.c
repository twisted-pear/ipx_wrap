#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

#define DEFAULT_PKT_TYPE 0x1E

enum ipxsend_error_codes {
	IPXSEND_ERR_OK = 0,
	IPXSEND_ERR_USAGE,
	IPXSEND_ERR_BIND,
	IPXSEND_ERR_GETSOCKNAME,
	IPXSEND_ERR_SEND,
	IPXSEND_ERR_MAX
};

struct ipxsend_cfg {
	bool verbose;
	__u8 pkt_type;
	struct ipx_addr local_addr;
	struct ipx_addr target_addr;
};

static _Noreturn void do_ipxsend(struct ipxsend_cfg *cfg, const char *to_send,
		size_t len)
{
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->local_addr;
	bind_msg.bind.pkt_type = cfg->pkt_type;
	bind_msg.bind.pkt_type_any = true;
	bind_msg.bind.recv_bcast = false;

	struct ipxw_mux_handle ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		exit(IPXSEND_ERR_BIND);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->local_addr))) {
			perror("IPX get bound address");
			ipxw_mux_unbind(ipxh);
			exit(IPXSEND_ERR_GETSOCKNAME);
		}

		fprintf(stderr, "bound to ");
		print_ipxaddr(stderr, &(cfg->local_addr));
		fprintf(stderr, "\n");
	}

	/* prepare destination address */
	struct sockaddr_ipx dst;
	dst.sipx_family = AF_IPX;
	dst.sipx_type = cfg->pkt_type;
	dst.sipx_network = cfg->target_addr.net;
	memcpy(dst.sipx_node, cfg->target_addr.node, sizeof(dst.sipx_node));
	dst.sipx_port = cfg->target_addr.sock;

	/* send the message */
	ssize_t sent = ipxw_sendto(ipxh, to_send, len, 0, (struct sockaddr *)
			&dst, sizeof(dst));
	if (sent < 0) {
		perror("sending message");
		ipxw_mux_unbind(ipxh);
		exit(IPXSEND_ERR_SEND);
	}

	ipxw_mux_unbind(ipxh);
	exit(IPXSEND_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: ipxsend [-v] [-t <packet type>] <local IPX addr> <target IPX address> <message>\n");
	exit(IPXSEND_ERR_USAGE);
}

static bool verify_cfg(struct ipxsend_cfg *cfg)
{
	return true;
}

int main(int argc, char **argv)
{
	struct ipxsend_cfg cfg = {
		.verbose = false,
		.pkt_type = DEFAULT_PKT_TYPE,
	};

	/* parse and verify command-line arguments */

	int opt;
	while ((opt = getopt(argc, argv, "t:v")) != -1) {
		switch (opt) {
			case 't':
				cfg.pkt_type = strtoul(optarg, NULL, 0);
				break;
			case 'v':
				cfg.verbose = true;
				break;
			default:
				usage();
		}
	}

	if (optind + 3 != argc) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind], &(cfg.local_addr))) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind + 1], &(cfg.target_addr))) {
		usage();
	}

	if (!verify_cfg(&cfg)) {
		usage();
	}

	do_ipxsend(&cfg, argv[optind + 2], strlen(argv[optind + 2]));
}
