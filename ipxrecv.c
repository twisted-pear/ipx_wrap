#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

#define DEFAULT_PKT_TYPE 0x1E

enum ipxrecv_error_codes {
	IPXRECV_ERR_OK = 0,
	IPXRECV_ERR_USAGE,
	IPXRECV_ERR_BIND,
	IPXRECV_ERR_GETSOCKNAME,
	IPXRECV_ERR_RECV,
	IPXRECV_ERR_SRC,
	IPXRECV_ERR_MAX
};

struct ipxrecv_cfg {
	bool verbose;
	__u8 pkt_type;
	struct ipx_addr local_addr;
};

char recv_buf[IPX_MAX_DATA_LEN + 1];

static _Noreturn void do_ipxrecv(struct ipxrecv_cfg *cfg)
{
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->local_addr;
	bind_msg.bind.pkt_type = cfg->pkt_type;
	bind_msg.bind.pkt_type_any = true;
	bind_msg.bind.recv_bcast = true;
	bind_msg.bind.recv_direct = true;

	struct ipxw_mux_handle ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		exit(IPXRECV_ERR_BIND);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->local_addr))) {
			perror("IPX get bound address");
			ipxw_mux_unbind(ipxh);
			exit(IPXRECV_ERR_GETSOCKNAME);
		}

		fprintf(stderr, "bound to ");
		print_ipxaddr(stderr, &(cfg->local_addr));
		fprintf(stderr, "\n");
	}

	/* prepare destination address */
	struct sockaddr_ipx src;
	socklen_t src_len = sizeof(src);

	/* receive the message */
	ssize_t rcvd = ipxw_mux_recvfrom(ipxh, recv_buf, IPX_MAX_DATA_LEN, 0,
			(struct sockaddr *) &src, &src_len);
	if (rcvd < 0) {
		perror("receiving message");
		ipxw_mux_unbind(ipxh);
		exit(IPXRECV_ERR_RECV);
	}
	recv_buf[rcvd] = '\0';

	if (src_len != sizeof(struct sockaddr_ipx)) {
		fprintf(stderr, "invalid source address\n");
		ipxw_mux_unbind(ipxh);
		exit(IPXRECV_ERR_SRC);
	}
	if (src.sipx_family != AF_IPX) {
		fprintf(stderr, "invalid source address\n");
		ipxw_mux_unbind(ipxh);
		exit(IPXRECV_ERR_SRC);
	}

	ipxw_mux_unbind(ipxh);

	struct ipx_addr src_ipxaddr = {
		.net = src.sipx_network,
		.sock = src.sipx_port
	};
	memcpy(src_ipxaddr.node, src.sipx_node, IPX_ADDR_NODE_BYTES);

	printf("got %ld bytes from ", rcvd);
	print_ipxaddr(stdout, &src_ipxaddr);
	printf(", type: %02hhx:\n", src.sipx_type);
	printf("%s\n", recv_buf);

	exit(IPXRECV_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: ipxrecv [-v] <local IPX addr>\n");
	exit(IPXRECV_ERR_USAGE);
}

static bool verify_cfg(struct ipxrecv_cfg *cfg)
{
	return true;
}

int main(int argc, char **argv)
{
	struct ipxrecv_cfg cfg = {
		.verbose = false,
		.pkt_type = DEFAULT_PKT_TYPE,
	};

	/* parse and verify command-line arguments */

	int opt;
	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
			case 'v':
				cfg.verbose = true;
				break;
			default:
				usage();
		}
	}

	if (optind + 1 != argc) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind], &(cfg.local_addr))) {
		usage();
	}

	if (!verify_cfg(&cfg)) {
		usage();
	}

	do_ipxrecv(&cfg);
}
