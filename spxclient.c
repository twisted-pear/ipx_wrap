#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

enum spxclient_error_codes {
	SPXCLIENT_ERR_OK = 0,
	SPXCLIENT_ERR_USAGE,
	SPXCLIENT_ERR_BIND,
	SPXCLIENT_ERR_GETSOCKNAME,
	SPXCLIENT_ERR_CONNECT,
	SPXCLIENT_ERR_MAX
};

struct spxclient_cfg {
	bool verbose;
	struct ipx_addr local_addr;
	struct ipx_addr target_addr;
};

static _Noreturn void do_spxclient(struct spxclient_cfg *cfg)
{
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->local_addr;
	bind_msg.bind.pkt_type = SPX_PKT_TYPE;
	bind_msg.bind.pkt_type_any = false;
	bind_msg.bind.recv_bcast = false;

	struct ipxw_mux_handle ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		exit(SPXCLIENT_ERR_BIND);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->local_addr))) {
			perror("IPX get bound address");
			ipxw_mux_unbind(ipxh);
			exit(SPXCLIENT_ERR_GETSOCKNAME);
		}

		fprintf(stderr, "bound to ");
		print_ipxaddr(stderr, &(cfg->local_addr));
		fprintf(stderr, "\n");
	}

	/* connect to the SPX server */
	struct ipxw_mux_spx_handle spxh = ipxw_mux_kspx_connect(ipxh,
			&(cfg->target_addr));
	if (ipxw_mux_spx_handle_is_error(spxh)) {
		perror("SPX connect");
		ipxw_mux_unbind(ipxh);
		exit(SPXCLIENT_ERR_CONNECT);
	}

	ipxw_mux_spx_conn_close(&spxh);
	ipxw_mux_unbind(ipxh);
	exit(SPXCLIENT_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: spxclient [-v] <local IPX addr> <target IPX address>\n");
	exit(SPXCLIENT_ERR_USAGE);
}

static bool verify_cfg(struct spxclient_cfg *cfg)
{
	return true;
}

int main(int argc, char **argv)
{
	struct spxclient_cfg cfg = {
		.verbose = false
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

	if (optind + 2 != argc) {
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

	do_spxclient(&cfg);
}
