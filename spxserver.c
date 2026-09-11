#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

enum spxserver_error_codes {
	SPXSERVER_ERR_OK = 0,
	SPXSERVER_ERR_USAGE,
	SPXSERVER_ERR_BIND,
	SPXSERVER_ERR_GETSOCKNAME,
	SPXSERVER_ERR_ACCEPT,
	SPXSERVER_ERR_SEND,
	SPXSERVER_ERR_MAX
};

struct spxserver_cfg {
	bool verbose;
	struct ipx_addr local_addr;
};

static _Noreturn void do_spxserver(struct spxserver_cfg *cfg)
{
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->local_addr;
	bind_msg.bind.pkt_type = SPX_PKT_TYPE;
	bind_msg.bind.pkt_type_any = false;
	bind_msg.bind.recv_bcast = false;
	bind_msg.bind.recv_direct = true;

	struct ipxw_mux_handle ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		exit(SPXSERVER_ERR_BIND);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->local_addr))) {
			perror("IPX get bound address");
			ipxw_mux_unbind(ipxh);
			exit(SPXSERVER_ERR_GETSOCKNAME);
		}

		fprintf(stderr, "bound to ");
		print_ipxaddr(stderr, &(cfg->local_addr));
		fprintf(stderr, "\n");
	}

	char connreq_buf[sizeof(struct spxhdr)];
	struct sockaddr_ipx src;
	socklen_t src_len = sizeof(struct sockaddr_ipx);
	ssize_t nrcvd = ipxw_mux_recvfrom(ipxh, connreq_buf, sizeof(struct
				spxhdr), 0, (struct sockaddr *) &src,
			&src_len);
	if (nrcvd < 0) {
		perror("SPX accept");
		ipxw_mux_unbind(ipxh);
		exit(SPXSERVER_ERR_ACCEPT);
	}

	__be16 remote_conn_id = ipxw_mux_kspx_check_for_conn_req(connreq_buf,
			nrcvd, &src);
	if (remote_conn_id == SPX_CONN_ID_UNKNOWN) {
		fprintf(stderr, "SPX accept: got invalid connection request\n");
		ipxw_mux_unbind(ipxh);
		exit(SPXSERVER_ERR_ACCEPT);
	}

	/* accept the SPX connection */
	struct ipxw_mux_spx_handle spxh = ipxw_mux_kspx_accept(ipxh,
			&src, remote_conn_id);
	if (ipxw_mux_spx_handle_is_error(spxh)) {
		perror("SPX accept");
		ipxw_mux_unbind(ipxh);
		exit(SPXSERVER_ERR_ACCEPT);
	}

	while (true) {
		char buf[SPX_MAX_DATA_LEN_WO_SIZNG + 1];
		__u8 ds_type = 0;
		__u8 spx_flags = 0;
		nrcvd = ipxw_mux_kspx_recv(spxh, buf,
				SPX_MAX_DATA_LEN_WO_SIZNG, 0, &ds_type,
				&spx_flags);
		if (nrcvd < 0) {
			perror("recv");
			break;
		}
		if (nrcvd == 0) {
			fprintf(stderr, "closed\n");
			break;
		}
		buf[nrcvd] = '\0';
		printf("rcvd %ld bytes (DS: %02hhx, Flags: %02hhx):\n", nrcvd,
				ds_type, spx_flags);
		puts(buf);

		long num = strtol(buf, NULL, 10);
		int nhex = snprintf(buf, SPX_MAX_DATA_LEN_WO_SIZNG, "%0lx\n",
				num);

		ssize_t nsent = ipxw_mux_kspx_send(spxh, buf, nhex, 0, 0x01,
				SPX_F_END_OF_MSG);
		if (nsent < 0) {
			perror("send");
			break;
		}
		printf("sent %ld bytes.\n", nsent);
	}

	ipxw_mux_spx_conn_close(&spxh);
	ipxw_mux_unbind(ipxh);
	exit(SPXSERVER_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: spxserver [-v] <local IPX addr>\n");
	exit(SPXSERVER_ERR_USAGE);
}

static bool verify_cfg(struct spxserver_cfg *cfg)
{
	return true;
}

int main(int argc, char **argv)
{
	struct spxserver_cfg cfg = {
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

	if (optind + 1 != argc) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind], &(cfg.local_addr))) {
		usage();
	}

	if (!verify_cfg(&cfg)) {
		usage();
	}

	do_spxserver(&cfg);
}
