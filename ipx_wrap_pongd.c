#include "ipx_wrap_ping.h"
#include "ipx_wrap_service_lib.h"

#define MAINTENANCE_INTERVAL_SECS INTERFACE_RESCAN_SECS

static struct ipxw_mux_msg *mk_pong(struct ipxw_mux_msg *ping)
{
	struct ipxw_mux_msg *pong = calloc(1, sizeof(struct ipxw_mux_msg) +
			ping->recv.data_len);
	if (pong == NULL) {
		return NULL;
	}

	pong->type = IPXW_MUX_XMIT;
	pong->xmit.daddr = ping->recv.saddr;
	pong->xmit.pkt_type = ping->recv.pkt_type;
	pong->xmit.data_len = ping->recv.data_len;

	struct ping_pkt *ping_pkt = (struct ping_pkt *) ping->data;
	struct ping_pkt *pong_pkt = (struct ping_pkt *) pong->data;

	memcpy(pong_pkt->ping, PING_STR, PING_STR_LEN);
	pong_pkt->version = PING_VERSION;
	pong_pkt->type = PING_TYPE_REPLY;
	pong_pkt->id = ping_pkt->id;
	pong_pkt->result = PING_RESULT_REPLY;
	memcpy(pong_pkt->data, ping_pkt->data, ping->recv.data_len -
			sizeof(struct ping_pkt));

	return pong;
}


static void handle_ping(struct ipxw_mux_msg *ping, struct if_entry *in_if, int epoll_fd)
{
	fprintf(stderr, "Received Ping message from "
			"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx: ",
			ntohl(ping->recv.saddr.net), ping->recv.saddr.node[0],
			ping->recv.saddr.node[1], ping->recv.saddr.node[2],
			ping->recv.saddr.node[3], ping->recv.saddr.node[4],
			ping->recv.saddr.node[5], ntohs(ping->recv.saddr.sock));

	/* not a valid Ping */
	if (ping->recv.data_len < sizeof(struct ping_pkt)) {
		fprintf(stderr, "invalid.\n");
		return;
	}

	struct ping_pkt *ping_pkt = (struct ping_pkt *) ping->data;

	/* not a Ping query */
	if (ping_pkt->type != PING_TYPE_QUERY) {
		fprintf(stderr, "not a query.\n");
		return;
	}

	fprintf(stderr, "(ID: %hu) ", ntohs(ping_pkt->id));

	do {
		struct ipxw_mux_msg *pong = mk_pong(ping);
		if (pong == NULL) {
			break;
		}

		if (!queue_msg_on_iface(in_if, pong, epoll_fd)) {
			free(pong);
			break;
		}

		fprintf(stderr, "Pong sent!\n");
		return;
	} while (0);

	fprintf(stderr, "\n");
	perror("sending Pong");
	fprintf(stderr, ".\n");
}

void service_cleanup_and_exit(void *ctx)
{
	/* do nothing */
}

void service_ifup(struct if_entry *iface, int epoll_fd, void *ctx)
{
	/* do nothing */
}

bool service_maintenance(void *ctx, time_t now_secs, int epoll_fd)
{
	/* do nothing */
	return true;
}

void service_handle_signal(int signal)
{
	/* do nothing */
}

bool service_handle_msg(struct ipxw_mux_msg *msg, struct if_entry *iface, int
		epoll_fd, void *ctx)
{
	handle_ping(msg, iface, epoll_fd);

	return true;
}

bool service_reload(void *ctx)
{
	/* do nothing */
	return true;
}

static _Noreturn void usage(void)
{
	printf("Usage: ipx_wrap_pongd <32-bit hex prefix>\n");
	exit(SRVC_ERR_USAGE);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		usage();
	}

	__be32 prefix = htonl(strtoul(argv[1], NULL, 0));
	if (prefix == 0) {
		usage();
	}

	struct if_bind_config ifcfg = {
		.prefix = prefix,
		.sock = PING_SOCK,
		.pkt_type = PING_PKT_TYPE,
		.pkt_type_any = true,
		.recv_bcast = true
	};

	run_service(NULL, &ifcfg, MAINTENANCE_INTERVAL_SECS);

	return 0;
}
