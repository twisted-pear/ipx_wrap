#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ipx_wrap_mux_proto.h"

int main(int argc, char **argv)
{
	if (argc != 3) {
		return 1;
	}

	struct ipv6_eui64_addr bind_addr;
	if (inet_pton(AF_INET6, argv[1], &bind_addr) != 1) {
		perror("parse bind addr");
		return 1;
	}
	__u16 bind_sock = strtoul(argv[2], NULL, 0);

	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr.net = bind_addr.ipx_net;
	memcpy(bind_msg.bind.addr.node, bind_addr.ipx_node_fst,
			sizeof(bind_addr.ipx_node_fst));
	memcpy(bind_msg.bind.addr.node + sizeof(bind_addr.ipx_node_fst),
			bind_addr.ipx_node_snd,
			sizeof(bind_addr.ipx_node_snd));
	bind_msg.bind.addr.sock = htons(bind_sock);
	bind_msg.bind.pkt_type = SPX_PKT_TYPE;
	bind_msg.bind.pkt_type_any = false;
	bind_msg.bind.recv_bcast = false;

	struct ipxw_mux_handle h = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(h)) {
		perror("bind");
		return 2;
	}
	printf("bind successful\n");

	ssize_t expected = ipxw_mux_peek_recvd_len(h, true);
	if (expected < 0) {
		perror("recv");
		ipxw_mux_unbind(h);
		return 3;
	}
	struct ipxw_mux_msg *data_msg = calloc(1, expected);
	if (data_msg == NULL) {
		perror("alloc");
		ipxw_mux_unbind(h);
		return 4;
	}

	data_msg->type = IPXW_MUX_RECV;
	data_msg->recv.data_len = expected - sizeof(*data_msg);
	ssize_t len = ipxw_mux_get_recvd(h, data_msg, true);
	if (len < 0) {
		perror("recv");
		free(data_msg);
		ipxw_mux_unbind(h);
		return 5;
	}
	printf("recvd %ld bytes\n", len);

	__be16 remote_conn_id = ipxw_mux_spx_check_for_conn_req(data_msg);
	if (remote_conn_id == SPX_CONN_ID_UNKNOWN) {
		fprintf(stderr, "invalid SPX packet\n");
		free(data_msg);
		ipxw_mux_unbind(h);
		return 6;
	}

	struct ipxw_mux_spx_handle spxh = ipxw_mux_spx_accept(h,
			&(data_msg->recv.saddr), remote_conn_id);
	if (ipxw_mux_spx_handle_is_error(spxh)) {
		perror("accept");
		free(data_msg);
		ipxw_mux_unbind(h);
		return 7;
	}

	printf("connection 0x%04hx accepted\n", remote_conn_id);
	sleep(60);

	free(data_msg);
	ipxw_mux_unbind(h);

	return 0;
}
