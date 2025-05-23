#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ipx_wrap_mux_proto.h"

int main(int argc, char **argv)
{
	if (argc != 6) {
		return 1;
	}

	struct ipv6_eui64_addr bind_addr;
	if (inet_pton(AF_INET6, argv[1], &bind_addr) != 1) {
		perror("parse bind addr");
		return 1;
	}
	__u16 bind_sock = strtoul(argv[2], NULL, 0);
	__u8 pkt_type = strtoul(argv[3], NULL, 0);
	__u8 pkt_type_any = strtoul(argv[4], NULL, 0);
	__u8 recv_bcast = strtoul(argv[5], NULL, 0);

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
	bind_msg.bind.pkt_type = pkt_type;
	bind_msg.bind.pkt_type_any = pkt_type_any;
	bind_msg.bind.recv_bcast = recv_bcast;

	struct ipxw_mux_handle h = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(h)) {
		perror("bind");
		return 2;
	}
	printf("bind successful\n");

	ssize_t expected = ipxw_mux_peek_recvd_len(h, true);
	if (expected < 0) {
		perror("recv");
		ipxw_mux_handle_close(h);
		return 3;
	}
	struct ipxw_mux_msg *data_msg = calloc(1, expected);
	if (data_msg == NULL) {
		perror("alloc");
		ipxw_mux_handle_close(h);
		return 4;
	}

	data_msg->type = IPXW_MUX_RECV;
	data_msg->recv.data_len = expected - sizeof(*data_msg);
	ssize_t len = ipxw_mux_get_recvd(h, data_msg, true);
	free(data_msg);
	if (len < 0) {
		perror("recv");
		ipxw_mux_handle_close(h);
		return 5;
	}
	printf("recvd %ld bytes\n", len);

	ipxw_mux_unbind(h);

	return 0;
}
