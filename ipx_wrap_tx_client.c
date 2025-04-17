#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ipx_wrap_mux_proto.h"

int main(int argc, char **argv)
{
	if (argc != 7) {
		return 1;
	}

	struct ipv6_eui64_addr bind_addr;
	if (inet_pton(AF_INET6, argv[1], &bind_addr) != 1) {
		perror("parse bind addr");
		return 1;
	}
	__u16 bind_sock = strtoul(argv[2], NULL, 0);
	struct ipv6_eui64_addr dest_addr;
	if (inet_pton(AF_INET6, argv[3], &dest_addr) != 1) {
		perror("parse dest addr");
		return 2;
	}
	__u16 dest_sock = strtoul(argv[4], NULL, 0);
	size_t payload_len = strtoul(argv[5], NULL, 0);
	__u8 pkt_type = strtoul(argv[6], NULL, 0);

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
	bind_msg.bind.recv_bcast = 0;

	int data_sock = ipxw_mux_bind(&bind_msg);
	if (data_sock < 0) {
		perror("bind");
		return 3;
	}
	printf("bind successful\n");

	struct ipxw_mux_msg *data_msg = calloc(1, IPXW_MUX_MSG_LEN);
	if (data_msg == NULL) {
		perror("alloc");
		close(data_sock);
		return 4;
	}

	data_msg->type = IPXW_MUX_XMIT;
	data_msg->xmit.data_len = payload_len;
	data_msg->xmit.daddr.net = dest_addr.ipx_net;
	memcpy(data_msg->xmit.daddr.node, dest_addr.ipx_node_fst,
			sizeof(dest_addr.ipx_node_fst));
	memcpy(data_msg->xmit.daddr.node + sizeof(dest_addr.ipx_node_fst),
			dest_addr.ipx_node_snd,
			sizeof(dest_addr.ipx_node_snd));
	data_msg->xmit.daddr.sock = htons(dest_sock);
	data_msg->xmit.pkt_type = pkt_type;
	ssize_t len = ipxw_mux_xmit(data_sock, data_msg);
	free(data_msg);
	if (len < 0) {
		perror("xmit");
		close(data_sock);
		return 5;
	}
	printf("xmitted %ld bytes\n", len);

	ipxw_mux_unbind(data_sock);

	return 0;
}
