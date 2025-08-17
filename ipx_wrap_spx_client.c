#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ipx_wrap_mux_proto.h"

int main(int argc, char **argv)
{
	if (argc != 5) {
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
		return 3;
	}
	printf("bind successful\n");

	struct ipx_addr ipx_dest_addr = {
		.net = dest_addr.ipx_net,
		.sock = htons(dest_sock)
	};
	memcpy(ipx_dest_addr.node, dest_addr.ipx_node_fst,
			sizeof(dest_addr.ipx_node_fst));
	memcpy(ipx_dest_addr.node + sizeof(dest_addr.ipx_node_fst),
			dest_addr.ipx_node_snd,
			sizeof(dest_addr.ipx_node_snd));

	struct ipxw_mux_spx_handle spxh = ipxw_mux_spx_connect(h,
			&ipx_dest_addr);
	if (ipxw_mux_spx_handle_is_error(spxh)) {
		perror("connect");
		ipxw_mux_handle_close(h);
		return 4;
	}

	printf("connection initialized\n");
	sleep(10);

	ipxw_mux_spx_close(spxh);
	ipxw_mux_unbind(h);

	return 0;
}
