#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ipx_wrap_mux_proto.h"

int main(int argc, char **argv)
{
	if (argc != 4) {
		return 1;
	}

	int bind_net_no = strtoul(argv[1], NULL, 0);
	int dest_net_no = strtoul(argv[2], NULL, 0);
	int recv_bcast = strtoul(argv[3], NULL, 0);

	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr.net = htonl(bind_net_no);
	bind_msg.bind.recv_bcast = recv_bcast;

	int data_sock = ipxw_mux_bind(&bind_msg);
	if (data_sock < 0) {
		fprintf(stderr, "bind failed: %s\n", strerror(-data_sock));
		return 1;
	}
	printf("bind successful\n");

	int i;
	for (i = 0; i < 20; i++) {
		fprintf(stderr, "iter %d\n", i);
		struct ipxw_mux_msg *data_msg = calloc(1, IPXW_MUX_MSG_LEN);
		if (data_msg == NULL) {
			perror("alloc");
			close(data_sock);
			return 2;
		}

		data_msg->type = IPXW_MUX_XMIT;
		data_msg->xmit.data_len = IPX_MAX_DATA_LEN - i;
		data_msg->xmit.daddr.net = htonl(dest_net_no);
		ssize_t len = ipxw_mux_xmit(data_sock, data_msg);
		free(data_msg);
		if (len < 0) {
			fprintf(stderr, "xmit failed: %s\n", strerror(-len));
			close(data_sock);
			return 3;
		}
		printf("xmitted %ld bytes\n", len);

		data_msg = calloc(1, IPXW_MUX_MSG_LEN);
		if (data_msg == NULL) {
			perror("alloc");
			close(data_sock);
			return 4;
		}

		len = ipxw_mux_get_recvd(data_sock, data_msg);
		free(data_msg);
		if (len < 0) {
			fprintf(stderr, "recv failed: %s\n", strerror(-len));
			close(data_sock);
			return 3;
		}

		printf("recvd %ld bytes\n", len);
	}

	fprintf(stderr, "sending unbind\n");
	ipxw_mux_unbind(data_sock);

	return 0;
}
