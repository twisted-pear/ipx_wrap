#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ipx_wrap_mux_proto.h"

static int global_data_sock = 0;

int record_bind(int data_sock, struct ipxw_mux_msg_bind *bind_msg, void *ctx)
{
	global_data_sock = data_sock;
	printf("recording binding: %d\n", data_sock);
	return 0;
}

int tx_msg(struct ipxw_mux_msg *msg, void *ctx)
{
	printf("txing msg with %d bytes\n", msg->xmit.data_len);
	struct ipx_addr none;
	memset(&none, 0, sizeof(none));

	struct ipxhdr *ipx_msg = ipxw_mux_xmit_msg_to_ipxh(msg, &none);
	if (ipx_msg == NULL) {
		fprintf(stderr, "failed to make ipx pkt\n");
		free(msg);
		return -1;
	}
	printf("made ipx pkt with %d bytes\n", ntohs(ipx_msg->pktlen));

	struct ipxw_mux_msg *recv_msg = ipxw_mux_ipxh_to_recv_msg(ipx_msg);
	if (recv_msg == NULL) {
		fprintf(stderr, "failed to make recv msg\n");
		free(ipx_msg);
		return -1;
	}
	printf("made recv msg with %d bytes\n", recv_msg->recv.data_len);

	ssize_t msg_len = ipxw_mux_recv(global_data_sock, recv_msg);
	if (msg_len < 0) {
		perror("recving msg");
		free(recv_msg);
		return -1;
	}
	printf("recvd msg with %ld bytes\n", msg_len);

	free(msg);
	return 0;
}

void handle_unbind(int data_sock, void *ctx)
{
	printf("unbinding %d\n", data_sock);
	close(data_sock);
}

int main(int argc, char **argv)
{
	int ctrl_sock = ipxw_mux_mk_ctrl_sock();
	if (ctrl_sock < 0) {
		fprintf(stderr, "creating ctrl socket failed: %s\n",
				strerror(-ctrl_sock));
		return 1;
	}

	while (1) {
		int err = ipxw_mux_do_ctrl(ctrl_sock, &record_bind, NULL);
		if (err < 0) {
			fprintf(stderr, "bind handling failed: %s\n",
					strerror(-err));
			close(ctrl_sock);
			return 2;
		}

		do {
			err = ipxw_mux_do_data(global_data_sock, &tx_msg,
					&handle_unbind, NULL, NULL);
		} while (err > 0);

		if (err < 0) {
			fprintf(stderr, "data handling failed: %s\n",
					strerror(-err));
			close(global_data_sock);
			close(ctrl_sock);
			return 3;
		}

		printf("unbound data socket\n");
	}

	close(ctrl_sock);

	return 0;
}
