#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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
