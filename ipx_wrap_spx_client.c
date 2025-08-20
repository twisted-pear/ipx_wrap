#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ipx_wrap_mux_proto.h"

#define MAX_EPOLL_EVENTS 64

static bool keep_going = true;

static void signal_handler(int signal)
{
	switch (signal) {
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			keep_going = false;
			break;
		default:
			assert(0);
	}
}

static int setup_timer(int epoll_fd)
{
	int tmr = timerfd_create(CLOCK_MONOTONIC, 0);
	if (tmr < 0) {
		return -1;
	}

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = tmr
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tmr, &ev) < 0) {
		close(tmr);
		return -1;
	}

	struct itimerspec tmr_spec = {
		.it_interval = { .tv_nsec = TICKS_MS * 1000 * 1000 },
		.it_value = { .tv_nsec = TICKS_MS * 1000 * 1000 }
	};
	if (timerfd_settime(tmr, 0, &tmr_spec, NULL) < 0) {
		close(tmr);
		return -1;
	}

	return tmr;
}

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

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		ipxw_mux_handle_close(h);
		return 5;
	}

	int tmr_fd = setup_timer(epoll_fd);
	if (tmr_fd < 0) {
		perror("creating connection maintenance timer");
		ipxw_mux_handle_close(h);
		return 6;
	}

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ipxw_mux_spx_handle_sock(spxh)
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_spx_handle_sock(spxh),
				&ev) < 0) {
		perror("registering SPX socket for event polling");
		ipxw_mux_handle_close(h);
		return 7;
	}

	ev.data.fd = fileno(stdin);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fileno(stdin), &ev) < 0) {
		perror("registering stdin for event polling");
		ipxw_mux_handle_close(h);
		return 8;
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting signal handler");
		ipxw_mux_handle_close(h);
		return 9;
	}

	struct __attribute__((packed)) {
		struct ipxw_mux_spx_msg msg;
		char data[SPX_MAX_DATA_LEN_WO_SIZNG];
	} spx_msg;

	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			ipxw_mux_handle_close(h);
			return 10;
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					ipxw_mux_handle_close(h);
					return 11;
				}

				/* maintain the connection */
				if (!ipxw_mux_spx_maintain(spxh)) {
					fprintf(stderr, "failed to maintain "
							"connection\n");
					ipxw_mux_handle_close(h);
					return 12;
				}

				/* consume all expirations */
				__u64 dummy;
				read(tmr_fd, &dummy, sizeof(dummy));

				continue;
			}

			/* stdin */
			if (evs[i].data.fd == fileno(stdin)) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "stdin error\n");
					ipxw_mux_handle_close(h);
					return 13;
				}

				if (!ipxw_mux_spx_xmit_ready(spxh)) {
					continue;
				}

				if (fgets(spx_msg.data,
							SPX_MAX_DATA_LEN_WO_SIZNG,
							stdin) == NULL) {
					fprintf(stderr, "stdin EOF\n");
					ipxw_mux_handle_close(h);
					return 14;
				}

				ssize_t sent_len = ipxw_mux_spx_xmit(spxh,
						&(spx_msg.msg),
						strlen(spx_msg.data) + 1,
						false);
				if (sent_len < 0) {
					perror("send");
					ipxw_mux_handle_close(h);
					return 15;
				}

				continue;
			}

			/* the connection socket */

			/* something went wrong */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "connection socket error\n");
				ipxw_mux_handle_close(h);
				return 16;
			}

			/* message received */
			ssize_t expected_msg_len =
				ipxw_mux_spx_peek_recvd_len(spxh, false);
			if (expected_msg_len < 0) {
				perror("receive peek");
				ipxw_mux_handle_close(h);
				return 17;
			}
			if (expected_msg_len > sizeof(spx_msg)) {
				fprintf(stderr, "received SPX msg too "
						"large\n");
				ipxw_mux_handle_close(h);
				return 18;
			}

			ssize_t rcvd_len = ipxw_mux_spx_get_recvd(spxh,
					&(spx_msg.msg), expected_msg_len -
					sizeof(struct ipxw_mux_spx_msg),
					false);
			if (rcvd_len < 0) {
				perror("receive");
				ipxw_mux_handle_close(h);
				return 19;
			}

			/* system msg */
			if (rcvd_len == 0) {
				continue;
			}

			/* print received message */
			size_t data_len = rcvd_len - sizeof(struct
					ipxw_mux_spx_msg);
			if (data_len == 0) {
				continue;
			}

			spx_msg.data[data_len - 1] = '\0';
			fputs(spx_msg.data, stdout);
		}
	}

	printf("closing connection\n");

	ipxw_mux_spx_close(spxh);
	ipxw_mux_unbind(h);

	return 0;
}
