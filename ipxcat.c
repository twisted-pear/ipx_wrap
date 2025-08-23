#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ipx_wrap_mux_proto.h"

#define DEFAULT_PKT_TYPE 0x1E
#define DEFAULT_IPX_DATA_LEN (SPX_MAX_DATA_LEN_WO_SIZNG - sizeof(struct \
			ipxhdr))

enum ipxcat_error_codes {
	IPXCAT_ERR_OK = 0,
	IPXCAT_ERR_USAGE,
	IPXCAT_ERR_EPOLL_FD,
	IPXCAT_ERR_TMR_FD,
	IPXCAT_ERR_STDIN_FD,
	IPXCAT_ERR_CONF_FD,
	IPXCAT_ERR_IPX_FD,
	IPXCAT_ERR_SPX_FD,
	IPXCAT_ERR_SIG_HANDLER,
	IPXCAT_ERR_BIND,
	IPXCAT_ERR_EPOLL_WAIT,
	IPXCAT_ERR_TMR_FAILURE,
	IPXCAT_ERR_CONF_FAILURE,
	IPXCAT_ERR_IPX_FAILURE,
	IPXCAT_ERR_SPX_FAILURE,
	IPXCAT_ERR_SPX_MAINT,
	IPXCAT_ERR_SPX_CONNECT,
	IPXCAT_ERR_SPX_ACCEPT,
	IPXCAT_ERR_MSG_ALLOC,
	IPXCAT_ERR_MSG_QUEUE,
	IPXCAT_ERR_MAX
};

#define MAX_EPOLL_EVENTS 64

STAILQ_HEAD(ipxw_msg_queue, ipxw_mux_msg);

struct ipxcat_cfg {
	bool verbose;
	bool listen;
	bool use_spx;
	bool accept_broadcasts;
	bool pkt_type_any;
	__u8 pkt_type;
	__u16 max_ipx_data_len;
	struct ipx_addr local_addr;
	struct ipx_addr remote_addr;
};

static bool keep_going = true;
static bool stdin_closed = false;
static struct ipxw_msg_queue ipx_out_queue = STAILQ_HEAD_INITIALIZER(
		ipx_out_queue);
static struct ipxw_msg_queue spx_out_queue = STAILQ_HEAD_INITIALIZER(
		spx_out_queue);
static struct ipxw_mux_handle ipxh = ipxw_mux_handle_init;
static struct ipxw_mux_spx_handle spxh = ipxw_mux_spx_handle_init;

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

static bool parse_ipxaddr(const char *str, struct ipx_addr *addr)
{
	__u32 net;
	__u16 sock;
	ssize_t res = sscanf(str,
			"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx",
			&net, &(addr->node[0]), &(addr->node[1]),
			&(addr->node[2]), &(addr->node[3]), &(addr->node[4]),
			&(addr->node[5]), &sock);
	if (res != 8) {
		return false;
	}

	addr->net = htonl(net);
	addr->sock = htons(sock);

	return true;
}

static void print_ipxaddr(FILE *f, const struct ipx_addr *addr)
{
	fprintf(f, "%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04x",
			ntohl(addr->net), addr->node[0], addr->node[1],
			addr->node[2], addr->node[3], addr->node[4],
			addr->node[5], ntohs(addr->sock));
}

static bool queue_out_msg(struct ipxw_msg_queue *q, int epoll_fd, int fd,
		struct ipxw_mux_msg *msg)
{
	/* reregister for ready-to-write events, now that messages are
	 * available */
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
		.data.fd = fd
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
		return false;
	}

	/* queue the config message on the config socket */
	STAILQ_INSERT_TAIL(q, msg, q_entry);

	return true;
}

static bool send_out_ipx_msg(struct ipxw_msg_queue *q, int epoll_fd, struct
		ipxw_mux_handle h)
{
	/* no msgs to send */
	if (STAILQ_EMPTY(q)) {
		/* unregister from ready-to-write events to avoid busy polling
		 */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP,
			.data.fd = ipxw_mux_handle_data(h)
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ipxw_mux_handle_data(h),
				&ev);

		return true;
	}

	struct ipxw_mux_msg *msg = STAILQ_FIRST(q);
	ssize_t err = ipxw_mux_xmit(h, msg, false);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return true;
		}

		/* other error, make sure to get rid of the message */
	}

	STAILQ_REMOVE_HEAD(q, q_entry);
	free(msg);

	return (err >= 0);
}

static bool send_out_spx_msg(struct ipxw_msg_queue *q, int epoll_fd, struct
		ipxw_mux_spx_handle h)
{
	/* no msgs to send */
	if (STAILQ_EMPTY(q)) {
		/* unregister from ready-to-write events to avoid busy polling
		 */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP,
			.data.fd = ipxw_mux_spx_handle_sock(h)
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ipxw_mux_spx_handle_sock(h),
				&ev);

		return true;
	}

	/* connection is not ready to transmit, retry later */
	if (!ipxw_mux_spx_xmit_ready(h)) {
		return true;
	}

	struct ipxw_mux_msg *msg = STAILQ_FIRST(q);
	struct ipxw_mux_spx_msg *spx_msg = (struct ipxw_mux_spx_msg *) msg;
	ssize_t err = ipxw_mux_spx_xmit(h, spx_msg, msg->xmit.data_len -
			sizeof(struct spxhdr), false);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return true;
		}

		/* other error, make sure to get rid of the message */
	}

	STAILQ_REMOVE_HEAD(q, q_entry);
	free(msg);

	return (err >= 0);
}

static _Noreturn void cleanup_and_exit(int epoll_fd, int tmr_fd, enum
		ipxcat_error_codes code)
{
	if (tmr_fd >= 0) {
		close(tmr_fd);
	}

	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	/* remove all undelivered messages */
	while (!STAILQ_EMPTY(&ipx_out_queue)) {
		struct ipxw_mux_msg *msg = STAILQ_FIRST(&ipx_out_queue);
		STAILQ_REMOVE_HEAD(&ipx_out_queue, q_entry);
		free(msg);
	}
	while (!STAILQ_EMPTY(&spx_out_queue)) {
		struct ipxw_mux_msg *msg = STAILQ_FIRST(&spx_out_queue);
		STAILQ_REMOVE_HEAD(&spx_out_queue, q_entry);
		free(msg);
	}

	ipxw_mux_spx_close(spxh);
	ipxw_mux_unbind(ipxh);

	exit(code);
}

static _Noreturn void do_ipxcat(struct ipxcat_cfg *cfg, int epoll_fd, int
		tmr_fd)
{
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->local_addr;
	bind_msg.bind.pkt_type = cfg->pkt_type;
	bind_msg.bind.pkt_type_any = cfg->pkt_type_any;
	bind_msg.bind.recv_bcast = cfg->accept_broadcasts;

	struct ipxw_mux_handle ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		cleanup_and_exit(epoll_fd, tmr_fd, IPXCAT_ERR_BIND);
	}

	if (cfg->verbose) {
		fprintf(stderr, "bound to ");
		print_ipxaddr(stderr, &(cfg->local_addr));
		fprintf(stderr, "\n");
	}

	struct epoll_event ev = {
		.events = EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ipxw_mux_handle_conf(ipxh)
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_conf(ipxh), &ev)
			< 0) {
		perror("registering config socket for event polling");
		cleanup_and_exit(epoll_fd, tmr_fd, IPXCAT_ERR_CONF_FD);
	}

	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = ipxw_mux_handle_data(ipxh);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_data(ipxh), &ev)
			< 0) {
		perror("registering IPX socket for event polling");
		cleanup_and_exit(epoll_fd, tmr_fd, IPXCAT_ERR_IPX_FD);
	}

	if (!cfg->listen) {
		/* only take input from STDIN when we are an IPX sender or SPX
		 * initiator */
		ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
		ev.data.fd = fileno(stdin);
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fileno(stdin), &ev) < 0)
		{
			perror("registering stdin for event polling");
			cleanup_and_exit(epoll_fd, tmr_fd,
					IPXCAT_ERR_STDIN_FD);
		}

		/* initiate SPX connection */
		if (cfg->use_spx) {
			spxh = ipxw_mux_spx_connect(ipxh, &(cfg->remote_addr));
			if (ipxw_mux_spx_handle_is_error(spxh)) {
				perror("SPX connect");
				cleanup_and_exit(epoll_fd, tmr_fd,
						IPXCAT_ERR_SPX_CONNECT);
			}

			ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
			ev.data.fd = ipxw_mux_spx_handle_sock(spxh);
			if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD,
						ipxw_mux_spx_handle_sock(spxh),
						&ev) < 0) {
				perror("registering SPX socket for event polling");
				cleanup_and_exit(epoll_fd, tmr_fd,
						IPXCAT_ERR_SPX_FD);
			}

			if (cfg->verbose) {
				fprintf(stderr, "connecting to ");
				print_ipxaddr(stderr, &(cfg->remote_addr));
				fprintf(stderr, "\n");
			}
		}
	}

	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		/* stop if STDIN reached EOF and no messages to send remain */
		if (stdin_closed) {
			if (STAILQ_EMPTY(&ipx_out_queue) &&
					STAILQ_EMPTY(&spx_out_queue)) {
				keep_going = false;
			}
		}

		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(epoll_fd, tmr_fd,
					IPXCAT_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(epoll_fd, tmr_fd,
							IPXCAT_ERR_TMR_FAILURE);
				}

				/* no SPX connection, do nothing */
				if (ipxw_mux_spx_handle_is_error(spxh)) {
					continue;
				}

				/* maintain the SPX connection */
				if (!ipxw_mux_spx_maintain(spxh)) {
					perror("maintaining connection");
					cleanup_and_exit(epoll_fd, tmr_fd,
							IPXCAT_ERR_SPX_MAINT);
				}

				/* consume all expirations */
				__u64 dummy;
				read(tmr_fd, &dummy, sizeof(dummy));

				continue;
			}

			/* stdin */
			if (evs[i].data.fd == fileno(stdin)) {
				/* we cannot send anything in this configuration */
				if (cfg->listen && !cfg->use_spx) {
					assert(0);
				}

				struct ipxw_mux_msg *msg = NULL;
				size_t max_data_len = cfg->max_ipx_data_len;
				if (cfg->use_spx) {
					msg = calloc(1, sizeof(struct
								ipxw_mux_spx_msg)
							+
							SPX_MAX_DATA_LEN_WO_SIZNG);
					max_data_len = SPX_MAX_DATA_LEN_WO_SIZNG;
				} else {
					msg = calloc(1, sizeof(struct
								ipxw_mux_msg) +
							cfg->max_ipx_data_len);
				}

				if (msg == NULL) {
					perror("allocating message");
					cleanup_and_exit(epoll_fd, tmr_fd,
							IPXCAT_ERR_MSG_ALLOC);
				}

				msg->type = IPXW_MUX_XMIT;

				char *data = (char *) msg->data;
				struct ipxw_msg_queue *q = &ipx_out_queue;
				int sockfd = ipxw_mux_handle_data(ipxh);
				if (cfg->use_spx) {
					data = (char *) ((struct ipxw_mux_spx_msg *)
							msg)->data;
					q = &spx_out_queue;
					sockfd =
						ipxw_mux_spx_handle_sock(spxh);
				} else {
					msg->xmit.pkt_type = cfg->pkt_type;
					msg->xmit.daddr = cfg->remote_addr;
				}

				// TODO: make the length calculation also work
				// with binary data
				if (fgets(data, max_data_len, stdin) == NULL) {
					free(msg);
					stdin_closed = true;
					continue;
				}

				/* record the message data length */
				msg->xmit.data_len = strlen(data) + 1;
				if (cfg->use_spx) {
					msg->xmit.data_len += sizeof(struct
							spxhdr);
				}

				if (!queue_out_msg(q, epoll_fd, sockfd, msg)) {
					free(msg);
					perror("queueing message");
					cleanup_and_exit(epoll_fd, tmr_fd,
							IPXCAT_ERR_MSG_QUEUE);
				}

				continue;
			}

			/* config socket */
			if (evs[i].data.fd == ipxw_mux_handle_conf(ipxh)) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "config socket error\n");
					cleanup_and_exit(epoll_fd, tmr_fd,
							IPXCAT_ERR_CONF_FAILURE);
				}

				continue;
			}

			/* SPX socket */
			if (evs[i].data.fd == ipxw_mux_spx_handle_sock(spxh)) {
				if (!cfg->use_spx ||
						ipxw_mux_spx_handle_is_error(spxh))
				{
					assert(0);
				}

				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "SPX socket error\n");
					cleanup_and_exit(epoll_fd, tmr_fd,
							IPXCAT_ERR_SPX_FAILURE);
				}

				/* can write to SPX socket */
				if (evs[i].events & EPOLLOUT) {
					if (!send_out_spx_msg(&spx_out_queue,
								epoll_fd,
								spxh)) {
						fprintf(stderr, "SPX socket error\n");
						cleanup_and_exit(epoll_fd,
								tmr_fd,
								IPXCAT_ERR_SPX_FAILURE);
					}
				}

				/* nothing to read from SPX socket */
				if (!(evs[i].events & EPOLLIN)) {
					continue;
				}

				/* SPX message received */
				ssize_t expected_msg_len =
					ipxw_mux_spx_peek_recvd_len(spxh,
							false);
				if (expected_msg_len < 0) {
					if (errno == EINTR) {
						continue;
					}

					perror("SPX receive peek");
					cleanup_and_exit(epoll_fd, tmr_fd,
							IPXCAT_ERR_SPX_FAILURE);
				}

				struct ipxw_mux_spx_msg *msg = calloc(1,
						expected_msg_len + 1);
				if (msg == NULL) {
					perror("allocating message");
					cleanup_and_exit(epoll_fd, tmr_fd,
							IPXCAT_ERR_MSG_ALLOC);
				}

				ssize_t rcvd_len = ipxw_mux_spx_get_recvd(spxh,
						msg, expected_msg_len -
						sizeof(struct
							ipxw_mux_spx_msg),
						false);
				if (rcvd_len < 0) {
					free(msg);
					if (errno == EINTR) {
						continue;
					}

					perror("SPX receive");
					cleanup_and_exit(epoll_fd, tmr_fd,
							IPXCAT_ERR_SPX_FAILURE);
				}

				/* system msg */
				if (rcvd_len == 0) {
					free(msg);
					continue;
				}

				/* print received message */
				size_t data_len = rcvd_len - sizeof(struct
						ipxw_mux_spx_msg);
				if (data_len == 0) {
					free(msg);
					continue;
				}
				msg->data[data_len] = '\0';

				fputs((char *) msg->data, stdout);

				free(msg);
				continue;
			}

			/* IPX socket */

			/* something went wrong */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "IPX socket error\n");
				cleanup_and_exit(epoll_fd, tmr_fd,
						IPXCAT_ERR_IPX_FAILURE);
			}

			/* can write to IPX socket */
			if (evs[i].events & EPOLLOUT) {
				if (!send_out_ipx_msg(&ipx_out_queue,
							epoll_fd,
							ipxh)) {
					fprintf(stderr, "IPX socket error\n");
					cleanup_and_exit(epoll_fd,
							tmr_fd,
							IPXCAT_ERR_IPX_FAILURE);
				}
			}

			/* nothing to read from IPX socket */
			if (!(evs[i].events & EPOLLIN)) {
				continue;
			}

			/* IPX message received */
			ssize_t expected_msg_len =
				ipxw_mux_peek_recvd_len(ipxh, false);
			if (expected_msg_len < 0) {
				if (errno == EINTR) {
					continue;
				}

				perror("IPX receive peek");
				cleanup_and_exit(epoll_fd, tmr_fd,
						IPXCAT_ERR_IPX_FAILURE);
			}

			struct ipxw_mux_msg *msg = calloc(1, expected_msg_len +
					1);
			if (msg == NULL) {
				perror("allocating message");
				cleanup_and_exit(epoll_fd, tmr_fd,
						IPXCAT_ERR_MSG_ALLOC);
			}

			msg->type = IPXW_MUX_RECV;
			msg->recv.data_len = expected_msg_len - sizeof(struct
					ipxw_mux_msg);
			ssize_t rcvd_len = ipxw_mux_get_recvd(ipxh, msg, false);
			if (rcvd_len < 0) {
				free(msg);
				if (errno == EINTR) {
					continue;
				}

				perror("IPX receive");
				cleanup_and_exit(epoll_fd, tmr_fd,
						IPXCAT_ERR_IPX_FAILURE);
			}

			/* handle incomming SPX connection here */
			if (cfg->listen && cfg->use_spx &&
					ipxw_mux_spx_handle_is_error(spxh)) {
				__be16 remote_conn_id =
					ipxw_mux_spx_check_for_conn_req(msg);
				if (remote_conn_id != SPX_CONN_ID_UNKNOWN) {
					spxh = ipxw_mux_spx_accept(ipxh,
							&(msg->recv.saddr),
							remote_conn_id);
					cfg->remote_addr = msg->recv.saddr;
					free(msg);
					if (ipxw_mux_spx_handle_is_error(spxh))
					{
						perror("SPX accept");
						cleanup_and_exit(epoll_fd,
								tmr_fd,
								IPXCAT_ERR_SPX_ACCEPT);
					}

					/* start taking input from STDIN */
					ev.events = EPOLLIN | EPOLLERR |
						EPOLLHUP;
					ev.data.fd = fileno(stdin);
					if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD,
								fileno(stdin),
								&ev) < 0) {
						perror("registering stdin for event polling");
						cleanup_and_exit(epoll_fd,
								tmr_fd,
								IPXCAT_ERR_STDIN_FD);
					}

					/* register SPX socket for reception */
					ev.events = EPOLLIN | EPOLLERR |
						EPOLLHUP;
					ev.data.fd =
						ipxw_mux_spx_handle_sock(spxh);
					if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD,
								ipxw_mux_spx_handle_sock(spxh),
								&ev) < 0) {
						perror("registering SPX socket for event polling");
						cleanup_and_exit(epoll_fd,
								tmr_fd,
								IPXCAT_ERR_SPX_FD);
					}

					if (cfg->verbose) {
						fprintf(stderr, "accepted connection %04x from ",
								ntohs(remote_conn_id));
						print_ipxaddr(stderr, &(cfg->remote_addr));
						fprintf(stderr, "\n");
					}

					continue;
				}
			}

			/* print received message */
			size_t data_len = msg->recv.data_len;
			if (data_len == 0) {
				free(msg);
				continue;
			}
			msg->data[data_len] = '\0';

			/* should not get IPX messages in these configs */
			if (cfg->use_spx || !cfg->listen) {
				if (cfg->verbose) {
					fprintf(stderr, "unexpected IPX message from");
					print_ipxaddr(stderr,
							&(msg->recv.saddr));
					fprintf(stderr, ": %s\n", (char *)
							msg->data);
				}
			} else {
				if (cfg->verbose) {
					printf("message from ");
					print_ipxaddr(stdout,
							&(msg->recv.saddr));
					printf(": ");
				}
				fputs((char *) msg->data, stdout);
			}

			free(msg);
		}
	}


	cleanup_and_exit(epoll_fd, tmr_fd, IPXCAT_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: ipxcat [-t <packet type>] <local IPX address> <remote IPX address>\n");
	printf("       ipxcat -s <local IPX address> <remote IPX address>\n");
	printf("       ipxcat -l [-t <packet type>] [-b] <local IPX address>\n");
	printf("       ipxcat -l -s <local IPX address>\n");
	exit(IPXCAT_ERR_USAGE);
}

static bool verify_cfg(struct ipxcat_cfg *cfg)
{
	if (!cfg->listen && (cfg->accept_broadcasts || cfg->pkt_type_any)) {
		return false;
	}

	if (cfg->use_spx && (cfg->accept_broadcasts || cfg->pkt_type !=
				SPX_PKT_TYPE)) {
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	struct ipxcat_cfg cfg = {
		.verbose = false,
		.listen = false,
		.use_spx = false,
		.accept_broadcasts = false,
		.pkt_type_any = true,
		.pkt_type = DEFAULT_PKT_TYPE,
		.max_ipx_data_len = DEFAULT_IPX_DATA_LEN
	};

	/* parse and verify command-line arguments */

	int opt;
	while ((opt = getopt(argc, argv, "blst:v")) != -1) {
		switch (opt) {
			case 'b':
				cfg.accept_broadcasts = true;
				break;
			case 'l':
				cfg.listen = true;
				break;
			case 's':
				cfg.use_spx = true;
				cfg.pkt_type_any = false;
				cfg.pkt_type = SPX_PKT_TYPE;
				break;
			case 't':
				cfg.pkt_type_any = false;
				cfg.pkt_type = strtoul(optarg, NULL, 0);
				break;
			case 'v':
				cfg.verbose = true;
				break;
			default:
				usage();
		}
	}

	if (optind >= argc) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind], &(cfg.local_addr))) {
		usage();
	}

	if (!cfg.listen) {
		cfg.pkt_type_any = false;

		if (optind + 1 >= argc) {
			usage();
		}

		if (!parse_ipxaddr(argv[optind + 1], &(cfg.remote_addr))) {
			usage();
		}
	} else {
		if (optind + 1 != argc) {
			usage();
		}
	}

	if (!verify_cfg(&cfg)) {
		usage();
	}

	/* initial setup */

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, -1, IPXCAT_ERR_EPOLL_FD);
	}

	int tmr_fd = setup_timer(epoll_fd);
	if (tmr_fd < 0) {
		perror("creating maintenance timer");
		cleanup_and_exit(epoll_fd, tmr_fd, IPXCAT_ERR_TMR_FD);
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting up signal handler");
		cleanup_and_exit(epoll_fd, tmr_fd, IPXCAT_ERR_SIG_HANDLER);
	}

	do_ipxcat(&cfg, epoll_fd, tmr_fd);
}
