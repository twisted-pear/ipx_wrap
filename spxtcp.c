#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

#define DEFAULT_SPX_TO_TCP_QUEUE_PAUSE_THRESHOLD (1024)
#define DEFAULT_TCP_TO_SPX_QUEUE_PAUSE_THRESHOLD (1024)

enum spxtcp_error_codes {
	SPXTCP_ERR_OK = 0,
	SPXTCP_ERR_USAGE,
	SPXTCP_ERR_EPOLL_FD,
	SPXTCP_ERR_TMR_FD,
	SPXTCP_ERR_CONF_FD,
	SPXTCP_ERR_IPX_FD,
	SPXTCP_ERR_SPX_FD,
	SPXTCP_ERR_TCP_FD,
	SPXTCP_ERR_SIG_HANDLER,
	SPXTCP_ERR_BIND,
	SPXTCP_ERR_GETSOCKNAME,
	SPXTCP_ERR_EPOLL_WAIT,
	SPXTCP_ERR_TMR_FAILURE,
	SPXTCP_ERR_CONF_FAILURE,
	SPXTCP_ERR_IPX_FAILURE,
	SPXTCP_ERR_SPX_FAILURE,
	SPXTCP_ERR_TCP_FAILURE,
	SPXTCP_ERR_SPX_MAINT,
	SPXTCP_ERR_CONNECT,
	SPXTCP_ERR_MSG_ALLOC,
	SPXTCP_ERR_MSG_QUEUE,
	SPXTCP_ERR_MAX
};

#define MAX_EPOLL_EVENTS 64
#define TCP_BACKLOG 64

struct spxtcp_cfg {
	bool verbose;
	bool listen_spx;
	bool listen_tcp;
	bool spx_1_only;
	bool ipv6;
	__u16 max_spx_data_len;
	size_t spx_to_tcp_queue_pause_threshold;
	size_t tcp_to_spx_queue_pause_threshold;
	struct ipx_addr spx_local_addr;
	struct ipx_addr spx_remote_addr;
	union {
		struct sockaddr_in tcp_local_addr4;
		struct sockaddr_in6 tcp_local_addr6;
	};
	union {
		struct sockaddr_in tcp_remote_addr4;
		struct sockaddr_in6 tcp_remote_addr6;
	};
};

static volatile sig_atomic_t keep_going = true;
static volatile sig_atomic_t reap_children = false;

static struct counted_msg_queue spx_to_tcp_queue = counted_msg_queue_init(spx_to_tcp_queue);
static struct counted_msg_queue tcp_to_spx_queue = counted_msg_queue_init(tcp_to_spx_queue);

/* connected handles */
static struct ipxw_mux_spx_handle spxh = ipxw_mux_spx_handle_init;
static int tcps = -1;
static bool tcps_disconnected = false;

/* unconnected handles */
static struct ipxw_mux_handle ipxh = ipxw_mux_handle_init;
static int tcpa = -1;

/* SPX connection maintenance timer */
static int tmr_fd = -1;

static void signal_handler(int signal)
{
	switch (signal) {
		case SIGCHLD:
			reap_children = true;
			break;
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

static bool queue_spx_msg(int epoll_fd, struct ipxw_mux_spx_msg *msg, size_t
		data_len)
{
	/* reregister for ready-to-write events on the TCP socket, now that
	 * messages are available */
	struct epoll_event ev = {
		.events = EPOLLOUT | EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP,
		.data.fd = tcps
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, tcps, &ev) < 0) {
		return false;
	}

	/* queue the SPX message */
	msg->mux_msg.recv.data_len = data_len;
	msg->remote_alloc_no = 0; /* we reuse the remote_alloc_no field as a
				     data pointer into our message to track how
				     much we managed to actually send via TCP
				     */
	msg->mux_msg.recv.is_spx = 1;
	counted_msg_queue_push(&spx_to_tcp_queue, &(msg->mux_msg));

	return true;

}

static bool queue_tcp_msg(int epoll_fd, struct ipxw_mux_spx_msg *msg, size_t
		data_len)
{
	/* reregister for ready-to-write events on the SPX socket, now that
	 * messages are available */
	struct epoll_event ev = {
		.events = EPOLLOUT | EPOLLIN | EPOLLERR | EPOLLHUP,
		.data.fd = ipxw_mux_spx_handle_sock(spxh)
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ipxw_mux_spx_handle_sock(spxh),
				&ev) < 0) {
		return false;
	}

	/* queue the SPX message */
	msg->mux_msg.type = IPXW_MUX_XMIT;
	msg->mux_msg.xmit.data_len = data_len;
	counted_msg_queue_push(&tcp_to_spx_queue, &(msg->mux_msg));

	return true;
}

static bool send_out_spx_msg(int epoll_fd)
{
	/* no msgs to send */
	if (counted_msg_queue_empty(&tcp_to_spx_queue)) {
		/* unregister SPX socket from ready-to-write events to avoid
		 * busy polling */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP,
			.data.fd = ipxw_mux_spx_handle_sock(spxh)
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD,
				ipxw_mux_spx_handle_sock(spxh), &ev);

		return true;
	}

	/* connection is not ready to transmit, retry later */
	if (!ipxw_mux_spx_xmit_ready(spxh)) {
		return true;
	}

	struct ipxw_mux_msg *msg = counted_msg_queue_peek(&tcp_to_spx_queue);
	struct ipxw_mux_spx_msg *spx_msg = (struct ipxw_mux_spx_msg *) msg;
	ssize_t err = ipxw_mux_spx_xmit(spxh, spx_msg, msg->xmit.data_len, false);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return true;
		}

		/* other error, make sure to get rid of the message */
	}

	counted_msg_queue_pop(&tcp_to_spx_queue);
	free(msg);

	return (err >= 0);
}

static bool send_out_tcp_msg(int epoll_fd)
{
	/* no msgs to send */
	if (counted_msg_queue_empty(&spx_to_tcp_queue)) {
		/* unregister TCP socket from ready-to-write events to avoid
		 * busy polling */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP,
			.data.fd = tcps
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, tcps, &ev);

		return true;
	}

	struct ipxw_mux_msg *msg = counted_msg_queue_peek(&spx_to_tcp_queue);
	struct ipxw_mux_spx_msg *spx_msg = (struct ipxw_mux_spx_msg *) msg;

	size_t already_sent = spx_msg->remote_alloc_no;
	size_t left_to_send = msg->recv.data_len - already_sent;
	__u8 *data = ipxw_mux_spx_msg_data(spx_msg) + already_sent;
	assert(already_sent < msg->recv.data_len);
	assert(left_to_send > 0);

	ssize_t sent_len = send(tcps, data, left_to_send, MSG_DONTWAIT);
	if (sent_len < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return true;
		}

		/* other error */
		return false;
	}

	already_sent += sent_len;
	spx_msg->remote_alloc_no = already_sent;

	if (already_sent == msg->recv.data_len) {
		counted_msg_queue_pop(&spx_to_tcp_queue);
		free(msg);
	}

	return true;
}

static _Noreturn void cleanup_and_exit(int epoll_fd, struct spxtcp_cfg *cfg,
		enum spxtcp_error_codes code)
{
	if (tmr_fd >= 0) {
		close(tmr_fd);
	}

	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	/* remove all undelivered messages */
	while (!counted_msg_queue_empty(&spx_to_tcp_queue)) {
		struct ipxw_mux_msg *msg =
			counted_msg_queue_pop(&spx_to_tcp_queue);
		free(msg);
	}
	while (!counted_msg_queue_empty(&tcp_to_spx_queue)) {
		struct ipxw_mux_msg *msg =
			counted_msg_queue_pop(&tcp_to_spx_queue);
		free(msg);
	}

	if (!ipxw_mux_spx_handle_is_error(spxh)) {
		ipxw_mux_spx_conn_close(&spxh);
	}

	if (tcps >= 0) {
		close(tcps);
	}

	if (!ipxw_mux_handle_is_error(ipxh)) {
		ipxw_mux_unbind(ipxh);
	}
	if (tcpa >= 0) {
		close(tcpa);
	}

	exit(code);
}

static void tcp_recv_loop(int epoll_fd, struct spxtcp_cfg *cfg)
{
	while (true) {
		/* do not attempt to send via SPX unless the connection is
		 * fully established */
		if (!ipxw_mux_spx_established(spxh)) {
			return;
		}

		if (counted_msg_queue_nitems(&tcp_to_spx_queue) >
				cfg->tcp_to_spx_queue_pause_threshold) {
			return;
		}

		int max_data_len = ipxw_mux_spx_max_data_len(spxh);
		struct ipxw_mux_spx_msg *msg = calloc(1, sizeof(struct
					ipxw_mux_spx_msg) + max_data_len);
		if (msg == NULL) {
			perror("allocating message");
			cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_MSG_ALLOC);
		}

		ipxw_mux_spx_prepare_xmit_msg(spxh, msg);
		__u8 *data = ipxw_mux_spx_msg_data(msg);

		ssize_t data_len = recv(tcps, data, max_data_len,
				MSG_DONTWAIT);
		if (data_len < 0) {
			free(msg);
			if (errno == EINTR) {
				continue;
			}

			if (!tcps_disconnected) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					return;
				}
			}

			perror("TCP receive");
			cleanup_and_exit(epoll_fd, cfg,
					SPXTCP_ERR_TCP_FAILURE);
		}

		/* nothing to read */
		if (data_len == 0) {
			free(msg);

			if (tcps_disconnected) {
				fprintf(stderr, "TCP connection closed\n");
				cleanup_and_exit(epoll_fd, cfg,
						SPXTCP_ERR_TCP_FAILURE);
			}

			return;
		}

		/* queue received message */
		if (!queue_tcp_msg(epoll_fd, msg, data_len)) {
			free(msg);
			perror("queueing message");
			cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_MSG_QUEUE);
		}
	}
}

static void spx_recv_loop(int epoll_fd, struct spxtcp_cfg *cfg)
{
	while (true) {
		/* cannot receive right now */
		if (!ipxw_mux_spx_recv_ready(spxh)) {
			return;
		}

		/* SPX message received */
		ssize_t expected_msg_len = ipxw_mux_spx_peek_recvd_len(spxh,
				false);
		if (expected_msg_len < 0) {
			if (errno == EINTR) {
				continue;
			}

			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}

			perror("SPX receive peek");
			cleanup_and_exit(epoll_fd, cfg,
					SPXTCP_ERR_SPX_FAILURE);
		}

		if (counted_msg_queue_nitems(&spx_to_tcp_queue) >
				cfg->spx_to_tcp_queue_pause_threshold) {
			return;
		}

		struct ipxw_mux_spx_msg *msg = calloc(1, expected_msg_len);
		if (msg == NULL) {
			perror("allocating message");
			cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_MSG_ALLOC);
		}

		size_t expected_data_len =
			ipxw_mux_spx_data_len(expected_msg_len,
					ipxw_mux_spx_handle_is_spxii(spxh));
		ssize_t rcvd_len = ipxw_mux_spx_get_recvd(spxh, msg,
			expected_data_len, false);
		if (rcvd_len < 0) {
			free(msg);
			if (errno == EINTR) {
				continue;
			}

			perror("SPX receive");
			cleanup_and_exit(epoll_fd, cfg,
					SPXTCP_ERR_SPX_FAILURE);
		}

		/* system msg */
		if (rcvd_len == 0) {
			free(msg);
			continue;
		}

		size_t data_len = ipxw_mux_spx_data_len(rcvd_len,
				ipxw_mux_spx_handle_is_spxii(spxh));
		if (data_len == 0) {
			free(msg);
			continue;
		}

		/* queue received message */
		if (!queue_spx_msg(epoll_fd, msg, data_len)) {
			free(msg);
			perror("queueing message");
			cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_MSG_QUEUE);
		}
	}
}

static _Noreturn void do_spx_to_tcp(int epoll_fd, struct spxtcp_cfg *cfg,
		struct ipxw_mux_spx_handle spxh_new, int tcps_new)
{
	/* close handles that accept connections */
	ipxw_mux_handle_close(ipxh);
	struct ipxw_mux_handle ipxh_reset = ipxw_mux_handle_init;
	ipxh = ipxh_reset;
	close(tcpa);
	tcpa = -1;

	/* close old epoll_fd and tmr_fd handles */
	close(epoll_fd);
	epoll_fd = -1;
	close(tmr_fd);
	tmr_fd = -1;

	/* connected handles must be ready */
	assert(!ipxw_mux_spx_handle_is_error(spxh_new));
	assert(tcps_new >= 0);

	/* make handles for our connection global */
	spxh = spxh_new;
	tcps = tcps_new;

	/* initial setup */

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_EPOLL_FD);
	}

	/* create connection maintenance timer */
	tmr_fd = setup_timer(epoll_fd);
	if (tmr_fd < 0) {
		perror("creating maintenance timer");
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_TMR_FD);
	}

	/* register signal handlers */
	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting up signal handler");
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_SIG_HANDLER);
	}

	/* register SPX socket for reception */
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data.fd = ipxw_mux_spx_handle_sock(spxh)
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_spx_handle_sock(spxh),
				&ev) < 0) {
		perror("registering SPX socket for event polling");
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_SPX_FD);
	}

	/* register TCP socket for reception */
	/* there may already be preexisting messages from the candidate SPX
	 * connection, hence we need to be ready to send them immediately */
	ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
	ev.data.fd = tcps;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tcps, &ev) < 0) {
		perror("registering TCP socket for event polling");
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_TCP_FD);
	}

	struct epoll_event evs[MAX_EPOLL_EVENTS];
	/* keep going as long as there are queued messages */
	while (keep_going || !counted_msg_queue_empty(&spx_to_tcp_queue) ||
			!counted_msg_queue_empty(&tcp_to_spx_queue)) {
		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS,
				TICKS_MS);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(epoll_fd, cfg,
							SPXTCP_ERR_TMR_FAILURE);
				}

				/* maintain the SPX connection */
				if (!ipxw_mux_spx_maintain(spxh)) {
					perror("maintaining connection");
					cleanup_and_exit(epoll_fd, cfg,
							SPXTCP_ERR_SPX_MAINT);
				}

				/* consume all expirations */
				__u64 dummy;
				read(tmr_fd, &dummy, sizeof(dummy));

				continue;
			}

			/* TCP socket */
			if (evs[i].data.fd == tcps) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "TCP socket error\n");
					cleanup_and_exit(epoll_fd, cfg,
							SPXTCP_ERR_TCP_FAILURE);
				}

				if (evs[i].events & EPOLLRDHUP) {
					tcps_disconnected = true;
				}

				/* can write to TCP socket */
				if (evs[i].events & EPOLLOUT) {
					if (!send_out_tcp_msg(epoll_fd)) {
						perror("TCP send");
						cleanup_and_exit(epoll_fd, cfg,
								SPXTCP_ERR_TCP_FAILURE);
					}
				}

				/* nothing to read from TCP socket */
				if ((evs[i].events & EPOLLIN) == 0) {
					continue;
				}

				/* receive TCP messages until there are no more
				 * or the queue is full */
				tcp_recv_loop(epoll_fd, cfg);

				continue;
			}

			/* SPX socket */

			/* something went wrong */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "SPX socket error\n");
				cleanup_and_exit(epoll_fd, cfg,
						SPXTCP_ERR_SPX_FAILURE);
			}

			/* can write to SPX socket */
			if (evs[i].events & EPOLLOUT) {
				if (!send_out_spx_msg(epoll_fd)) {
					perror("SPX send");
					cleanup_and_exit(epoll_fd, cfg,
							SPXTCP_ERR_SPX_FAILURE);
				}
			}

			/* nothing to read from SPX socket */
			if ((evs[i].events & EPOLLIN) == 0) {
				continue;
			}

			/* receive SPX messages until there are no more
			 * or the queue is full */
			spx_recv_loop(epoll_fd, cfg);

			continue;
		}
	}

	cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_OK);
}

static int tcp_bind(struct spxtcp_cfg *cfg)
{
	/* bind TCP socket */
	int domain;
	struct sockaddr *sa;
	socklen_t sa_len;
	if (cfg->ipv6) {
		domain = AF_INET6;
		sa = (struct sockaddr *) &(cfg->tcp_local_addr6);
		sa_len = sizeof(cfg->tcp_local_addr6);
	} else {
		domain = AF_INET;
		sa = (struct sockaddr *) &(cfg->tcp_local_addr4);
		sa_len = sizeof(cfg->tcp_local_addr4);
	}

	int sock = socket(domain, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		return -1;
	}
	if (bind(sock, sa, sa_len) == -1) {
		close(sock);
		return -1;
	}

	return sock;
}

static bool tcp_connect(int sock, struct spxtcp_cfg *cfg)
{
	struct sockaddr *sa;
	socklen_t sa_len;
	if (cfg->ipv6) {
		sa = (struct sockaddr *) &(cfg->tcp_remote_addr6);
		sa_len = sizeof(cfg->tcp_remote_addr6);
	} else {
		sa = (struct sockaddr *) &(cfg->tcp_remote_addr4);
		sa_len = sizeof(cfg->tcp_remote_addr4);
	}

	if (connect(sock, sa, sa_len) == -1) {
		return false;
	}

	return true;
}

static bool sockaddr_to_str_and_port(const struct sockaddr *sa, socklen_t
		sa_len, char *addr_str_buf, __be16 *port)
{
	const char *ret = NULL;
	if (sa_len == sizeof(struct sockaddr_in6)) {
		ret = inet_ntop(AF_INET6, &(((const struct sockaddr_in6 *)
						sa)->sin6_addr), addr_str_buf,
				INET6_ADDRSTRLEN);
		*port = ((const struct sockaddr_in6 *) sa)->sin6_port;
	} else if (sa_len == sizeof(struct sockaddr_in)) {
		ret = inet_ntop(AF_INET, &(((const struct sockaddr_in *)
						sa)->sin_addr), addr_str_buf,
				INET_ADDRSTRLEN);
		*port = ((const struct sockaddr_in *) sa)->sin_port;
	} else {
		assert(0);
	}
	if (ret == NULL) {
		return false;
	}

	return true;
}

static bool tcp_print_bound_addr(int sock)
{
	union {
		struct sockaddr_in sin4;
		struct sockaddr_in6 sin6;
	} sin;
	socklen_t sin_len = sizeof(sin);

	if (getsockname(sock, (struct sockaddr *) &sin, &sin_len) == -1) {
		return false;
	}

	char addr_str_buf[INET6_ADDRSTRLEN + 1] = { 0 }; /* +1 for \0 */
	__be16 port = 0;
	if (!sockaddr_to_str_and_port((struct sockaddr *) &sin, sin_len,
				addr_str_buf, &port)) {
		return false;
	}

	fprintf(stderr, "TCP bound to %s:%hu\n", addr_str_buf, ntohs(port));
	return true;
}

static bool tcp_print_peer_addr(int sock)
{
	union {
		struct sockaddr_in sin4;
		struct sockaddr_in6 sin6;
	} sin;
	socklen_t sin_len = sizeof(sin);

	if (getpeername(sock, (struct sockaddr *) &sin, &sin_len) == -1) {
		return false;
	}

	char addr_str_buf[INET6_ADDRSTRLEN + 1] = { 0 }; /* +1 for \0 */
	__be16 port = 0;
	if (!sockaddr_to_str_and_port((struct sockaddr *) &sin, sin_len,
				addr_str_buf, &port)) {
		return false;
	}

	fprintf(stderr, "TCP connected to %s:%hu\n", addr_str_buf, ntohs(port));
	return true;
}

static struct ipxw_mux_spx_handle spxh_candidate = ipxw_mux_spx_handle_init;
static int tcps_candidate = -1;

static void close_spx_candidate(void)
{
	ipxw_mux_spx_handle_close(&spxh_candidate);
	struct ipxw_mux_spx_handle spxh_reset = ipxw_mux_spx_handle_init;
	spxh_candidate = spxh_reset;

	/* remove whatever messages the candidate SPX connection received */
	while (!counted_msg_queue_empty(&spx_to_tcp_queue)) {
		struct ipxw_mux_msg *msg =
			counted_msg_queue_pop(&spx_to_tcp_queue);
		free(msg);
	}
}

static void do_fork(int epoll_fd, struct spxtcp_cfg *cfg)
{
	assert(!ipxw_mux_spx_handle_is_error(spxh_candidate));
	assert(tcps_candidate != -1);

	pid_t child_pid = fork();
	if (child_pid == 0) {
		/* child */
		do_spx_to_tcp(epoll_fd, cfg, spxh_candidate, tcps_candidate);
		assert(0);
	}

	/* parent */

	if (child_pid < 0) {
		perror("fork");
	}

	/* reset candidates in case of fork */
	close_spx_candidate();
	close(tcps_candidate);
	tcps_candidate = -1;
}

static void handle_new_incoming_spx_connection(int epoll_fd, struct spxtcp_cfg
		*cfg, struct ipxw_mux_spx_handle spxh_new)
{
	/* already have an SPX connection, throw away new one */
	if (!ipxw_mux_spx_handle_is_error(spxh_candidate)) {
		ipxw_mux_spx_conn_close(&spxh_new);
		return;
	}

	/* need a TCP connection also */
	if (tcps_candidate == -1) {
		/* go back to waiting for an incoming TCP connection */
		if (cfg->listen_tcp) {
			spxh_candidate = spxh_new;
			return;
		}

		/* establish the TCP connection to the specified remote */
		/* if this fails, we throw away the candidate SPX connection
		 * and return */
		int tcps_new = tcp_bind(cfg);
		if (tcps_new == -1) {
			perror("TCP bind");
			ipxw_mux_spx_conn_close(&spxh_new);
			return;
		}

		if (cfg->verbose) {
			if (!tcp_print_bound_addr(tcps_new)) {
				perror("TCP get bound address");
			}
		}

		if (!tcp_connect(tcps_new, cfg)) {
			perror("TCP connect");
			close(tcps_new);
			ipxw_mux_spx_conn_close(&spxh_new);
			return;
		}
	
		if (cfg->verbose) {
			if (!tcp_print_peer_addr(tcps_new)) {
				perror("TCP get peer address");
			}
		}

		tcps_candidate = tcps_new;
		spxh_candidate = spxh_new;
	/* already have TCP candidate, continue */
	} else {
		spxh_candidate = spxh_new;
	}

	do_fork(epoll_fd, cfg);
}

static void handle_new_incoming_tcp_connection(int epoll_fd, struct spxtcp_cfg
		*cfg, int tcps_new)
{
	/* already have a TCP connection, throw away new one */
	if (tcps_candidate >= 0) {
		close(tcps_new);
		return;
	}

	/* need an SPX connection also */
	if (ipxw_mux_spx_handle_is_error(spxh_candidate)) {
		/* go back to waiting for an incoming SPX connection */
		if (cfg->listen_spx) {
			tcps_candidate = tcps_new;
			return;
		}

		/* establish the SPX connection to the specified remote */
		/* if this fails, we throw away the candidate TCP connection
		 * and return */
		int spxii_size_negotiation_hint = cfg->spx_1_only ? -1 :
			cfg->max_spx_data_len;
		struct ipxw_mux_spx_handle spxh_new =
			ipxw_mux_spx_connect(ipxh, &(cfg->spx_remote_addr),
					spxii_size_negotiation_hint);
		if (ipxw_mux_spx_handle_is_error(spxh_new)) {
			perror("SPX connect");
			close(tcps_new);
			return;
		}

		if (cfg->verbose) {
			fprintf(stderr, "SPX connected to ");
			print_ipxaddr(stderr, &(cfg->spx_remote_addr));
			fprintf(stderr, "\n");
		}

		tcps_candidate = tcps_new;
		spxh_candidate = spxh_new;
	/* already have SPX candidate, continue */
	} else {
		tcps_candidate = tcps_new;
	}

	do_fork(epoll_fd, cfg);
}

static void originate_tcp_and_spx_connection(int epoll_fd, struct spxtcp_cfg
		*cfg)
{
	int tcps_new = -1;
	struct ipxw_mux_spx_handle spxh_new = ipxw_mux_spx_handle_init;

	do {
		/* establish the SPX connection to the specified remote */
		int spxii_size_negotiation_hint = cfg->spx_1_only ? -1 :
			cfg->max_spx_data_len;
		struct ipxw_mux_spx_handle spxh_new =
			ipxw_mux_spx_connect(ipxh, &(cfg->spx_remote_addr),
					spxii_size_negotiation_hint);
		if (ipxw_mux_spx_handle_is_error(spxh_new)) {
			perror("SPX connect");
			break;
		}

		if (cfg->verbose) {
			fprintf(stderr, "SPX connected to ");
			print_ipxaddr(stderr, &(cfg->spx_remote_addr));
			fprintf(stderr, "\n");
		}

		/* establish the TCP connection to the specified remote */
		int tcps_new = tcp_bind(cfg);
		if (tcps_new == -1) {
			perror("TCP bind");
			break;
		}

		if (cfg->verbose) {
			if (!tcp_print_bound_addr(tcps_new)) {
				perror("TCP get bound address");
			}
		}

		if (!tcp_connect(tcps_new, cfg)) {
			perror("TCP connect");
			break;
		}
	
		if (cfg->verbose) {
			if (!tcp_print_peer_addr(tcps_new)) {
				perror("TCP get peer address");
			}
		}

		do_spx_to_tcp(epoll_fd, cfg, spxh_new, tcps_new);
	} while (0);

	if (tcps_new >= 0) {
		close(tcps_new);
	}

	if (!ipxw_mux_spx_handle_is_error(spxh_new)) {
		ipxw_mux_spx_conn_close(&spxh_new);
	}
}

static int tcp_accept(struct spxtcp_cfg *cfg)
{
	union {
		struct sockaddr_in sin4;
		struct sockaddr_in6 sin6;
	} sin;
	socklen_t sin_len = sizeof(sin);

	int ret = accept(tcpa, (struct sockaddr *) &sin, &sin_len);
	if (ret < 0) {
		return -1;
	}

	if (cfg->verbose) {
		char addr_str_buf[INET6_ADDRSTRLEN + 1] = { 0 }; /* +1 for \0 */
		__be16 port = 0;
		if (!sockaddr_to_str_and_port((struct sockaddr *) &sin,
					sin_len, addr_str_buf, &port)) {
			return ret;
		}

		fprintf(stderr, "accepted TCP connection from %s:%hu\n",
				addr_str_buf, ntohs(port));
	}

	return ret;
}

static struct ipxw_mux_spx_handle spx_accept(struct spxtcp_cfg *cfg)
{
	static struct ipxw_mux_spx_handle ret = ipxw_mux_spx_handle_init;

	/* IPX message received */
	ssize_t expected_msg_len = ipxw_mux_peek_recvd_len(ipxh,
			false);
	if (expected_msg_len < 0) {
		return ret;
	}

	struct ipxw_mux_msg *msg = calloc(1, expected_msg_len);
	if (msg == NULL) {
		return ret;
	}

	do {
		msg->type = IPXW_MUX_RECV;
		msg->recv.data_len = expected_msg_len - sizeof(struct
				ipxw_mux_msg);
		ssize_t rcvd_len = ipxw_mux_get_recvd(ipxh, msg, false);
		if (rcvd_len < 0) {
			free(msg);
			return ret;
		}

		bool spxii = false;
		__be16 remote_conn_id = ipxw_mux_spx_check_for_conn_req(msg,
				&spxii);

		/* not an SPX connection request */
		if (remote_conn_id == SPX_CONN_ID_UNKNOWN) {
			if (cfg->verbose) {
				fprintf(stderr, "received invalid SPX "
						"connection request from ");
				print_ipxaddr(stderr, &(msg->recv.saddr));
				fprintf(stderr, "\n");
			}

			errno = EREMOTEIO;
			break;
		}

		int spxii_size_negotiation_hint = (cfg->spx_1_only || !spxii) ?
			-1 : cfg->max_spx_data_len;
		struct ipxw_mux_spx_handle spxh_new = ipxw_mux_spx_accept(ipxh,
				&(msg->recv.saddr), remote_conn_id,
				spxii_size_negotiation_hint);
		if (ipxw_mux_spx_handle_is_error(spxh_new)) {
			break;
		}

		if (cfg->verbose) {
			fprintf(stderr, "accepted SPX connection from ");
			print_ipxaddr(stderr, &(msg->recv.saddr));
			fprintf(stderr, "\n");
		}

		free(msg);
		return spxh_new;
	} while (0);

	free(msg);
	return ret;
}

static bool spx_candidate_recv_loop(struct spxtcp_cfg *cfg)
{
	while (true) {
		/* cannot receive right now */
		if (!ipxw_mux_spx_recv_ready(spxh_candidate)) {
			return true;
		}

		/* SPX message received */
		ssize_t expected_msg_len =
			ipxw_mux_spx_peek_recvd_len(spxh_candidate, false);
		if (expected_msg_len < 0) {
			if (errno == EINTR) {
				continue;
			}

			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return true;
			}

			return false;
		}

		if (counted_msg_queue_nitems(&spx_to_tcp_queue) >
				cfg->spx_to_tcp_queue_pause_threshold) {
			return true;
		}

		struct ipxw_mux_spx_msg *msg = calloc(1, expected_msg_len);
		if (msg == NULL) {
			return false;
		}

		size_t expected_data_len =
			ipxw_mux_spx_data_len(expected_msg_len,
					ipxw_mux_spx_handle_is_spxii(spxh_candidate));
		ssize_t rcvd_len = ipxw_mux_spx_get_recvd(spxh_candidate, msg,
				expected_data_len, false);
		if (rcvd_len < 0) {
			free(msg);
			if (errno == EINTR) {
				continue;
			}

			return false;
		}

		/* system msg */
		if (rcvd_len == 0) {
			free(msg);
			continue;
		}

		size_t data_len = ipxw_mux_spx_data_len(rcvd_len,
				ipxw_mux_spx_handle_is_spxii(spxh_candidate));
		if (data_len == 0) {
			free(msg);
			continue;
		}

		/* queue the SPX message */
		msg->mux_msg.recv.data_len = data_len;
		msg->remote_alloc_no = 0; /* we reuse the remote_alloc_no field as a
					     data pointer into our message to track how
					     much we managed to actually send via TCP
					     */
		msg->mux_msg.recv.is_spx = 1;
		counted_msg_queue_push(&spx_to_tcp_queue, &(msg->mux_msg));

		return true;
	}
}

static void print_child_status(pid_t child_pid, int wstatus)
{
	if (WIFEXITED(wstatus)) {
		fprintf(stderr, "%d exited, status=%d\n",
				child_pid,
				WEXITSTATUS(wstatus));
	} else if (WIFSIGNALED(wstatus)) {
		fprintf(stderr, "%d killed by signal %d\n",
				child_pid, WTERMSIG(wstatus));
	} else if (WIFSTOPPED(wstatus)) {
		fprintf(stderr, "%d stopped by signal %d\n",
				child_pid, WSTOPSIG(wstatus));
	}
}

static void do_reap_children(struct spxtcp_cfg *cfg)
{
	int wstatus;
	pid_t child_pid;
	while ((child_pid  = waitpid(-1, &wstatus, WNOHANG)) > 0) {
		if (cfg->verbose) {
			print_child_status(child_pid, wstatus);
		}
	}
}

static _Noreturn void do_wait_for_conns(struct spxtcp_cfg *cfg)
{
	/* connected handles must be unused */
	assert(ipxw_mux_spx_handle_is_error(spxh));
	assert(tcps < 0);

	/* initial setup */

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_EPOLL_FD);
	}

	/* create connection maintenance timer */
	tmr_fd = setup_timer(epoll_fd);
	if (tmr_fd < 0) {
		perror("creating maintenance timer");
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_TMR_FD);
	}

	/* register signal handlers */
	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0
			|| sigaction(SIGCHLD, &sig_act, NULL) < 0) {
		perror("setting up signal handler");
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_SIG_HANDLER);
	}

	/* bind IPX socket */
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->spx_local_addr;
	bind_msg.bind.pkt_type = SPX_PKT_TYPE;
	bind_msg.bind.pkt_type_any = false;
	bind_msg.bind.recv_bcast = false;

	ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_BIND);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->spx_local_addr))) {
			perror("IPX get bound address");
			cleanup_and_exit(epoll_fd, cfg,
					SPXTCP_ERR_GETSOCKNAME);
		}

		fprintf(stderr, "SPX bound to ");
		print_ipxaddr(stderr, &(cfg->spx_local_addr));
		fprintf(stderr, "\n");
	}

	/* register config socket for event polling */
	struct epoll_event ev = {
		.events = EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ipxw_mux_handle_conf(ipxh)
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_conf(ipxh), &ev)
			< 0) {
		perror("registering config socket for event polling");
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_CONF_FD);
	}

	if (cfg->listen_spx) {
		ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
		ev.data.fd = ipxw_mux_handle_data(ipxh);
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD,
					ipxw_mux_handle_data(ipxh), &ev) < 0) {
			perror("registering IPX socket for event polling");
			cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_IPX_FD);
		}
	}

	if (cfg->listen_tcp) {
		/* bind TCP socket */
		tcpa = tcp_bind(cfg);
		if (tcpa == -1) {
			perror("TCP bind");
			cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_BIND);
		}

		if (cfg->verbose) {
			if (!tcp_print_bound_addr(tcpa)) {
				perror("TCP get bound address");
				cleanup_and_exit(epoll_fd, cfg,
						SPXTCP_ERR_GETSOCKNAME);
			}
		}

		if (listen(tcpa, TCP_BACKLOG) == -1) {
			perror("listening on TCP socket");
			cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_TCP_FD);
		}

		ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
		ev.data.fd = tcpa;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tcpa, &ev) < 0) {
			perror("registering TCP socket for event polling");
			cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_TCP_FD);
		}
	}

	/* we need to start both connections */
	if (!cfg->listen_spx && !cfg->listen_tcp) {
		originate_tcp_and_spx_connection(epoll_fd, cfg);
		cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_CONNECT);
	}

	/* wait for necessary incoming connections */
	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		if (reap_children) {
			do_reap_children(cfg);
			reap_children = false;
		}

		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(epoll_fd, cfg,
							SPXTCP_ERR_TMR_FAILURE);
				}

				/* consume all expirations */
				__u64 dummy;
				read(tmr_fd, &dummy, sizeof(dummy));

				/* no candidate connection to maintain */
				if (ipxw_mux_spx_handle_is_error(spxh_candidate)) {
					continue;
				}

				/* maintain the candidate SPX connection */
				if (!ipxw_mux_spx_maintain(spxh_candidate)) {
					perror("maintaining connection");
					close_spx_candidate();
					continue;
				}
				if (!spx_candidate_recv_loop(cfg)) {
					perror("maintaining connection");
					close_spx_candidate();
					continue;
				}

				continue;
			}

			/* IPX conf socket */
			if (evs[i].data.fd == ipxw_mux_handle_conf(ipxh)) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "IPX config socket "
							"error\n");
					cleanup_and_exit(epoll_fd, cfg,
							SPXTCP_ERR_CONF_FAILURE);
				}

				continue;
			}

			/* TCP socket */
			if (evs[i].data.fd == tcpa) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "TCP socket error\n");
					cleanup_and_exit(epoll_fd, cfg,
							SPXTCP_ERR_TCP_FAILURE);
				}

				/* no connection to accept */
				if ((evs[i].events & EPOLLIN) == 0) {
					continue;
				}

				/* accept TCP connection */
				int tcps_new = tcp_accept(cfg);
				if (tcps_new < 0) {
					perror("TCP accept");
					continue;
				}
				handle_new_incoming_tcp_connection(epoll_fd,
						cfg, tcps_new);

				continue;
			}

			/* IPX socket */

			/* something went wrong */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "IPX socket error\n");
				cleanup_and_exit(epoll_fd, cfg,
						SPXTCP_ERR_IPX_FAILURE);
			}

			/* nothing to read from IPX socket */
			if ((evs[i].events & EPOLLIN) == 0) {
				continue;
			}

			/* accept SPX connection */
			struct ipxw_mux_spx_handle spxh_new = spx_accept(cfg);
			if (ipxw_mux_spx_handle_is_error(spxh_new)) {
				perror("SPX accept");
				continue;
			}
			handle_new_incoming_spx_connection(epoll_fd, cfg,
					spxh_new);

			continue;
		}
	}

	cleanup_and_exit(epoll_fd, cfg, SPXTCP_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: ipxtcp [-v] [-1] [-6] [-d <maximum SPX data bytes>] [-s <remote IPX address>] [-t <remote IP address>:<remote port>] <local IPX address> <local IP address>:<local port>\n");
	exit(SPXTCP_ERR_USAGE);
}

static bool verify_cfg(struct spxtcp_cfg *cfg)
{
	if (cfg->max_spx_data_len < 1 || cfg->max_spx_data_len >
			SPXII_MAX_DATA_LEN) {
		return false;
	}

	return true;
}

static bool parse_ipaddr_and_port(bool ipv6, char *arg, struct sockaddr *sa)
{
	char *last_colon = strrchr(arg, ':');
	if (last_colon == NULL) {
		return false;
	}

	*last_colon = '\0';
	char *ipaddr_str = arg;
	char *port_str = last_colon + 1;

	if (ipv6) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) sa;
		sa6->sin6_family = AF_INET6;
		sa6->sin6_scope_id = 0;
		sa6->sin6_flowinfo = 0;
		if (inet_pton(AF_INET6, ipaddr_str, &(sa6->sin6_addr)) != 1) {
			return false;
		}
		sa6->sin6_port = htons(strtoul(port_str, NULL, 0));
	} else {
		struct sockaddr_in *sa4 = (struct sockaddr_in *) sa;
		sa4->sin_family = AF_INET;
		memset(&(sa4->sin_zero), 0, sizeof(sa4->sin_zero));
		if (inet_pton(AF_INET, ipaddr_str, &(sa4->sin_addr)) != 1) {
			return false;
		}
		sa4->sin_port = htons(strtoul(port_str, NULL, 0));
	}

	return true;
}

int main(int argc, char **argv)
{
	struct spxtcp_cfg cfg = {
		.verbose = false,
		.listen_spx = true,
		.listen_tcp = true,
		.spx_1_only = false,
		.ipv6 = false,
		.max_spx_data_len = SPX_MAX_DATA_LEN_WO_SIZNG,
		.spx_to_tcp_queue_pause_threshold = DEFAULT_SPX_TO_TCP_QUEUE_PAUSE_THRESHOLD,
		.tcp_to_spx_queue_pause_threshold = DEFAULT_TCP_TO_SPX_QUEUE_PAUSE_THRESHOLD,
	};

	/* parse and verify command-line arguments */

	bool remote_ip_addr_already_set = false;
	int opt;
	while ((opt = getopt(argc, argv, "16d:s:t:v")) != -1) {
		switch (opt) {
			case '1':
				cfg.spx_1_only = true;
				break;
			case '6':
				/* don't allow setting the remote IP addr
				 * before we have decided on IPv4 vs IPv6 */
				if (remote_ip_addr_already_set) {
					usage();
				}

				cfg.ipv6 = true;
				break;
			case 'd':
				cfg.max_spx_data_len = strtoul(optarg, NULL, 0);
				break;
			case 's':
				if (!parse_ipxaddr(optarg, &(cfg.spx_remote_addr))) {
					usage();
				}
				cfg.listen_spx = false;

				break;
			case 't':
				if (!parse_ipaddr_and_port(cfg.ipv6, optarg,
							(struct sockaddr *)
							&(cfg.tcp_remote_addr4)))
				{
					usage();
				}
				cfg.listen_tcp = false;

				remote_ip_addr_already_set = true;
				break;
			case 'v':
				cfg.verbose = true;
				break;
			default:
				usage();
		}
	}

	if (optind + 1 >= argc) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind], &(cfg.spx_local_addr))) {
		usage();
	}

	if (!parse_ipaddr_and_port(cfg.ipv6, argv[optind + 1], (struct sockaddr
					*) &(cfg.tcp_local_addr4))) {
		usage();
	}

	if (!verify_cfg(&cfg)) {
		usage();
	}

	do_wait_for_conns(&cfg);
}
