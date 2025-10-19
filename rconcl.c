#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/md5.h>

#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

#define DEFAULT_RX_QUEUE_PAUSE_THRESHOLD (1024)
#define DEFAULT_TX_QUEUE_PAUSE_THRESHOLD (1024)

enum rconcl_error_codes {
	RCONCL_ERR_OK = 0,
	RCONCL_ERR_USAGE,
	RCONCL_ERR_EPOLL_FD,
	RCONCL_ERR_TMR_FD,
	RCONCL_ERR_STDIN_FD,
	RCONCL_ERR_SPX_FD,
	RCONCL_ERR_SIG_HANDLER,
	RCONCL_ERR_BIND,
	RCONCL_ERR_GETSOCKNAME,
	RCONCL_ERR_EPOLL_WAIT,
	RCONCL_ERR_TMR_FAILURE,
	RCONCL_ERR_SPX_FAILURE,
	RCONCL_ERR_SPX_MAINT,
	RCONCL_ERR_CONNECT,
	RCONCL_ERR_MSG_ALLOC,
	RCONCL_ERR_MSG_QUEUE,
	RCONCL_ERR_AUTH,
	RCONCL_ERR_PROTO,
	RCONCL_ERR_MAX
};

#define MAX_EPOLL_EVENTS 64

struct rconcl_cfg {
	bool verbose;
	bool spx_1_only;
	__u16 max_spx_data_len;
	size_t rx_queue_pause_threshold;
	size_t tx_queue_pause_threshold;
	struct ipx_addr spx_local_addr;
	struct ipx_addr spx_remote_addr;
};

enum rcon_request_code {
	RCON_REQUEST_MIN = 0,
	RCON_REQUEST_DIGEST,
	RCON_REQUEST_SCREEN_OPEN,
	RCON_REQUEST_SCREEN_CLOSE,
	RCON_REQUEST_SCREEN_ACTIVATE,
	RCON_REQUEST_SCREEN_INPUT,
	RCON_REQUEST_SCREEN_RESET,
	RCON_REQUEST_PROXY_CONNECT,
	RCON_REQUEST_PROXY_CONNECT_NAME,
	RCON_REQUEST_SCREEN_ACK,
	RCON_REQUEST_UNAUTHORISE_LOGIN, // TODO: ???
	RCON_REQUEST_MAX,
};

enum rcon_reply_code {
	RCON_REPLY_MIN = 0,
	RCON_REPLY_DIGEST_NONCE,
	RCON_REPLY_DIGEST_ERROR,
	RCON_REPLY_DIGEST_OK,
	RCON_REPLY_SCREENLIST,
	RCON_REPLY_SCREEN_DESTROYED,
	RCON_REPLY_SCREEN_LOCKED,
	RCON_REPLY_SCREEN_UNLOCKED,
	RCON_REPLY_SCREEN_COPY,
	RCON_REPLY_SCREEN_CHANGE,
	RCON_REPLY_PROXY,
	RCON_REPLY_SERVER_NAME,
	RCON_REPLY_MAX
};

struct rcon_request {
	__be16 data_len;
	__be16 code;
	__be32 screen_id;
	__u8 data[0];
};

struct rcon_reply {
	__be16 data_len;
	__be16 code;
	__be32 screen_id;
	__u8 data[0];
};

#define RCON_NONCE_LEN 4

static volatile sig_atomic_t keep_going = true;

static struct counted_msg_queue rx_queue = counted_msg_queue_init(rx_queue);
static struct counted_msg_queue tx_queue = counted_msg_queue_init(tx_queue);

/* connected handle */
static struct ipxw_mux_spx_handle spxh = ipxw_mux_spx_handle_init;

/* SPX connection maintenance timer */
static int tmr_fd = -1;

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

static bool queue_spx_msg(int epoll_fd, struct ipxw_mux_spx_msg *msg, size_t
		data_len)
{
	// TODO
	/* reregister for ready-to-write events on the TCP socket, now that
	 * messages are available */
	/*struct epoll_event ev = {
		.events = EPOLLOUT | EPOLLIN | EPOLLERR | EPOLLHUP,
		.data.fd = tcps
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, tcps, &ev) < 0) {
		return false;
	}*/

	/* queue the SPX message */
	msg->mux_msg.recv.data_len = data_len;
	msg->mux_msg.recv.is_spx = 1;
	counted_msg_queue_push(&rx_queue, &(msg->mux_msg));

	return true;
}

static bool send_out_spx_msg(int epoll_fd)
{
	/* no msgs to send */
	if (counted_msg_queue_empty(&tx_queue)) {
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

	struct ipxw_mux_msg *msg = counted_msg_queue_peek(&tx_queue);
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

	counted_msg_queue_pop(&tx_queue);
	free(msg);

	return (err >= 0);
}

static _Noreturn void cleanup_and_exit(int epoll_fd, struct rconcl_cfg *cfg,
		enum rconcl_error_codes code)
{
	if (tmr_fd >= 0) {
		close(tmr_fd);
	}

	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	/* remove all queued messages */
	while (!counted_msg_queue_empty(&rx_queue)) {
		struct ipxw_mux_msg *msg = counted_msg_queue_pop(&rx_queue);
		free(msg);
	}
	while (!counted_msg_queue_empty(&tx_queue)) {
		struct ipxw_mux_msg *msg = counted_msg_queue_pop(&tx_queue);
		free(msg);
	}

	if (!ipxw_mux_spx_handle_is_error(spxh)) {
		ipxw_mux_spx_conn_close(&spxh);
	}

	exit(code);
}

static void spx_recv_loop(int epoll_fd, struct rconcl_cfg *cfg)
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
					RCONCL_ERR_SPX_FAILURE);
		}

		if (counted_msg_queue_nitems(&rx_queue) >
				cfg->rx_queue_pause_threshold) {
			return;
		}

		struct ipxw_mux_spx_msg *msg = calloc(1, expected_msg_len);
		if (msg == NULL) {
			perror("allocating message");
			cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_MSG_ALLOC);
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
					RCONCL_ERR_SPX_FAILURE);
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
			cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_MSG_QUEUE);
		}
	}
}

enum rconcl_event {
	RCONCL_EVENT_EXIT = (1 << 0),
	RCONCL_EVENT_MSG = (1 << 1),
	RCONCL_EVENT_STDIN = (1 << 2)
};

static enum rconcl_event wait_for_event(int epoll_fd, struct rconcl_cfg *cfg)
{
	struct epoll_event evs[MAX_EPOLL_EVENTS];

	enum rconcl_event ret = 0;

	while (keep_going) {
		ret = 0;

		/* if there are still messages left, don't wait */
		int epoll_tmo = TICKS_MS;
		if (!counted_msg_queue_empty(&rx_queue)) {
			epoll_tmo = 0;
		}

		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS,
				epoll_tmo);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(epoll_fd, cfg,
							RCONCL_ERR_TMR_FAILURE);
				}

				/* maintain the SPX connection */
				if (!ipxw_mux_spx_maintain(spxh)) {
					perror("maintaining connection");
					cleanup_and_exit(epoll_fd, cfg,
							RCONCL_ERR_SPX_MAINT);
				}

				/* consume all expirations */
				__u64 dummy;
				read(tmr_fd, &dummy, sizeof(dummy));

				continue;
			}

			/* stdin */
			if (evs[i].data.fd == fileno(stdin)) {
				ret |= RCONCL_EVENT_STDIN;
				continue;
			}

			/* SPX socket */

			/* something went wrong */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "SPX socket error\n");
				cleanup_and_exit(epoll_fd, cfg,
						RCONCL_ERR_SPX_FAILURE);
			}

			/* can write to SPX socket */
			if (evs[i].events & EPOLLOUT) {
				if (!send_out_spx_msg(epoll_fd)) {
					perror("SPX send");
					cleanup_and_exit(epoll_fd, cfg,
							RCONCL_ERR_SPX_FAILURE);
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

		/* if messages are left in the RX queue, notify */
		if (!counted_msg_queue_empty(&rx_queue)) {
			ret |= RCONCL_EVENT_MSG;
		}

		if (ret != 0) {
			return ret;
		}
	}

	return RCONCL_EVENT_EXIT;
}

static struct ipxw_mux_spx_msg *rcon_prepare_request(__u16 data_len, __u16
		code, __u32 screen_id)
{
	if (code <= RCON_REQUEST_MIN || code >= RCON_REQUEST_MAX) {
		return NULL;
	}

	int max_data_len = ipxw_mux_spx_max_data_len(spxh);
	int req_data_len = sizeof(struct rcon_request) + data_len;

	if (max_data_len < req_data_len) {
		return NULL;
	}

	struct ipxw_mux_spx_msg *msg = calloc(1, sizeof(struct
				ipxw_mux_spx_msg) + req_data_len);
	if (msg == NULL) {
		return NULL;
	}

	ipxw_mux_spx_prepare_xmit_msg(spxh, msg);
	struct rcon_request *req = (struct rcon_request *)
		ipxw_mux_spx_msg_data(msg);
	req->data_len = htons(data_len);
	req->code = htons(code);
	req->screen_id = htonl(screen_id);

	msg->mux_msg.type = IPXW_MUX_XMIT;
	msg->mux_msg.xmit.data_len = req_data_len;

	return msg;
}

static struct ipxw_mux_spx_msg *rcon_digest_request(const __u8 *hash)
{
	struct ipxw_mux_spx_msg *msg = rcon_prepare_request(MD5_DIGEST_LENGTH,
			RCON_REQUEST_DIGEST, 0);
	if (msg == NULL) {
		return NULL;
	}

	struct rcon_request *req = (struct rcon_request *)
		ipxw_mux_spx_msg_data(msg);
	memcpy(req->data, hash, MD5_DIGEST_LENGTH);

	return msg;
}

static bool rcon_request_push(int epoll_fd, struct ipxw_mux_spx_msg *msg)
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

	struct rcon_request *req = (struct rcon_request *)
		ipxw_mux_spx_msg_data(msg);
	int req_data_len = sizeof(struct rcon_request) + ntohs(req->data_len);

	msg->mux_msg.xmit.data_len = req_data_len;
	counted_msg_queue_push(&tx_queue, &(msg->mux_msg));

	return true;
}

static struct ipxw_mux_spx_msg *rcon_reply_pop(void)
{
	assert(!counted_msg_queue_empty(&rx_queue));

	struct ipxw_mux_msg *msg = counted_msg_queue_pop(&rx_queue);
	struct ipxw_mux_spx_msg *spx_msg = (struct ipxw_mux_spx_msg *) msg;

	if (msg->recv.data_len < sizeof(struct rcon_reply)) {
		return NULL;
	}

	struct rcon_reply *rep = (struct rcon_reply *)
		ipxw_mux_spx_msg_data(spx_msg);

	if (ntohs(rep->code) <= RCON_REPLY_MIN || ntohs(rep->code) >=
			RCON_REPLY_MAX) {
		return NULL;
	}
	if (ntohs(rep->data_len) != msg->recv.data_len - sizeof(struct
				rcon_reply)) {
		return NULL;
	}

	return spx_msg;
}

static bool rcon_auth(int epoll_fd, struct rconcl_cfg *cfg, const char *password)
{
	// TODO: verbosity

	struct ipxw_mux_spx_msg *msg = NULL;

	do {
		/* wait for nonce and compute response */

		if ((wait_for_event(epoll_fd, cfg) & RCONCL_EVENT_MSG) == 0) {
			break;
		}

		struct ipxw_mux_spx_msg *msg = rcon_reply_pop();
		if (msg == NULL) {
			break;
		}

		struct rcon_reply *rep = (struct rcon_reply *)
			ipxw_mux_spx_msg_data(msg);
		if (ntohs(rep->code) != RCON_REPLY_DIGEST_NONCE) {
			break;
		}
		if (ntohs(rep->data_len) < RCON_NONCE_LEN) {
			break;
		}

		// TODO: remove
		printf("Nonce: ");
		int i;
		for (i = 0; i < ntohs(rep->data_len); i++) {
			printf("%hhx ", rep->data[i]);
		}
		printf("\n");

		/* calculate response to server's challenge */
		__u8 pw_hash[MD5_DIGEST_LENGTH + RCON_NONCE_LEN];
		MD5((const unsigned char *) password, strlen(password),
				pw_hash);
		memcpy(pw_hash + MD5_DIGEST_LENGTH, rep->data, RCON_NONCE_LEN);
		__u8 nonce_hash[MD5_DIGEST_LENGTH];
		MD5(pw_hash, MD5_DIGEST_LENGTH + RCON_NONCE_LEN, nonce_hash);

		free(msg);
		msg = NULL;

		/* wait for server name */

		if ((wait_for_event(epoll_fd, cfg) & RCONCL_EVENT_MSG) == 0) {
			break;
		}

		msg = rcon_reply_pop();
		if (msg == NULL) {
			break;
		}

		rep = (struct rcon_reply *) ipxw_mux_spx_msg_data(msg);
		if (ntohs(rep->code) != RCON_REPLY_SERVER_NAME) {
			break;
		}

		// TODO: remove
		char server_name_buf[128];
		memset(server_name_buf, 0, 128);
		size_t server_name_len = ntohs(rep->data_len) > 127 ? 127 :
			ntohs(rep->data_len);
		memcpy(server_name_buf, rep->data, server_name_len);
		printf("Server Name: %s\n", server_name_buf);

		free(msg);
		msg = NULL;

		/* send response to the server's nonce */

		struct ipxw_mux_spx_msg *req_digest =
			rcon_digest_request(nonce_hash);
		if (req_digest == NULL) {
			break;
		}

		if (!rcon_request_push(epoll_fd, req_digest)) {
			break;
		}

		/* wait for auth result */

		if ((wait_for_event(epoll_fd, cfg) & RCONCL_EVENT_MSG) == 0) {
			break;
		}

		msg = rcon_reply_pop();
		if (msg == NULL) {
			break;
		}

		rep = (struct rcon_reply *) ipxw_mux_spx_msg_data(msg);
		if (ntohs(rep->code) != RCON_REPLY_DIGEST_OK) {
			break;
		}

		free(msg);
		return true;

	} while (0);

	if (msg != NULL) {
		free(msg);
	}

	return false;
}

static bool rcon_main(int epoll_fd, struct rconcl_cfg *cfg)
{
	while (true) {
		enum rconcl_event ev = wait_for_event(epoll_fd, cfg);

		/* message received */
		if ((ev & RCONCL_EVENT_MSG) != 0) {
			fprintf(stderr, "message received\n");
		}

		/* stdin */
		if ((ev & RCONCL_EVENT_STDIN) != 0) {
			fprintf(stderr, "stdin\n");
		}

		/* stdin */
		if ((ev & RCONCL_EVENT_EXIT) != 0) {
			return true;
		}
	}
}

static _Noreturn void do_rconcl(struct rconcl_cfg *cfg, char *password)
{
	/* initial setup */

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_EPOLL_FD);
	}

	/* create connection maintenance timer */
	tmr_fd = setup_timer(epoll_fd);
	if (tmr_fd < 0) {
		perror("creating maintenance timer");
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_TMR_FD);
	}

	/* register signal handlers */
	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting up signal handler");
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_SIG_HANDLER);
	}

	/* establish SPX connection */

	/* bind IPX socket */
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->spx_local_addr;
	bind_msg.bind.pkt_type = SPX_PKT_TYPE;
	bind_msg.bind.pkt_type_any = false;
	bind_msg.bind.recv_bcast = false;

	struct ipxw_mux_handle ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_BIND);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->spx_local_addr))) {
			perror("IPX get bound address");
			ipxw_mux_unbind(ipxh);
			cleanup_and_exit(epoll_fd, cfg,
					RCONCL_ERR_GETSOCKNAME);
		}

		fprintf(stderr, "SPX bound to ");
		print_ipxaddr(stderr, &(cfg->spx_local_addr));
		fprintf(stderr, "\n");
	}

	/* establish the SPX connection to the specified remote */
	int spxii_size_negotiation_hint = cfg->spx_1_only ? -1 :
		cfg->max_spx_data_len;
	spxh = ipxw_mux_spx_connect(ipxh, &(cfg->spx_remote_addr),
			spxii_size_negotiation_hint);
	if (ipxw_mux_spx_handle_is_error(spxh)) {
		perror("SPX connect");
		ipxw_mux_unbind(ipxh);
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_CONNECT);
	}

	if (cfg->verbose) {
		fprintf(stderr, "SPX connected to ");
		print_ipxaddr(stderr, &(cfg->spx_remote_addr));
		fprintf(stderr, "\n");
	}

	ipxw_mux_handle_close(ipxh);

	// TODO: establish SPX connection and gate it properly until it is
	// fully established

	/* register SPX socket for reception */
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data.fd = ipxw_mux_spx_handle_sock(spxh)
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_spx_handle_sock(spxh),
				&ev) < 0) {
		perror("registering SPX socket for event polling");
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_SPX_FD);
	}

	bool auth_succeeded = rcon_auth(epoll_fd, cfg, password);
	/* destroy password, as it is no longer needed */
	memset(password, 0, strlen(password));

	if (!auth_succeeded) {
		fprintf(stderr, "Authentication failed!\n");
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_AUTH);
	}

	// TODO: handle screen list

	/* register stdin for reading */
	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = fileno(stdin);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fileno(stdin), &ev) < 0) {
		perror("registering STDIN for event polling");
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_STDIN_FD);
	}

	if (!rcon_main(epoll_fd, cfg)) {
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_PROTO);
	}

	cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: rconcl [-v] [-1] [-d <maximum SPX data bytes>] <local IPX address> <remote IPX address\n");
	exit(RCONCL_ERR_USAGE);
}

static bool verify_cfg(struct rconcl_cfg *cfg)
{
	if (cfg->max_spx_data_len < 1 || cfg->max_spx_data_len >
			SPXII_MAX_DATA_LEN) {
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	struct rconcl_cfg cfg = {
		.verbose = false,
		.spx_1_only = false,
		.max_spx_data_len = SPX_MAX_DATA_LEN_WO_SIZNG,
		.rx_queue_pause_threshold = DEFAULT_RX_QUEUE_PAUSE_THRESHOLD,
		.tx_queue_pause_threshold = DEFAULT_TX_QUEUE_PAUSE_THRESHOLD,
	};

	/* parse and verify command-line arguments */

	int opt;
	while ((opt = getopt(argc, argv, "1d:v")) != -1) {
		switch (opt) {
			case '1':
				cfg.spx_1_only = true;
				break;
			case 'd':
				cfg.max_spx_data_len = strtoul(optarg, NULL, 0);
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

	if (!parse_ipxaddr(argv[optind + 1], &(cfg.spx_remote_addr))) {
		usage();
	}

	if (!verify_cfg(&cfg)) {
		usage();
	}

	// TODO: ask for password
	char password[] = "admin";

	do_rconcl(&cfg, password);
}
