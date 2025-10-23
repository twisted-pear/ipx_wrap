#include <assert.h>
#include <menu.h>
#include <ncurses.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/md5.h>

#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

#define MAX_PASSWORD_LEN 32

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
	RCONCL_ERR_UI,
	RCONCL_ERR_PASS,
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

struct rcon_screen {
	__be32 screen_id;
	char *screen_name;
	ITEM *menu_item;
	TAILQ_ENTRY(rcon_screen) list_entry;
};

TAILQ_HEAD(rcon_screen_list, rcon_screen);

struct rcon_screen_list screen_list = TAILQ_HEAD_INITIALIZER(screen_list);

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

static MENU *screen_menu = NULL;

static bool in_screen_menu(void)
{
	return screen_menu != NULL;
}

static void unpost_screen_menu(void)
{
	if (screen_menu == NULL) {
		return;
	}

	unpost_menu(screen_menu);

	ITEM **screen_items = menu_items(screen_menu);
	ITEM *exit_item = NULL;

	int n_items = item_count(screen_menu);
	if (n_items > 0) {
		exit_item = screen_items[n_items - 1];
	}

	free_menu(screen_menu);
	free(screen_items);
	free(exit_item);

	screen_menu = NULL;

	echo();
}

static bool post_screen_menu(void)
{
	if (screen_menu != NULL) {
		return false;
	}

	ITEM **screen_items = NULL;

	/* insert all screens */
	struct rcon_screen *sc;
	size_t i = 0;
	TAILQ_FOREACH(sc, &screen_list, list_entry) {
		ITEM **screen_items_new = reallocarray(screen_items, i + 1, sizeof(ITEM *));
		if (screen_items_new == NULL) {
			free(screen_items);
			return false;
		}
		screen_items = screen_items_new;
		screen_items[i] = sc->menu_item;

		i++;
	}

	ITEM **screen_items_new = reallocarray(screen_items, i + 2, sizeof(ITEM *));
	if (screen_items_new == NULL) {
		free(screen_items);
		return false;
	}
	screen_items = screen_items_new;

	/* insert the "exit" menu item */
	screen_items[i] = new_item("Exit", NULL);
	if (screen_items[i] == NULL) {
		free(screen_items);
		return false;
	}
	set_item_userptr(screen_items[i], NULL);

	/* insert the terminating NULL */
	screen_items[i + 1] = NULL;

	screen_menu = new_menu(screen_items);
	if (screen_menu == NULL) {
		free(screen_items);
		return false;
	}

	if (post_menu(screen_menu) != E_OK) {
		free_menu(screen_menu);
		free(screen_items);
		screen_menu = NULL;

		return false;
	}

	noecho();

	return true;
}

static void init_ui(void)
{
	initscr();
}

static void cleanup_ui(void)
{
	unpost_screen_menu();
}

static bool config_ui(void)
{
	do {
		if (cbreak() == ERR) {
			break;
		}

		if (nodelay(stdscr, true) == ERR) {
			break;
		}

		if (keypad(stdscr, true) == ERR) {
			break;
		}

		return true;
	} while (0);

	endwin();
	return false;
}

static void leave_ui(void)
{
	if (!isendwin()) {
		def_prog_mode();
		endwin();
	}
}

static void enter_ui(void)
{
	reset_prog_mode();
	refresh();
}

static void rcon_empty_screenlist(void);

static _Noreturn void cleanup_and_exit(int epoll_fd, struct rconcl_cfg *cfg,
		enum rconcl_error_codes code)
{
	cleanup_ui();

	rcon_empty_screenlist();

	if (!isendwin()) {
		endwin();
	}

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

			leave_ui();
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
			leave_ui();
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

			leave_ui();
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
			leave_ui();
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

			leave_ui();
			perror("event polling");
			cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					leave_ui();
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(epoll_fd, cfg,
							RCONCL_ERR_TMR_FAILURE);
				}

				/* maintain the SPX connection */
				if (!ipxw_mux_spx_maintain(spxh)) {
					leave_ui();
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
				leave_ui();
				fprintf(stderr, "SPX socket error\n");
				cleanup_and_exit(epoll_fd, cfg,
						RCONCL_ERR_SPX_FAILURE);
			}

			/* can write to SPX socket */
			if (evs[i].events & EPOLLOUT) {
				if (!send_out_spx_msg(epoll_fd)) {
					leave_ui();
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

static int rcon_data_next_int(__u8 *data, __u16 len, __u16 start, __s32 *out) {
	if (start >= len) {
		return -1;
	}
	if (len - start < 4) {
		return -1;
	}

	*out = (__s32)((data[start] << 24) | (data[start+1] << 16) |
			(data[start+2] << 8) | data[start+3]);
	return start + 4;
}

static int rcon_data_next_str(__u8 *data, __u16 len, __u16 start, char **out) {
	if (start >= len) {
		return -1;
	}

	int nstr_len = strnlen((char *) (data + start), len - start);
	char *nstr = malloc(nstr_len + 1);
	if (nstr == NULL) {
		return -1;
	}
	memcpy(nstr, data + start, nstr_len);
	nstr[nstr_len] = '\0';

	*out = nstr;

	/* +1 for the \0, if that doesn't exist, the next call to
	 * rcon_data_next_* will just fail */
	return start + nstr_len + 1;
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

	do {
		if (msg->recv.data_len < sizeof(struct rcon_reply)) {
			break;
		}

		struct rcon_reply *rep = (struct rcon_reply *)
			ipxw_mux_spx_msg_data(spx_msg);

		if (ntohs(rep->code) <= RCON_REPLY_MIN || ntohs(rep->code) >=
				RCON_REPLY_MAX) {
			break;
		}
		if (ntohs(rep->data_len) != msg->recv.data_len - sizeof(struct
					rcon_reply)) {
			break;
		}

		return spx_msg;
	} while (0);

	free(msg);
	return NULL;
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

		msg = rcon_reply_pop();
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
			free(req_digest);
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

static void rcon_free_screen(struct rcon_screen *sc)
{
	free_item(sc->menu_item);
	free(sc->screen_name);
	free(sc);
}

static struct rcon_screen *rcon_new_screen(__s32 id, char *name)
{
	struct rcon_screen *sc = malloc(sizeof(struct rcon_screen));
	if (sc == NULL) {
		return NULL;
	}

	ITEM *menu_item = new_item(name, NULL);
	if (menu_item == NULL) {
		free(sc);
		return NULL;
	}

	sc->screen_id = htonl(id);
	sc->screen_name = name;
	sc->menu_item = menu_item;

	set_item_userptr(menu_item, sc);

	return sc;
}

static bool rcon_add_screen(__s32 id, char *name)
{
	struct rcon_screen *sc = rcon_new_screen(id, name);
	if (sc == NULL) {
		return false;
	}

	TAILQ_INSERT_TAIL(&screen_list, sc, list_entry);
	return true;
}

static void rcon_empty_screenlist(void)
{
	while (!TAILQ_EMPTY(&screen_list)) {
		struct rcon_screen *sc = TAILQ_FIRST(&screen_list);
		TAILQ_REMOVE(&screen_list, sc, list_entry);
		rcon_free_screen(sc);
	}
}

static bool rcon_fill_screenlist(struct rcon_reply *rep)
{
	if (ntohs(rep->code) != RCON_REPLY_SCREENLIST) {
		return false;
	}

	int pos = 0;
	while (true) {
		__s32 screen_id;
		char *screen_name;

		pos = rcon_data_next_int(rep->data,
				ntohs(rep->data_len), pos, &screen_id);
		/* no more screens, exit */
		if (pos < 0) {
			return true;
		}

		pos = rcon_data_next_str(rep->data,
				ntohs(rep->data_len), pos,
				&screen_name);
		/* screen ID but no screen name, error */
		if (pos < 0) {
			break;
		}

		if (!rcon_add_screen(screen_id, screen_name)) {
			free(screen_name);
			break;
		}
	}

	/* empty half-filled screen list in case of error */
	rcon_empty_screenlist();

	return false;
}

static bool rcon_handle_screenlist(int epoll_fd, struct rconcl_cfg *cfg)
{
	/* wait for screen list and process it */

	if ((wait_for_event(epoll_fd, cfg) & RCONCL_EVENT_MSG) == 0) {
		return false;
	}

	struct ipxw_mux_spx_msg *msg = rcon_reply_pop();
	if (msg == NULL) {
		return false;
	}

	struct rcon_reply *rep = (struct rcon_reply *)
		ipxw_mux_spx_msg_data(msg);

	bool success = rcon_fill_screenlist(rep);
	free(msg);

	return success;
}

static void rcon_print_screenlist(void)
{
	printf("Screen List:\n");

	struct rcon_screen *sc;
	TAILQ_FOREACH(sc, &screen_list, list_entry) {
		printf("%08x: %s\n", ntohl(sc->screen_id), sc->screen_name);
	}
}

static void handle_screen_menu_input(int c)
{
	switch (c) {
		case KEY_DOWN:
		case 'j':
			menu_driver(screen_menu, REQ_DOWN_ITEM);
			return;
		case KEY_UP:
		case 'k':
			menu_driver(screen_menu, REQ_UP_ITEM);
			return;
		case KEY_ENTER:
		case '\n':
		case '\r':
			break;
		default:
			return;
	}

	ITEM *cur = current_item(screen_menu);
	if (cur == NULL) {
		return;
	}

	struct rcon_screen *sc = item_userptr(cur);

	/* exit item selected */
	if (sc == NULL) {
		keep_going = false;
		return;
	}

	// TODO: switch to the selected screen!
}

static bool rcon_main(int epoll_fd, struct rconcl_cfg *cfg)
{
	clear();
	if (!post_screen_menu()) {
		return false;
	}
	refresh();

	while (true) {
		enum rconcl_event ev = wait_for_event(epoll_fd, cfg);

		/* exit */
		if ((ev & RCONCL_EVENT_EXIT) != 0) {
			return true;
		}

		/* message received */
		if ((ev & RCONCL_EVENT_MSG) != 0) {
			struct ipxw_mux_spx_msg *msg = rcon_reply_pop();
			if (msg == NULL) {
				fprintf(stderr, "invalid message received\n");
			} else {
				// TODO: actually handle the message
				free(msg);
			}
		}

		/* stdin */
		if ((ev & RCONCL_EVENT_STDIN) != 0) {
			int c = ERR;
			while (true) {
				c = getch();
				if (c == ERR) {
					break;
				}

				if (in_screen_menu()) {
					handle_screen_menu_input(c);
				}
			}
		}
	}
}

static bool read_password(char *password)
{
	printw("Enter RCONSOLE password: ");
	noecho();
	int err = getnstr(password, MAX_PASSWORD_LEN);
	password[MAX_PASSWORD_LEN] = '\0';
	echo();

	return err != ERR;
}

static _Noreturn void do_rconcl(struct rconcl_cfg *cfg)
{
	/* initial setup */

	/* prepare ncurses UI */
	init_ui();

	/* ask for password */
	char password[MAX_PASSWORD_LEN + 1];
	bool password_read = read_password(password);

	/* leave ncurses UI for setup */
	leave_ui();

	if (!password_read) {
		fprintf(stderr, "failed to read password\n");
		cleanup_and_exit(-1, cfg, RCONCL_ERR_PASS);
	}

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

	/* authenticate */
	bool auth_succeeded = rcon_auth(epoll_fd, cfg, password);
	/* destroy password, as it is no longer needed */
	memset(password, 0, strlen(password));

	if (!auth_succeeded) {
		fprintf(stderr, "Authentication failed!\n");
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_AUTH);
	}

	printf("Authenticated!\n");

	/* read screen list */
	if (!rcon_handle_screenlist(epoll_fd, cfg)) {
		leave_ui();
		fprintf(stderr, "Failed to fetch screen list!\n");
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_PROTO);
	}

	if (cfg->verbose) {
		rcon_print_screenlist();
	}

	/* enter the UI and set it up for use */
	enter_ui();
	if (!config_ui()) {
		leave_ui();
		fprintf(stderr, "failed to set up UI\n");
		cleanup_and_exit(epoll_fd, cfg, RCONCL_ERR_UI);
	}

	/* register stdin for reading */
	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = fileno(stdin);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fileno(stdin), &ev) < 0) {
		leave_ui();
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

	do_rconcl(&cfg);
}
