/* Much of this code was taken from or inspired by rconip-2.5:
 * https://rconip.sourceforge.net/index.html */
#include <assert.h>
#include <ctype.h>
#include <limits.h>
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

#define RCON_LINES 25
#define RCON_COLUMNS 80

#define SCREEN_ESCAPE_KEY (KEY_MAX + 1)
static const char *screen_escape_seq = "\033X"; /* Alt+Shift+X */

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
	RCONCL_ERR_MSG_REASSEMBLE,
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

#define CURRENT_SCREEN_NONE 0xFFFFFFFF
static __be32 current_screen_id = CURRENT_SCREEN_NONE;
static struct rcon_screen_list screen_list = TAILQ_HEAD_INITIALIZER(screen_list);

static __u8 cp850[UCHAR_MAX + 1] = {
	[0x10] = '>',
	[0x11] = '<',
	[0x1E] = '^',
	[0x1F] = 'v'
};

static __u8 *current_cp = &cp850[0];

#define RCON_NONCE_LEN 4

static volatile sig_atomic_t keep_going = true;

static struct ipx_msg_queue rx_queue = STAILQ_HEAD_INITIALIZER(rx_queue);
static struct ipx_msg_queue tx_queue = STAILQ_HEAD_INITIALIZER(tx_queue);

/* connected handle */
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

static bool send_out_spx_msg(int epoll_fd)
{
	/* no msgs to send */
	if (STAILQ_EMPTY(&tx_queue)) {
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

	struct queued_ipx_msg *msg = STAILQ_FIRST(&tx_queue);
	ssize_t err = ipxw_mux_kspx_send(spxh, msg->data, msg->data_len,
			MSG_DONTWAIT, msg->datastream_type, msg->spx_flags);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return true;
		}

		/* other error, make sure to get rid of the message */
	}

	STAILQ_REMOVE_HEAD(&tx_queue, q_entry);
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
	free_item(exit_item);
	free(screen_items);

	screen_menu = NULL;
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
		ITEM **screen_items_new = reallocarray(screen_items, i + 1,
				sizeof(ITEM *));
		if (screen_items_new == NULL) {
			free(screen_items);
			return false;
		}
		screen_items = screen_items_new;
		screen_items[i] = sc->menu_item;

		i++;
	}

	ITEM **screen_items_new = reallocarray(screen_items, i + 2, sizeof(ITEM
				*));
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
		free_item(screen_items[i]);
		free(screen_items);
		return false;
	}

	if (post_menu(screen_menu) != E_OK) {
		free_menu(screen_menu);
		free_item(screen_items[i]);
		free(screen_items);
		screen_menu = NULL;

		return false;
	}

	return true;
}

static void init_ui(void)
{
	initscr();

	start_color();
}

static void cleanup_ui(void)
{
	unpost_screen_menu();
}

static bool config_ui(void)
{
	do {
		if (raw() == ERR) {
			break;
		}

		if (wresize(stdscr, RCON_LINES, RCON_COLUMNS) == ERR) {
			break;
		}

		if (nodelay(stdscr, true) == ERR) {
			break;
		}

		if (nonl() == ERR) {
			break;
		}

		if (keypad(stdscr, true) == ERR) {
			break;
		}

		if (define_key(screen_escape_seq, SCREEN_ESCAPE_KEY) == ERR) {
			break;
		}

		noecho();

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

static struct queued_ipx_msg *incomplete_msg = NULL;

static _Noreturn void cleanup_and_exit(int epoll_fd, enum rconcl_error_codes
		code)
{
	cleanup_ui();

	rcon_empty_screenlist();

	if (!isendwin()) {
		endwin();
	}

	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	/* remove all queued messages */
	while (!STAILQ_EMPTY(&rx_queue)) {
		struct queued_ipx_msg *msg = STAILQ_FIRST(&rx_queue);
		STAILQ_REMOVE_HEAD(&rx_queue, q_entry);
		free(msg);
	}
	while (!STAILQ_EMPTY(&tx_queue)) {
		struct queued_ipx_msg *msg = STAILQ_FIRST(&tx_queue);
		STAILQ_REMOVE_HEAD(&tx_queue, q_entry);
		free(msg);
	}

	/* free any incomplete message */
	free(incomplete_msg);

	if (!ipxw_mux_spx_handle_is_error(spxh)) {
		ipxw_mux_spx_conn_close(&spxh);
	}

	exit(code);
}

static bool continue_msg(struct queued_ipx_msg *msg, size_t data_len, struct
		queued_ipx_msg **to_queue)
{
	assert(data_len <= USHRT_MAX);

	bool end_of_msg = (msg->spx_flags & SPX_F_END_OF_MSG) != 0;

	if (incomplete_msg == NULL) {
		msg->data_len = data_len;
		msg->is_spx = true;
		incomplete_msg = msg;
	} else {
		size_t incomplete_msg_data_len = incomplete_msg->data_len;
		assert(incomplete_msg_data_len <= USHRT_MAX);
		if (USHRT_MAX - incomplete_msg_data_len < data_len) {
			return false;
		}

		size_t new_data_len = incomplete_msg_data_len + data_len;
		size_t new_msg_len = sizeof(struct queued_ipx_msg) +
			new_data_len;

		struct queued_ipx_msg *new_msg = realloc(incomplete_msg,
				new_msg_len);
		if (new_msg == NULL) {
			return false;
		}

		__u8 *new_msg_data = new_msg->data;
		__u8 *msg_data = msg->data;
		memcpy(new_msg_data + incomplete_msg_data_len, msg_data,
				data_len);
		new_msg->data_len = new_data_len;

		incomplete_msg = new_msg;
		free(msg);
	}

	if (end_of_msg) {
		*to_queue = incomplete_msg;
		incomplete_msg = NULL;
	} else {
		*to_queue = NULL;
	}

	return true;
}

static void spx_recv_loop(int epoll_fd, struct rconcl_cfg *cfg)
{
	while (true) {
		/* SPX message received */
		__u8 dummy_data;
		__u8 dummy_ds_type;
		__u8 dummy_spx_flags;
		ssize_t expected_data_len = ipxw_mux_kspx_recv(spxh,
				&dummy_data, 1, MSG_PEEK | MSG_TRUNC |
				MSG_DONTWAIT, &dummy_ds_type,
				&dummy_spx_flags);
		if (expected_data_len < 0) {
			if (errno == EINTR) {
				continue;
			}

			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}

			leave_ui();
			perror("SPX receive peek");
			cleanup_and_exit(epoll_fd, RCONCL_ERR_SPX_FAILURE);
		}

		// TOOD: reinstate rx_queue limit

		struct queued_ipx_msg *msg = calloc(1, sizeof(struct
					queued_ipx_msg) + expected_data_len);
		if (msg == NULL) {
			leave_ui();
			perror("allocating message");
			cleanup_and_exit(epoll_fd, RCONCL_ERR_MSG_ALLOC);
		}

		msg->is_spx = true;
		ssize_t rcvd_len = ipxw_mux_kspx_recv(spxh, msg->data,
				expected_data_len, MSG_DONTWAIT,
				&(msg->datastream_type), &(msg->spx_flags));
		if (rcvd_len < 0) {
			free(msg);
			if (errno == EINTR) {
				continue;
			}

			leave_ui();
			perror("SPX receive");
			cleanup_and_exit(epoll_fd, RCONCL_ERR_SPX_FAILURE);
		}

		if (rcvd_len == 0) {
			free(msg);
			continue;
		}

		/* continue previous message */
		struct queued_ipx_msg *msg_to_queue = NULL;
		if (!continue_msg(msg, rcvd_len, &msg_to_queue)) {
			free(msg);
			leave_ui();
			fprintf(stderr, "failed to reassemble message\n");
			cleanup_and_exit(epoll_fd, RCONCL_ERR_MSG_REASSEMBLE);
		}

		/* queue received message, if complete */
		if (msg_to_queue != NULL) {
			STAILQ_INSERT_TAIL(&rx_queue, msg_to_queue, q_entry);
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
		int epoll_tmo = -1;
		if (!STAILQ_EMPTY(&rx_queue)) {
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
			cleanup_and_exit(epoll_fd, RCONCL_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
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
				cleanup_and_exit(epoll_fd,
						RCONCL_ERR_SPX_FAILURE);
			}

			/* can write to SPX socket */
			if (evs[i].events & EPOLLOUT) {
				if (!send_out_spx_msg(epoll_fd)) {
					leave_ui();
					perror("SPX send");
					cleanup_and_exit(epoll_fd,
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
		if (!STAILQ_EMPTY(&rx_queue)) {
			ret |= RCONCL_EVENT_MSG;
		}

		if (ret != 0) {
			return ret;
		}
	}

	return RCONCL_EVENT_EXIT;
}

static int rcon_data_next_byte(__u8 *data, __u16 len, __u16 start, __u8 *out)
{
	if (start >= len) {
		return -1;
	}
	if (len - start < 1) {
		return -1;
	}

	*out = data[start];
	return start + 1;
}

static int rcon_data_next_int(__u8 *data, __u16 len, __u16 start, __s32 *out)
{
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

static int rcon_data_next_str(__u8 *data, __u16 len, __u16 start, char **out)
{
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

static struct queued_ipx_msg *rcon_prepare_request(__u16 data_len, __u16
		code, __be32 screen_id)
{
	if (code <= RCON_REQUEST_MIN || code >= RCON_REQUEST_MAX) {
		return NULL;
	}

	int max_data_len = ipxw_mux_spx_max_data_len(spxh);
	int req_data_len = sizeof(struct rcon_request) + data_len;

	if (max_data_len < req_data_len) {
		return NULL;
	}

	struct queued_ipx_msg *msg = calloc(1, sizeof(struct queued_ipx_msg) +
			req_data_len);
	if (msg == NULL) {
		return NULL;
	}

	struct rcon_request *req = (struct rcon_request *) msg->data;
	req->data_len = htons(data_len);
	req->code = htons(code);
	req->screen_id = screen_id;

	msg->is_spx = true;
	msg->datastream_type = SPX_DS_NONE;
	msg->data_len = req_data_len;

	return msg;
}

static struct queued_ipx_msg *rcon_digest_request(const __u8 *hash)
{
	struct queued_ipx_msg *msg = rcon_prepare_request(MD5_DIGEST_LENGTH,
			RCON_REQUEST_DIGEST, 0);
	if (msg == NULL) {
		return NULL;
	}

	struct rcon_request *req = (struct rcon_request *) msg->data;
	memcpy(req->data, hash, MD5_DIGEST_LENGTH);

	return msg;
}

static struct queued_ipx_msg *rcon_screen_ack(__be32 screen_id, __s32 sid)
{
	struct queued_ipx_msg *msg = rcon_prepare_request(sizeof(__be32),
			RCON_REQUEST_SCREEN_ACK, screen_id);
	if (msg == NULL) {
		return NULL;
	}

	__be32 data = htonl(sid);

	struct rcon_request *req = (struct rcon_request *) msg->data;
	memcpy(req->data, &data, sizeof(__be32));

	return msg;
}

static struct queued_ipx_msg *rcon_input_request(__be32 screen_id, int chr)
{
	struct queued_ipx_msg *msg = rcon_prepare_request(sizeof(__be16),
			RCON_REQUEST_SCREEN_INPUT, screen_id);
	if (msg == NULL) {
		return NULL;
	}

	__be16 data = htons((__u16) chr);

	struct rcon_request *req = (struct rcon_request *) msg->data;
	memcpy(req->data, &data, sizeof(__be16));

	return msg;
}

static bool rcon_request_push(int epoll_fd, struct queued_ipx_msg *msg)
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

	// TODO: split request into multiple messages if necessary
	msg->spx_flags |= SPX_F_END_OF_MSG;

	/* queue the SPX message */
	struct rcon_request *req = (struct rcon_request *) msg->data;
	int req_data_len = sizeof(struct rcon_request) + ntohs(req->data_len);

	msg->data_len = req_data_len;
	STAILQ_INSERT_TAIL(&tx_queue, msg, q_entry);

	return true;
}

static struct queued_ipx_msg *rcon_reply_pop(void)
{
	assert(!STAILQ_EMPTY(&rx_queue));

	struct queued_ipx_msg *msg = STAILQ_FIRST(&rx_queue);
	STAILQ_REMOVE_HEAD(&rx_queue, q_entry);

	do {
		if (msg->data_len < sizeof(struct rcon_reply)) {
			break;
		}

		struct rcon_reply *rep = (struct rcon_reply *) msg->data;

		if (ntohs(rep->code) <= RCON_REPLY_MIN || ntohs(rep->code) >=
				RCON_REPLY_MAX) {
			break;
		}
		if (ntohs(rep->data_len) != msg->data_len - sizeof(struct
					rcon_reply)) {
			break;
		}

		return msg;
	} while (0);

	free(msg);
	return NULL;
}

static bool rcon_set_codepage(char *cp_name)
{
	if (strcmp("850", cp_name) == 0) {
		current_cp = &cp850[0];
		return true;
	}

	current_cp = &cp850[0];
	return false;
}

static bool rcon_auth(int epoll_fd, struct rconcl_cfg *cfg, const char *password)
{
	struct queued_ipx_msg *msg = NULL;

	do {
		/* wait for nonce and compute response */

		if ((wait_for_event(epoll_fd, cfg) & RCONCL_EVENT_MSG) == 0) {
			break;
		}

		msg = rcon_reply_pop();
		if (msg == NULL) {
			break;
		}

		struct rcon_reply *rep = (struct rcon_reply *) msg->data;
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

		rep = (struct rcon_reply *) msg->data;
		if (ntohs(rep->code) != RCON_REPLY_SERVER_NAME) {
			break;
		}

		/* retrieve the server name */

		char *server_name = NULL;
		int pos = rcon_data_next_str(rep->data,
				ntohs(rep->data_len), 0, &server_name);
		if (pos < 0) {
			break;
		}

		if (cfg->verbose) {
			printf("Server Name: %s\n", server_name);
		}

		free(server_name);

		/* retrieve the codepage */

		char *cp = NULL;
		pos = rcon_data_next_str(rep->data, ntohs(rep->data_len), pos,
				&cp);
		if (pos < 0) {
			break;
		}

		bool cp_found = rcon_set_codepage(cp);

		if (cfg->verbose) {
			printf("Server Codepage: %s\n", cp);
			if (!cp_found) {
				printf("Using default codepage 850.\n");
			}
		}

		free(cp);

		free(msg);
		msg = NULL;

		/* send response to the server's nonce */

		struct queued_ipx_msg *req_digest =
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

		rep = (struct rcon_reply *) msg->data;
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

	struct queued_ipx_msg *msg = rcon_reply_pop();
	if (msg == NULL) {
		return false;
	}

	struct rcon_reply *rep = (struct rcon_reply *) msg->data;

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

static bool enter_screen(int epoll_fd, __be32 screen_id)
{
	struct queued_ipx_msg *msg = rcon_prepare_request(0,
			RCON_REQUEST_SCREEN_OPEN, screen_id);
	if (msg == NULL) {
		return false;
	}

	if (!rcon_request_push(epoll_fd, msg)) {
		free(msg);
		return false;
	}

	current_screen_id = screen_id;
	unpost_screen_menu();

	return true;
}

static void leave_screen(void)
{
	if (current_screen_id == CURRENT_SCREEN_NONE) {
		return;
	}

	clear();
	current_screen_id = CURRENT_SCREEN_NONE;
	if (!post_screen_menu()) {
		return;
	}
	refresh();
}

static int translate_key(int c)
{
	int ret = -1;
	bool shift = false;
	switch(c) {
		case KEY_HOME:
			ret = 71;
			break;

		case KEY_END:
			ret = 79;
			break;

		case KEY_PPAGE:
			ret = 73;
			break;

		case KEY_NPAGE:
			ret = 81;
			break;

		case KEY_UP:
			ret = 72;
			break;

		case KEY_DOWN:
			ret = 80;
			break;

		case KEY_LEFT:
			ret = 75;
			break;

		case KEY_RIGHT:
			ret = 77;
			break;

		case KEY_F(1):
		case KEY_F(2):
		case KEY_F(3):
		case KEY_F(4):
		case KEY_F(5):
		case KEY_F(6):
		case KEY_F(7):
		case KEY_F(8):
		case KEY_F(9):
		case KEY_F(10):
			ret = ((c - KEY_F(1) + 0x70) - 112) + 59;
			break;

		case '\n':
		case '\r':
		case KEY_ENTER:
			ret = 13;
			shift = true;
			break;

		case KEY_IC: /* insert character */
			ret = 82;
			break;

		case 033: /* ESC */
			ret = 27;
			shift = true;
			break;

		case KEY_DC: /* delete character */
			ret = 83;
			break;

		case KEY_BACKSPACE:
			ret = 8;
			shift = true;
			break;

		case KEY_STAB: /* tab */
			ret = 15;
			break;
		case KEY_BTAB: /* shift+tab */
			ret = 9;
			shift = true;
			break;
		default:
			return -1;
	}

	if(shift) {
		ret <<= 8;
	}
	return ret;
}

static void handle_screen_input(int epoll_fd, int c)
{
	if (c == SCREEN_ESCAPE_KEY) {
		leave_screen();
		return;
	}

	if (!isprint(c)) {
		c = translate_key(c);
		if (c == -1) {
			return;
		}
	} else {
		c <<= 8;
	}

	struct queued_ipx_msg *req = rcon_input_request(current_screen_id, c);
	if (req == NULL) {
		leave_ui();
		perror("allocating message");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_MSG_ALLOC);
	}

	if (!rcon_request_push(epoll_fd, req)) {
		free(req);
		leave_ui();
		perror("queueing message");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_MSG_ALLOC);
	}
}

static void handle_screen_menu_input(int epoll_fd, int c)
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

	enter_screen(epoll_fd, sc->screen_id);
}

#define WIN_FG_BLUE 0x0001
#define WIN_FG_GREEN 0x0002
#define WIN_FG_RED 0x0004
#define WIN_FG_INTENSITY 0x0008
#define WIN_BG_BLUE 0x0010
#define WIN_BG_GREEN 0x0020
#define WIN_BG_RED 0x0040
#define WIN_BG_INTENSITY 0x0080

static int get_ncurses_color(__u8 win_col_attr)
{
	switch (win_col_attr) {
		case 0:
			return COLOR_BLACK;
		case WIN_FG_BLUE:
			return COLOR_BLUE;
		case WIN_FG_GREEN:
			return COLOR_GREEN;
		case WIN_FG_RED:
			return COLOR_RED;
		case (WIN_FG_BLUE | WIN_FG_GREEN):
			return COLOR_CYAN;
		case (WIN_FG_BLUE | WIN_FG_RED):
			return COLOR_MAGENTA;
		case (WIN_FG_GREEN | WIN_FG_RED):
			return COLOR_YELLOW;
		case (WIN_FG_BLUE | WIN_FG_GREEN | WIN_FG_RED):
			return COLOR_WHITE;
		default:
			assert(0);
	}
}

static int translate_attrs(__u8 attrs)
{
	__u8 fg_col_attr = attrs & (WIN_FG_BLUE | WIN_FG_GREEN | WIN_FG_RED);
	__u8 bg_col_attr = attrs & (WIN_BG_BLUE | WIN_BG_GREEN | WIN_BG_RED);

	int fg_col = get_ncurses_color(fg_col_attr);
	int bg_col = get_ncurses_color(bg_col_attr >> 4);
	__u16 cp_name = fg_col | (bg_col << 3);
	init_pair(cp_name, fg_col, bg_col);

	int new_attrs = COLOR_PAIR(cp_name);

	if ((attrs & WIN_FG_INTENSITY) != 0) {
		new_attrs |= A_BOLD;
	}
	if ((attrs & WIN_BG_INTENSITY) != 0) {
		new_attrs |= A_STANDOUT;
	}

	return new_attrs;
}

static __u8 get_byte_from_codepage(__u8 c, __u8 *cp)
{
	if (cp[c] != 0) {
		return cp[c];
	}

	return c;
}

// TODO: clean up!
static bool screen_draw(__u8 *data, __u16 len, int pos, bool update)
{
	static char screen_content[RCON_LINES * RCON_COLUMNS] = {0};
	static char screen_attrs[RCON_LINES * RCON_COLUMNS] = {0};
	static char screen_content_expanded[RCON_LINES * RCON_COLUMNS * 4] = {0};

	__u8 xpos = 0;
	pos = rcon_data_next_byte(data, len, pos, &xpos);
	if (pos < 0) {
		return false;
	}

	__u8 ypos = 0;
	pos = rcon_data_next_byte(data, len, pos, &ypos);
	if (pos < 0) {
		return false;
	}

	__u8 b;
	__u8 b2;
	int state = 0;
	int i = 0;
	int j = 0;
	int k = 0;
	while ((pos = rcon_data_next_byte(data, len, pos, &b)) >= 0) {
		switch (state) {
			case 0:
				switch (b) {
					case 27:
						state = 1;
						break;
					case 28:
						state = 3;
						break;
					case 29:
						state = 6;
						break;
					default:
						screen_content_expanded[i++] = b;
						break;
				}
				break;

			case 1: // repeat1_1
				b2 = b;
				state = 2;
				break;

			case 2: // repeat1_2
				k = b;
				if (i + k > 8000) {
					break;
				}

				if (b2 == 29) {
					for (j = 0; j < k / 2; j++) {
						screen_content_expanded[i++] = 29;
					}
					if (k % 2) {
						state = 6;
					} else {
						state = 0;
					}
				} else {
					for (j = 0; j < k; j++) {
						screen_content_expanded[i++] = b2;
					}
					state = 0;
				}

				break;

			case 3: // repeat2_1
				b2 = b;
				state = 4;
				break;

			case 4: // repeat2_2
				k = b;
				state = 5;
				break;

			case 5: // repeat2_3
				k += b << 8;
				if (i + k > 8000) {
					break;
				}

				for (j = 0; j < k; j++) {
					screen_content_expanded[i++] = b2;
				}

				state = 0;
				break;

			case 6: // escape
				switch (b) {
					case 1: // 27
						screen_content_expanded[i++] = 27;
						break;
					case 2: // 28
						screen_content_expanded[i++] = 28;
						break;
					case 29: // 29
						screen_content_expanded[i++] = 29;
						break;
					default:
						break;
				}

				state = 0;
				break;

			default:
				assert(0);
		}
	}

	/* abort if the server sent the wrong number of characters */
	if (i != RCON_LINES * RCON_COLUMNS * 2) {
		return false;
	}

	if (update) {
		for (i = 0; i < RCON_LINES * RCON_COLUMNS; i++) {
			screen_content[i] ^= screen_content_expanded[i];
			screen_attrs[i] ^= screen_content_expanded[(RCON_LINES
					* RCON_COLUMNS) + i];
		}
	} else {
		memcpy(screen_content, screen_content_expanded, RCON_LINES *
				RCON_COLUMNS);
		memcpy(screen_attrs, &screen_content_expanded[RCON_LINES *
				RCON_COLUMNS], RCON_LINES * RCON_COLUMNS);
	}

	move(0, 0);
	for (i = 0; i < RCON_LINES * RCON_COLUMNS; i++) {
		__u8 cont = get_byte_from_codepage(screen_content[i],
				current_cp);
		addch(cont | translate_attrs(screen_attrs[i]));
	}
	move(ypos, xpos);
	refresh();

	return true;
}

static bool rcon_handle_reply(int epoll_fd, struct queued_ipx_msg *msg)
{
	bool update = true;
	struct rcon_reply *rep = (struct rcon_reply *) msg->data;
	switch (ntohs(rep->code)) {
		case RCON_REPLY_SCREENLIST:
			bool in_menu = in_screen_menu();
			if (in_menu) {
				unpost_screen_menu();
			}

			rcon_empty_screenlist();
			if (!rcon_fill_screenlist(rep)) {
				return false;
			}

			if (in_menu) {
				if (!post_screen_menu()) {
					return false;
				}
				refresh();
			}

			return true;
		case RCON_REPLY_SCREEN_DESTROYED:
			if (rep->screen_id == current_screen_id) {
				leave_screen();
			}
			return true;

		case RCON_REPLY_SCREEN_LOCKED:
		case RCON_REPLY_SCREEN_UNLOCKED:
			/* nothing to do */
			return true;

		case RCON_REPLY_SCREEN_COPY:
			update = false;
			/* fall through on purpuse */
		case RCON_REPLY_SCREEN_CHANGE:
			int pos = 0;

			__s32 sid = 0;
			pos = rcon_data_next_int(rep->data,
					ntohs(rep->data_len), pos, &sid);
			if (pos < 0) {
				return false;
			}

			if (rep->screen_id == current_screen_id) {
				if (!screen_draw(rep->data,
							ntohs(rep->data_len),
							pos, update)) {
					return false;
				}
			}

			struct queued_ipx_msg *req =
				rcon_screen_ack(current_screen_id, sid);
			if (req == NULL) {
				return false;
			}

			if (!rcon_request_push(epoll_fd, req)) {
				free(req);
				return false;
			}

			return true;
		default:
			return false;
	}
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

		assert(!in_screen_menu() || current_screen_id ==
				CURRENT_SCREEN_NONE);
		assert(current_screen_id != CURRENT_SCREEN_NONE ||
				in_screen_menu());

		/* exit */
		if ((ev & RCONCL_EVENT_EXIT) != 0) {
			return true;
		}

		/* message received */
		if ((ev & RCONCL_EVENT_MSG) != 0) {
			struct queued_ipx_msg *msg = rcon_reply_pop();
			if (msg == NULL) {
				return false;
			}

			/* actually handle the message */
			bool success = rcon_handle_reply(epoll_fd, msg);
			free(msg);
			if (!success) {
				return false;
			}
		}

		/* stdin */
		if ((ev & RCONCL_EVENT_STDIN) != 0) {
			int c = getch();
			if (c == ERR) {
				continue;
			}

			if (in_screen_menu()) {
				handle_screen_menu_input(epoll_fd, c);
				refresh();
			} else {
				handle_screen_input(epoll_fd, c);
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
		cleanup_and_exit(-1, RCONCL_ERR_PASS);
	}

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_EPOLL_FD);
	}

	/* register signal handlers */
	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting up signal handler");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_SIG_HANDLER);
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
	bind_msg.bind.recv_direct = true;

	struct ipxw_mux_handle ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_BIND);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->spx_local_addr))) {
			perror("IPX get bound address");
			ipxw_mux_unbind(ipxh);
			cleanup_and_exit(epoll_fd, RCONCL_ERR_GETSOCKNAME);
		}

		fprintf(stderr, "SPX bound to ");
		print_ipxaddr(stderr, &(cfg->spx_local_addr));
		fprintf(stderr, "\n");
	}

	/* establish the SPX connection to the specified remote */
	spxh = ipxw_mux_kspx_connect(ipxh, &(cfg->spx_remote_addr));
	if (ipxw_mux_spx_handle_is_error(spxh)) {
		perror("SPX connect");
		ipxw_mux_unbind(ipxh);
		cleanup_and_exit(epoll_fd, RCONCL_ERR_CONNECT);
	}

	if (cfg->verbose) {
		fprintf(stderr, "SPX connected to ");
		print_ipxaddr(stderr, &(cfg->spx_remote_addr));
		fprintf(stderr, "\n");
	}

	ipxw_mux_handle_close(ipxh);

	/* register SPX socket for reception */
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data.fd = ipxw_mux_spx_handle_sock(spxh)
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_spx_handle_sock(spxh),
				&ev) < 0) {
		perror("registering SPX socket for event polling");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_SPX_FD);
	}

	/* authenticate */
	bool auth_succeeded = rcon_auth(epoll_fd, cfg, password);
	/* destroy password, as it is no longer needed */
	memset(password, 0, strlen(password));

	if (!auth_succeeded) {
		fprintf(stderr, "Authentication failed!\n");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_AUTH);
	}

	printf("Authenticated!\n");

	/* read screen list */
	if (!rcon_handle_screenlist(epoll_fd, cfg)) {
		leave_ui();
		fprintf(stderr, "Failed to fetch screen list!\n");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_PROTO);
	}

	if (cfg->verbose) {
		rcon_print_screenlist();
	}

	/* enter the UI and set it up for use */
	enter_ui();
	if (!config_ui()) {
		leave_ui();
		fprintf(stderr, "failed to set up UI\n");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_UI);
	}

	/* register stdin for reading */
	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = fileno(stdin);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fileno(stdin), &ev) < 0) {
		leave_ui();
		perror("registering STDIN for event polling");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_STDIN_FD);
	}

	if (!rcon_main(epoll_fd, cfg)) {
		leave_ui();
		fprintf(stderr, "protocoll error\n");
		cleanup_and_exit(epoll_fd, RCONCL_ERR_PROTO);
	}

	cleanup_and_exit(epoll_fd, RCONCL_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: rconcl [-v] [-1] [-d <maximum SPX data bytes>] <local IPX address> <remote IPX address>\n");
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
