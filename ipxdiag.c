#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

#define DEFAULT_PKT_TYPE 0x1E
#define DEFAULT_WAIT_SECS 5
#define MAX_EXCLUDE_ADDRS 80

enum ipxdiag_error_codes {
	IPXDIAG_ERR_OK = 0,
	IPXDIAG_ERR_USAGE,
	IPXDIAG_ERR_EPOLL_FD,
	IPXDIAG_ERR_TMR_FD,
	IPXDIAG_ERR_STDOUT_FD,
	IPXDIAG_ERR_CONF_FD,
	IPXDIAG_ERR_IPX_FD,
	IPXDIAG_ERR_SIG_HANDLER,
	IPXDIAG_ERR_BIND,
	IPXDIAG_ERR_GETSOCKNAME,
	IPXDIAG_ERR_EPOLL_WAIT,
	IPXDIAG_ERR_TMR_FAILURE,
	IPXDIAG_ERR_CONF_FAILURE,
	IPXDIAG_ERR_IPX_FAILURE,
	IPXDIAG_ERR_DIAG_REQ_CREATE,
	IPXDIAG_ERR_DIAG_REQ_SEND,
	IPXDIAG_ERR_MSG_ALLOC,
	IPXDIAG_ERR_MSG_QUEUE,
	IPXDIAG_ERR_MAX
};

#define MAX_EPOLL_EVENTS 64

struct ipxdiag_cfg {
	bool verbose;
	time_t wait_secs;
	__u8 pkt_type;
	__u8 n_exclude_addrs;
	__u8 exclude_addrs[MAX_EXCLUDE_ADDRS][IPX_ADDR_NODE_BYTES];
	struct ipx_addr local_addr;
	struct ipx_addr target_addr;
};

struct ipx_diag_req {
	__u8 n_exclude_addrs;
	__u8 exclude_addrs[0][IPX_ADDR_NODE_BYTES];
} __attribute__((packed));

enum ipx_diag_component_id {
	IPX_DIAG_COMPONENT_IPXSPX = 0,
	IPX_DIAG_COMPONENT_BRIDGE_DRV,
	IPX_DIAG_COMPONENT_SHELL_DRV,
	IPX_DIAG_COMPONENT_SHELL,
	IPX_DIAG_COMPONENT_VAP_SHELL,
	IPX_DIAG_COMPONENT_SIMPLE_MAX = IPX_DIAG_COMPONENT_VAP_SHELL,
	IPX_DIAG_COMPONENT_BRIDGE_EXTERNAL,
	IPX_DIAG_COMPONENT_FILE_SRV_OR_BRIDGE_INTERNAL,
	IPX_DIAG_COMPONENT_NON_DEDICATED_IPXSPX,
	IPX_DIAG_COMPONENT_STAR_68000,
	IPX_DIAG_COMPONENT_MAX
};

static const char* ipx_diag_component_name[IPX_DIAG_COMPONENT_MAX] = {
	[IPX_DIAG_COMPONENT_IPXSPX] = "IPX / SPX",
	[IPX_DIAG_COMPONENT_BRIDGE_DRV] = "Bridge Driver",
	[IPX_DIAG_COMPONENT_SHELL_DRV] = "Shell Driver",
	[IPX_DIAG_COMPONENT_SHELL] = "Shell",
	[IPX_DIAG_COMPONENT_VAP_SHELL] = "VAP Shell",
	[IPX_DIAG_COMPONENT_BRIDGE_EXTERNAL] = "Bridge (External)",
	[IPX_DIAG_COMPONENT_FILE_SRV_OR_BRIDGE_INTERNAL] = "File Server / Bridge (Internal)",
	[IPX_DIAG_COMPONENT_NON_DEDICATED_IPXSPX] = "Non-Dedicated IPX / SPX",
	[IPX_DIAG_COMPONENT_STAR_68000] = "Star 68000 (IPX only)"
};

enum ipx_diag_local_net_type {
	IPX_DIAG_LOCAL_NET_LAN = 0,
	IPX_DIAG_LOCAL_NET_NON_DEDICATED_FILE_SERVER,
	IPX_DIAG_LOCAL_NET_REDIRECTED_REMOTE_LINE,
	IPX_DIAG_LOCAL_NET_MAX
};

static const char* ipx_diag_local_net_type_name[IPX_DIAG_LOCAL_NET_MAX] = {
	[IPX_DIAG_LOCAL_NET_LAN] = "LAN Board",
	[IPX_DIAG_LOCAL_NET_NON_DEDICATED_FILE_SERVER] = "Non-Dedicated File Server (Virtual Board)",
	[IPX_DIAG_LOCAL_NET_REDIRECTED_REMOTE_LINE] = "Redirected Remote Line"
};

struct ipx_diag_component_simple {
	__u8 component_id;
} __attribute__((packed));

struct ipx_diag_local_net {
	__u8 type;
	__be32 net;
	__u8 node[IPX_ADDR_NODE_BYTES];
} __attribute__((packed));

struct ipx_diag_component_extended {
	__u8 component_id;
	__u8 n_local_nets;
	struct ipx_diag_local_net local_nets[0];
} __attribute__((packed));

struct ipx_diag_rsp {
	__u8 major_version;
	__u8 minor_version;
	__be16 spx_diag_sock;
	__u8 n_components;
	struct ipx_diag_component_simple components[0];
} __attribute__((packed));

struct diag_rsp_cursor {
	void *pos;
};

static volatile sig_atomic_t keep_going = true;
static bool stdout_is_file = false;
struct ipxw_msg_queue in_queue = STAILQ_HEAD_INITIALIZER(in_queue);

static struct ipxw_mux_handle ipxh = ipxw_mux_handle_init;

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

static int setup_timer(int epoll_fd, time_t secs)
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
		.it_interval = { .tv_sec = 0, .tv_nsec = 0 },
		.it_value = { .tv_sec = secs, .tv_nsec = 0 }
	};
	if (timerfd_settime(tmr, 0, &tmr_spec, NULL) < 0) {
		close(tmr);
		return -1;
	}

	return tmr;
}

static bool queue_in_msg(int epoll_fd, struct ipxw_mux_msg *msg)
{
	/* reregister for ready-to-write events, now that messages are
	 * available */
	if (!stdout_is_file) {
		struct epoll_event ev = {
			.events = EPOLLOUT | EPOLLERR | EPOLLHUP,
			.data.fd = fileno(stdout)
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fileno(stdout), &ev) <
				0) {
			return false;
		}
	}

	/* queue the input message */
	STAILQ_INSERT_TAIL(&in_queue, msg, q_entry);

	return true;
}

static bool diag_component_is_simple(enum ipx_diag_component_id id)
{
	return (id <= IPX_DIAG_COMPONENT_SIMPLE_MAX);
}

static int parse_diag_local_net(struct diag_rsp_cursor *cur, void *data_end,
		struct ipx_diag_local_net **net_out)
{
	struct ipx_diag_local_net *net = cur->pos;
	if ((void *) (net + 1) > data_end) {
		return -1;
	}

	/* invalid network type */
	if (net->type >= IPX_DIAG_LOCAL_NET_MAX) {
		return -1;
	}

	*net_out = net;
	cur->pos = net + 1;

	return net->type;
}

static int parse_diag_component(struct diag_rsp_cursor *cur, void *data_end,
		struct ipx_diag_component_extended **comp_out)
{
	struct ipx_diag_component_simple *comp = cur->pos;
	if ((void *) (comp + 1) > data_end) {
		return -1;
	}

	/* invalid component ID */
	if (comp->component_id >= IPX_DIAG_COMPONENT_MAX) {
		return -1;
	}

	*comp_out = (struct ipx_diag_component_extended *) comp;

	/* simple component */
	if (diag_component_is_simple(comp->component_id)) {
		cur->pos = comp + 1;
		return comp->component_id;
	}

	/* extended component */
	struct ipx_diag_component_extended *comp_ext = cur->pos;
	if ((void *) (comp_ext + 1) > data_end) {
		return -1;
	}

	cur->pos = comp_ext + 1;
	return comp_ext->component_id;
}

static int parse_diag_rsp(struct diag_rsp_cursor *cur, void *data_end, struct
		ipx_diag_rsp **rsp_out)
{
	struct ipx_diag_rsp *rsp = cur->pos;
	if ((void *) (rsp + 1) > data_end) {
		return -1;
	}

	cur->pos = rsp + 1;
	*rsp_out = rsp;

	return rsp->n_components;
}

static void print_diag_msg(struct ipxw_mux_msg *msg, bool verbose)
{
	void *data = msg->data;
	void *data_end = msg->data + msg->recv.data_len;

	struct diag_rsp_cursor cur = { .pos = data };

	printf("response from ");
	print_ipxaddr(stdout, &(msg->recv.saddr));

	if (verbose) {
		printf(" (packet type: %02hhx)", msg->recv.pkt_type);
	}

	printf(":\n");

	struct ipx_diag_rsp *rsp = NULL;
	if (parse_diag_rsp(&cur, data_end, &rsp) < 0) {
		printf("\tmalformed response!\n");
		return;
	}

	printf("\tmajor version: %hhu\n", rsp->major_version);
	printf("\tminor version: %hhu\n", rsp->minor_version);
	printf("\tSPX diagnostics socket: %04hx\n", ntohs(rsp->spx_diag_sock));
	printf("\t# of components: %hhu\n", rsp->n_components);
	printf("\tcomponents:\n");

	int i;
	for (i = 0; i < rsp->n_components; i++) {
		struct ipx_diag_component_extended *comp = NULL;
		int component_id = parse_diag_component(&cur, data_end, &comp);
		if (component_id < 0) {
			printf("\t\tcomponent %d malformed!\n", i);
			return;
		}

		printf("\t\tcomponent %d - %s (%d)\n", i,
				ipx_diag_component_name[component_id],
				component_id);
		if (diag_component_is_simple(component_id)) {
			continue;
		}

		/* have an extended component */
		printf("\t\t# of local networks: %hhu\n", comp->n_local_nets);
		printf("\t\tlocal networks:\n");

		int j;
		for (j = 0; j < comp->n_local_nets; j++) {
			struct ipx_diag_local_net *net = NULL;
			int net_type = parse_diag_local_net(&cur, data_end,
					&net);
			if (net_type < 0) {
				printf("\t\t\tlocal network %d malformed!\n", j);
				return;
			}

			printf("\t\t\tlocal network %d - %s (%d):\n", j,
					ipx_diag_local_net_type_name[net_type],
					net_type);
			printf("\t\t\t\t");
			print_ipx_if_addr(stdout, (const struct ipx_if_addr *)
					&(net->net));
			printf("\n");
		}
	}
}

static bool print_in_msg(int epoll_fd, struct ipxdiag_cfg *cfg)
{
	/* no msgs to print */
	if (STAILQ_EMPTY(&in_queue)) {
		if (!stdout_is_file) {
			/* unregister from ready-to-write events to avoid busy
			 * polling */
			struct epoll_event ev = {
				.events = EPOLLERR | EPOLLHUP,
				.data.fd = fileno(stdout)
			};
			epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fileno(stdout),
					&ev);
		}

		return false;
	}

	struct ipxw_mux_msg *msg = STAILQ_FIRST(&in_queue);
	STAILQ_REMOVE_HEAD(&in_queue, q_entry);

	print_diag_msg(msg, cfg->verbose);

	free(msg);

	return true;
}

static _Noreturn void cleanup_and_exit(int epoll_fd, int tmr_fd, struct
		ipxdiag_cfg *cfg, enum ipxdiag_error_codes code)
{
	/* output all queued received message */
	while (print_in_msg(epoll_fd, cfg));

	if (tmr_fd >= 0) {
		close(tmr_fd);
	}

	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	ipxw_mux_unbind(ipxh);

	exit(code);
}

static void ipx_recv(int epoll_fd, int tmr_fd, struct ipxdiag_cfg *cfg)
{
	/* IPX message received */
	ssize_t expected_msg_len = ipxw_mux_peek_recvd_len(ipxh, false);
	if (expected_msg_len < 0) {
		if (errno == EINTR) {
			return;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}

		perror("IPX receive peek");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg,
				IPXDIAG_ERR_IPX_FAILURE);
	}

	struct ipxw_mux_msg *msg = calloc(1, expected_msg_len + 1);
	if (msg == NULL) {
		perror("allocating message");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXDIAG_ERR_MSG_ALLOC);
	}

	msg->type = IPXW_MUX_RECV;
	msg->recv.data_len = expected_msg_len - sizeof(struct ipxw_mux_msg);
	ssize_t rcvd_len = ipxw_mux_get_recvd(ipxh, msg, false);
	if (rcvd_len < 0) {
		free(msg);
		if (errno == EINTR) {
			return;
		}

		perror("IPX receive");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg,
				IPXDIAG_ERR_IPX_FAILURE);
	}

	size_t data_len = msg->recv.data_len;
	if (data_len == 0) {
		free(msg);
		return;
	}
	msg->data[data_len] = '\0';

	/* queue received message */
	if (!queue_in_msg(epoll_fd, msg)) {
		free(msg);
		perror("queueing message");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXDIAG_ERR_MSG_QUEUE);
	}
}

static struct ipxw_mux_msg *mk_diag_req(struct ipxdiag_cfg *cfg)
{
	size_t diag_req_data_len = sizeof(struct ipx_diag_req) +
		(cfg->n_exclude_addrs * IPX_ADDR_NODE_BYTES);
	struct ipxw_mux_msg *diag_req_msg = calloc(1, sizeof(struct
				ipxw_mux_msg) + diag_req_data_len);
	if (diag_req_msg == NULL) {
		return NULL;
	}

	diag_req_msg->type = IPXW_MUX_XMIT;
	diag_req_msg->xmit.daddr = cfg->target_addr;
	diag_req_msg->xmit.pkt_type = cfg->pkt_type;
	diag_req_msg->xmit.data_len = diag_req_data_len;

	struct ipx_diag_req *diag_req_data = (struct ipx_diag_req *)
		diag_req_msg->data;
	diag_req_data->n_exclude_addrs = cfg->n_exclude_addrs;
	size_t i;
	for (i = 0; i < cfg->n_exclude_addrs; i++) {
		memcpy(diag_req_data->exclude_addrs[i], cfg->exclude_addrs[i],
				IPX_ADDR_NODE_BYTES);
	}

	return diag_req_msg;
}

static _Noreturn void do_ipxdiag(struct ipxdiag_cfg *cfg, int epoll_fd, int
		tmr_fd)
{
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->local_addr;
	bind_msg.bind.pkt_type = cfg->pkt_type;
	bind_msg.bind.pkt_type_any = true;
	bind_msg.bind.recv_bcast = false;

	ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXDIAG_ERR_BIND);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->local_addr))) {
			perror("IPX get bound address");
			cleanup_and_exit(epoll_fd, tmr_fd, cfg,
					IPXDIAG_ERR_GETSOCKNAME);
		}

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
		cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXDIAG_ERR_CONF_FD);
	}

	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = ipxw_mux_handle_data(ipxh);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_data(ipxh), &ev)
			< 0) {
		perror("registering IPX socket for event polling");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXDIAG_ERR_IPX_FD);
	}

	/* get ready to send output to STDOUT */
	ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
	ev.data.fd = fileno(stdout);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fileno(stdout),
				&ev) < 0) {
		/* EPERM most likely means that stdout is a regular file, in
		 * that case we cannot poll and just try to read it in every
		 * loop interation */
		if (errno == EPERM) {
			stdout_is_file = true;
		} else {
			perror("registering stdout for event polling");
			cleanup_and_exit(epoll_fd, tmr_fd, cfg,
					IPXDIAG_ERR_STDOUT_FD);
		}
	}

	/* build the diagnostics request */
	struct ipxw_mux_msg *diag_req = mk_diag_req(cfg);
	if (diag_req == NULL) {
		perror("creating diagnostics request");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg,
				IPXDIAG_ERR_DIAG_REQ_CREATE);
	}

	/* send the actual diagnostics request */
	if (ipxw_mux_xmit(ipxh, diag_req, true) < 0) {
		free(diag_req);
		perror("sending diagnostics request");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg,
				IPXDIAG_ERR_DIAG_REQ_SEND);
	}
	free(diag_req);

	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		/* stdout */
		if (stdout_is_file) {
			print_in_msg(epoll_fd, cfg);
		}

		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS,
				TICKS_MS);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(epoll_fd, tmr_fd, cfg,
					IPXDIAG_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(epoll_fd, tmr_fd, cfg,
							IPXDIAG_ERR_TMR_FAILURE);
				}

				/* we are done waiting for replies, exit */
				keep_going = false;

				/* consume all expirations */
				__u64 dummy;
				read(tmr_fd, &dummy, sizeof(dummy));

				continue;
			}

			/* stdout */
			if (evs[i].data.fd == fileno(stdout)) {
				print_in_msg(epoll_fd, cfg);
				continue;
			}

			/* config socket */
			if (evs[i].data.fd == ipxw_mux_handle_conf(ipxh)) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "config socket error\n");
					cleanup_and_exit(epoll_fd, tmr_fd, cfg,
							IPXDIAG_ERR_CONF_FAILURE);
				}

				continue;
			}

			/* IPX socket */

			/* something went wrong */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "IPX socket error\n");
				cleanup_and_exit(epoll_fd, tmr_fd, cfg,
						IPXDIAG_ERR_IPX_FAILURE);
			}

			/* nothing to read from IPX socket */
			if ((evs[i].events & EPOLLIN) == 0) {
				continue;
			}

			/* receive IPX messages until there are no more or the
			 * queue is full */
			ipx_recv(epoll_fd, tmr_fd, cfg);

			continue;
		}
	}

	cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXDIAG_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: ipxdiag [-v] [-t <packet type>] [-w <wait seconds>] [-e <excluded target node> ...] <local IPX addr> <target IPX address>\n");
	exit(IPXDIAG_ERR_USAGE);
}

static bool verify_cfg(struct ipxdiag_cfg *cfg)
{
	/* excluding addresses is only sensible when transmitting to a
	 * broadcast address */
	if (memcmp(cfg->target_addr.node, IPX_BCAST_NODE, IPX_ADDR_NODE_BYTES)
			!= 0) {
		if (cfg->n_exclude_addrs != 0) {
			return false;
		}
	}

	return true;
}

int main(int argc, char **argv)
{
	struct ipxdiag_cfg cfg = {
		.verbose = false,
		.wait_secs = DEFAULT_WAIT_SECS,
		.pkt_type = DEFAULT_PKT_TYPE,
		.n_exclude_addrs = 0
	};

	/* parse and verify command-line arguments */

	int opt;
	while ((opt = getopt(argc, argv, "e:t:vw:")) != -1) {
		switch (opt) {
			case 'e':
				if (cfg.n_exclude_addrs >= MAX_EXCLUDE_ADDRS) {
					fprintf(stderr, "too many exclude addresses\n");
					exit(IPXDIAG_ERR_USAGE);
				}

				if (!parse_ipx_node_addr(optarg,
							cfg.exclude_addrs[cfg.n_exclude_addrs]))
				{
					usage();
				}

				cfg.n_exclude_addrs++;
				break;
			case 't':
				cfg.pkt_type = strtoul(optarg, NULL, 0);
				break;
			case 'v':
				cfg.verbose = true;
				break;
			case 'w':
				cfg.wait_secs = strtoul(optarg, NULL, 0);
				break;
			default:
				usage();
		}
	}

	if (optind + 2 != argc) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind], &(cfg.local_addr))) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind + 1], &(cfg.target_addr))) {
		usage();
	}

	if (!verify_cfg(&cfg)) {
		usage();
	}

	/* initial setup */

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, -1, &cfg, IPXDIAG_ERR_EPOLL_FD);
	}

	int tmr_fd = setup_timer(epoll_fd, cfg.wait_secs);
	if (tmr_fd < 0) {
		perror("creating maintenance timer");
		cleanup_and_exit(epoll_fd, tmr_fd, &cfg, IPXDIAG_ERR_TMR_FD);
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting up signal handler");
		cleanup_and_exit(epoll_fd, tmr_fd, &cfg,
				IPXDIAG_ERR_SIG_HANDLER);
	}

	do_ipxdiag(&cfg, epoll_fd, tmr_fd);
}
