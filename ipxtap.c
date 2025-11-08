#include <assert.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

#define DEFAULT_PKT_TYPE 0x1E

enum ipxtap_error_codes {
	IPXTAP_ERR_OK = 0,
	IPXTAP_ERR_USAGE,
	IPXTAP_ERR_EPOLL_FD,
	IPXTAP_ERR_CONF_FD,
	IPXTAP_ERR_IPX_FD,
	IPXTAP_ERR_TAP_FD,
	IPXTAP_ERR_TAP_MTU,
	IPXTAP_ERR_SIG_HANDLER,
	IPXTAP_ERR_BIND,
	IPXTAP_ERR_GETSOCKNAME,
	IPXTAP_ERR_GET_OIF_DATA_LEN,
	IPXTAP_ERR_OIF_DATA_LEN_ZERO,
	IPXTAP_ERR_EPOLL_WAIT,
	IPXTAP_ERR_CONF_FAILURE,
	IPXTAP_ERR_IPX_FAILURE,
	IPXTAP_ERR_TAP_FAILURE,
	IPXTAP_ERR_MSG_ALLOC,
	IPXTAP_ERR_MAX
};

#define MAX_EPOLL_EVENTS 64

struct ipxtap_cfg {
	bool verbose;
	bool accept_broadcasts;
	bool pkt_type_any;
	__u8 pkt_type;
	struct ipx_addr local_addr;
	struct ipx_addr remote_addr;
	char interface_name[IFNAMSIZ + 1];
};

static volatile sig_atomic_t keep_going = true;

static struct ipxw_mux_handle ipxh = ipxw_mux_handle_init;
static int if_fd = -1;

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

static _Noreturn void cleanup_and_exit(int epoll_fd, enum ipxtap_error_codes
		code)
{
	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	if (if_fd >= 0) {
		close(if_fd);
	}

	ipxw_mux_unbind(ipxh);

	exit(code);
}

static void if_to_ipx(int epoll_fd, struct ipxtap_cfg *cfg)
{
	size_t max_msg_len = sizeof(struct ipxw_mux_msg) + IPX_MAX_DATA_LEN;

	struct ipxw_mux_msg *msg = calloc(1, max_msg_len);
	if (msg == NULL) {
		perror("allocating message");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_MSG_ALLOC);
	}

	ssize_t n_read = read(if_fd, msg->data, IPX_MAX_DATA_LEN);
	if (n_read < 0) {
		free(msg);

		if (cfg->verbose) {
			perror("receiving from interface");
		}

		return;
	}

	msg->type = IPXW_MUX_XMIT;
	msg->xmit.data_len = n_read;
	msg->xmit.pkt_type = cfg->pkt_type;
	msg->xmit.daddr = cfg->remote_addr;
	ssize_t err = ipxw_mux_xmit(ipxh, msg, false);
	if (err < 0) {
		free(msg);

		if (errno == EINTR) {
			return;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}

		perror("IPX xmit");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_IPX_FAILURE);
	}

	free(msg);
}

static void ipx_to_if(int epoll_fd, struct ipxtap_cfg *cfg)
{
	/* IPX message received */
	ssize_t expected_msg_len = ipxw_mux_peek_recvd_len(ipxh,
			false);
	if (expected_msg_len < 0) {
		if (errno == EINTR) {
			return;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}

		perror("IPX receive peek");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_IPX_FAILURE);
	}

	struct ipxw_mux_msg *msg = calloc(1, expected_msg_len);
	if (msg == NULL) {
		perror("allocating message");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_MSG_ALLOC);
	}

	msg->type = IPXW_MUX_RECV;
	msg->recv.data_len = expected_msg_len - sizeof(struct
			ipxw_mux_msg);
	ssize_t rcvd_len = ipxw_mux_get_recvd(ipxh, msg, false);
	if (rcvd_len < 0) {
		free(msg);
		if (errno == EINTR) {
			return;
		}

		perror("IPX receive");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_IPX_FAILURE);
	}

	size_t data_len = msg->recv.data_len;
	if (data_len == 0) {
		free(msg);
		return;
	}

	/* write to if_fd and free msg */
	ssize_t err = write(if_fd, msg->data, data_len);
	free(msg);
	if (err < 0) {
		if (cfg->verbose) {
			perror("sending to interface");
		}
	}
}

static _Noreturn void do_ipxtap(struct ipxtap_cfg *cfg, int epoll_fd)
{
	/* bind IPX socket */
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->local_addr;
	bind_msg.bind.pkt_type = cfg->pkt_type;
	bind_msg.bind.pkt_type_any = cfg->pkt_type_any;
	bind_msg.bind.recv_bcast = cfg->accept_broadcasts;

	ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_BIND);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->local_addr))) {
			perror("IPX get bound address");
			cleanup_and_exit(epoll_fd, IPXTAP_ERR_GETSOCKNAME);
		}

		fprintf(stderr, "bound to ");
		print_ipxaddr(stderr, &(cfg->local_addr));
		fprintf(stderr, "\n");
	}

	/* calculate interface MTU */
	int max_oif_data_len = ipxw_get_outif_max_ipx_data_len_for_dst(ipxh,
			&(cfg->remote_addr));
	if (max_oif_data_len < 0) {
		perror("getting output interface max data length");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_GET_OIF_DATA_LEN);
	}
	if (max_oif_data_len < sizeof(struct ethhdr)) {
		fprintf(stderr, "output interface MTU too small\n");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_OIF_DATA_LEN_ZERO);
	}

	size_t mtu = max_oif_data_len - sizeof(struct ethhdr);

	/* make TAP devicee */
	if_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	if (if_fd == -1) {
		perror("opening TAP device");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_TAP_FD);
	}

	struct ifreq tap_req;
	memset(&tap_req, 0, sizeof(tap_req));

	tap_req.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_TUN_EXCL;
	memcpy(tap_req.ifr_name, cfg->interface_name,
			strlen(cfg->interface_name) + 1);
	if (ioctl(if_fd, TUNSETIFF, &tap_req) == -1) {
		perror("configuring TAP device");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_TAP_FD);
	}

	/* set TAP device MTU */
	int dummy_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (dummy_sock < 0) {
		perror("setting MTU for TAP device");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_TAP_MTU);
	}

	tap_req.ifr_mtu = mtu;
	if (ioctl(dummy_sock, SIOCSIFMTU, &tap_req) == -1) {
		close(dummy_sock);
		perror("setting MTU for TAP device");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_TAP_MTU);
	}
	close(dummy_sock);

	if (cfg->verbose) {
		fprintf(stderr, "set MTU for %s to %lu bytes\n",
				cfg->interface_name, mtu);
	}

	/* set up polling */
	struct epoll_event ev = {
		.events = EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ipxw_mux_handle_conf(ipxh)
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_conf(ipxh), &ev)
			< 0) {
		perror("registering config socket for event polling");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_CONF_FD);
	}

	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = ipxw_mux_handle_data(ipxh);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_data(ipxh), &ev)
			< 0) {
		perror("registering IPX socket for event polling");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_IPX_FD);
	}

	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = if_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, if_fd, &ev) < 0) {
		perror("registering TAP socket for event polling");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_TAP_FD);
	}

	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(epoll_fd, IPXTAP_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* TAP socket */
			if (evs[i].data.fd == if_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "TAP socket error\n");
					cleanup_and_exit(epoll_fd,
							IPXTAP_ERR_TAP_FAILURE);
				}

				if_to_ipx(epoll_fd, cfg);

				continue;
			}


			/* config socket */
			if (evs[i].data.fd == ipxw_mux_handle_conf(ipxh)) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "config socket error\n");
					cleanup_and_exit(epoll_fd,
							IPXTAP_ERR_CONF_FAILURE);
				}

				continue;
			}

			/* IPX socket */

			/* something went wrong */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "IPX socket error\n");
				cleanup_and_exit(epoll_fd,
						IPXTAP_ERR_IPX_FAILURE);
			}

			/* receive an IPX message and send it to the interface */
			ipx_to_if(epoll_fd, cfg);

			continue;
		}
	}

	cleanup_and_exit(epoll_fd, IPXTAP_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: ipxtap [-v] [-b] [-a] [-t <packet type>] <interface name> <local IPX address> <remote IPX address>\n");
	exit(IPXTAP_ERR_USAGE);
}

static bool verify_cfg(struct ipxtap_cfg *cfg)
{
	return true;
}

int main(int argc, char **argv)
{
	struct ipxtap_cfg cfg = {
		.verbose = false,
		.accept_broadcasts = false,
		.pkt_type_any = true,
		.pkt_type = DEFAULT_PKT_TYPE,
	};

	/* parse and verify command-line arguments */

	int opt;
	while ((opt = getopt(argc, argv, "abt:v")) != -1) {
		switch (opt) {
			case 'a':
				cfg.pkt_type_any = true;
				break;
			case 'b':
				cfg.accept_broadcasts = true;
				break;
			case 't':
				cfg.pkt_type = strtoul(optarg, NULL, 0);
				break;
			case 'v':
				cfg.verbose = true;
				break;
			default:
				usage();
		}
	}

	if (optind + 2 >= argc) {
		usage();
	}

	if (strlen(argv[optind]) > IFNAMSIZ) {
		fprintf(stderr, "Interface name too long!\n");
		exit(IPXTAP_ERR_USAGE);
	}
	strncpy(cfg.interface_name, argv[optind], IFNAMSIZ);
	cfg.interface_name[IFNAMSIZ] = '\0';

	if (!parse_ipxaddr(argv[optind + 1], &(cfg.local_addr))) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind + 2], &(cfg.remote_addr))) {
		usage();
	}

	if (!verify_cfg(&cfg)) {
		usage();
	}

	/* initial setup */

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_EPOLL_FD);
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting up signal handler");
		cleanup_and_exit(epoll_fd, IPXTAP_ERR_SIG_HANDLER);
	}

	do_ipxtap(&cfg, epoll_fd);
}
