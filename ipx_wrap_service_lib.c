#include "ipx_wrap_service_lib.h"

static struct if_entry *ht_sock_to_if = NULL;
static struct if_entry *ht_ipx_addr_to_if = NULL;

static bool reload_now = false;
static bool keep_going = true;

bool get_now_secs(time_t *now_secs)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
		return false;
	}

	*now_secs = now.tv_sec;
	return true;
}

bool queue_msg_on_iface(struct if_entry *iface, struct ipxw_mux_msg *msg, int
		epoll_fd)
{
	int data_sock = ipxw_mux_handle_data(iface->mux_handle);

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
		.data.fd = data_sock
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, data_sock, &ev) < 0) {
		return false;
	}

	/* queue the message on the interface */
	STAILQ_INSERT_TAIL(&iface->out_queue, msg, q_entry);

	return true;
}

static struct ipxw_mux_msg *recv_msg(struct if_entry *iface)
{
	ssize_t expected = ipxw_mux_peek_recvd_len(iface->mux_handle, false);
	if (expected < 0) {
		return NULL;
	}

	struct ipxw_mux_msg *msg = calloc(1, expected);
	if (msg == NULL) {
		return NULL;
	}

	msg->type = IPXW_MUX_RECV;
	msg->recv.data_len = expected - sizeof(*msg);
	ssize_t msg_len = ipxw_mux_get_recvd(iface->mux_handle, msg, false);
	if (msg_len < 0) {
		free(msg);
		return NULL;
	}

	return msg;
}

static ssize_t send_queued_msgs(struct if_entry *iface, int epoll_fd)
{
	int data_sock = ipxw_mux_handle_data(iface->mux_handle);

	/* no msgs to send */
	if (STAILQ_EMPTY(&iface->out_queue)) {
		/* unregister from ready-to-write events to avoid busy polling
		 */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP,
			.data.fd = data_sock
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, data_sock, &ev);

		return 0;
	}

	struct ipxw_mux_msg *xmit_msg = STAILQ_FIRST(&iface->out_queue);
	ssize_t err = ipxw_mux_xmit(iface->mux_handle, xmit_msg, false);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return 0;
		}

		/* other error, make sure to get rid of the message */
	}

	STAILQ_REMOVE_HEAD(&iface->out_queue, q_entry);
	free(xmit_msg);

	return err;
}

static void cleanup_iface(struct if_entry *iface)
{
	/* unbind from the muxer */
	ipxw_mux_unbind(iface->mux_handle);

	/* remove all undelivered messages */
	while (!STAILQ_EMPTY(&iface->out_queue)) {
		struct ipxw_mux_msg *msg = STAILQ_FIRST(&iface->out_queue);
		STAILQ_REMOVE_HEAD(&iface->out_queue, q_entry);
		free(msg);
	}

	/* remove the interface from all hash tables */
	HASH_DELETE(h_data_sock, ht_sock_to_if, iface);
	HASH_DELETE(h_ipx_addr, ht_ipx_addr_to_if, iface);

	free(iface);
}

_Noreturn void cleanup_and_exit(int tmr_fd, int epoll_fd, void *service_ctx,
		int exit_code)
{
	/* remove all interfaces */
	struct if_entry *e;
	struct if_entry *tmp;
	HASH_ITER(h_data_sock, ht_sock_to_if, e, tmp) {
		cleanup_iface(e);
	}

	service_cleanup_and_exit(service_ctx);

	/* close the timer fd */
	if (tmr_fd >= 0) {
		close(tmr_fd);
	}

	/* close down epoll fd */
	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	exit(exit_code);
}

static struct if_entry *add_iface(struct ipv6_eui64_addr *ipv6_addr, const
		struct if_bind_config *ifcfg, int epoll_fd)
{
	struct if_entry *iface = calloc(1, sizeof(struct if_entry));
	if (iface == NULL) {
		fprintf(stderr, "failed to allocate interface\n");
		return NULL;
	}

	iface->addr.net = ipv6_addr->ipx_net;
	memcpy(iface->addr.node, ipv6_addr->ipx_node_fst,
			sizeof(ipv6_addr->ipx_node_fst));
	memcpy(iface->addr.node + sizeof(ipv6_addr->ipx_node_fst),
			ipv6_addr->ipx_node_snd,
			sizeof(ipv6_addr->ipx_node_snd));
	iface->addr.sock = htons(ifcfg->sock);

	STAILQ_INIT(&iface->out_queue);

	struct if_entry *iface_found = NULL;
	HASH_FIND(h_ipx_addr, ht_ipx_addr_to_if, &iface->addr,
			sizeof(iface->addr), iface_found);
	if (iface_found != NULL) {
		/* interface already exists */
		free(iface);
		return iface_found;
	}

	struct ipxw_mux_msg bind_msg;
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = iface->addr;
	bind_msg.bind.pkt_type = ifcfg->pkt_type;
	bind_msg.bind.pkt_type_any = ifcfg->pkt_type_any;
	bind_msg.bind.recv_bcast = ifcfg->recv_bcast;

	do {
		iface->mux_handle = ipxw_mux_bind(&bind_msg);
		if (ipxw_mux_handle_is_error(iface->mux_handle)) {
			break;
		}

		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
			.data = {
				.fd = ipxw_mux_handle_data(iface->mux_handle)
			}
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD,
					ipxw_mux_handle_data(iface->mux_handle),
					&ev) < 0)
		{
			break;
		}

		/* add new interface entry */
		HASH_ADD(h_ipx_addr, ht_ipx_addr_to_if, addr,
				sizeof(iface->addr), iface);
		HASH_ADD_KEYPTR(h_data_sock, ht_sock_to_if,
				&iface->mux_handle.data_sock,
				sizeof(iface->mux_handle.data_sock), iface);

		printf("adding interface "
				"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx\n",
				ntohl(iface->addr.net), iface->addr.node[0],
				iface->addr.node[1], iface->addr.node[2],
				iface->addr.node[3], iface->addr.node[4],
				iface->addr.node[5], ntohs(iface->addr.sock));

		return iface;
	} while (0);

	fprintf(stderr, "failed to add interface "
			"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx\n",
			ntohl(iface->addr.net), iface->addr.node[0],
			iface->addr.node[1], iface->addr.node[2],
			iface->addr.node[3], iface->addr.node[4],
			iface->addr.node[5], ntohs(iface->addr.sock));

	ipxw_mux_handle_close(iface->mux_handle);
	free(iface);

	return NULL;
}


/* FIXME: we cannot handle an address migrating from one interface to another,
 * but this should not happen with IPX anyway */
static bool scan_interfaces(const struct if_bind_config *ifcfg, int epoll_fd)
{
	/* iterate over all addresses to find the interface to our IPv6 addr */
	struct ifaddrs *addrs;
	struct ifaddrs *iter;

	int err = -1;
	do {
		err = getifaddrs(&addrs);
	} while (err < 0 && errno == EINTR);
	if (err < 0) {
		return false;
	}

	/* if the loop exits normally, we were unable to find the IPv6 addr */
	for (iter = addrs; iter != NULL; iter = iter->ifa_next) {
		if (iter->ifa_addr == NULL) {
			continue;
		}
		if (iter->ifa_addr->sa_family != AF_INET6) {
			continue;
		}

		struct sockaddr_in6 *iter_sa = (struct sockaddr_in6 *)
			iter->ifa_addr;
		struct ipv6_eui64_addr *ipv6_addr = (struct ipv6_eui64_addr *)
			&iter_sa->sin6_addr;
		if (ipv6_addr->prefix != ifcfg->prefix) {
			continue;
		}

		/* get or create a new interface for this address */
		struct if_entry *iface = add_iface(ipv6_addr, ifcfg, epoll_fd);
		/* an error occurred during interface creation, try next
		 * interface */
		if (iface == NULL) {
			continue;
		}

		/* mark the returned interface, so that we keep it */
		iface->keep = true;
	}

	freeifaddrs(addrs);

	struct if_entry *e;
	struct if_entry *tmp;
	HASH_ITER(h_ipx_addr, ht_ipx_addr_to_if, e, tmp) {
		if (!e->keep) {
			cleanup_iface(e);
		} else {
			e->keep = false;
		}
	}

	return true;
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
		.it_interval = { .tv_sec = secs },
		.it_value = { .tv_sec = secs }
	};
	if (timerfd_settime(tmr, 0, &tmr_spec, NULL) < 0) {
		close(tmr);
		return -1;
	}

	return tmr;
}

bool is_timeout_expired(time_t now_secs, time_t timeout_secs, time_t last)
{
	time_t diff;
	__builtin_sub_overflow(now_secs, last, &diff);
	if (diff > timeout_secs) {
		return true;
	}

	return false;
}

static void signal_handler(int signal)
{
	switch (signal) {
		case SIGHUP:
			reload_now = true;
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

bool for_each_iface(bool (*per_iface_cb)(struct if_entry *iface, void *ctx),
		void *ctx)
{
	/* do for all interfaces */
	struct if_entry *e;
	struct if_entry *tmp;
	HASH_ITER(h_data_sock, ht_sock_to_if, e, tmp) {
		if (!per_iface_cb(e, ctx)) {
			return false;
		}
	}

	return true;
}

_Noreturn void run_service(void *service_ctx, const struct if_bind_config
		*ifcfg, int maintenance_interval_secs)
{
	int epoll_fd = -1;
	int tmr_fd = -1;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(tmr_fd, epoll_fd, service_ctx,
				SRVC_ERR_EPOLL_FD);
	}

	tmr_fd = setup_timer(epoll_fd, maintenance_interval_secs);
	if (tmr_fd < 0) {
		perror("creating maintenance timer");
		cleanup_and_exit(tmr_fd, epoll_fd, service_ctx,
				SRVC_ERR_TMR_FD);
	}

	/* scan all interfaces for addresses within the prefix, we manage those
	 * interfaces */
	if (!scan_interfaces(ifcfg, epoll_fd)) {
		perror("adding interfaces");
		cleanup_and_exit(tmr_fd, epoll_fd, service_ctx,
				SRVC_ERR_IFACE_SCAN);
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGHUP, &sig_act, NULL) < 0
			|| sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting signal handler");
		cleanup_and_exit(tmr_fd, epoll_fd, service_ctx,
				SRVC_ERR_SIG_HANDLER);
	}

	time_t last_interface_scan = 0;
	time_t now_secs = 0;
	ssize_t err;
	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		/* received SIGHUP, do interface rescan and reload service */
		if (reload_now) {
			if (!scan_interfaces(ifcfg, epoll_fd)) {
				perror("scanning interfaces");
				cleanup_and_exit(tmr_fd, epoll_fd, service_ctx,
						SRVC_ERR_IFACE_SCAN);
			}

			if (!service_reload(service_ctx)) {
				fprintf(stderr, "failed to reload service\n");
				cleanup_and_exit(tmr_fd, epoll_fd, service_ctx,
						SRVC_ERR_RELOAD);
			}

			reload_now = false;
		}

		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(tmr_fd, epoll_fd, service_ctx,
					SRVC_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(tmr_fd, epoll_fd,
							service_ctx,
							SRVC_ERR_TMR_FAILURE);
				}

				if (!get_now_secs(&now_secs)) {
					perror("getting current time");
					cleanup_and_exit(tmr_fd, epoll_fd,
							service_ctx,
							SRVC_ERR_GET_TIME);
				}

				/* check if inferfaces need to be rescanned */
				if (is_timeout_expired(now_secs,
							INTERFACE_RESCAN_SECS,
							last_interface_scan)) {
					/* rescan the interfaces */
					if (!scan_interfaces(ifcfg, epoll_fd))
					{
						perror("scanning interfaces");
						cleanup_and_exit(tmr_fd,
								epoll_fd,
								service_ctx,
								SRVC_ERR_IFACE_SCAN);
					}
					last_interface_scan = now_secs;
				}

				/* call the service maintenance routine */
				if (!service_maintenance(service_ctx, now_secs,
							epoll_fd)) {
					fprintf(stderr, "service maintenance "
							"failed\n");
				}

				/* consume all expirations */
				__u64 dummy;
				read(tmr_fd, &dummy, sizeof(dummy));

				continue;
			}

			/* one of the interface sockets */

			struct if_entry *iface;
			int data_sock = evs[i].data.fd;
			HASH_FIND(h_data_sock, ht_sock_to_if, &data_sock,
					sizeof(data_sock), iface);
			/* interface already deleted */
			if (iface == NULL) {
				continue;
			}

			/* can receive */
			if (evs[i].events & EPOLLIN) {
				struct ipxw_mux_msg *msg = recv_msg(iface);
				if (msg == NULL) {
					perror("receiving msg");
				} else {
					if (!service_handle_msg(msg, iface,
								service_ctx)) {
						fprintf(stderr, "failed to "
								"handle "
								"message\n");
					}
					free(msg);
				}
			}

			/* send queued pkts */
			if (evs[i].events & EPOLLOUT) {
				err = send_queued_msgs(iface, epoll_fd);
				if (err < 0) {
					/* get rid of the interface */
					perror("sending msg");
					cleanup_iface(iface);
					continue;
				} else if (err == 0) {
					/* nothing happened */
				}
			}

			/* something went wrong, remove interface */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "interface lost\n");
				cleanup_iface(iface);
				continue;
			}
		}
	}

	cleanup_and_exit(tmr_fd, epoll_fd, service_ctx, SRVC_ERR_OK);
}
