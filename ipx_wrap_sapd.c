#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "uthash.h"
#include "ipx_wrap_mux_proto.h"

#define MAINTENANCE_INTERVAL_SECS 10
#define INTERFACE_RESCAN_SECS 30
#define MAX_EPOLL_EVENTS 64

#define SAP_SOCK 0x0452
#define SAP_PKT_TYPE 0x04
#define SAP_EXPIRY_SECS (60*5)
#define SAP_MAX_SRVS_PER_PKT 7 /* max observed */
#define SAP_BCAST_INTERVAL_SECS 60

#define SAP_SRV_TYPE_WILD htons(0xFFFF)

#define SAP_PKT_TYPE_GENERAL_SQ htons(1)
#define SAP_PKT_TYPE_NEAREST_SQ htons(3)
#define SAP_RSP_TYPE_PERIODIC_BC htons(2)
#define SAP_RSP_TYPE_GENERAL_SQ htons(2)
#define SAP_RSP_TYPE_NEAREST_SQ htons(4)

STAILQ_HEAD(ipxw_msg_queue, ipxw_mux_msg);

struct srv_data {
	__be16 srv_type;
	__u8 srv_name[48];
	struct ipx_addr srv_addr;
	__be16 intermediate_nets;
} __attribute__((packed));

// TODO: servers must unique by name and type
struct srv_entry {
	struct srv_data data;
	/* hash entry */
	UT_hash_handle hh; /* by IPX addr */
	/* list entry */
	LIST_ENTRY(srv_entry) type_list_entry; /* list per server type */
	/* last time the server transmitted an advertisement */
	time_t last_seen;
	__be32 learned_from_net;
};

struct srv_id_pkt {
	__be16 rsp_type;
	struct srv_data data[0];
} __attribute__((packed));

struct srv_query {
	__be16 pkt_type;
	__be16 srv_type;
} __attribute__((packed));

LIST_HEAD(srv_entries, srv_entry);

struct srv_type_list {
	/* server type */
	__be16 srv_type;
	/* hash entry */
	UT_hash_handle hh; /* by server type */
	/* list of servers of that type */
	struct srv_entries entries;
};

struct if_entry {
	/* the handle for the binding */
	struct ipxw_mux_handle mux_handle;
	/* ipx address we are bound to */
	struct ipx_addr addr;
	/* hash entry */
	UT_hash_handle h_data_sock; /* by data socket */
	UT_hash_handle h_ipx_addr; /* by IPX addr */
	/* msgs to send */
	struct ipxw_msg_queue out_queue;
	/* whether to keep the interface after the if-scan */
	bool keep;
};

static struct srv_entry *ht_ipx_addr_to_srv = NULL;
static struct srv_type_list *ht_srv_type_to_srv_list = NULL;

static struct if_entry *ht_sock_to_if = NULL;
static struct if_entry *ht_ipx_addr_to_if = NULL;

static bool queue_msg_on_iface(struct if_entry *iface, struct ipxw_mux_msg
		*msg, int epoll_fd)
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

static bool prepare_sap_bcast_for_iface(struct if_entry *iface, int epoll_fd)
{
	struct ipxw_mux_msg *bcast = calloc(1, sizeof(struct ipxw_mux_msg) +
			sizeof(struct srv_id_pkt));
	struct srv_id_pkt *sap = (struct srv_id_pkt *) bcast->data;

	bcast->type = IPXW_MUX_XMIT;
	bcast->xmit.daddr.net = iface->addr.net;
	memcpy(bcast->xmit.daddr.node, IPX_BCAST_NODE, IPX_ADDR_NODE_BYTES);
	bcast->xmit.daddr.sock = htons(SAP_SOCK);
	bcast->xmit.pkt_type = SAP_PKT_TYPE;
	bcast->xmit.data_len = sizeof(struct srv_id_pkt);

	sap->rsp_type = SAP_RSP_TYPE_PERIODIC_BC;

	if (!queue_msg_on_iface(iface, bcast, epoll_fd)) {
		free(bcast);
		return false;
	}

	return true;
}

static void prepare_sap_bcasts(int epoll_fd)
{
	printf("preparing SAP broadcast\n");

	/* prepare broadcast for all interfaces */
	struct if_entry *e;
	struct if_entry *tmp;
	HASH_ITER(h_data_sock, ht_sock_to_if, e, tmp) {
		if (!prepare_sap_bcast_for_iface(e, epoll_fd)) {
			perror("sending SAP bcast");
		}
	}
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

static void cleanup_srv_type_list(struct srv_type_list *l)
{
	while (!LIST_EMPTY(&l->entries)) {
		struct srv_entry *e = LIST_FIRST(&l->entries);
		HASH_DEL(ht_ipx_addr_to_srv, e);
		LIST_REMOVE(e, type_list_entry);
		free(e);
	}

	HASH_DEL(ht_srv_type_to_srv_list, l);
	free(l);
}

static _Noreturn void cleanup_and_exit(int tmr_fd, int epoll_fd, int exit_code)
{
	/* remove all interfaces */
	struct if_entry *e;
	struct if_entry *tmp;
	HASH_ITER(h_data_sock, ht_sock_to_if, e, tmp) {
		cleanup_iface(e);
	}

	/* clean up the database */
	struct srv_type_list *le;
	struct srv_type_list *ltmp;
	HASH_ITER(hh, ht_srv_type_to_srv_list, le, ltmp) {
		cleanup_srv_type_list(le);
	}

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

static struct if_entry *add_iface(struct ipv6_eui64_addr *ipv6_addr, int
		epoll_fd)
{
	struct if_entry *iface = calloc(1, sizeof(struct if_entry));
	if (iface == NULL) {
		return NULL;
	}

	iface->addr.net = ipv6_addr->ipx_net;
	memcpy(iface->addr.node, ipv6_addr->ipx_node_fst,
			sizeof(ipv6_addr->ipx_node_fst));
	memcpy(iface->addr.node + sizeof(ipv6_addr->ipx_node_fst),
			ipv6_addr->ipx_node_snd,
			sizeof(ipv6_addr->ipx_node_snd));
	iface->addr.sock = htons(SAP_SOCK);

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
	bind_msg.bind.pkt_type = SAP_PKT_TYPE;
	bind_msg.bind.pkt_type_any = false;
	bind_msg.bind.recv_bcast = true;

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

	ipxw_mux_handle_close(iface->mux_handle);
	free(iface);

	return NULL;
}


/* FIXME: we cannot handle an address migrating from one interface to another,
 * but this should not happen with IPX anyway */
static bool scan_interfaces(__be32 prefix, int epoll_fd)
{
	/* iterate over all addresses to find the interface to our IPv6 addr */
	struct ifaddrs *addrs;
	struct ifaddrs *iter;

	if (getifaddrs(&addrs) < 0) {
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
		if (ipv6_addr->prefix != prefix) {
			continue;
		}

		/* get or create a new interface for this address */
		struct if_entry *iface = add_iface(ipv6_addr, epoll_fd);
		/* an error occurred during interface creation, abort */
		if (iface == NULL) {
			freeifaddrs(addrs);
			return false;
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

static int check_timeout_expired(time_t timeout_secs, time_t last, time_t
		*new_now)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
		return -1;
	}

	time_t now_secs = now.tv_sec;

	time_t diff;
	__builtin_sub_overflow(now_secs, last, &diff);
	if (diff > timeout_secs) {
		*new_now = now_secs;
		return 1;
	}

	return 0;
}

static _Noreturn void usage() {
	printf("Usage: ipx_wrap_sapd <32-bit hex prefix>\n");
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		usage();
	}

	__be32 prefix = htonl(strtoul(argv[1], NULL, 0));
	if (prefix == 0) {
		usage();
	}

	int epoll_fd = -1;
	int tmr_fd = -1;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(tmr_fd, epoll_fd, 2);
	}

	tmr_fd = setup_timer(epoll_fd, MAINTENANCE_INTERVAL_SECS);
	if (tmr_fd < 0) {
		perror("creating interface rescan timer");
		cleanup_and_exit(tmr_fd, epoll_fd, 3);
	}

	/* scan all interfaces for addresses within the prefix, we manage those
	 * interfaces */
	if (!scan_interfaces(prefix, epoll_fd)) {
		perror("adding interfaces");
		cleanup_and_exit(tmr_fd, epoll_fd, 4);
	}

	time_t last_interface_scan = 0;
	time_t last_service_bcast = 0;
	time_t current_secs = 0;
	ssize_t err;
	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (1) {
		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == -EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(tmr_fd, epoll_fd, 5);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(tmr_fd, epoll_fd, 6);
				}

				/* check if inferfaces need to be rescanned */
				err = check_timeout_expired(
						INTERFACE_RESCAN_SECS,
						last_interface_scan,
						&current_secs);
				if (err < 0) {
					perror("interface rescan timer");
					cleanup_and_exit(tmr_fd, epoll_fd, 7);
				} else if (err > 0) {
					/* rescan the interfaces */
					if (!scan_interfaces(prefix, epoll_fd))
					{
						perror("scanning interfaces");
						cleanup_and_exit(tmr_fd,
								epoll_fd, 8);
					}
					last_interface_scan = current_secs;
				}

				err = check_timeout_expired(
						SAP_BCAST_INTERVAL_SECS,
						last_service_bcast,
						&current_secs);
				if (err < 0) {
					perror("SAP expiry timer");
					cleanup_and_exit(tmr_fd, epoll_fd, 9);
				} else if (err > 0) {
					/* send the SAP broadcast on all
					 * interfaces */
					prepare_sap_bcasts(epoll_fd);
					last_service_bcast = current_secs;
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

			/* can xmit */
			if (evs[i].events & EPOLLIN) {
				// TODO
			}

			/* send queued pkts */
			if (evs[i].events & EPOLLOUT) {
				err = send_queued_msgs(iface, epoll_fd);
				if (err < 0) {
					/* get rid of the client */
					perror("recving data");
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

	cleanup_and_exit(tmr_fd, epoll_fd, 0);

	return 0;
}
