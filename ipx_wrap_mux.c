#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/epoll.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "uthash.h"
#include "ipx_wrap_mux_proto.h"

#define MAX_EPOLL_EVENTS 64

STAILQ_HEAD(ipxw_msg_queue, ipxw_mux_msg);

struct if_entry;

struct bind_entry {
	/* if the hash table key is the socket */
	int sock;
	/* if the hash table key is the address */
	struct ipx_addr addr;
	/* if the hash table key is the IPX socket number */
	__be16 ipx_sock;
	/* hash entries */
	UT_hash_handle h_sock;
	UT_hash_handle h_addr;
	UT_hash_handle h_ipx_sock;
	/* recvd msgs for this binding's socket */
	struct ipxw_msg_queue in_queue;
	/* corresponding interface */
	struct if_entry *iface;
	/* remaining data */
	__u8 pkt_type;
	__u8 recv_bcast:1,
	     pkt_type_any:1,
	     reserved:6;
};

struct if_entry {
	/* net and node IPX addr */
	struct __attribute__((packed)) {
		__be32 net;
		__u8 node[IPX_ADDR_NODE_BYTES];
	} addr;
	/* the actual UDP socket */
	int udp_sock;
	/* hash entry */
	UT_hash_handle h_ipx_addr;
	UT_hash_handle h_udp_sock;
	/* msgs to send */
	struct ipxw_msg_queue out_queue;
	/* bindings indexed by the IPX socket */
	struct bind_entry *ht_ipx_sock_to_bind;
	/* IPv6 prefix */
	__be32 prefix;
};

static struct bind_entry *ht_sock_to_bind = NULL;
static struct bind_entry *ht_addr_to_bind = NULL;
static struct if_entry *ht_addr_to_iface = NULL;
static struct if_entry *ht_sock_to_iface = NULL;

static struct bind_entry *get_bind_entry_by_sock(int sock)
{
	struct bind_entry *bind;

	HASH_FIND(h_sock, ht_sock_to_bind, &sock, sizeof(int), bind);
	return bind;
}

static struct bind_entry *get_bind_entry_by_addr(struct ipx_addr *addr)
{
	struct bind_entry *bind;

	HASH_FIND(h_addr, ht_addr_to_bind, addr, sizeof(struct ipx_addr),
			bind);
	return bind;
}

static struct bind_entry *get_bind_entry_by_ipx_sock(struct if_entry *iface,
		__be16 ipx_sock)
{
	struct bind_entry *bind;

	HASH_FIND(h_ipx_sock, iface->ht_ipx_sock_to_bind, &ipx_sock,
			sizeof(__be16), bind);
	return bind;
}

static int record_bind(int data_sock, struct ipxw_mux_msg_bind *bind_msg, void
		*ctx)
{
	/* illegal network bindings */
	if (bind_msg->addr.net == IPX_NET_LOCAL) {
		fprintf(stderr, "binding to local net not allowed\n");
		return -1;
	}
	if (bind_msg->addr.net == IPX_NET_ALL_ROUTES) {
		fprintf(stderr, "binding to all routes net not allowed\n");
		return -1;
	}
	if (bind_msg->addr.net == IPX_NET_DEFAULT_ROUTE) {
		fprintf(stderr, "binding to default route net not allowed\n");
		return -1;
	}

	/* illegal node bindings */
	if (memcmp(bind_msg->addr.node, IPX_BCAST_NODE, IPX_ADDR_NODE_BYTES) ==
			0) {
		fprintf(stderr, "binding to broadcast node not allowed\n");
		return -1;
	}

	/* available addresses */
	struct if_entry *avail = NULL;
	HASH_FIND(h_ipx_addr, ht_addr_to_iface, &bind_msg->addr,
			sizeof(bind_msg->addr.net) +
			sizeof(bind_msg->addr.node), avail);
	if (avail == NULL) {
		fprintf(stderr, "bind address not allowed\n");
		return -1;
	}

	/* check if someone already bound to this address */
	struct bind_entry *e = get_bind_entry_by_addr(&bind_msg->addr);
	if (e != NULL) {
		fprintf(stderr, "binding already in use\n");
		return -1;
	}

	/* this should never happen because file descriptors should be unique
	 * within the process */
	e = get_bind_entry_by_sock(data_sock);
	assert(e == NULL);

	/* this should never happen because we already matched against the full
	 * address and the iface depends on net and node address */
	e = get_bind_entry_by_ipx_sock(avail, bind_msg->addr.sock);
	assert(e == NULL);

	/* make and fill new binding entry */
	e = calloc(1, sizeof(struct bind_entry));
	if (e == NULL) {
		perror("allocating binding");
		return -1;
	}

	e->sock = data_sock;
	e->addr = bind_msg->addr;
	e->ipx_sock = bind_msg->addr.sock;
	e->iface = avail;
	e->pkt_type = bind_msg->pkt_type;
	e->pkt_type_any = bind_msg->pkt_type_any;
	e->recv_bcast = bind_msg->recv_bcast;
	STAILQ_INIT(&e->in_queue);

	/* register for epoll */
	int epoll_fd = *((int *) ctx);
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = data_sock
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, data_sock, &ev) < 0) {
		perror("registering for event polling");
		free(e);
		return -1;
	}

	/* save binding */
	HASH_ADD(h_sock, ht_sock_to_bind, sock, sizeof(int), e);
	HASH_ADD(h_addr, ht_addr_to_bind, addr, sizeof(struct ipx_addr), e);
	HASH_ADD(h_ipx_sock, avail->ht_ipx_sock_to_bind, ipx_sock, sizeof(__be16), e);

	/* show the new binding in full */
	printf("bound %d to %08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx, ",
			data_sock, ntohl(bind_msg->addr.net),
			bind_msg->addr.node[0], bind_msg->addr.node[1],
			bind_msg->addr.node[2], bind_msg->addr.node[3],
			bind_msg->addr.node[4], bind_msg->addr.node[5],
			ntohs(bind_msg->addr.sock));
	if (bind_msg->pkt_type_any) {
		printf("pkt type: any, ");
	} else {
		printf("pkt type: %02hhx, ", bind_msg->pkt_type);
	}
	printf("recv bcasts: %s\n", bind_msg->recv_bcast ? "yes" : "no");

	return 0;
}

static ssize_t udp_send(int udp_sock, struct if_entry *iface)
{
	/* no msgs to send */
	if (STAILQ_EMPTY(&iface->out_queue)) {
		return 0;
	}

	struct ipxw_mux_msg *xmit_msg = STAILQ_FIRST(&iface->out_queue);

	/* have to remove the message from the queue as we are going to rewrite
	 * it */
	STAILQ_REMOVE_HEAD(&iface->out_queue, q_entry);

	/* turn xmit msg into an ipx message */
	struct ipx_addr saddr = {
		.net = iface->addr.net,
		.sock = xmit_msg->xmit.ssock
	};
	memcpy(&saddr.node, iface->addr.node, IPX_ADDR_NODE_BYTES);
	struct ipxhdr *ipx_msg = ipxw_mux_xmit_msg_to_ipxh(xmit_msg, &saddr);

	/* build IPv6 destination addr */
	struct sockaddr_in6 ipv6_dst = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(IPX_IN_IPV6_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	struct ipv6_eui64_addr *send_addr = (struct ipv6_eui64_addr *)
		&ipv6_dst.sin6_addr;
	send_addr->prefix = iface->prefix;
	send_addr->ipx_net = ipx_msg->daddr.net;
	memcpy(send_addr->ipx_node_fst, ipx_msg->daddr.node,
			sizeof(send_addr->ipx_node_fst));
	send_addr->fffe = htons(0xfffe);
	memcpy(send_addr->ipx_node_snd, ipx_msg->daddr.node +
			sizeof(send_addr->ipx_node_fst),
			sizeof(send_addr->ipx_node_snd));

	size_t pktlen = ntohs(ipx_msg->pktlen);

	/* retry if we get EINTR */
	ssize_t len;
	do {
		len = sendto(udp_sock, ipx_msg, pktlen, 0, (struct sockaddr *)
				&ipv6_dst,
				sizeof(ipv6_dst));
	} while (len < 0 && errno == EINTR);

	/* free the msg, we can't do anything about potential errors now */
	free(ipx_msg);

	/* didn't send the whole packet */
	if (len != pktlen) {
		len = -1;
		errno = EMSGSIZE;
	}

	return len;
}

static int tx_msg(int data_sock, struct ipxw_mux_msg *msg, void *ctx)
{
	struct bind_entry *be_xmit = get_bind_entry_by_sock(data_sock);
	if (be_xmit == NULL) {
		free(msg);
		return -1;
	}

	assert(msg->type == IPXW_MUX_XMIT);

	msg->xmit.ssock = be_xmit->addr.sock;

	/* queue the message on the interface */
	STAILQ_INSERT_TAIL(&be_xmit->iface->out_queue, msg, q_entry);
	return 0;
}

static ssize_t udp_recv(int udp_sock, struct if_entry *iface)
{
	ssize_t ret = -1;

	struct ipxhdr *ipx_msg = malloc(IPXW_MUX_MSG_LEN);
	if (ipx_msg == NULL) {
		return -1;
	}

	do {
		ssize_t len = recv(udp_sock, ipx_msg, IPXW_MUX_MSG_LEN, 0);
		if (len < 0) {
			break;
		}

		/* need at least the IPX header */
		if (len < sizeof(struct ipxhdr)) {
			errno = EMSGSIZE;
			break;
		}

		/* get the binding for the destination socket */
		struct bind_entry *be_recv = get_bind_entry_by_ipx_sock(iface,
				ipx_msg->daddr.sock);
		if (be_recv == NULL) {
			/* this is ok, there is just nobody listening */
			ret = 0;
			break;
		}

		/* convert to recv msg */
		struct ipxw_mux_msg *recv_msg =
			ipxw_mux_ipxh_to_recv_msg(ipx_msg);
		if (recv_msg == NULL) {
			errno = EINVAL;
			break;
		}

		/* not interested in this packet as it is a broadcast */
		if (!be_recv->recv_bcast && recv_msg->recv.is_bcast) {
			ret = 0;
			break;
		}

		/* not interested in this packet type */
		if (!be_recv->pkt_type_any && be_recv->pkt_type !=
				recv_msg->recv.pkt_type) {
			ret = 0;
			break;
		}

		/* queue the msg for the client */
		STAILQ_INSERT_TAIL(&be_recv->in_queue, recv_msg, q_entry);
		return len;
	} while (0);

	/* something went wrong, free the msg buffer */
	free(ipx_msg);
	return ret;
}

static ssize_t recv_msg(int data_sock)
{
	struct bind_entry *be = get_bind_entry_by_sock(data_sock);

	/* socket could be polled but is not registered anymore, do nothing */
	if (be == NULL) {
		return 0;
	}

	/* corrupt data structures? */
	assert(be->sock == data_sock);

	/* no msgs to receive */
	if (STAILQ_EMPTY(&be->in_queue)) {
		return 0;
	}

	struct ipxw_mux_msg *msg = STAILQ_FIRST(&be->in_queue);
	ssize_t err = ipxw_mux_recv(data_sock, msg);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (err == -EINTR || err == -EAGAIN || err == -EWOULDBLOCK)  {
			return 0;
		}

		/* other error, make sure to get rid of the message */
		perror("recving msg");
	}

	STAILQ_REMOVE_HEAD(&be->in_queue, q_entry);
	free(msg);

	return err;
}

static void unbind_entry(struct bind_entry *e, int epoll_fd)
{
	/* remove all undelivered messages */
	while (!STAILQ_EMPTY(&e->in_queue)) {
		struct ipxw_mux_msg *msg = STAILQ_FIRST(&e->in_queue);
		STAILQ_REMOVE_HEAD(&e->in_queue, q_entry);
		free(msg);
	}

	/* remove the bind entry from all data structures */
	HASH_DELETE(h_sock, ht_sock_to_bind, e);
	HASH_DELETE(h_addr, ht_addr_to_bind, e);
	HASH_DELETE(h_ipx_sock, e->iface->ht_ipx_sock_to_bind, e);

	int sock = e->sock;

	/* deregister from event polling, no error handling, as there is
	 * nothing we can do */
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock, NULL);

	/* close the socket and free */
	close(sock);
	free(e);

	printf("%d unbound\n", sock);
}

static void handle_unbind(int data_sock, void *ctx)
{
	struct bind_entry *e = get_bind_entry_by_sock(data_sock);
	if (e == NULL) {
		fprintf(stderr, "no binding found for %d\n", data_sock);
		return;
	}

	int epoll_fd = *((int *) ctx);
	unbind_entry(e, epoll_fd);
}

static _Noreturn void cleanup_and_exit(int epoll_fd, int ctrl_sock, int exit_code)
{
	/* remove all bindings */
	struct bind_entry *e;
	struct bind_entry *tmp;
	HASH_ITER(h_sock, ht_sock_to_bind, e, tmp) {
		unbind_entry(e, epoll_fd);
	}

	/* remove all interfaces */
	struct if_entry *ie;
	struct if_entry *itmp;
	HASH_ITER(h_ipx_addr, ht_addr_to_iface, ie, itmp) {
		HASH_DELETE(h_ipx_addr, ht_addr_to_iface, ie);
		HASH_DELETE(h_udp_sock, ht_sock_to_iface, ie);
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ie->udp_sock, NULL);
		free(ie);
	}

	if (ctrl_sock >= 0) {
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ctrl_sock, NULL);
		close(ctrl_sock);
	}

	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	exit(exit_code);
}

static int mk_udp_socket(char *ifname)
{
	/* determine the ifindex */
	__u32 ifidx = if_nametoindex(ifname);
	if (ifidx == 0) {
		return -1;
	}

	/* prepare the UDP socket */
	int udp_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_sock < 0) {
		return -1;
	}

	/* bind the socket to the interface */
	if (setsockopt(udp_sock, SOL_SOCKET, SO_BINDTODEVICE, ifname,
				strlen(ifname)) < 0) {
		close(udp_sock);
		return -1;
	}

	/* join the all nodes multicast group */
	struct ipv6_mreq group;
	group.ipv6mr_interface = ifidx;
	memcpy(&group.ipv6mr_multiaddr, IPV6_MCAST_ALL_NODES,
			sizeof(group.ipv6mr_multiaddr));
	if (setsockopt(udp_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group,
				sizeof(group)) < 0) {
		close(udp_sock);
		return -1;
	}

	/* bind to the port (but not the interface IP) */
	struct sockaddr_in6 source = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(IPX_IN_IPV6_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	memset(&source.sin6_addr, 0x00, sizeof(source.sin6_addr));
	if (bind(udp_sock, (struct sockaddr *) &source, sizeof(source)) < 0) {
		close(udp_sock);
		return -1;
	}

	return udp_sock;
}

static bool add_iface(struct ipv6_eui64_addr *ipv6_addr, int epoll_fd)
{
	struct if_entry *iface = calloc(1, sizeof(struct if_entry));
	if (iface == NULL) {
		return false;
	}

	/* prepare data that can be prepared without additional work */
	iface->prefix = ipv6_addr->prefix;

	iface->addr.net = ipv6_addr->ipx_net;
	memcpy(iface->addr.node, ipv6_addr->ipx_node_fst,
			sizeof(ipv6_addr->ipx_node_fst));
	memcpy(iface->addr.node + sizeof(ipv6_addr->ipx_node_fst),
			ipv6_addr->ipx_node_snd,
			sizeof(ipv6_addr->ipx_node_snd));

	STAILQ_INIT(&iface->out_queue);

	struct if_entry *iface_found = NULL;
	HASH_FIND(h_ipx_addr, ht_addr_to_iface, &iface->addr,
			sizeof(iface->addr), iface_found);
	if (iface_found != NULL) {
		/* interface for IPX addr already exists */
		free(iface);
		return true;
	}

	/* iterate over all addresses to find the interface to our IPv6 addr */
	struct ifaddrs *addrs;
	struct ifaddrs *iter;

	if (getifaddrs(&addrs) < 0) {
		free(iface);
		return false;
	}

	/* if the loop exits normally, we were unable to find the IPv6 addr */
	errno = ENOENT;
	for (iter = addrs; iter != NULL; iter = iter->ifa_next) {
		if (iter->ifa_addr == NULL) {
			continue;
		}
		if (iter->ifa_addr->sa_family != AF_INET6) {
			continue;
		}
		struct sockaddr_in6 *iter_sa = (struct sockaddr_in6 *)
			iter->ifa_addr;
		if (memcmp(ipv6_addr, &iter_sa->sin6_addr, sizeof(struct
						ipv6_eui64_addr)) != 0) {
			continue;
		}

		/* got address */

		/* determine ifindex or bail out */
		if (iter->ifa_name == NULL) {
			break;
		}

		int udp_sock = mk_udp_socket(iter->ifa_name);
		if (udp_sock < 0) {
			break;
		}

		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
			.data = {
				.fd = udp_sock
			}
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, udp_sock, &ev) < 0) {
			close(udp_sock);
			break;
		}

		freeifaddrs(addrs);

		/* this should not happen, as file descriptors are unique
		 * within the process */
		HASH_FIND(h_udp_sock, ht_sock_to_iface, &udp_sock, sizeof(int),
				iface_found);
		assert(iface_found == NULL);

		/* add new interface entry */
		iface->udp_sock = udp_sock;
		HASH_ADD(h_ipx_addr, ht_addr_to_iface, addr,
				sizeof(iface->addr), iface);
		HASH_ADD(h_udp_sock, ht_sock_to_iface, udp_sock, sizeof(int),
				iface);
		return true;
	}

	/* address not found or other error */

	freeifaddrs(addrs);
	free(iface);

	return false;
}

static _Noreturn void usage() {
	printf("Usage: ipx_wrap_mux <ipv6 addr> [<ipv6 addr>]...\n");
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
	}

	int ctrl_sock = -1;
	int epoll_fd = -1;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, ctrl_sock, 2);
	}

	/* save all the IPX addresses we manage in the hash */
	struct ipv6_eui64_addr addr_buf;
	int i;
	for (i = 1; i < argc; i++) {
		if (inet_pton(AF_INET6, argv[i], &addr_buf) != 1) {
			usage();
		}

		if (!add_iface(&addr_buf, epoll_fd)) {
			perror("adding interfaces");
			cleanup_and_exit(epoll_fd, ctrl_sock, 3);
		}
	}

	ctrl_sock = ipxw_mux_mk_ctrl_sock();
	if (ctrl_sock < 0) {
		fprintf(stderr, "creating ctrl socket failed: %s\n",
				strerror(-ctrl_sock));
		cleanup_and_exit(epoll_fd, ctrl_sock, 4);
	}

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ctrl_sock
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctrl_sock, &ev) < 0) {
		perror("registering ctrl socket for event polling");
		cleanup_and_exit(epoll_fd, ctrl_sock, 5);
	}

	ssize_t err;
	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (1) {
		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == -EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(epoll_fd, ctrl_sock, 6);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* ctrl socket */
			if (evs[i].data.fd == ctrl_sock) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "control socket error\n");
					cleanup_and_exit(epoll_fd, ctrl_sock,
							7);
				}

				/* incoming bind msg */
				err = ipxw_mux_do_ctrl(ctrl_sock, &record_bind,
						&epoll_fd);
				if (err < 0) {
					perror("handle binding");
				}

				continue;
			}

			/* one of the UDP sockets */
			struct if_entry *iface;
			HASH_FIND(h_udp_sock, ht_sock_to_iface,
					&evs[i].data.fd, sizeof(int), iface);
			if (iface != NULL) {
				/* something went wrong, unbind */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					// TODO: think about what to do here
					continue;
				}

				/* can recv */
				if (evs[i].events & EPOLLIN) {
					err = udp_recv(evs[i].data.fd, iface);
					if (err < 0 && errno != EINTR) {
						perror("UDP recv");
					} else if (err == 0) {
						/* nobody was interested */
					}
				}

				/* can xmit */
				if (evs[i].events & EPOLLOUT) {
					err = udp_send(evs[i].data.fd, iface);
					if (err < 0) {
						perror("UDP send");
					} else if (err == 0) {
						/* nothing happend */
					}
				}

				continue;
			}

			/* one of the data sockets */

			/* something went wrong, unbind */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				handle_unbind(evs[i].data.fd, &epoll_fd);
				continue;
			}

			/* can xmit */
			if (evs[i].events & EPOLLIN) {
				err = ipxw_mux_do_data(evs[i].data.fd, &tx_msg,
						&handle_unbind, NULL,
						&epoll_fd);
				if (err < 0 && errno != EINTR) {
					perror("xmitting data");
				} else if (err == 0) {
					// unbound
				}
			}

			/* can recv */
			if (evs[i].events & EPOLLOUT) {
				err = recv_msg(evs[i].data.fd);
				if (err < 0) {
					/* get rid of the client */
					perror("recving data");
					handle_unbind(evs[i].data.fd, &epoll_fd);
				} else if (err == 0) {
					/* nothing happened */
				}
			}
		}
	}

	cleanup_and_exit(epoll_fd, ctrl_sock, 0);

	return 0;
}
