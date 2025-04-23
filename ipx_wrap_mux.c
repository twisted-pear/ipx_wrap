#define _GNU_SOURCE
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
#include <sys/capability.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "uthash.h"
#include "ipx_wrap_mux_proto.h"

#define INTERFACE_RESCAN_SECS 30
#define MAX_EPOLL_EVENTS 64

STAILQ_HEAD(ipxw_msg_queue, ipxw_mux_msg);

struct if_entry;

struct bind_entry {
	/* if the hash table key is the IPX socket number */
	__be16 ipx_sock;
	/* the data socket */
	int sock;
	/* hash entries */
	UT_hash_handle h_ipx_sock;
	UT_hash_handle hh; /* by socket */
	/* recvd msgs for this binding's socket */
	struct ipxw_msg_queue in_queue;
	/* corresponding interface */
	struct if_entry *iface;
	/* handle for muxing */
	struct ipxw_mux_handle h;
	/* remaining data */
	__u8 pkt_type;
	__u8 recv_bcast:1,
	     pkt_type_any:1,
	     reserved:6;
};

struct ipx_if_addr {
	__be32 net;
	__u8 node[IPX_ADDR_NODE_BYTES];
} __attribute__((packed));

struct sub_process {
	/* net and node IPX addr */
	struct ipx_if_addr addr;
	/* the socket used to talk to the sub-process */
	int sub_sock;
	/* hash entry */
	UT_hash_handle h_ipx_addr;
	UT_hash_handle hh; /* by socket */
	/* the sub-process' PID */
	pid_t sub_pid;
	/* whether to keep the process after the if-scan */
	bool keep;
};

struct if_entry {
	/* net and node IPX addr */
	struct ipx_if_addr addr;
	/* the actual UDP socket */
	int udp_sock;
	/* msgs to send */
	struct ipxw_msg_queue out_queue;
	/* bindings indexed by the IPX socket */
	struct bind_entry *ht_ipx_sock_to_bind;
	/* IPv6 prefix */
	__be32 prefix;
};

struct do_ctx {
	struct bind_entry *be;
	int epoll_fd;
};

static struct bind_entry *ht_sock_to_bind = NULL;
static struct sub_process *ht_ipx_addr_to_sub = NULL;
static struct sub_process *ht_sock_to_sub = NULL;

static int tmr_fd = -1;

static struct bind_entry *get_bind_entry_by_sock(int sock)
{
	struct bind_entry *bind;

	HASH_FIND_INT(ht_sock_to_bind, &sock, bind);
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

static struct sub_process *get_sub_process_by_sock(int sock)
{
	struct sub_process *sub;

	HASH_FIND_INT(ht_sock_to_sub, &sock, sub);
	return sub;
}

static struct sub_process *get_sub_process_by_ipx_addr(struct ipx_if_addr
		*addr)
{
	struct sub_process *sub;

	HASH_FIND(h_ipx_addr, ht_ipx_addr_to_sub, addr, sizeof(*addr), sub);
	return sub;
}

static bool record_bind(struct if_entry *iface, struct ipxw_mux_handle h, int
		epoll_fd, struct ipxw_mux_msg_bind *bind_msg)
{
	/* illegal network bindings */
	if (bind_msg->addr.net == IPX_NET_LOCAL) {
		fprintf(stderr, "binding to local net not allowed\n");
		return false;
	}
	if (bind_msg->addr.net == IPX_NET_ALL_ROUTES) {
		fprintf(stderr, "binding to all routes net not allowed\n");
		return false;
	}
	if (bind_msg->addr.net == IPX_NET_DEFAULT_ROUTE) {
		fprintf(stderr, "binding to default route net not allowed\n");
		return false;
	}

	/* illegal node bindings */
	if (memcmp(bind_msg->addr.node, IPX_BCAST_NODE, IPX_ADDR_NODE_BYTES) ==
			0) {
		fprintf(stderr, "binding to broadcast node not allowed\n");
		return false;
	}

	/* not sure how we got this message, but we can only bind to the
	 * address of our interface */
	if (iface->addr.net != bind_msg->addr.net) {
		fprintf(stderr, "bind address not allowed\n");
		return false;
	}
	if (memcmp(iface->addr.node, bind_msg->addr.node, IPX_ADDR_NODE_BYTES)
			!= 0) {
		fprintf(stderr, "bind address not allowed\n");
		return false;
	}

	/* socket already in use */
	struct bind_entry *e = get_bind_entry_by_ipx_sock(iface,
			bind_msg->addr.sock);
	if (e != NULL) {
		fprintf(stderr, "binding already in use\n");
		return false;
	}

	/* the process trying to bind needs CAP_NET_BIND_SERVICE to use one of
	 * the low sockets */
	if (ntohs(bind_msg->addr.sock) < ntohs(IPX_MIN_DYNAMIC_SOCKET)) {
		struct ucred data_creds;
		socklen_t data_creds_len = sizeof(data_creds);
		if (getsockopt(ipxw_mux_handle_conf(h), SOL_SOCKET,
					SO_PEERCRED, &data_creds,
					&data_creds_len) < 0) {
			perror("obtaining process credentials");
			return false;
		}

		cap_t data_caps = cap_get_pid(data_creds.pid);
		if (data_caps == NULL) {
			perror("obtaining process capabilities");
			return false;
		}

		cap_flag_value_t on;
		if (cap_get_flag(data_caps, CAP_NET_BIND_SERVICE,
					CAP_PERMITTED, &on) != 0) {
			perror("checking for CAP_NET_BIND_SERVICE");
			cap_free(data_caps);
			return false;
		}
		cap_free(data_caps);

		if (on != CAP_SET) {
			fprintf(stderr, "bind to low socket not permitted\n");
			return false;
		}
	}

	/* make and fill new binding entry */
	e = calloc(1, sizeof(struct bind_entry));
	if (e == NULL) {
		perror("allocating binding");
		return false;
	}

	e->sock = ipxw_mux_handle_data(h);
	e->ipx_sock = bind_msg->addr.sock;
	e->iface = iface;
	e->h = h;
	e->pkt_type = bind_msg->pkt_type;
	e->pkt_type_any = bind_msg->pkt_type_any;
	e->recv_bcast = bind_msg->recv_bcast;
	STAILQ_INIT(&e->in_queue);

	/* register for epoll */
	/* data socket */
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ipxw_mux_handle_data(h)
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_data(h), &ev) <
			0) {
		perror("registering for event polling");
		free(e);
		return false;
	}
	/* config socket */
	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = -ipxw_mux_handle_data(h);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_conf(h), &ev) <
			0) {
		perror("registering for event polling");
		free(e);
		return false;
	}

	/* save binding */
	HASH_ADD(h_ipx_sock, iface->ht_ipx_sock_to_bind, ipx_sock, sizeof(__be16), e);
	HASH_ADD_INT(ht_sock_to_bind, sock, e);

	/* show the new binding in full */
	printf("bound %d:%d to %08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx, ",
			ipxw_mux_handle_data(h), ipxw_mux_handle_conf(h),
			ntohl(bind_msg->addr.net), bind_msg->addr.node[0],
			bind_msg->addr.node[1], bind_msg->addr.node[2],
			bind_msg->addr.node[3], bind_msg->addr.node[4],
			bind_msg->addr.node[5], ntohs(bind_msg->addr.sock));
	if (bind_msg->pkt_type_any) {
		printf("pkt type: any, ");
	} else {
		printf("pkt type: %02hhx, ", bind_msg->pkt_type);
	}
	printf("recv bcasts: %s\n", bind_msg->recv_bcast ? "yes" : "no");

	return true;
}

static ssize_t udp_send(struct if_entry *iface, int epoll_fd)
{
	int udp_sock = iface->udp_sock;

	/* no msgs to send */
	if (STAILQ_EMPTY(&iface->out_queue)) {
		/* unregister from ready-to-write events to avoid busy polling
		 */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP,
			.data.fd = udp_sock
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, udp_sock, &ev);

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
	if (len >= 0 && len != pktlen) {
		len = -1;
		errno = ECOMM;
	}

	return len;
}

static int tx_msg(struct ipxw_mux_handle h, struct ipxw_mux_msg *msg, void
		*ctx)
{
	struct do_ctx *context = (struct do_ctx *) ctx;
	struct bind_entry *be_xmit = context->be;
	if (be_xmit == NULL) {
		return -1;
	}

	assert(msg->type == IPXW_MUX_XMIT);

	msg->xmit.ssock = be_xmit->ipx_sock;

	/* reregister for ready-to-write events, now that messages are
	 * available */
	int udp_sock = be_xmit->iface->udp_sock;
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
		.data.fd = udp_sock
	};
	if (epoll_ctl(context->epoll_fd, EPOLL_CTL_MOD, udp_sock, &ev) < 0) {
		return -1;
	}

	/* queue the message on the interface */
	STAILQ_INSERT_TAIL(&be_xmit->iface->out_queue, msg, q_entry);

	return 0;
}

static ssize_t peek_udp_recv_len(int udp_sock)
{
	struct ipxhdr ipxh;
	ssize_t rcvd_len = recv(udp_sock, &ipxh, sizeof(ipxh), MSG_PEEK);
	if (rcvd_len < 0) {
		return -1;
	}

	do {
		/* we need the IPX header to determine the message length */
		if (rcvd_len != sizeof(ipxh)) {
			errno = EREMOTEIO;
			break;
		}

		size_t pkt_len = ntohs(ipxh.pktlen);

		/* the length must fit at least the header */
		if (pkt_len < sizeof(ipxh)) {
			errno = EREMOTEIO;
			break;
		}

		/* the payload must fit */
		if (pkt_len > IPXW_MUX_MSG_LEN) {
			errno = EREMOTEIO;
			break;
		}

		return pkt_len;
	} while (0);

	/* clear out the invalid message */
	recv(udp_sock, &ipxh, 0, 0);

	return -1;
}

static ssize_t udp_recv(struct if_entry *iface, int epoll_fd)
{
	ssize_t ret = -1;

	int udp_sock = iface->udp_sock;
	ssize_t expected = peek_udp_recv_len(udp_sock);
	if (expected < 0) {
		return -1;
	}

	struct ipxhdr *ipx_msg = malloc(expected);
	if (ipx_msg == NULL) {
		return -1;
	}

	do {
		ssize_t len = recv(udp_sock, ipx_msg, expected, 0);
		if (len < 0) {
			break;
		}

		/* need at least the IPX header */
		if (len < sizeof(struct ipxhdr)) {
			errno = EREMOTEIO;
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

		/* check the message length, the header could lie to us */
		if (recv_msg->recv.data_len + sizeof(*recv_msg) != expected) {
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

		/* reregister for ready-to-write events, now that messages are
		 * available */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
			.data.fd = be_recv->sock
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, be_recv->sock, &ev) < 0)
		{
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

static void unbind_entry(struct bind_entry *e)
{
	/* remove all undelivered messages */
	while (!STAILQ_EMPTY(&e->in_queue)) {
		struct ipxw_mux_msg *msg = STAILQ_FIRST(&e->in_queue);
		STAILQ_REMOVE_HEAD(&e->in_queue, q_entry);
		free(msg);
	}

	/* remove the bind entry from all data structures */
	HASH_DELETE(h_ipx_sock, e->iface->ht_ipx_sock_to_bind, e);
	HASH_DEL(ht_sock_to_bind, e);

	struct ipxw_mux_handle h = e->h;

	/* close the socket and free */
	ipxw_mux_handle_close(e->h);
	free(e);

	printf("%d:%d unbound\n", ipxw_mux_handle_data(h),
			ipxw_mux_handle_conf(h));
}

static void handle_unbind(int data_sock)
{
	struct bind_entry *e = get_bind_entry_by_sock(data_sock);
	if (e == NULL) {
		/* already unbound */
		return;
	}

	unbind_entry(e);
}

static int handle_conf_msg(struct ipxw_mux_handle h, struct ipxw_mux_msg *msg,
		void *ctx)
{
	struct do_ctx *context = (struct do_ctx *) ctx;
	struct bind_entry *be_conf = context->be;
	if (be_conf == NULL) {
		return -1;
	}

	/* we only support unbind messages for now */
	if (msg->type != IPXW_MUX_UNBIND) {
		return -1;
	}

	unbind_entry(be_conf);

	return 0;

}

static ssize_t conf_msg(int data_sock, int epoll_fd)
{
	struct bind_entry *be_conf = get_bind_entry_by_sock(data_sock);
	if (be_conf == NULL) {
		errno = ENOENT;
		return -1;
	}

	ssize_t expected = ipxw_mux_peek_conf_len(be_conf->h);
	if (expected < 0) {
		return -1;
	}

	struct ipxw_mux_msg *msg = calloc(1, expected);
	if (msg == NULL) {
		return -1;
	}

	msg->type = IPXW_MUX_CONF;
	msg->conf.data_len = expected - sizeof(*msg);

	struct do_ctx ctx = {
		.be = be_conf,
		.epoll_fd = epoll_fd
	};
	ssize_t err = ipxw_mux_do_conf(be_conf->h, msg, &handle_conf_msg,
			&ctx);

	/* always get rid of the message, it is handled immediately in
	 * ipxw_mux_do_conf */
	free(msg);

	return err;
}

static ssize_t xmit_msg(int data_sock, int epoll_fd)
{
	struct bind_entry *be_xmit = get_bind_entry_by_sock(data_sock);
	if (be_xmit == NULL) {
		errno = ENOENT;
		return -1;
	}

	ssize_t expected = ipxw_mux_peek_xmit_len(be_xmit->h);
	if (expected < 0) {
		return -1;
	}

	struct ipxw_mux_msg *msg = calloc(1, expected);
	if (msg == NULL) {
		return -1;
	}

	msg->type = IPXW_MUX_XMIT;
	msg->xmit.data_len = expected - sizeof(*msg);

	struct do_ctx ctx = {
		.be = be_xmit,
		.epoll_fd = epoll_fd
	};
	ssize_t err = ipxw_mux_do_xmit(be_xmit->h, msg, &tx_msg, &ctx);
	if (err < 0) {
		/* some error */
		free(msg);
	} else if (err == 0) {
		/* should not happen */
		free(msg);
	} else {
		/* message queued for sending */
	}

	return err;
}

static ssize_t recv_msg(int data_sock, int epoll_fd)
{
	struct bind_entry *be = get_bind_entry_by_sock(data_sock);
	if (be == NULL) {
		/* already unbound */
		return 0;
	}

	/* no msgs to receive */
	if (STAILQ_EMPTY(&be->in_queue)) {
		/* unregister from ready-to-write events to avoid busy polling
		 */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP,
			.data.fd = data_sock
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, data_sock, &ev);

		return 0;
	}

	struct ipxw_mux_msg *msg = STAILQ_FIRST(&be->in_queue);
	ssize_t err = ipxw_mux_recv(be->h, msg);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return 0;
		}

		/* other error, make sure to get rid of the message */
		perror("recving msg");
	}

	STAILQ_REMOVE_HEAD(&be->in_queue, q_entry);
	free(msg);

	return err;
}

static void cleanup_sub_process(struct sub_process *sub, bool sub_setup)
{
	assert(sub != NULL);
	assert(sub->sub_sock >= 0);
	assert(sub->sub_pid >= 0);

	if (!sub_setup) {
		printf("dropping interface "
				"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
				ntohl(sub->addr.net), sub->addr.node[0],
				sub->addr.node[1], sub->addr.node[2],
				sub->addr.node[3], sub->addr.node[4],
				sub->addr.node[5]);
	}

	int cpid = sub->sub_pid;

	/* close socket */
	close(sub->sub_sock);

	/* remove the sub-process entry */
	HASH_DELETE(h_ipx_addr, ht_ipx_addr_to_sub, sub);
	HASH_DEL(ht_sock_to_sub, sub);
	free(sub);

	/* collect the child process, no error handling, since we can't do
	 * anything */
	int err = -1;
	do {
		err = waitpid(cpid, NULL, 0);
	} while (err < 0 && errno == EINTR);
}

static void cleanup_sub_processes(bool sub_setup)
{
	struct sub_process *se;
	struct sub_process *stmp;
	HASH_ITER(h_ipx_addr, ht_ipx_addr_to_sub, se, stmp) {
		cleanup_sub_process(se, sub_setup);
	}
}

static void cleanup_iface(struct if_entry *iface)
{
	/* close UDP socket */
	close(iface->udp_sock);

	/* remove all bindings */
	struct bind_entry *e;
	struct bind_entry *tmp;
	HASH_ITER(h_ipx_sock, iface->ht_ipx_sock_to_bind, e, tmp) {
		unbind_entry(e);
	}

	/* remove all undelivered messages */
	while (!STAILQ_EMPTY(&iface->out_queue)) {
		struct ipxw_mux_msg *msg = STAILQ_FIRST(&iface->out_queue);
		STAILQ_REMOVE_HEAD(&iface->out_queue, q_entry);
		free(msg);
	}

	free(iface);
}

static _Noreturn void cleanup_and_exit(struct if_entry *iface, int epoll_fd,
		int ctrl_sock, int exit_code)
{
	/* remove all sub-processes (if any) */
	cleanup_sub_processes(false);

	/* remove the interface (if any) */
	if (iface != NULL) {
		cleanup_iface(iface);
	}

	/* close the timer fd */
	if (tmr_fd >= 0) {
		close(tmr_fd);
	}

	/* close down control socket */
	if (ctrl_sock >= 0) {
		close(ctrl_sock);
	}

	/* close down epoll fd */
	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	exit(exit_code);
}

static int mk_udp_socket(const char *ifname)
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

static struct if_entry *mk_iface(struct ipv6_eui64_addr *ipv6_addr, const char
		*ifname)
{
	struct if_entry *iface = calloc(1, sizeof(struct if_entry));
	if (iface == NULL) {
		return NULL;
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

	/* make and bind the UDP socket for our interface */
	int udp_sock = mk_udp_socket(ifname);
	if (udp_sock < 0) {
		free(iface);
		return NULL;
	}
	iface->udp_sock = udp_sock;

	return iface;
}

static ssize_t handle_bind_msg_sub(struct if_entry *iface, int ctrl_sock, int
		epoll_fd)
{
	/* prepare response msg */
	struct ipxw_mux_msg resp_msg;
	memset(&resp_msg, 0, sizeof(struct ipxw_mux_msg));
	resp_msg.type = IPXW_MUX_BIND_ERR;
	resp_msg.err.err = EACCES;

	struct ipxw_mux_msg bind_msg;

	struct ipxw_mux_handle h = ipxw_mux_recv_bind_msg(ctrl_sock,
			&bind_msg);
	/* couldn't even receive the bind msg, just quit */
	if (ipxw_mux_handle_is_error(h)) {
		return -1;
	}
	assert(bind_msg.type == IPXW_MUX_BIND);

	/* binding failed, send error response */
	if (!record_bind(iface, h, epoll_fd, &bind_msg.bind)) {
		ipxw_mux_send_bind_resp(h, &resp_msg);
		ipxw_mux_handle_close(h);

		errno = EACCES;
		return -1;
	}

	/* binding succeeded, send ack response */
	resp_msg.err.err = 0;
	resp_msg.type = IPXW_MUX_BIND_ACK;
	ipxw_mux_send_bind_resp(h, &resp_msg);

	return 0;
}

static ssize_t handle_bind_msg_main(int ctrl_sock)
{
	/* prepare our error msg, just in case */
	struct ipxw_mux_msg err_msg;
	memset(&err_msg, 0, sizeof(struct ipxw_mux_msg));
	err_msg.type = IPXW_MUX_BIND_ERR;
	err_msg.err.err = EACCES;

	struct ipxw_mux_msg bind_msg;

	struct ipxw_mux_handle h = ipxw_mux_recv_bind_msg(ctrl_sock, &bind_msg);
	/* couldn't even receive the bind msg, just quit */
	if (ipxw_mux_handle_is_error(h)) {
		return -1;
	}
	assert(bind_msg.type == IPXW_MUX_BIND);

	struct ipx_if_addr addr;
	addr.net = bind_msg.bind.addr.net;
	memcpy(addr.node, bind_msg.bind.addr.node, IPX_ADDR_NODE_BYTES);
	struct sub_process *sub = get_sub_process_by_ipx_addr(&addr);

	/* no sub-process listening on the desired interface */
	if (sub == NULL) {
		fprintf(stderr, "bind address not allowed\n");
		ipxw_mux_send_bind_resp(h, &err_msg);
		ipxw_mux_handle_close(h);

		errno = EACCES;
		return -1;
	}

	/* try to send the sockets to the appropriate sub-process */

	/* much of this code was taken from
	 * https://man7.org/tlpi/code/online/dist/sockets/scm_rights_send.c.html
	 */

	struct msghdr msgh;
	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;

	/* send the full message */
	struct iovec iov;
	iov.iov_base = &bind_msg;
	iov.iov_len = sizeof(bind_msg);

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	/* prepare the ancillary data buffer */
	int fds[2] = { ipxw_mux_handle_data(h), ipxw_mux_handle_conf(h) };
	union {
		char buf[CMSG_SPACE(sizeof(fds))]; /* Space large
						      enough to hold an
						      'int' */
		struct cmsghdr align;
	} ctrl_msg;
	memset(ctrl_msg.buf, 0, sizeof(ctrl_msg.buf));

	msgh.msg_control = ctrl_msg.buf;
	msgh.msg_controllen = sizeof(ctrl_msg.buf);

	/* prepare ctrl msg header */
	struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
	if (cmsgp == NULL)  {
		fprintf(stderr, "failed to pass binding to sub-process\n");
		err_msg.err.err = EINVAL;
		ipxw_mux_send_bind_resp(h, &err_msg);
		ipxw_mux_handle_close(h);

		errno = EINVAL;
		return -1;

	}
	cmsgp->cmsg_level = SOL_SOCKET;
	cmsgp->cmsg_type = SCM_RIGHTS;

	/* store the socket fd we want to send */
	cmsgp->cmsg_len = CMSG_LEN(sizeof(fds));
	memcpy(CMSG_DATA(cmsgp), fds, sizeof(fds));

	/* send the ctrl msg */
	/* should always transmit the entire msg or nothing */
	ssize_t err;
	do {
		err = sendmsg(sub->sub_sock, &msgh, MSG_DONTWAIT);
	} while (err < 0 && errno == EINTR);

	if (err < 0) {
		fprintf(stderr, "passing binding to sub-process failed\n");
		err_msg.err.err = errno;
		ipxw_mux_send_bind_resp(h, &err_msg);
		ipxw_mux_handle_close(h);
		return -1;
	}

	ipxw_mux_handle_close(h);
	return 0;
}

static _Noreturn void do_sub_process(struct if_entry *iface, int ctrl_sock)
{
	int epoll_fd = -1;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(iface, epoll_fd, ctrl_sock, 4);
	}

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ctrl_sock
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctrl_sock, &ev) < 0) {
		perror("registering ctrl socket for event polling");
		cleanup_and_exit(iface, epoll_fd, ctrl_sock, 5);
	}

	ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
	ev.data.fd = iface->udp_sock;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, iface->udp_sock, &ev) < 0) {
		perror("registering UDP socket for event polling");
		cleanup_and_exit(iface, epoll_fd, ctrl_sock, 5);
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
			cleanup_and_exit(iface, epoll_fd, ctrl_sock, 6);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* ctrl socket */
			if (evs[i].data.fd == ctrl_sock) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "control socket error\n");
					cleanup_and_exit(iface, epoll_fd,
							ctrl_sock, 7);
				}

				/* incoming bind msg */
				err = handle_bind_msg_sub(iface, ctrl_sock,
						epoll_fd);
				if (err < 0 && errno != EINTR) {
					perror("handle binding");
				}

				continue;
			}

			/* UDP socket */
			if (evs[i].data.fd == iface->udp_sock) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "UDP socket error\n");
					cleanup_and_exit(iface, epoll_fd,
							ctrl_sock, 7);
				}

				/* can recv */
				if (evs[i].events & EPOLLIN) {
					err = udp_recv(iface, epoll_fd);
					if (err < 0 && errno != EINTR) {
						perror("UDP recv");
					} else if (err == 0) {
						/* nobody was interested */
					}
				}

				/* can xmit */
				if (evs[i].events & EPOLLOUT) {
					err = udp_send(iface, epoll_fd);
					if (err < 0) {
						perror("UDP send");
					} else if (err == 0) {
						/* nothing happend */
					}
				}

				continue;

			}

			/* one of the config sockets */
			if (evs[i].data.fd < 0) {
				/* incoming conf msg */
				if (evs[i].events & EPOLLIN) {
					err = conf_msg(-evs[i].data.fd,
							epoll_fd);
					if (err < 0 && errno != EINTR) {
						perror("handling conf msg");
					} else if (err == 0) {
						/* should not happen */
						continue;
					}
				}

				/* something went wrong, unbind */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					handle_unbind(-evs[i].data.fd);
					continue;
				}

				continue;
			}

			/* one of the data sockets */

			/* can xmit */
			if (evs[i].events & EPOLLIN) {
				err = xmit_msg(evs[i].data.fd, epoll_fd);
				if (err < 0 && errno != EINTR) {
					perror("xmitting data");
				} else if (err == 0) {
					/* should not happen */
					continue;
				}
			}

			/* can recv */
			if (evs[i].events & EPOLLOUT) {
				err = recv_msg(evs[i].data.fd, epoll_fd);
				if (err < 0) {
					/* get rid of the client */
					perror("recving data");
					handle_unbind(evs[i].data.fd);
					continue;
				} else if (err == 0) {
					/* nothing happened */
				}
			}

			/* something went wrong, unbind */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				handle_unbind(evs[i].data.fd);
				continue;
			}
		}
	}

	cleanup_and_exit(iface, epoll_fd, ctrl_sock, 0);
}

static struct sub_process *add_sub(struct ipv6_eui64_addr *ipv6_addr, const
		char *ifname, int epoll_fd, int ctrl_sock)
{
	struct sub_process *sub = calloc(1, sizeof(struct sub_process));
	if (sub == NULL) {
		return NULL;
	}

	sub->addr.net = ipv6_addr->ipx_net;
	memcpy(sub->addr.node, ipv6_addr->ipx_node_fst,
			sizeof(ipv6_addr->ipx_node_fst));
	memcpy(sub->addr.node + sizeof(ipv6_addr->ipx_node_fst),
			ipv6_addr->ipx_node_snd,
			sizeof(ipv6_addr->ipx_node_snd));
	sub->sub_sock = -1;

	struct sub_process *sub_found =
		get_sub_process_by_ipx_addr(&sub->addr);
	if (sub_found != NULL) {
		/* sub-process for IPX addr already exists */
		free(sub);
		return sub_found;
	}

	int sv[2] = { -1, -1 };
	struct if_entry *iface = NULL;
	do {
		if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
			break;
		}
		sub->sub_sock = sv[0];

		struct epoll_event ev = {
			.events = EPOLLERR | EPOLLHUP,
			.data = {
				.fd = sub->sub_sock
			}
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sub->sub_sock, &ev) < 0)
		{
			break;
		}

		iface = mk_iface(ipv6_addr, ifname);
		if (iface == NULL) {
			break;
		}

		int child_pid = fork();
		if (child_pid < 0) {
			break;
		}

		if (child_pid == 0) {
			/* child */

			/* delete the created sub-process entry */
			close(sub->sub_sock);
			free(sub);

			/* close unused fds */
			if (ctrl_sock >= 0) {
				close(ctrl_sock);
			}
			if (tmr_fd >= 0) {
				close(tmr_fd);
				tmr_fd = -1;
			}
			close(epoll_fd);

			/* get rid of all previously created sub-process entries */
			cleanup_sub_processes(true);

			ctrl_sock = sv[1];

			/* set sub-process name to something helpful */
			char sub_name[16];
			snprintf(sub_name, 16, "ipxmux %08x",
					ntohl(iface->addr.net));
			sub_name[15] = '\0';
			/* no error handling, this is for convenience only */
			prctl(PR_SET_NAME, sub_name, 0, 0, 0);

			/* doesn't return */
			do_sub_process(iface, ctrl_sock);
		}

		/* parent */

		sub->sub_pid = child_pid;

		cleanup_iface(iface);
		close(sv[1]);

		/* add new sub-process entry */
		HASH_ADD(h_ipx_addr, ht_ipx_addr_to_sub, addr, sizeof(sub->addr), sub);
		HASH_ADD_INT(ht_sock_to_sub, sub_sock, sub);

		printf("adding interface "
				"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
				ntohl(sub->addr.net), sub->addr.node[0],
				sub->addr.node[1], sub->addr.node[2],
				sub->addr.node[3], sub->addr.node[4],
				sub->addr.node[5]);

		return sub;
	} while (0);

	if (sv[1] >= 0) {
		close(sv[1]);
	}
	if (iface != NULL) {
		cleanup_iface(iface);
	}
	if (sub->sub_sock >= 0) {
		close(sub->sub_sock);
	}
	free(sub);

	return NULL;
}

/* FIXME: we cannot handle an address migrating from one interface to another,
 * but this should not happen with IPX anyway */
static bool scan_interfaces(__be32 prefix, int epoll_fd, int ctrl_sock)
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

		if (iter->ifa_name == NULL) {
			continue;
		}

		/* get or create a new sub-process for this address */
		struct sub_process *if_sub = add_sub(ipv6_addr, iter->ifa_name,
				epoll_fd, ctrl_sock);
		/* an error occurred during process creation, abort */
		if (if_sub == NULL) {
			freeifaddrs(addrs);
			return false;
		}

		/* mark the returned sub-process, so that we keep it */
		if_sub->keep = true;
	}

	freeifaddrs(addrs);

	struct sub_process *se;
	struct sub_process *stmp;
	HASH_ITER(h_ipx_addr, ht_ipx_addr_to_sub, se, stmp) {
		if (!se->keep) {
			cleanup_sub_process(se, false);
		} else {
			se->keep = false;
		}
	}

	return true;
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
		.it_interval = { .tv_sec = INTERFACE_RESCAN_SECS },
		.it_value = { .tv_sec = INTERFACE_RESCAN_SECS }
	};
	if (timerfd_settime(tmr, 0, &tmr_spec, NULL) < 0) {
		close(tmr);
		return -1;
	}

	return tmr;
}

static _Noreturn void usage() {
	printf("Usage: ipx_wrap_mux <32-bit hex prefix>\n");
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

	int ctrl_sock = -1;
	int epoll_fd = -1;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 2);
	}

	tmr_fd = setup_timer(epoll_fd);
	if (tmr_fd < 0) {
		perror("creating interface rescan timer");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 3);
	}

	/* scan all interfaces for addresses within the prefix, we manage those
	 * interfaces */
	if (!scan_interfaces(prefix, epoll_fd, ctrl_sock)) {
		perror("adding sub-process");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 4);
	}

	ctrl_sock = ipxw_mux_mk_ctrl_sock();
	if (ctrl_sock < 0) {
		perror("creating ctrl socket");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 5);
	}

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ctrl_sock
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctrl_sock, &ev) < 0) {
		perror("registering ctrl socket for event polling");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 6);
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
			cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 7);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* ctrl socket */
			if (evs[i].data.fd == ctrl_sock) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "control socket error\n");
					cleanup_and_exit(NULL, epoll_fd,
							ctrl_sock, 8);
				}

				/* incoming bind msg */
				err = handle_bind_msg_main(ctrl_sock);
				if (err < 0 && errno != EINTR) {
					perror("handle binding");
				}

				continue;
			}

			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(NULL, epoll_fd,
							ctrl_sock, 9);
				}

				/* incoming rescan the interfaces */
				if (!scan_interfaces(prefix, epoll_fd,
							ctrl_sock)) {
					perror("adding sub-process");
					cleanup_and_exit(NULL, epoll_fd,
							ctrl_sock, 10);
				}

				/* consume all expirations */
				__u64 dummy;
				read(tmr_fd, &dummy, sizeof(dummy));

				continue;
			}

			/* one of the sub-process sockets */

			/* something went wrong, remove sub-process */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "sub process died\n");
				struct sub_process *sub =
					get_sub_process_by_sock(evs[i].data.fd);
				/* already deleted */
				if (sub == NULL) {
					continue;
				}
				cleanup_sub_process(sub, false);
				continue;
			}
		}
	}

	cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 0);

	return 0;
}
