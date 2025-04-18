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
	/* remaining data */
	__u8 pkt_type;
	__u8 recv_bcast:1,
	     pkt_type_any:1,
	     reserved:6;
};

struct sub_process {
	/* net and node IPX addr */
	struct __attribute__((packed)) {
		__be32 net;
		__u8 node[IPX_ADDR_NODE_BYTES];
	} addr;
	/* the socket used to talk to the sub-process */
	int sub_sock;
	/* hash entry */
	UT_hash_handle h_ipx_addr;
	UT_hash_handle hh; /* by socket */
	/* the sub-process' PID */
	pid_t sub_pid;
};

struct if_entry {
	/* net and node IPX addr */
	struct __attribute__((packed)) {
		__be32 net;
		__u8 node[IPX_ADDR_NODE_BYTES];
	} addr;
	/* the actual UDP socket */
	int udp_sock;
	/* msgs to send */
	struct ipxw_msg_queue out_queue;
	/* bindings indexed by the IPX socket */
	struct bind_entry *ht_ipx_sock_to_bind;
	/* IPv6 prefix */
	__be32 prefix;
};

static struct bind_entry *ht_sock_to_bind = NULL;
static struct sub_process *ht_ipx_addr_to_sub = NULL;
static struct sub_process *ht_sock_to_sub = NULL;

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

static bool record_bind(struct if_entry *iface, int data_sock, int epoll_fd,
		struct ipxw_mux_msg_bind *bind_msg)
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

	/* make and fill new binding entry */
	e = calloc(1, sizeof(struct bind_entry));
	if (e == NULL) {
		perror("allocating binding");
		return false;
	}

	e->sock = data_sock;
	e->ipx_sock = bind_msg->addr.sock;
	e->iface = iface;
	e->pkt_type = bind_msg->pkt_type;
	e->pkt_type_any = bind_msg->pkt_type_any;
	e->recv_bcast = bind_msg->recv_bcast;
	STAILQ_INIT(&e->in_queue);

	/* register for epoll */
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = data_sock
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, data_sock, &ev) < 0) {
		perror("registering for event polling");
		free(e);
		return false;
	}

	/* save binding */
	HASH_ADD(h_ipx_sock, iface->ht_ipx_sock_to_bind, ipx_sock, sizeof(__be16), e);
	HASH_ADD_INT(ht_sock_to_bind, sock, e);

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

	return true;
}

static ssize_t udp_send(struct if_entry *iface)
{
	int udp_sock = iface->udp_sock;

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
	if (len >= 0 && len != pktlen) {
		len = -1;
		errno = ECOMM;
	}

	return len;
}

static int tx_msg(int data_sock, struct ipxw_mux_msg *msg, void *ctx)
{
	struct bind_entry *be_xmit = get_bind_entry_by_sock(data_sock);
	if (be_xmit == NULL) {
		return -1;
	}

	assert(msg->type == IPXW_MUX_XMIT);

	msg->xmit.ssock = be_xmit->ipx_sock;

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

static ssize_t udp_recv(struct if_entry *iface)
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

	int sock = e->sock;

	/* close the socket and free */
	close(sock);
	free(e);

	printf("%d unbound\n", sock);
}

static void handle_unbind(int data_sock, void *ctx)
{
	struct bind_entry *e = get_bind_entry_by_sock(data_sock);
	if (e == NULL) {
		/* already unbound */
		return;
	}

	unbind_entry(e);
}

static ssize_t xmit_msg(int data_sock)
{
	ssize_t expected = ipxw_mux_peek_xmit_len(data_sock);
	if (expected < 0) {
		return -1;
	}

	struct ipxw_mux_msg *msg = calloc(1, expected);
	if (msg == NULL) {
		return -1;
	}

	msg->type = IPXW_MUX_XMIT;
	msg->xmit.data_len = expected - sizeof(*msg);

	ssize_t err = ipxw_mux_do_xmit(data_sock, msg, &tx_msg, &handle_unbind,
			NULL, NULL);
	if (err < 0) {
		/* some error */
		free(msg);
	} else if (err == 0) {
		/* unbind message */
		free(msg);
	} else {
		/* message queued for sending */
	}

	return err;
}

static ssize_t recv_msg(int data_sock)
{
	struct bind_entry *be = get_bind_entry_by_sock(data_sock);
	if (be == NULL) {
		/* already unbound */
		return 0;
	}

	/* no msgs to receive */
	if (STAILQ_EMPTY(&be->in_queue)) {
		return 0;
	}

	struct ipxw_mux_msg *msg = STAILQ_FIRST(&be->in_queue);
	ssize_t err = ipxw_mux_recv(be->sock, msg);
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

static void cleanup_sub_process(struct sub_process *sub)
{
	assert(sub != NULL);
	assert(sub->sub_sock >= 0);
	assert(sub->sub_pid >= 0);

	/* close socket */
	close(sub->sub_sock);

	/* remove the sub-process entry */
	HASH_DELETE(h_ipx_addr, ht_ipx_addr_to_sub, sub);
	HASH_DEL(ht_sock_to_sub, sub);
	free(sub);
}

static void cleanup_sub_processes()
{
	struct sub_process *se;
	struct sub_process *stmp;
	HASH_ITER(h_ipx_addr, ht_ipx_addr_to_sub, se, stmp) {
		cleanup_sub_process(se);
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
	cleanup_sub_processes();

	/* remove the interface (if any) */
	if (iface != NULL) {
		cleanup_iface(iface);
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

static struct if_entry *mk_iface(struct ipv6_eui64_addr *ipv6_addr)
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

	/* iterate over all addresses to find the interface to our IPv6 addr */
	struct ifaddrs *addrs;
	struct ifaddrs *iter;

	if (getifaddrs(&addrs) < 0) {
		free(iface);
		return NULL;
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

		iface->udp_sock = udp_sock;

		freeifaddrs(addrs);
		return iface;
	}

	/* address not found or other error */

	freeifaddrs(addrs);
	free(iface);
	return NULL;
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

	int data_sock = ipxw_mux_recv_bind_msg(ctrl_sock, &bind_msg);
	/* couldn't even receive the bind msg, just quit */
	if (data_sock < 0) {
		return -1;
	}
	assert(bind_msg.type == IPXW_MUX_BIND);

	/* binding failed, send error response */
	if (!record_bind(iface, data_sock, epoll_fd, &bind_msg.bind)) {
		ipxw_mux_send_bind_resp(data_sock, &resp_msg);
		close(data_sock);

		errno = EACCES;
		return -1;
	}

	/* binding succeeded, send ack response */
	resp_msg.err.err = 0;
	resp_msg.type = IPXW_MUX_BIND_ACK;
	ipxw_mux_send_bind_resp(data_sock, &resp_msg);

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

	int data_sock = ipxw_mux_recv_bind_msg(ctrl_sock, &bind_msg);
	/* couldn't even receive the bind msg, just quit */
	if (data_sock < 0) {
		return -1;
	}
	assert(bind_msg.type == IPXW_MUX_BIND);

	struct sub_process *sub;
	struct __attribute__((packed)) {
		__be32 net;
		__u8 node[IPX_ADDR_NODE_BYTES];
	} addr;
	addr.net = bind_msg.bind.addr.net;
	memcpy(addr.node, bind_msg.bind.addr.node, IPX_ADDR_NODE_BYTES);
	HASH_FIND(h_ipx_addr, ht_ipx_addr_to_sub, &addr, sizeof(addr), sub);

	/* no sub-process listening on the desired interface */
	if (sub == NULL) {
		fprintf(stderr, "bind address not allowed\n");
		ipxw_mux_send_bind_resp(data_sock, &err_msg);
		close(data_sock);

		errno = EACCES;
		return -1;
	}

	/* try to send the data socket to the appropriate sub-process */

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
	union {
		char buf[CMSG_SPACE(sizeof(int))]; /* Space large
						      enough to hold an
						      'int' */
		struct cmsghdr align;
	} ctrl_msg;
	memset(ctrl_msg.buf, 0, sizeof(ctrl_msg.buf));

	msgh.msg_control = ctrl_msg.buf;
	msgh.msg_controllen = sizeof(ctrl_msg.buf);

	/* prepare ctrl msg header */
	struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
	cmsgp->cmsg_level = SOL_SOCKET;
	cmsgp->cmsg_type = SCM_RIGHTS;

	/* store the socket fd we want to send */
	cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsgp), &data_sock, sizeof(int));

	/* send the ctrl msg */
	/* should always transmit the entire msg or nothing */
	ssize_t err;
	do {
		err = sendmsg(sub->sub_sock, &msgh, MSG_DONTWAIT);
	} while (err < 0 && errno == EINTR);

	if (err < 0) {
		fprintf(stderr, "passing binding to sub-process failed\n");
		err_msg.err.err = errno;
		ipxw_mux_send_bind_resp(data_sock, &err_msg);
		close(data_sock);
		return -1;
	}

	close(data_sock);
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
					err = udp_recv(iface);
					if (err < 0 && errno != EINTR) {
						perror("UDP recv");
					} else if (err == 0) {
						/* nobody was interested */
					}
				}

				/* can xmit */
				if (evs[i].events & EPOLLOUT) {
					err = udp_send(iface);
					if (err < 0) {
						perror("UDP send");
					} else if (err == 0) {
						/* nothing happend */
					}
				}

				continue;

			}

			/* one of the data sockets */

			/* can xmit */
			if (evs[i].events & EPOLLIN) {
				err = xmit_msg(evs[i].data.fd);
				if (err < 0 && errno != EINTR) {
					perror("xmitting data");
				} else if (err == 0) {
					/* unbound */
					continue;
				}
			}

			/* can recv */
			if (evs[i].events & EPOLLOUT) {
				err = recv_msg(evs[i].data.fd);
				if (err < 0) {
					/* get rid of the client */
					perror("recving data");
					handle_unbind(evs[i].data.fd, NULL);
					continue;
				} else if (err == 0) {
					/* nothing happened */
				}
			}

			/* something went wrong, unbind */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				handle_unbind(evs[i].data.fd, NULL);
				continue;
			}
		}
	}

	cleanup_and_exit(iface, epoll_fd, ctrl_sock, 0);
}

static bool add_sub(struct ipv6_eui64_addr *ipv6_addr, int epoll_fd, int
		ctrl_sock)
{
	struct sub_process *sub = calloc(1, sizeof(struct sub_process));
	if (sub == NULL) {
		return false;
	}

	sub->addr.net = ipv6_addr->ipx_net;
	memcpy(sub->addr.node, ipv6_addr->ipx_node_fst,
			sizeof(ipv6_addr->ipx_node_fst));
	memcpy(sub->addr.node + sizeof(ipv6_addr->ipx_node_fst),
			ipv6_addr->ipx_node_snd,
			sizeof(ipv6_addr->ipx_node_snd));
	sub->sub_sock = -1;

	struct sub_process *sub_found = NULL;
	HASH_FIND(h_ipx_addr, ht_ipx_addr_to_sub, &sub->addr,
			sizeof(sub->addr), sub_found);
	if (sub_found != NULL) {
		/* sub-process for IPX addr already exists */
		free(sub);
		return true;
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

		iface = mk_iface(ipv6_addr);
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

			/* close unused sockets */
			close(ctrl_sock);
			close(epoll_fd);

			/* get rid of all previously created sub-process entries */
			cleanup_sub_processes();

			ctrl_sock = sv[1];

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
		return true;
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
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 2);
	}

	/* save all the IPX addresses we manage in the hash */
	struct ipv6_eui64_addr addr_buf;
	int i;
	for (i = 1; i < argc; i++) {
		if (inet_pton(AF_INET6, argv[i], &addr_buf) != 1) {
			usage();
		}

		if (!add_sub(&addr_buf, epoll_fd, ctrl_sock)) {
			perror("adding sub-process");
			cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 3);
		}
	}

	ctrl_sock = ipxw_mux_mk_ctrl_sock();
	if (ctrl_sock < 0) {
		perror("creating ctrl socket");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 4);
	}

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ctrl_sock
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctrl_sock, &ev) < 0) {
		perror("registering ctrl socket for event polling");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 5);
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
			cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 6);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* ctrl socket */
			if (evs[i].data.fd == ctrl_sock) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "control socket error\n");
					cleanup_and_exit(NULL, epoll_fd,
							ctrl_sock, 7);
				}

				/* incoming bind msg */
				err = handle_bind_msg_main(ctrl_sock);
				if (err < 0 && errno != EINTR) {
					perror("handle binding");
				}

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
				cleanup_sub_process(sub);
				continue;
			}
		}
	}

	cleanup_and_exit(NULL, epoll_fd, ctrl_sock, 0);

	return 0;
}
