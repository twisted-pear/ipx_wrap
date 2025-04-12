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

#include "uthash.h"
#include "ipx_wrap_mux_proto.h"

#define MAX_EPOLL_EVENTS 64

LIST_HEAD(bcast_list, bind_entry);
STAILQ_HEAD(recv_msg_queue, ipxw_mux_msg);

struct bind_entry {
	/* if the hash table key is the socket */
	int sock;
	/* if the hash table key is the address */
	struct ipx_addr addr;
	/* hash entries */
	UT_hash_handle h_sock;
	UT_hash_handle h_addr;
	/* list entry */
	LIST_ENTRY(bind_entry) nw_bcast_entry;
	/* recvd msgs for this binding's socket */
	struct recv_msg_queue in_queue;
	/* remaining data */
	__u8 pkt_type;
	__u8 recv_bcast:1,
	     pkt_type_any:1,
	     reserved:6;
};

struct nw_bcast_list {
	__be32 nw;
	UT_hash_handle hh;
	struct bcast_list bcast_recvers;
};

struct avail_ipx_addr {
	struct __attribute__((packed)) {
		__be32 net;
		__u8 node[IPX_ADDR_NODE_BYTES];
	} addr;
	UT_hash_handle hh;
};

struct bind_entry *ht_sock_to_bind = NULL;
struct bind_entry *ht_addr_to_bind = NULL;
struct nw_bcast_list *ht_nw_to_bcast_list = NULL;
struct avail_ipx_addr *ht_avail_ipx_addrs = NULL;

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

static struct bcast_list *get_bcast_list(__be32 nw)
{
	struct nw_bcast_list *bcl;
	HASH_FIND_INT(ht_nw_to_bcast_list, &nw, bcl);

	/* create the missing bcast list */
	if (bcl == NULL) {
		bcl = calloc(1, sizeof(struct nw_bcast_list));
		if (bcl == NULL) {
			return NULL;
		}

		LIST_INIT(&bcl->bcast_recvers);
		HASH_ADD_INT(ht_nw_to_bcast_list, nw, bcl);
	}

	return &bcl->bcast_recvers;
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
	struct avail_ipx_addr *avail = NULL;
	HASH_FIND(hh, ht_avail_ipx_addrs, &bind_msg->addr,
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
	if (e != NULL) {
		fprintf(stderr, "socket already in use\n");
		return -1;
	}

	/* make and fill new binding entry */
	e = calloc(1, sizeof(struct bind_entry));
	if (e == NULL) {
		perror("allocating binding");
		return -1;
	}

	e->sock = data_sock;
	e->addr = bind_msg->addr;
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

	/* register for broadcasts */
	if (e->recv_bcast) {
		struct bcast_list *bcl = get_bcast_list(e->addr.net);
		if (bcl == NULL) {
			perror("allocating network broadcast list");
			epoll_ctl(epoll_fd, EPOLL_CTL_DEL, data_sock, NULL);
			free(e);
			return -1;
		}

		LIST_INSERT_HEAD(bcl, e, nw_bcast_entry);
	}

	/* save binding */
	HASH_ADD(h_sock, ht_sock_to_bind, sock, sizeof(int), e);
	HASH_ADD(h_addr, ht_addr_to_bind, addr, sizeof(struct ipx_addr), e);

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

static int tx_msg(int data_sock, struct ipxw_mux_msg *msg, void *ctx)
{
	/* xmit part */
	printf("txing msg with %d bytes\n", msg->xmit.data_len);

	struct bind_entry *be_xmit = get_bind_entry_by_sock(data_sock);
	if (be_xmit == NULL) {
		fprintf(stderr, "no binding for %d\n", data_sock);
		free(msg);
		return -1;
	}

	struct ipxhdr *ipx_msg = ipxw_mux_xmit_msg_to_ipxh(msg,
			&be_xmit->addr);
	if (ipx_msg == NULL) {
		fprintf(stderr, "failed to make ipx pkt\n");
		free(msg);
		return -1;
	}
	printf("made ipx pkt with %d bytes\n", ntohs(ipx_msg->pktlen));

	// TODO: restrict for pkt type and handle bcasts

	/* udp packet would go out here */

	/* recv part */
	struct bind_entry *be_recv = get_bind_entry_by_addr(&ipx_msg->daddr);
	if (be_recv == NULL) {
		fprintf(stderr, "no binding address\n");
		free(ipx_msg);
		return -1;
	}

	struct ipxw_mux_msg *recv_msg = ipxw_mux_ipxh_to_recv_msg(ipx_msg);
	if (recv_msg == NULL) {
		fprintf(stderr, "failed to make recv msg\n");
		free(ipx_msg);
		return -1;
	}
	printf("made recv msg with %d bytes\n", recv_msg->recv.data_len);

	STAILQ_INSERT_TAIL(&be_recv->in_queue, recv_msg, q_entry);

	return 0;
}

static int recv_msg(int data_sock)
{
	struct bind_entry *be = get_bind_entry_by_sock(data_sock);

	/* socket could be polled but is not registered anymore, do nothing */
	if (be == NULL) {
		return 0;
	}

	/* corrupt data structures? */
	assert(be->sock == data_sock);

	ssize_t err;

	/* no msgs to receive, just check if the client is still alive */
	if (STAILQ_EMPTY(&be->in_queue)) {
		return 0;
	}

	struct ipxw_mux_msg *msg = STAILQ_FIRST(&be->in_queue);
	err = ipxw_mux_recv(data_sock, msg);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (err == -EINTR || err == -EAGAIN || err == -EWOULDBLOCK)  {
			return 0;
		}

		/* other error, make sure to get rid of the message */
		perror("recving msg");
	} else {
		printf("recvd msg with %ld bytes\n", err);
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
	if (e->recv_bcast) {
		LIST_REMOVE(e, nw_bcast_entry);
	}

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
	// TODO: handle UDP socket here too

	/* remove all bindings */
	struct bind_entry *e;
	struct bind_entry *tmp;
	HASH_ITER(h_sock, ht_sock_to_bind, e, tmp) {
		unbind_entry(e, epoll_fd);
	}

	/* remove all allowed IPX bind addrs */
	struct avail_ipx_addr *ae;
	struct avail_ipx_addr *atmp;
	HASH_ITER(hh, ht_avail_ipx_addrs, ae, atmp) {
		HASH_DELETE(hh, ht_avail_ipx_addrs, ae);
		free(ae);
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

static bool add_avail_ipx_addr(struct ipv6_eui64_addr *ipv6_addr)
{
	struct avail_ipx_addr *ipx_avail = malloc(sizeof(struct
				avail_ipx_addr));
	if (ipx_avail == NULL) {
		return false;
	}

	ipx_avail->addr.net = ipv6_addr->ipx_net;
	memcpy(ipx_avail->addr.node, ipv6_addr->ipx_node_fst,
			sizeof(ipv6_addr->ipx_node_fst));
	memcpy(ipx_avail->addr.node + sizeof(ipv6_addr->ipx_node_fst),
			ipv6_addr->ipx_node_snd,
			sizeof(ipv6_addr->ipx_node_snd));

	struct avail_ipx_addr *ipx_avail_found = NULL;
	HASH_FIND(hh, ht_avail_ipx_addrs, &ipx_avail->addr,
			sizeof(ipx_avail->addr), ipx_avail_found);
	if (ipx_avail_found != NULL) {
		/* IPX addr already exists */
		free(ipx_avail);
	} else {
		/* add new IPX addr */
		HASH_ADD(hh, ht_avail_ipx_addrs, addr, sizeof(ipx_avail->addr),
				ipx_avail);
	}

	return true;
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

	/* save all the IPX addresses we manage in the hash */
	struct ipv6_eui64_addr addr_buf;
	int i;
	for (i = 1; i < argc; i++) {
		if (inet_pton(AF_INET6, argv[i], &addr_buf) != 1) {
			usage();
		}

		if (!add_avail_ipx_addr(&addr_buf)) {
			perror("setting allowed bind addrs");
			exit(2);
		}
	}

	int ctrl_sock = -1;
	int epoll_fd = -1;

	ctrl_sock = ipxw_mux_mk_ctrl_sock();
	if (ctrl_sock < 0) {
		fprintf(stderr, "creating ctrl socket failed: %s\n",
				strerror(-ctrl_sock));
		cleanup_and_exit(epoll_fd, ctrl_sock, 3);
	}

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
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

	int err;
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

			/* one of the data sockets */

			/* something went wrong, unbind */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "error on socket %d\n",
						evs[i].data.fd);
				handle_unbind(evs[i].data.fd, &epoll_fd);
				continue;
			}

			/* can xmit */
			if (evs[i].events & EPOLLIN) {
				err = ipxw_mux_do_data(evs[i].data.fd, &tx_msg,
						&handle_unbind, NULL,
						&epoll_fd);
				if (err < 0 && errno != -EINTR) {
					perror("data handling for xmit");
				} else if (err == 0) {
					printf("unbound data socket %d\n",
							evs[i].data.fd);
				} else {
					printf("handled xmit on socket %d\n",
							evs[i].data.fd);
				}
			}

			/* can recv */
			if (evs[i].events & EPOLLOUT) {
				err = recv_msg(evs[i].data.fd);
				if (err < 0) {
					/* get rid of the client */
					perror("recving data");
					fprintf(stderr, "error on socket %d\n",
							evs[i].data.fd);
					handle_unbind(evs[i].data.fd, &epoll_fd);
				} else if (err == 0) {
					// nothing happened
				} else {
					printf("recvd %d bytes on socket %d\n",
							err, evs[i].data.fd);
				}
			}
		}
	}

	cleanup_and_exit(epoll_fd, ctrl_sock, 0);

	return 0;
}
