#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <errno.h>

#include "uthash.h"
#include "ipx_wrap_mux_proto.h"

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
	__u8 pkt_type;
	__u8 recv_bcast:1,
	     pkt_type_any:1,
	     reserved:6;
};

LIST_HEAD(bcast_list, bind_entry);

struct nw_bcast_list {
	__be32 nw;
	UT_hash_handle hh;
	struct bcast_list bcast_recvers;
};

struct bind_entry *ht_sock_to_bind = NULL;
struct bind_entry *ht_addr_to_bind = NULL;
struct nw_bcast_list *ht_nw_to_bcast_list = NULL;

struct bind_entry *get_bind_entry_by_sock(int sock)
{
	struct bind_entry *bind;

	HASH_FIND(h_sock, ht_sock_to_bind, &sock, sizeof(int), bind);
	return bind;
}

struct bind_entry *get_bind_entry_by_addr(struct ipx_addr *addr)
{
	struct bind_entry *bind;

	HASH_FIND(h_addr, ht_addr_to_bind, addr, sizeof(struct ipx_addr),
			bind);
	return bind;
}

struct bcast_list *get_bcast_list(__be32 nw)
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

int record_bind(int data_sock, struct ipxw_mux_msg_bind *bind_msg, void *ctx)
{
	// TODO: restrict addresses that can be bound to

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

	/* register for broadcasts */
	if (e->recv_bcast) {
		struct bcast_list *bcl = get_bcast_list(e->addr.net);
		if (bcl == NULL) {
			perror("allocating network broadcast list");
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

	// TODO: register for epoll

	return 0;
}

int tx_msg(int data_sock, struct ipxw_mux_msg *msg, void *ctx)
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

	ssize_t msg_len = ipxw_mux_recv(be_recv->sock, recv_msg);
	if (msg_len < 0) {
		perror("recving msg");
		free(recv_msg);
		return -1;
	}
	printf("recvd msg with %ld bytes\n", msg_len);

	free(msg);
	return 0;
}

void handle_unbind(int data_sock, void *ctx)
{
	struct bind_entry *e = get_bind_entry_by_sock(data_sock);
	if (e == NULL) {
		fprintf(stderr, "no binding found for %d\n", data_sock);
		return;
	}

	HASH_DELETE(h_sock, ht_sock_to_bind, e);
	HASH_DELETE(h_addr, ht_addr_to_bind, e);
	if (e->recv_bcast) {
		LIST_REMOVE(e, nw_bcast_entry);
	}

	close(data_sock);
	free(e);

	// TODO: unregister for epoll

	printf("%d unbound\n", data_sock);
}

int main(int argc, char **argv)
{
	int ctrl_sock = ipxw_mux_mk_ctrl_sock();
	if (ctrl_sock < 0) {
		fprintf(stderr, "creating ctrl socket failed: %s\n",
				strerror(-ctrl_sock));
		return 1;
	}

	while (1) {
		int data_sock = ipxw_mux_do_ctrl(ctrl_sock, &record_bind,
				NULL);
		if (data_sock < 0) {
			fprintf(stderr, "bind handling failed: %s\n",
					strerror(-data_sock));
			close(ctrl_sock);
			return 2;
		}

		int err;
		do {
			err = ipxw_mux_do_data(data_sock, &tx_msg,
					&handle_unbind, NULL, NULL);
		} while (err > 0);

		if (err < 0) {
			fprintf(stderr, "data handling failed: %s\n",
					strerror(-err));
			handle_unbind(data_sock, NULL);
			close(ctrl_sock);
			return 3;
		}

		printf("unbound data socket\n");
	}

	close(ctrl_sock);

	return 0;
}
