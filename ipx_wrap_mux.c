#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/queue.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "uthash.h"
#include "ipx_wrap_mux_proto.h"

#include "ipx_wrap_mux_kern.skel.h"

#define INTERFACE_RESCAN_SECS 30
#define MAX_EPOLL_EVENTS 64

// TODO: apply muxer/demuxer bpf programs to all interfaces
// TODO: add a way to close an SPX connection properly in a multi-process
// scenario

enum muxer_error_codes {
	MUX_ERR_OK = 0,
	MUX_ERR_USAGE,
	MUX_ERR_BPF,
	MUX_ERR_EPOLL_FD,
	MUX_ERR_TMR_FD,
	MUX_ERR_CTRL_FD,
	MUX_ERR_IFACE_SCAN,
	MUX_ERR_SIG_HANDLER,
	MUX_ERR_EPOLL_WAIT,
	MUX_ERR_CTRL_FAILURE,
	MUX_ERR_TMR_FAILURE,
	MUX_ERR_MAX
};

STAILQ_HEAD(ipxw_msg_queue, ipxw_mux_msg);

struct if_entry;

struct spx_connection {
	__be16 conn_id;
	UT_hash_handle hh; /* by connection ID */
};

struct bind_entry {
	/* if the hash table key is the IPX socket number */
	__be16 ipx_sock;
	/* the config socket */
	int conf_sock;
	/* hash entries */
	UT_hash_handle h_ipx_sock;
	UT_hash_handle hh; /* by conf socket */
	/* outgoing config messages get queued here */
	struct ipxw_msg_queue conf_queue;
	/* corresponding interface */
	struct if_entry *iface;
	/* hash table of SPX connections */
	struct spx_connection *ht_id_to_spx_conn;
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
	/* ifindex */
	__u32 ifidx;
	/* BPF links for the programs attached to the interface */
	struct bpf_link *ingress_link;
	struct bpf_link *egress_link;
};

struct if_entry {
	/* net and node IPX addr */
	struct ipx_if_addr addr;
	/* bindings indexed by the IPX socket */
	struct bind_entry *ht_ipx_sock_to_bind;
	/* IPv6 prefix */
	__be32 prefix;
	/* ifindex */
	__u32 ifidx;
};

struct do_ctx {
	struct bind_entry *be;
	int epoll_fd;
};

static struct bind_entry *ht_conf_sock_to_bind = NULL;
static struct sub_process *ht_ipx_addr_to_sub = NULL;
static struct sub_process *ht_sock_to_sub = NULL;

static int tmr_fd = -1;
static struct ipx_wrap_mux_kern *bpf_kern = NULL;

static bool rescan_now = false;
static bool keep_going = true;

static int sort_bind_entry_by_ipx_sock(struct bind_entry *a, struct bind_entry
		*b)
{
	return ntohs(a->ipx_sock) - ntohs(b->ipx_sock);
}

static int sort_spx_conn_by_id(struct spx_connection *a, struct spx_connection
		*b)
{
	return ntohs(a->conn_id) - ntohs(b->conn_id);
}

static struct bind_entry *get_bind_entry_by_conf_sock(int conf_sock)
{
	struct bind_entry *bind;

	HASH_FIND_INT(ht_conf_sock_to_bind, &conf_sock, bind);
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

static struct spx_connection *get_spx_conn_by_conn_id(struct bind_entry *e,
		__be16 conn_id)
{
	struct spx_connection *c;

	HASH_FIND(hh, e->ht_id_to_spx_conn, &conn_id, sizeof(__be16), c);
	return c;
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

static __be16 find_next_free_dyn_sock(struct if_entry *iface)
{
	size_t range = ntohs(IPX_MIN_WELL_KNOWN_SOCKET) -
		ntohs(IPX_MIN_DYNAMIC_SOCKET);
	__u16 offset;

	/* if getting a random number fails, act as if no socket is free, the
	 * condition is temporary until the URANDOM source has been seeded */
	if (getrandom(&offset, sizeof(__u16), 0) != sizeof(__u16)) {
		return IPX_MIN_WELL_KNOWN_SOCKET;
	}

	struct bind_entry *e = NULL;

	offset = offset % range;
	for (int i = 0; i < range; i++) {
		__u16 candidate = ((offset + i) % range) +
			ntohs(IPX_MIN_DYNAMIC_SOCKET);

		e = get_bind_entry_by_ipx_sock(iface, htons(candidate));
		if (e == NULL) {
			return htons(candidate);
		}
	}

	return IPX_MIN_WELL_KNOWN_SOCKET;
}

static __be16 find_next_free_spx_conn_id(struct bind_entry *e)
{
	size_t range = USHRT_MAX;
	__u16 offset;

	/* if getting a random number fails, act as if no socket is free, the
	 * condition is temporary until the URANDOM source has been seeded */
	if (getrandom(&offset, sizeof(__u16), 0) != sizeof(__u16)) {
		return SPX_CONN_ID_UNKNOWN;
	}

	struct spx_connection *c = NULL;

	offset = offset % range;
	for (int i = 0; i < range; i++) {
		__u16 candidate = ((offset + i) % range);

		c = get_spx_conn_by_conn_id(e, htons(candidate));
		if (c == NULL) {
			return htons(candidate);
		}
	}

	return SPX_CONN_ID_UNKNOWN;
}

static bool has_net_bind_service(struct ipxw_mux_handle h)
{
	struct ucred data_creds;
	socklen_t data_creds_len = sizeof(data_creds);
	if (getsockopt(ipxw_mux_handle_conf(h), SOL_SOCKET, SO_PEERCRED,
				&data_creds, &data_creds_len) < 0) {
		return false;
	}

	cap_t data_caps = cap_get_pid(data_creds.pid);
	if (data_caps == NULL) {
		return false;
	}

	cap_flag_value_t on;
	if (cap_get_flag(data_caps, CAP_NET_BIND_SERVICE, CAP_PERMITTED, &on)
			!= 0) {
		cap_free(data_caps);
		return false;
	}
	cap_free(data_caps);

	return on == CAP_SET;
}

static bool record_spx_conn(struct bind_entry *e, struct
		ipxw_mux_msg_spx_connect *conn_req, int conn_fd, struct
		ipxw_mux_msg_spx_connect *conn_rsp, bool accepted)
{
	struct ipx_addr bind_addr = {
		.net = e->iface->addr.net,
		.sock = e->ipx_sock
	};
	memcpy(bind_addr.node, e->iface->addr.node, IPX_ADDR_NODE_BYTES);

	/* fill in the response */
	conn_rsp->addr = bind_addr;
	conn_rsp->err = ENOTSUP;

	__be16 conn_id = find_next_free_spx_conn_id(e);
	/* no free connection ID */
	if (conn_id == SPX_CONN_ID_UNKNOWN) {
		conn_rsp->err = EACCES;
		return false;
	}

	/* make and fill new connection entry */
	struct spx_connection *conn = calloc(1, sizeof(struct spx_connection));
	if (conn == NULL) {
		perror("allocating connection");
		conn_rsp->err = errno;
		return false;
	}
	conn->conn_id = conn_id;

	struct spx_conn_key spx_key = {
		.bind_addr = bind_addr,
		.conn_id = conn_id
	};

	do {
		/* register the connection in the BPF maps */
		struct bpf_spx_state spx_state = {
			.remote_addr = conn_req->addr,
			.local_addr = bind_addr,
			.remote_id = (accepted ? conn_req->conn_id :
					SPX_CONN_ID_UNKNOWN),
			.local_id = conn_id,
			.remote_alloc_no = 0,
			.local_alloc_no = 0,
			.remote_expected_sequence = 0,
			.local_current_sequence = 0,
			.neg_size_to_local = 0,
			.prefix = e->iface->prefix
		};
		__u64 conn_fd64 = conn_fd;
		int err =
			bpf_map__update_elem(bpf_kern->maps.ipx_wrap_mux_spx_sock_ingress,
					&spx_key, sizeof(struct spx_conn_key),
					&conn_fd64, sizeof(__u64),
					BPF_NOEXIST);
		if (err != 0) {
			errno = -err;
			perror("registering SPX connection in BPF map");
			conn_rsp->err = errno;
			break;
		}
		__u32 conn_fd32 = conn_fd;
		err =
			bpf_map__update_elem(bpf_kern->maps.ipx_wrap_mux_spx_state,
					&conn_fd32, sizeof(__u32), &spx_state,
					sizeof(struct bpf_spx_state),
					BPF_NOEXIST);
		if (err != 0) {
			errno = -err;
			perror("registering SPX connection in BPF map");
			conn_rsp->err = errno;
			break;
		}

		/* save SPX connection */
		HASH_ADD_INORDER(hh, e->ht_id_to_spx_conn, conn_id,
				sizeof(__be16), conn, sort_spx_conn_by_id);

		/* reset the error code for the response */
		conn_rsp->err = 0;
		conn_rsp->conn_id = conn_id;

		/* show the new SPX connection */
		printf("SPX connection %04hx: "
				"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx -> "
				"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx\n",
				ntohs(conn_id),
				ntohl(bind_addr.net),
				bind_addr.node[0], bind_addr.node[1],
				bind_addr.node[2], bind_addr.node[3],
				bind_addr.node[4], bind_addr.node[5],
				ntohs(bind_addr.sock),
				ntohl(conn_req->addr.net),
				conn_req->addr.node[0], conn_req->addr.node[1],
				conn_req->addr.node[2], conn_req->addr.node[3],
				conn_req->addr.node[4], conn_req->addr.node[5],
				ntohs(conn_req->addr.sock));

		return true;
	} while (0);

	/* remove the SPX connection from the BPF maps */
	bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_spx_sock_ingress,
			&spx_key, sizeof(struct spx_conn_key), 0);
	__u32 conn_fd32 = conn_fd;
	bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_spx_state, &conn_fd32,
			sizeof(__u32), 0);

	free(conn);
	return false;
}

static bool record_bind(struct if_entry *iface, struct ipxw_mux_handle h, int
		epoll_fd, struct ipxw_mux_msg_bind *bind_msg)
{
	/* not sure how we got this message, but we can only bind to the
	 * address of our interface */
	if (iface->addr.net != bind_msg->addr.net) {
		fprintf(stderr, "bind address not allowed\n");
		errno = EACCES;
		return false;
	}
	if (memcmp(iface->addr.node, bind_msg->addr.node, IPX_ADDR_NODE_BYTES)
			!= 0) {
		fprintf(stderr, "bind address not allowed\n");
		errno = EACCES;
		return false;
	}

	/* no socket was specified, find the lowest dynamic socket */
	if (ntohs(bind_msg->addr.sock) == 0) {
		__be16 next_free_dyn_sock = find_next_free_dyn_sock(iface);
		if (ntohs(next_free_dyn_sock) >=
				ntohs(IPX_MIN_WELL_KNOWN_SOCKET)) {
			fprintf(stderr, "dynamic sockets exhausted\n");
			errno = EADDRINUSE;
			return false;
		}

		bind_msg->addr.sock = next_free_dyn_sock;
	}

	/* socket already in use */
	struct bind_entry *e = get_bind_entry_by_ipx_sock(iface,
			bind_msg->addr.sock);
	if (e != NULL) {
		fprintf(stderr, "binding already in use\n");
		errno = EADDRINUSE;
		return false;
	}

	/* the process trying to bind needs CAP_NET_BIND_SERVICE to use one of
	 * the low sockets */
	if (ntohs(bind_msg->addr.sock) < ntohs(IPX_MIN_DYNAMIC_SOCKET)) {
		if (!has_net_bind_service(h)) {
			fprintf(stderr, "bind to low socket not permitted\n");
			errno = EACCES;
			return false;
		}
	}

	/* make and fill new binding entry */
	e = calloc(1, sizeof(struct bind_entry));
	if (e == NULL) {
		perror("allocating binding");
		return false;
	}

	e->conf_sock = ipxw_mux_handle_conf(h);
	e->ipx_sock = bind_msg->addr.sock;
	e->iface = iface;
	e->pkt_type = bind_msg->pkt_type;
	e->pkt_type_any = bind_msg->pkt_type_any;
	e->recv_bcast = bind_msg->recv_bcast;
	e->ht_id_to_spx_conn = NULL;
	STAILQ_INIT(&e->conf_queue);

	struct mc_bind_entry_key map_key_mc = {
		.ifidx = iface->ifidx,
		.dst_sock = bind_msg->addr.sock
	};

	do {
		/* register the binding in the BPF maps */
		struct bpf_bind_entry be = {
			.addr = bind_msg->addr,
			.prefix = iface->prefix,
			.pkt_type = bind_msg->pkt_type,
			.pkt_type_any = bind_msg->pkt_type_any,
			.recv_bcast = bind_msg->recv_bcast
		};
		int err =
			bpf_map__update_elem(bpf_kern->maps.ipx_wrap_mux_bind_entries_uc,
					&(bind_msg->addr), sizeof(struct
						ipx_addr), &be, sizeof(struct
							bpf_bind_entry),
					BPF_NOEXIST);
		if (err != 0) {
			errno = -err;
			perror("registering unicast binding in BPF map");
			break;
		}
		err =
			bpf_map__update_elem(bpf_kern->maps.ipx_wrap_mux_bind_entries_mc,
					&map_key_mc, sizeof(struct
						mc_bind_entry_key), &be,
					sizeof(struct bpf_bind_entry),
					BPF_NOEXIST);
		if (err != 0) {
			errno = -err;
			perror("registering multicast binding in BPF map");
			break;
		}

		/* register the data socket in the BPF maps */
		__u64 data_sock_fd64 = ipxw_mux_handle_data(h);
		err =
			bpf_map__update_elem(bpf_kern->maps.ipx_wrap_mux_sock_ingress,
					&(bind_msg->addr), sizeof(struct
						ipx_addr), &data_sock_fd64,
					sizeof(__u64), BPF_NOEXIST);
		if (err != 0) {
			errno = -err;
			perror("registering data socket in BPF map");
			break;
		}
		__u32 data_sock_fd32 = ipxw_mux_handle_data(h);
		err =
			bpf_map__update_elem(bpf_kern->maps.ipx_wrap_mux_bind_egress,
					&data_sock_fd32, sizeof(__u32),
					&(bind_msg->addr), sizeof(struct
						ipx_addr), BPF_NOEXIST);
		if (err != 0) {
			errno = -err;
			perror("registering data socket in BPF map");
			break;
		}

		/* register for epoll */
		/* config socket */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP,
			.data = {
				.fd = ipxw_mux_handle_conf(h)
			}
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_conf(h),
					&ev) < 0) {
			perror("registering for event polling");
			break;
		}

		/* save binding */
		HASH_ADD_INORDER(h_ipx_sock, iface->ht_ipx_sock_to_bind,
				ipx_sock, sizeof(__be16), e,
				sort_bind_entry_by_ipx_sock);
		HASH_ADD_INT(ht_conf_sock_to_bind, conf_sock, e);

		/* show the new binding in full */
		printf("bound %d:%d to %08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx, ",
				ipxw_mux_handle_data(h),
				ipxw_mux_handle_conf(h),
				ntohl(bind_msg->addr.net),
				bind_msg->addr.node[0], bind_msg->addr.node[1],
				bind_msg->addr.node[2], bind_msg->addr.node[3],
				bind_msg->addr.node[4], bind_msg->addr.node[5],
				ntohs(bind_msg->addr.sock));
		if (bind_msg->pkt_type_any) {
			printf("pkt type: any, ");
		} else {
			printf("pkt type: %02hhx, ", bind_msg->pkt_type);
		}
		printf("recv bcasts: %s\n", bind_msg->recv_bcast ? "yes" :
				"no");

		return true;
	} while (0);

	/* remove the bind entries from the BPF maps */
	bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_bind_entries_uc,
			&(bind_msg->addr), sizeof(struct ipx_addr), 0);
	bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_bind_entries_mc,
			&map_key_mc, sizeof(struct mc_bind_entry_key), 0);

	/* remove the data socket from the BPF maps */
	bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_sock_ingress,
			&(bind_msg->addr), sizeof(struct ipx_addr), 0);

	free(e);
	return false;
}

static void delete_spx_conn(struct bind_entry *e, struct spx_connection *conn)
{
	struct spx_conn_key conn_key = {
		.bind_addr = {
			.net = e->iface->addr.net,
			.sock = e->ipx_sock
		},
		.conn_id = conn->conn_id
	};
	memcpy(conn_key.bind_addr.node, e->iface->addr.node,
			IPX_ADDR_NODE_BYTES);

	bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_spx_sock_ingress,
			&conn_key, sizeof(struct spx_conn_key), 0);

	HASH_DEL(e->ht_id_to_spx_conn, conn);
	free(conn);

	printf("SPX connection %04hx closed\n", ntohs(conn_key.conn_id));
}

static void unbind_entry(struct bind_entry *e)
{
	assert(e != NULL);

	/* remove all undelivered config messages */
	while (!STAILQ_EMPTY(&e->conf_queue)) {
		struct ipxw_mux_msg *msg = STAILQ_FIRST(&e->conf_queue);
		STAILQ_REMOVE_HEAD(&e->conf_queue, q_entry);
		free(msg);
	}

	struct spx_connection *spx_conn;
	struct spx_connection *spx_conn_tmp;
	HASH_ITER(hh, e->ht_id_to_spx_conn, spx_conn, spx_conn_tmp) {
		delete_spx_conn(e, spx_conn);
	}

	/* remove the bind entries from the BPF maps */
	struct ipx_addr map_key_uc = {
		.net = e->iface->addr.net,
		.sock = e->ipx_sock
	};
	memcpy(map_key_uc.node, e->iface->addr.node, IPX_ADDR_NODE_BYTES);
	bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_bind_entries_uc,
			&map_key_uc, sizeof(struct ipx_addr), 0);

	struct mc_bind_entry_key map_key_mc = {
		.ifidx = e->iface->ifidx,
		.dst_sock = e->ipx_sock
	};
	bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_bind_entries_mc,
			&map_key_mc, sizeof(struct mc_bind_entry_key), 0);

	/* remove the data socket from the BPF maps */
	bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_sock_ingress,
			&map_key_uc, sizeof(struct ipx_addr), 0);

	/* remove the bind entry from all data structures */
	HASH_DELETE(h_ipx_sock, e->iface->ht_ipx_sock_to_bind, e);
	HASH_DEL(ht_conf_sock_to_bind, e);

	int conf_sock = e->conf_sock;

	/* close the socket and free */
	close(conf_sock);
	free(e);

	printf("%d unbound\n", conf_sock);
}

static bool queue_conf_msg(struct bind_entry *be, struct ipxw_mux_msg *msg, int epoll_fd)
{
	/* reregister for ready-to-write events, now that config messages are
	 * available */
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
		.data.fd = be->conf_sock
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, be->conf_sock,
				&ev) < 0) {
		return false;
	}

	/* queue the config message on the config socket */
	STAILQ_INSERT_TAIL(&be->conf_queue, msg, q_entry);

	return true;
}

static bool handle_conf_msg(int conf_sock, struct ipxw_mux_msg *msg, int fd,
		void *ctx)
{
	struct do_ctx *context = (struct do_ctx *) ctx;
	struct bind_entry *be_conf = context->be;
	if (be_conf == NULL) {
		return false;
	}

	/* check message type and prepare response */
	struct ipxw_mux_msg *rsp_msg = NULL;
	bool spx_accepted = false;
	enum ipxw_mux_msg_type spx_rsp_type = IPXW_MUX_SPX_CONNECT;
	switch (msg->type) {
		case IPXW_MUX_UNBIND:
			unbind_entry(be_conf);
			return true;
		case IPXW_MUX_GETSOCKNAME:
			rsp_msg = calloc(1, sizeof(struct ipxw_mux_msg));
			if (rsp_msg == NULL) {
				return false;
			}

			rsp_msg->type = IPXW_MUX_GETSOCKNAME;
			rsp_msg->getsockname.addr.net =
				be_conf->iface->addr.net;
			memcpy(rsp_msg->getsockname.addr.node,
					be_conf->iface->addr.node,
					IPX_ADDR_NODE_BYTES);
			rsp_msg->getsockname.addr.sock = be_conf->ipx_sock;
			rsp_msg->getsockname.pkt_type = be_conf->pkt_type;
			rsp_msg->getsockname.recv_bcast = be_conf->recv_bcast;
			rsp_msg->getsockname.pkt_type_any =
				be_conf->pkt_type_any;

			break;
		case IPXW_MUX_SPX_ACCEPT:
			spx_accepted = true;
			spx_rsp_type = IPXW_MUX_SPX_ACCEPT;
		case IPXW_MUX_SPX_CONNECT:
			/* we need the fd */
			if (fd < 0) {
				return false;
			}

			rsp_msg = calloc(1, sizeof(struct ipxw_mux_msg));
			if (rsp_msg == NULL) {
				close(fd);
				return false;
			}
			rsp_msg->type = spx_rsp_type;

			/* no error handling, if we get this far the response
			 * message will contain the appropriate error */
			record_spx_conn(be_conf, &(msg->spx_connect), fd,
					&(rsp_msg->spx_connect), spx_accepted);

			close(fd);
			break;
		case IPXW_MUX_SPX_CLOSE:
			struct spx_connection *conn = NULL;
			HASH_FIND_INT(be_conf->ht_id_to_spx_conn,
					&(msg->spx_close.conn_id), conn);
			if (conn != NULL) {
				delete_spx_conn(be_conf, conn);
			}
			return true;
		default:
			return false;
	}

	/* if we reach this code there must be a response message */
	assert(rsp_msg != NULL);

	int epoll_fd = context->epoll_fd;
	if (!queue_conf_msg(be_conf, rsp_msg, epoll_fd)) {
		free(rsp_msg);
		return false;
	}

	return true;
}

static ssize_t conf_msg(struct bind_entry *be_conf, int epoll_fd)
{
	assert(be_conf != NULL);

	ssize_t expected = ipxw_mux_peek_conf_len(be_conf->conf_sock);
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
	ssize_t err = ipxw_mux_do_conf(be_conf->conf_sock, msg,
			&handle_conf_msg, &ctx);

	/* always get rid of the message, it is handled immediately in
	 * ipxw_mux_do_conf */
	free(msg);

	return err;
}

static ssize_t conf_rsp(struct bind_entry *be, int epoll_fd)
{
	assert(be != NULL);

	/* no conf msgs to send */
	if (STAILQ_EMPTY(&be->conf_queue)) {
		/* unregister from ready-to-write events to avoid busy polling
		 */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP,
			.data.fd = be->conf_sock
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, be->conf_sock, &ev);

		return 0;
	}

	struct ipxw_mux_msg *msg = STAILQ_FIRST(&be->conf_queue);
	ssize_t err = ipxw_mux_recv_conf(be->conf_sock, msg);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return 0;
		}

		/* other error, make sure to get rid of the message */
	}

	STAILQ_REMOVE_HEAD(&be->conf_queue, q_entry);
	free(msg);

	return err;
}

static void cleanup_sub_process_bpf_bindings(struct sub_process *sub)
{
	struct ipx_addr sock_key;
	struct ipx_addr sock_key_next;

	int res =
		bpf_map__get_next_key(bpf_kern->maps.ipx_wrap_mux_sock_ingress,
				NULL, &sock_key, sizeof(struct ipx_addr));
	for (; res == 0; sock_key = sock_key_next) {
		/* fetch the next key first, since we modify the map below */
		res = bpf_map__get_next_key(
				bpf_kern->maps.ipx_wrap_mux_sock_ingress,
				&sock_key, &sock_key_next, sizeof(struct
					ipx_addr));

		/* this entry does not belong to the sub-process, skip */
		if (memcmp(&(sub->addr), &sock_key, sizeof(struct ipx_if_addr))
				!= 0) {
			continue;
		}

		fprintf(stderr, "cleaning up mapping for %08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx\n",
				ntohl(sock_key.net), sock_key.node[0],
				sock_key.node[1], sock_key.node[2],
				sock_key.node[3], sock_key.node[4],
				sock_key.node[5], ntohs(sock_key.sock));

		/* remove the bind entries from the BPF maps */
		bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_bind_entries_uc,
				&sock_key, sizeof(struct ipx_addr), 0);
		struct mc_bind_entry_key mc_key = {
			.ifidx = sub->ifidx,
			.dst_sock = sock_key.sock
		};
		bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_bind_entries_mc,
				&mc_key, sizeof(struct mc_bind_entry_key), 0);

		/* remove the data socket from the BPF maps */
		bpf_map__delete_elem(bpf_kern->maps.ipx_wrap_mux_sock_ingress,
				&sock_key, sizeof(struct ipx_addr), 0);
	}
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

		cleanup_sub_process_bpf_bindings(sub);
		bpf_link__detach(sub->ingress_link);
		bpf_link__detach(sub->egress_link);
		bpf_link__destroy(sub->ingress_link);
		bpf_link__destroy(sub->egress_link);
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
	/* remove all bindings */
	struct bind_entry *e;
	struct bind_entry *tmp;
	HASH_ITER(h_ipx_sock, iface->ht_ipx_sock_to_bind, e, tmp) {
		unbind_entry(e);
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
	/* main process exiting */
	} else {
		/* close and remove all BPF objects */
		if (bpf_kern != NULL) {
			ipx_wrap_mux_kern__destroy(bpf_kern);
		}
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

	/* determine the ifindex */
	__u32 ifidx = if_nametoindex(ifname);
	if (ifidx == 0) {
		free(iface);
		return NULL;
	}

	iface->ifidx = ifidx;

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
		resp_msg.err.err = errno;
		ipxw_mux_send_bind_resp(ipxw_mux_handle_conf(h), &resp_msg);
		ipxw_mux_handle_close(h);

		return -1;
	}

	/* binding succeeded, send ack response */
	resp_msg.err.err = 0;
	resp_msg.type = IPXW_MUX_BIND_ACK;
	resp_msg.ack.prefix = iface->prefix;
	ipxw_mux_send_bind_resp(ipxw_mux_handle_conf(h), &resp_msg);

	close(ipxw_mux_handle_data(h));

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

	struct ipxw_mux_handle h = ipxw_mux_recv_bind_msg(ctrl_sock,
			&bind_msg);
	/* couldn't even receive the bind msg, just quit */
	if (ipxw_mux_handle_is_error(h)) {
		return -1;
	}
	assert(bind_msg.type == IPXW_MUX_BIND);

	do {
		/* illegal networks, reject */
		if (bind_msg.bind.addr.net == IPX_NET_LOCAL) {
			fprintf(stderr, "no net to bind to specified\n");
			errno = EADDRNOTAVAIL;
			break;
		}
		if (bind_msg.bind.addr.net == IPX_NET_ALL_ROUTES) {
			fprintf(stderr, "binding to all routes net not "
					"allowed\n");
			errno = EACCES;
			break;
		}
		if (bind_msg.bind.addr.net == IPX_NET_DEFAULT_ROUTE) {
			fprintf(stderr, "binding to default route net not "
					"allowed\n");
			errno = EACCES;
			break;
		}

		/* illegal node bindings */
		if (memcmp(bind_msg.bind.addr.node, IPX_BCAST_NODE,
					IPX_ADDR_NODE_BYTES) == 0) {
			fprintf(stderr, "binding to broadcast node not "
					"allowed\n");
			errno = EACCES;
			break;
		}

		struct sub_process *sub = NULL;
		/* no node address specified, guess from the network */
		if (memcmp(bind_msg.bind.addr.node, IPX_NO_NODE,
					IPX_ADDR_NODE_BYTES) == 0) {
			struct sub_process *se = NULL;
			struct sub_process *stmp = NULL;
			/* find a sub-process with a matching network number...
			 */
			HASH_ITER(h_ipx_addr, ht_ipx_addr_to_sub, se, stmp) {
				if (bind_msg.bind.addr.net == se->addr.net) {
					/* ... and take the node part */
					memcpy(bind_msg.bind.addr.node,
							se->addr.node,
							IPX_ADDR_NODE_BYTES);
					sub = se;
					break;
				}
			}
		} else {
			struct ipx_if_addr addr;
			addr.net = bind_msg.bind.addr.net;
			memcpy(addr.node, bind_msg.bind.addr.node,
					IPX_ADDR_NODE_BYTES);
			sub = get_sub_process_by_ipx_addr(&addr);
		}

		/* no sub-process listening on the desired interface */
		if (sub == NULL) {
			fprintf(stderr, "no interface with the specified "
					"address\n");
			errno = EADDRNOTAVAIL;
			break;
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
		int fds[2] = { ipxw_mux_handle_data(h), ipxw_mux_handle_conf(h)
		};
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
			fprintf(stderr, "failed to pass binding to "
					"sub-process\n");
			errno = EINVAL;
			break;
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
			fprintf(stderr, "failed to pass binding to "
					"sub-process\n");
			break;
		}

		ipxw_mux_handle_close(h);
		return 0;
	} while (0);

	/* reject binding and send back error */
	err_msg.err.err = errno;
	ipxw_mux_send_bind_resp(ipxw_mux_handle_conf(h), &err_msg);
	ipxw_mux_handle_close(h);

	return -1;
}

static void signal_handler(int signal)
{
	switch (signal) {
		case SIGHUP:
			rescan_now = true;
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

static _Noreturn void do_sub_process(struct if_entry *iface, int ctrl_sock)
{
	int epoll_fd = -1;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(iface, epoll_fd, ctrl_sock, MUX_ERR_EPOLL_FD);
	}

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ctrl_sock
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctrl_sock, &ev) < 0) {
		perror("registering ctrl socket for event polling");
		cleanup_and_exit(iface, epoll_fd, ctrl_sock, MUX_ERR_CTRL_FD);
	}

	/* ignore SIGHUP, keep handler for SIGINT, SIGQUIT and SIGTERM */
	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("resetting signal handler");
		cleanup_and_exit(iface, epoll_fd, ctrl_sock,
				MUX_ERR_SIG_HANDLER);
	}
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = SIG_IGN;
	if (sigaction(SIGHUP, &sig_act, NULL) < 0) {
		perror("resetting signal handler");
		cleanup_and_exit(iface, epoll_fd, ctrl_sock,
				MUX_ERR_SIG_HANDLER);
	}

	ssize_t err;
	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(iface, epoll_fd, ctrl_sock,
					MUX_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* ctrl socket */
			if (evs[i].data.fd == ctrl_sock) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "control socket error\n");
					cleanup_and_exit(iface, epoll_fd,
							ctrl_sock,
							MUX_ERR_CTRL_FAILURE);
				}

				/* incoming bind msg */
				err = handle_bind_msg_sub(iface, ctrl_sock,
						epoll_fd);
				if (err < 0 && errno != EINTR) {
					perror("handle binding");
				}

				continue;
			}

			/* one of the config sockets */
			struct bind_entry *e =
				get_bind_entry_by_conf_sock(evs[i].data.fd);
			/* bindind already deleted */
			if (e == NULL) {
				continue;
			}

			/* incoming conf msg */
			if (evs[i].events & EPOLLIN) {
				err = conf_msg(e, epoll_fd);
				if (err < 0 && errno != EINTR) {
					perror("handling conf msg");
				} else if (err == 0) {
					/* should not happen */
					continue;
				}

				/* this is important!
				 * conf_msg could have deleted the
				 * binding, therefore we need to check
				 * if it still exists at this point */
				e =
					get_bind_entry_by_conf_sock(evs[i].data.fd);
				if (e == NULL) {
					continue;
				}
			}

			/* outgoing conf response */
			if (evs[i].events & EPOLLOUT) {
				err = conf_rsp(e, epoll_fd);
				if (err < 0) {
					/* get rid of the client */
					perror("sending conf msg");
					unbind_entry(e);
					continue;
				} else if (err == 0) {
					/* nothing happened */
				}
			}

			/* something went wrong, unbind */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				unbind_entry(e);
				continue;
			}
		}
	}

	cleanup_and_exit(iface, epoll_fd, ctrl_sock, MUX_ERR_OK);
}

static struct sub_process *add_sub(struct ipv6_eui64_addr *ipv6_addr, const
		char *ifname, int epoll_fd, int ctrl_sock)
{
	struct sub_process *sub = calloc(1, sizeof(struct sub_process));
	if (sub == NULL) {
		fprintf(stderr, "failed to allocate sub-process\n");
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

		sub->ifidx = if_nametoindex(ifname);
		if (sub->ifidx == 0) {
			break;
		}

		iface = mk_iface(ipv6_addr, ifname);
		if (iface == NULL) {
			break;
		}

		/* attach the ingress demuxer to the interface */
		sub->ingress_link =
			bpf_program__attach_tcx(bpf_kern->progs.ipx_wrap_demux,
					sub->ifidx, NULL);
		if (sub->ingress_link == NULL) {
			break;
		}

		/* attach the egress muxer to the interface */
		sub->egress_link =
			bpf_program__attach_tcx(bpf_kern->progs.ipx_wrap_mux,
					sub->ifidx, NULL);
		if (sub->egress_link == NULL) {
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

	fprintf(stderr, "failed to add interface "
			"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
			ntohl(sub->addr.net), sub->addr.node[0],
			sub->addr.node[1], sub->addr.node[2],
			sub->addr.node[3], sub->addr.node[4],
			sub->addr.node[5]);

	if (sv[1] >= 0) {
		close(sv[1]);
	}
	if (sub->ingress_link != NULL) {
		bpf_link__detach(sub->ingress_link);
		bpf_link__destroy(sub->ingress_link);
	}
	if (sub->egress_link != NULL) {
		bpf_link__detach(sub->egress_link);
		bpf_link__destroy(sub->egress_link);
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
		if (ipv6_addr->prefix != prefix) {
			continue;
		}

		if (iter->ifa_name == NULL) {
			continue;
		}

		/* get or create a new sub-process for this address */
		struct sub_process *if_sub = add_sub(ipv6_addr, iter->ifa_name,
				epoll_fd, ctrl_sock);
		/* an error occurred during process creation, try next
		 * interface address */
		if (if_sub == NULL) {
			continue;
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

static bool setup_bpf(void)
{
	/* load the muxer/demuxer bpf programs and maps */
	bpf_kern = ipx_wrap_mux_kern__open_and_load();
	if (bpf_kern == NULL) {
		return false;
	}

	return true;
}

static _Noreturn void usage()
{
	printf("Usage: ipx_wrap_mux <32-bit hex prefix>\n");
	exit(MUX_ERR_USAGE);
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

	if (!setup_bpf()) {
		perror("load BPF kernel objects");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, MUX_ERR_BPF);
	}

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, MUX_ERR_EPOLL_FD);
	}

	tmr_fd = setup_timer(epoll_fd);
	if (tmr_fd < 0) {
		perror("creating interface rescan timer");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, MUX_ERR_TMR_FD);
	}

	/* scan all interfaces for addresses within the prefix, we manage those
	 * interfaces */
	if (!scan_interfaces(prefix, epoll_fd, ctrl_sock)) {
		perror("adding sub-process");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock,
				MUX_ERR_IFACE_SCAN);
	}

	ctrl_sock = ipxw_mux_mk_ctrl_sock();
	if (ctrl_sock < 0) {
		perror("creating ctrl socket");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, MUX_ERR_CTRL_FD);
	}

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ctrl_sock
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctrl_sock, &ev) < 0) {
		perror("registering ctrl socket for event polling");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock, MUX_ERR_CTRL_FD);
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGHUP, &sig_act, NULL) < 0
			|| sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting signal handler");
		cleanup_and_exit(NULL, epoll_fd, ctrl_sock,
				MUX_ERR_SIG_HANDLER);
	}

	ssize_t err;
	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		/* received SIGHUP, do interface rescan immediately */
		if (rescan_now) {
			if (!scan_interfaces(prefix, epoll_fd, ctrl_sock)) {
				perror("adding sub-process");
				cleanup_and_exit(NULL, epoll_fd, ctrl_sock,
						MUX_ERR_IFACE_SCAN);
			}
			rescan_now = false;
		}

		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(NULL, epoll_fd, ctrl_sock,
					MUX_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* ctrl socket */
			if (evs[i].data.fd == ctrl_sock) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "control socket error\n");
					cleanup_and_exit(NULL, epoll_fd,
							ctrl_sock,
							MUX_ERR_CTRL_FAILURE);
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
							ctrl_sock,
							MUX_ERR_TMR_FAILURE);
				}

				/* rescan the interfaces */
				if (!scan_interfaces(prefix, epoll_fd,
							ctrl_sock)) {
					perror("adding sub-process");
					cleanup_and_exit(NULL, epoll_fd,
							ctrl_sock,
							MUX_ERR_IFACE_SCAN);
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

	cleanup_and_exit(NULL, epoll_fd, ctrl_sock, MUX_ERR_OK);

	return 0;
}
