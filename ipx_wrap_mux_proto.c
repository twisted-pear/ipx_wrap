#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "uthash.h"
#include "ipx_wrap_mux_proto.h"

void ipxw_mux_handle_close(struct ipxw_mux_handle h)
{
	if (h.data_sock >= 0) {
		close(h.data_sock);
	}
	if (h.conf_sock >= 0) {
		close(h.conf_sock);
	}

	h.data_sock = -1;
	h.conf_sock = -1;
	h.prefix = 0;
}

bool ipxw_mux_handle_is_error(struct ipxw_mux_handle h)
{
	// TODO: only for conf sock?
	return (h.data_sock < 0) || (h.conf_sock < 0);
}

int ipxw_mux_handle_data(struct ipxw_mux_handle h)
{
	return h.data_sock;
}

int ipxw_mux_handle_conf(struct ipxw_mux_handle h)
{
	return h.conf_sock;
}

/* socket-like api */

struct ipxw_mux_sk {
	/* the data socket, is a key for the hash table */
	int data_sock;
	/* hash entry */
	UT_hash_handle hh; /* by data socket */
	struct ipx_addr bind_addr;
	struct ipxw_mux_handle h;
	bool bound;
	bool cloexec;
};

struct ipxw_mux_sk_buffer {
	union {
		struct ipxw_mux_msg mux_msg;
		__u8 buf[IPXW_MUX_MSG_LEN];
	};
};

_Static_assert(sizeof(struct ipxw_mux_sk_buffer) - offsetof(struct
			ipxw_mux_msg, data) == IPX_MAX_DATA_LEN);

struct ipxw_mux_sk_buffer sk_buf;

struct ipxw_mux_sk *ht_fd_to_mux_sk = NULL;

int ipxw_mux_sk_socket(int domain, int type, int protocol)
{
	/* IPX or nothing */
	if (domain != AF_IPX) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	/* caller must implement SPX themself if they need it */
	if ((type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) != SOCK_DGRAM) {
		errno = ESOCKTNOSUPPORT;
		return -1;
	}

	/* reject unsupported flags */
	if ((type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC | SOCK_DGRAM)) != 0) {
		errno = EINVAL;
		return -1;
	}

	int data_sock = ipxw_mux_mk_data_sock();
	if (data_sock < 0) {
		return -1;
	}

	struct ipxw_mux_sk *sk = NULL;
	do {
		if ((type & SOCK_NONBLOCK) != 0) {
			if (fcntl(data_sock, F_SETFL, O_NONBLOCK) < 0) {
				break;
			}
		}

		if ((type & SOCK_CLOEXEC) != 0) {
			if (fcntl(data_sock, F_SETFL, FD_CLOEXEC) < 0) {
				break;
			}
		}

		/* a previous IPX socket wasn't closed properly and now there
		 * is a conflict, can't do anything here */
		HASH_FIND_INT(ht_fd_to_mux_sk, &data_sock, sk);
		if (sk != NULL) {
			sk = NULL;
			break;
		}

		sk = calloc(1, sizeof(struct ipxw_mux_sk));
		if (sk == NULL) {
			break;
		}

		sk->data_sock = data_sock;
		sk->cloexec = (type & SOCK_CLOEXEC) != 0;

		HASH_ADD_INT(ht_fd_to_mux_sk, data_sock, sk);

		return sk->data_sock;
	} while (0);

	if (sk != NULL) {
		free(sk);
	}

	close(data_sock);

	return -1;
}

int ipxw_mux_sk_bind(int sockfd, const struct sockaddr *addr, socklen_t
		addrlen)
{
	if (addrlen != sizeof(struct sockaddr_ipx)) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_ipx *ipx_addr = (struct sockaddr_ipx *) addr;
	if (ipx_addr->sipx_family != AF_IPX) {
		errno = EINVAL;
		return -1;
	}

	struct ipxw_mux_sk *sk;
	HASH_FIND_INT(ht_fd_to_mux_sk, &sockfd, sk);
	if (sk == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	struct ipxw_mux_msg bind_msg;
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr.sock = ipx_addr->sipx_port;
	bind_msg.bind.addr.net = ipx_addr->sipx_network;
	memcpy(bind_msg.bind.addr.node, ipx_addr->sipx_node,
			IPX_ADDR_NODE_BYTES);
	bind_msg.bind.pkt_type = ipx_addr->sipx_type;
	if (bind_msg.bind.pkt_type == IPXW_MUX_SK_PKT_TYPE_ANY) {
		bind_msg.bind.pkt_type_any = 1;
	}
	bind_msg.bind.recv_bcast = 1; /* apparently the in-kernel driver used
					 to do this too */

	struct ipxw_mux_handle h = ipxw_mux_bind_data_sock(&bind_msg,
			sk->data_sock);
	do {
		if (ipxw_mux_handle_is_error(h)) {
			/* ipxw_mux_bind_socketpair closed our sockets, get rid
			 * of the entry so it can't be reused */
			break;
		}

		if (sk->data_sock != h.data_sock) {
			/* this should never happen */
			ipxw_mux_unbind(h);
			errno = EINVAL;
			break;
		}

		if (sk->cloexec) {
			/* propagate the CLOEXEC flag to the config socket too
			 */
			if (fcntl(h.conf_sock, F_SETFL, FD_CLOEXEC) < 0) {
				ipxw_mux_unbind(h);
				break;
			}
		}

		sk->h = h;
		sk->bound = true;
		return 0;
	} while (0);

	HASH_DEL(ht_fd_to_mux_sk, sk);
	free(sk);
	return -1;
}

ssize_t ipxw_mux_sk_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	/* reject unsupported flags */
	if ((flags & ~(MSG_DONTWAIT)) != 0) {
		errno = EINVAL;
		return -1;
	}
	bool block = (flags & (MSG_DONTWAIT)) == 0;

	/* we need an IPX destination address */
	if (dest_addr == NULL || addrlen < sizeof(struct sockaddr_ipx)) {
		errno = EINVAL;
		return -1;
	}
	struct sockaddr_ipx *daddr = (struct sockaddr_ipx *) dest_addr;
	if (daddr->sipx_family != AF_IPX) {
		errno = EINVAL;
		return -1;
	}

	if (len > IPX_MAX_DATA_LEN) {
		errno = EMSGSIZE;
		return -1;
	}

	/* look up the socket */
	struct ipxw_mux_sk *sk;
	HASH_FIND_INT(ht_fd_to_mux_sk, &sockfd, sk);
	if (sk == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	/* socket has to be bound */
	if (!sk->bound) {
		errno = EINVAL;
		return -1;
	}

	/* prepare the xmit message */
	memset(&sk_buf, 0, sizeof(struct ipxw_mux_msg));
	sk_buf.mux_msg.type = IPXW_MUX_XMIT;

	/* fill in the destination address */
	sk_buf.mux_msg.xmit.data_len = len;
	sk_buf.mux_msg.xmit.daddr.sock = daddr->sipx_port;
	sk_buf.mux_msg.xmit.daddr.net = daddr->sipx_network;
	memcpy(sk_buf.mux_msg.xmit.daddr.node, daddr->sipx_node,
			IPX_ADDR_NODE_BYTES);
	sk_buf.mux_msg.xmit.pkt_type = daddr->sipx_type;

	/* copy over the data */
	memcpy(sk_buf.mux_msg.data, buf, len);
	sk_buf.mux_msg.xmit.data_len = len;

	/* send */
	ssize_t sent_len = ipxw_mux_xmit(sk->h, &sk_buf.mux_msg, block);
	/* clean up the buffer, regardless of result */
	memset(&sk_buf, 0, sizeof(sk_buf));
	if (sent_len < 0) {
		return -1;
	}

	/* return the length of the sent data */
	return sent_len - offsetof(struct ipxw_mux_msg, data);
}

ssize_t ipxw_mux_sk_recvfrom(int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen)
{
	/* reject unsupported flags */
	if ((flags & ~(MSG_DONTWAIT)) != 0) {
		errno = EINVAL;
		return -1;
	}
	bool block = (flags & (MSG_DONTWAIT)) == 0;

	/* filter invalid parameters */
	if (src_addr != NULL && addrlen == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* check for invalid addrlen */
	if (*addrlen < 0) {
		errno = EINVAL;
		return -1;
	}

	/* look up the socket */
	struct ipxw_mux_sk *sk;
	HASH_FIND_INT(ht_fd_to_mux_sk, &sockfd, sk);
	if (sk == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	/* socket has to be bound */
	if (!sk->bound) {
		errno = EINVAL;
		return -1;
	}

	/* can only receive this much */
	if (len > IPX_MAX_DATA_LEN) {
		errno = EINVAL;
		return -1;
	}

	/* receive */
	memset(&sk_buf, 0, sizeof(sk_buf));
	sk_buf.mux_msg.type = IPXW_MUX_RECV;
	sk_buf.mux_msg.recv.data_len = IPX_MAX_DATA_LEN;
	ssize_t rcvd_len = ipxw_mux_get_recvd(sk->h, &sk_buf.mux_msg, block);
	if (rcvd_len < 0) {
		return -1;
	}

	/* return the data */
	ssize_t ret_len = (len > sk_buf.mux_msg.recv.data_len) ?
		sk_buf.mux_msg.recv.data_len : len;
	memcpy(buf, sk_buf.mux_msg.data, ret_len);

	/* return the address, if desired */
	if (src_addr != NULL) {
		struct sockaddr_ipx saddr;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sipx_family = AF_IPX;
		saddr.sipx_port = sk_buf.mux_msg.recv.saddr.sock;
		saddr.sipx_network = sk_buf.mux_msg.recv.saddr.net;
		memcpy(saddr.sipx_node, sk_buf.mux_msg.recv.saddr.node,
				IPX_ADDR_NODE_BYTES);
		saddr.sipx_type = sk_buf.mux_msg.recv.pkt_type;

		socklen_t src_addr_len = (sizeof(saddr) > *addrlen) ? *addrlen
			: sizeof(saddr);
		memcpy(src_addr, &saddr, src_addr_len);
		*addrlen = sizeof(saddr);
	}

	return ret_len;
}

int ipxw_mux_sk_getsockname(int sockfd, struct sockaddr *restrict addr,
		socklen_t *restrict addrlen)
{
	/* filter invalid parameters */
	if (addr == NULL || addrlen == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* check for invalid addrlen */
	if (*addrlen < 0) {
		errno = EINVAL;
		return -1;
	}

	/* look up the socket */
	struct ipxw_mux_sk *sk;
	HASH_FIND_INT(ht_fd_to_mux_sk, &sockfd, sk);
	if (sk == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	/* socket has to be bound */
	if (!sk->bound) {
		errno = EINVAL;
		return -1;
	}

	/* prepare in message */
	struct ipxw_mux_msg in_msg;
	memset(&in_msg, 0, sizeof(in_msg));
	in_msg.type = IPXW_MUX_GETSOCKNAME;

	/* prepare out message */
	struct ipxw_mux_msg out_msg;
	memset(&out_msg, 0, sizeof(out_msg));
	out_msg.type = IPXW_MUX_CONF;

	ssize_t out_len = ipxw_mux_send_recv_conf_msg(sk->h, &in_msg,
			&out_msg);
	if (out_len < 0) {
		return -1;
	}

	/* verify output message */
	if (out_len != sizeof(out_msg)) {
		errno = EINVAL;
		return -1;
	}
	if (out_msg.type != IPXW_MUX_GETSOCKNAME) {
		errno = EINVAL;
		return -1;
	}

	/* return the address */
	struct sockaddr_ipx sk_addr;
	memset(&sk_addr, 0, sizeof(sk_addr));
	sk_addr.sipx_family = AF_IPX;
	sk_addr.sipx_port = out_msg.getsockname.addr.sock;
	sk_addr.sipx_network = out_msg.getsockname.addr.net;
	memcpy(sk_addr.sipx_node, out_msg.getsockname.addr.node,
			IPX_ADDR_NODE_BYTES);
	sk_addr.sipx_type = out_msg.getsockname.pkt_type_any ?
		IPXW_MUX_SK_PKT_TYPE_ANY : out_msg.getsockname.pkt_type;

	/* set the output length */
	socklen_t sk_addr_len = (sizeof(sk_addr) > *addrlen) ? *addrlen :
		sizeof(sk_addr);
	memcpy(addr, &sk_addr, sk_addr_len);
	*addrlen = sizeof(sk_addr);

	return 0;
}

int ipxw_mux_sk_close(int fd)
{
	struct ipxw_mux_sk *sk;
	HASH_FIND_INT(ht_fd_to_mux_sk, &fd, sk);
	if (sk == NULL) {
		errno = EBADF;
		return -1;
	}

	if (sk->bound) {
		ipxw_mux_unbind(sk->h);
	} else {
		/* unbind closes the handle itself */
		ipxw_mux_handle_close(sk->h);
	}
	HASH_DEL(ht_fd_to_mux_sk, sk);
	free(sk);

	return 0;
}

/* client functions */

int ipxw_mux_mk_data_sock(void)
{
	int data_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (data_sock < 0) {
		return -1;
	}

	// TODO: fix this!
	struct sockaddr_in6 dummy_bind = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
		.sin6_port = 0,
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};

	if (bind(data_sock, (struct sockaddr *) &dummy_bind,
				sizeof(dummy_bind)) < 0) {
		close(data_sock);
		return -1;
	}

	return data_sock;
}

/* much of this code was taken from
 * https://man7.org/tlpi/code/online/dist/sockets/scm_rights_send.c.html */
struct ipxw_mux_handle ipxw_mux_bind_data_sock(const struct ipxw_mux_msg
		*bind_msg, int data_sock)
{
	struct ipxw_mux_handle ret = {
		.data_sock = -1,
		.conf_sock = -1,
		.prefix = 0
	};

	int ctrl_sock = -1;
	int sv_conf[2] = { -1, -1 };

	do {
		if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv_conf) < 0) {
			break;
		}

		/* force msg type */
		if (bind_msg->type != IPXW_MUX_BIND) {
			errno = EINVAL;
			break;
		}

		ctrl_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (ctrl_sock < 0) {
			break;
		}

		/* prepare control socket abstract name */
		struct sockaddr_un ctrl_addr;
		memset(&ctrl_addr, 0, sizeof(ctrl_addr));

		ctrl_addr.sun_family = AF_UNIX;
		socklen_t ctrl_addr_len = strlen(IPXW_MUX_CTRL_SOCK_NAME);
		memcpy(&ctrl_addr.sun_path[1], IPXW_MUX_CTRL_SOCK_NAME,
				ctrl_addr_len);
		ctrl_addr_len += offsetof(struct sockaddr_un, sun_path) + 1;

		struct msghdr msgh;
		msgh.msg_name = &ctrl_addr;
		msgh.msg_namelen = ctrl_addr_len;

		/* send the full message */
		struct iovec iov;
		iov.iov_base = (struct ipxw_mux_msg *) bind_msg;
		iov.iov_len = sizeof(*bind_msg);

		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;

		/* prepare the ancillary data buffer */

		int fds[2] = { data_sock, sv_conf[1] };
		union {
			char buf[CMSG_SPACE(sizeof(fds))]; /* Space large
							      enough to hold
							      two 'int's */
			struct cmsghdr align;
		} ctrl_msg;
		memset(ctrl_msg.buf, 0, sizeof(ctrl_msg.buf));

		msgh.msg_control = ctrl_msg.buf;
		msgh.msg_controllen = sizeof(ctrl_msg.buf);

		/* prepare ctrl msg header */
		struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
		if (cmsgp == NULL) {
			errno = EINVAL;
			break;
		}
		cmsgp->cmsg_level = SOL_SOCKET;
		cmsgp->cmsg_type = SCM_RIGHTS;

		/* store the socket fd we want to send */
		cmsgp->cmsg_len = CMSG_LEN(sizeof(fds));
		memcpy(CMSG_DATA(cmsgp), fds, sizeof(fds));

		/* send the ctrl msg, this blocks */
		/* should always transmit the entire msg or nothing */
		ssize_t sent_len = -1;
		do {
			sent_len = sendmsg(ctrl_sock, &msgh, 0);
		} while (sent_len < 0 && errno == EINTR);
		if (sent_len < 0) {
			break;
		}

		ret.data_sock = data_sock;
		ret.conf_sock = sv_conf[0];

		/* receive a reply, this blocks */
		struct ipxw_mux_msg res;
		ssize_t res_len = -1;
		do {
			res_len = recv(ret.conf_sock, &res, sizeof(res), 0);
		} while (res_len < 0 && errno == EINTR);
		if (res_len < 0) {
			break;
		}

		/* should not happen, but if it does we report the error */
		if (res_len != sizeof(res)) {
			errno = EREMOTEIO;
			break;
		}

		switch (res.type) {
			case IPXW_MUX_BIND_ACK:
				close(sv_conf[1]);
				close(ctrl_sock);
				ret.prefix = res.ack.prefix;
				return ret;
			case IPXW_MUX_BIND_ERR:
				errno = res.err.err;
				break;
			default:
				errno = ENOTSUP;
				break;
		}
	} while (0);

	close(data_sock);

	if (sv_conf[0] >= 0) {
		close(sv_conf[0]);
	}
	if (sv_conf[1] >= 0) {
		close(sv_conf[1]);
	}

	if (ctrl_sock >= 0) {
		close(ctrl_sock);
	}

	ret.data_sock = -1;
	ret.conf_sock = -1;
	return ret;
}

struct ipxw_mux_handle ipxw_mux_bind(const struct ipxw_mux_msg *bind_msg)
{
	struct ipxw_mux_handle err = {
		.data_sock = -1,
		.conf_sock = -1
	};

	int data_sock = ipxw_mux_mk_data_sock();
	if (data_sock < 0) {
		return err;
	}

	return ipxw_mux_bind_data_sock(bind_msg, data_sock);
}

void ipxw_mux_unbind(struct ipxw_mux_handle h)
{
	struct ipxw_mux_msg unbind_msg;

	/* no error handling, nothing that can be done */
	unbind_msg.type = IPXW_MUX_UNBIND;
	send(h.conf_sock, &unbind_msg, sizeof(unbind_msg), MSG_DONTWAIT);

	ipxw_mux_handle_close(h);
}

ssize_t ipxw_mux_send_recv_conf_msg(struct ipxw_mux_handle h, const struct
		ipxw_mux_msg *conf_in, struct ipxw_mux_msg *conf_out)
{
	size_t in_len = sizeof(struct ipxw_mux_msg);

	/* check message type and, if necessary, data length, adjust in_len */
	switch (conf_in->type) {
		case IPXW_MUX_GETSOCKNAME:
			break;
		default:
			errno = EOPNOTSUPP;
			return -1;

	}

	/* force out msg type */
	if (conf_out->type != IPXW_MUX_CONF) {
		errno = EINVAL;
		return -1;
	}

	/* check if out msg is sane */
	if (conf_out->conf.data_len > IPX_MAX_DATA_LEN) {
		errno = EINVAL;
		return -1;
	}

	/* send the message, this blocks */
	ssize_t sent_len = send(h.conf_sock, conf_in, in_len, 0);
	if (sent_len < 0) {
		return -1;
	}

	if (sent_len != in_len) {
		errno = ECOMM;
		return -1;
	}

	/* prepare length for receive */
	size_t expected_out_len = sizeof(struct ipxw_mux_msg) +
		conf_out->conf.data_len;

	/* receive the response, this blocks */
	ssize_t rcvd_len = -1;
	do {
		rcvd_len = recv(h.conf_sock, conf_out, expected_out_len, 0);
	} while (rcvd_len < 0 && errno == EINTR);
	if (rcvd_len < 0) {
		return -1;
	}

	/* we must at least receive a whole message */
	if (rcvd_len < sizeof(struct ipxw_mux_msg)) {
		errno = EREMOTEIO;
		return -1;
	}

	size_t out_len = sizeof(struct ipxw_mux_msg);

	/* check message type and, if necessary, data length, adjust out_len */
	switch (conf_in->type) {
		case IPXW_MUX_GETSOCKNAME:
			break;
		default:
			errno = EOPNOTSUPP;
			return -1;
	}

	/* the reply message must contain the correct length, if it has one */
	if (rcvd_len != out_len) {
		errno = EREMOTEIO;
		return -1;
	}

	return rcvd_len;
}

ssize_t ipxw_mux_xmit(struct ipxw_mux_handle h, const struct ipxw_mux_msg *msg,
		bool block)
{
	/* check message type */
	if (msg->type != IPXW_MUX_XMIT) {
		errno = EINVAL;
		return -1;
	}

	if (msg->xmit.data_len > IPX_MAX_DATA_LEN) {
		errno = EMSGSIZE;
		return -1;
	}

	size_t msg_len = sizeof(struct ipxw_mux_msg) + msg->xmit.data_len;

	struct sockaddr_in6 dummy_dst = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(IPX_IN_IPV6_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	struct ipv6_eui64_addr *dummy_daddr = (struct ipv6_eui64_addr *)
		&dummy_dst.sin6_addr;
	dummy_daddr->prefix = h.prefix;
	dummy_daddr->ipx_net = msg->xmit.daddr.net;
	memcpy(dummy_daddr->ipx_node_fst, msg->xmit.daddr.node,
			IPX_ADDR_NODE_BYTES / 2);
	dummy_daddr->fffe = htons(0xfffe);
	memcpy(dummy_daddr->ipx_node_snd, &(msg->xmit.daddr.node[3]),
			IPX_ADDR_NODE_BYTES / 2);

	/* send message, may block */
	/* rewriting to IPX happens in the BPF program */
	int flags = (block ? 0 : MSG_DONTWAIT);
	ssize_t sent_len = sendto(h.data_sock, msg, msg_len, flags, (struct
				sockaddr *) &dummy_dst, sizeof(dummy_dst));
	if (sent_len < 0) {
		return -1;
	}

	if (sent_len != msg_len) {
		errno = ECOMM;
		return -1;
	}

	return sent_len;
}

ssize_t ipxw_mux_peek_recvd_len(struct ipxw_mux_handle h, bool block)
{
	struct ipxw_mux_msg msg;

	int flags = (block ? 0 : MSG_DONTWAIT) | MSG_PEEK;
	ssize_t rcvd_len = recv(h.data_sock, &msg, sizeof(msg), flags);
	if (rcvd_len < 0) {
		return -1;
	}

	do {
		/* need the ipxw_mux_msg */
		if (rcvd_len != sizeof(msg)) {
			errno = EREMOTEIO;
			break;
		}

		// TODO: move to kernel
		if (ipxw_mux_ipxh_to_recv_msg((struct ipxhdr *) &msg) == NULL) {
			errno = EINVAL;
			break;
		}

		/* which has to be of the correct type */
		if (msg.type != IPXW_MUX_RECV) {
			errno = EINVAL;
			break;
		}

		/* and the data must fit */
		if (msg.recv.data_len > IPX_MAX_DATA_LEN) {
			errno = EREMOTEIO;
			break;
		}

		/* return the size of the message to receive */
		return msg.recv.data_len + sizeof(msg);
	} while (0);

	/* clear out invalid message */
	recv(h.data_sock, &msg, 0, 0);

	return -1;
}

ssize_t ipxw_mux_get_recvd(struct ipxw_mux_handle h, struct ipxw_mux_msg *msg,
		bool block)
{
	/* check if the msg buffer is ok */
	if (msg->type != IPXW_MUX_RECV) {
		errno = EINVAL;
		return -1;
	}

	if (msg->recv.data_len > IPX_MAX_DATA_LEN) {
		errno = EINVAL;
		return -1;
	}

	size_t max_msg_len = msg->recv.data_len + sizeof(struct ipxw_mux_msg);

	/* receive a msg, may block */
	int flags = (block ? 0 : MSG_DONTWAIT);
	ssize_t rcvd_len = recv(h.data_sock, msg, max_msg_len, flags);
	if (rcvd_len < 0) {
		return -1;
	}

	/* need at least a full msg */
	if (rcvd_len < sizeof(struct ipxw_mux_msg)) {
		errno = EREMOTEIO;
		return -1;
	}

	// TODO: move to kernel
	if (ipxw_mux_ipxh_to_recv_msg((struct ipxhdr *) msg) == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* which has to be of the correct type */
	if (msg->type != IPXW_MUX_RECV) {
		errno = EINVAL;
		return -1;
	}

	/* and the data needs to be the correct length */
	size_t data_len = rcvd_len - sizeof(struct ipxw_mux_msg);
	if (msg->recv.data_len != data_len) {
		errno = EREMOTEIO;
		return -1;
	}

	return rcvd_len;
}

/* muxer functions */

int ipxw_mux_mk_ctrl_sock()
{
	int ctrl_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (ctrl_sock < 0) {
		return -1;
	}

	struct sockaddr_un ctrl_addr;
	memset(&ctrl_addr, 0, sizeof(ctrl_addr));

	/* set address to well-known muxer address */
	ctrl_addr.sun_family = AF_UNIX;
	socklen_t ctrl_addr_len = strlen(IPXW_MUX_CTRL_SOCK_NAME);
	memcpy(&ctrl_addr.sun_path[1], IPXW_MUX_CTRL_SOCK_NAME,
			ctrl_addr_len);
	ctrl_addr_len += offsetof(struct sockaddr_un, sun_path) + 1;

	/* bind the socket */
	if (bind(ctrl_sock, (struct sockaddr *) &ctrl_addr, ctrl_addr_len) < 0) {
		close(ctrl_sock);
		return -1;
	}

	return ctrl_sock;
}

void ipxw_mux_send_bind_resp(int conf_sock, const struct
		ipxw_mux_msg *resp_msg)
{
	/* no error handling or reporting, since there is nothing we or the
	 * caller can do */
	if (resp_msg->type != IPXW_MUX_BIND_ERR && resp_msg->type !=
			IPXW_MUX_BIND_ACK) {
		return;
	}

	/* send the reply */
	ssize_t err;
	do {
		err = send(conf_sock, resp_msg, sizeof(struct ipxw_mux_msg),
				MSG_DONTWAIT);
	} while (err < 0 && errno == EINTR);
}

/* much of this code was taken from
 * https://man7.org/tlpi/code/online/dist/sockets/scm_rights_recv.c.html */
struct ipxw_mux_handle ipxw_mux_recv_bind_msg(int ctrl_sock, struct
		ipxw_mux_msg *bind_msg)
{
	struct ipxw_mux_handle ret = {
		.data_sock = -1,
		.conf_sock = -1
	};

	do {
		struct msghdr msgh;
		msgh.msg_name = NULL;
		msgh.msg_namelen = 0;

		struct iovec iov;
		iov.iov_base = bind_msg;
		iov.iov_len = sizeof(*bind_msg);

		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;

		/* prepare the ancillary data buffer */
		int fds[2];
		union {
			char buf[CMSG_SPACE(sizeof(fds))]; /* Space large
							      enough to hold
							      two 'int's */
			struct cmsghdr align;
		} ctrl_msg;

		msgh.msg_control = ctrl_msg.buf;
		msgh.msg_controllen = sizeof(ctrl_msg.buf);

		/* receive a bind message */
		/* this can block if the caller didn't check if data is
		 * available first */
		ssize_t rcvd_len = recvmsg(ctrl_sock, &msgh, 0);
		if (rcvd_len < 0) {
			break;
		}

		/* should not happen, but if it does we report the error */
		if (rcvd_len != sizeof(*bind_msg)) {
			errno = EREMOTEIO;
			break;
		}

		/* get ctrl msg */
		struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);

		/* validate ctrl msg */
		if (cmsgp == NULL) {
			errno = EINVAL;
			break;
		}
		if (cmsgp->cmsg_len != CMSG_LEN(sizeof(fds))) {
			errno = EINVAL;
			break;
		}
		if (cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type !=
				SCM_RIGHTS) {
			errno = EINVAL;
			break;
		}

		/* retrive data and config sockets */
		memcpy(fds, CMSG_DATA(cmsgp), sizeof(fds));
		ret.data_sock = fds[0];
		ret.conf_sock = fds[1];

		if (ret.data_sock < 0 || ret.conf_sock < 0) {
			errno = EINVAL;
			break;
		}

		/* validate bind msg */
		if (bind_msg->type != IPXW_MUX_BIND) {
			errno = ENOTSUP;
			break;
		}

		return ret;
	} while (0);

	/* close a received sockets if an error occurred */
	ipxw_mux_handle_close(ret);

	ret.data_sock = -1;
	ret.conf_sock = -1;
	return ret;
}

ssize_t ipxw_mux_peek_conf_len(int conf_sock)
{
	struct ipxw_mux_msg msg;

	ssize_t rcvd_len = recv(conf_sock, &msg, sizeof(msg), MSG_PEEK);
	if (rcvd_len < 0) {
		return -1;
	}

	do {
		/* need the ipxw_mux_msg */
		if (rcvd_len != sizeof(msg)) {
			errno = EREMOTEIO;
			break;
		}

		/* which has to be of the correct type */
		if (msg.type == IPXW_MUX_UNBIND) {
			/* nothing */
			return sizeof(msg);

		} else if (msg.type == IPXW_MUX_GETSOCKNAME) {
			/* nothing */
			return sizeof(msg);
		}

		/* no other message type permitted */
		errno = EINVAL;
	} while (0);

	/* clear out invalid message */
	recv(conf_sock, &msg, 0, 0);

	return -1;
}

ssize_t ipxw_mux_do_conf(int conf_sock, struct ipxw_mux_msg *msg, bool
		(*handle_conf_msg_cb)(int conf_sock, struct ipxw_mux_msg *msg,
			void *ctx), void *conf_ctx)
{
	/* check if the message buffer is ok */
	if (msg->type != IPXW_MUX_CONF) {
		errno = EINVAL;
		return -1;
	}

	if (msg->conf.data_len > IPX_MAX_DATA_LEN) {
		errno = EINVAL;
		return -1;
	}

	size_t max_msg_len = msg->conf.data_len + sizeof(struct ipxw_mux_msg);

	/* receive msg, this can block if the caller didn't make sure that data
	 * is available */
	ssize_t rcvd_msg_len = recv(conf_sock, msg, max_msg_len, 0);
	if (rcvd_msg_len < 0) {
		return -1;
	}

	/* must at least receive a full mux msg */
	if (rcvd_msg_len < sizeof(struct ipxw_mux_msg)) {
		errno = EREMOTEIO;
		return -1;
	}

	/* should be a more specific message type */
	/* verify message length for all accepted types */
	switch (msg->type) {
		case IPXW_MUX_UNBIND:
		case IPXW_MUX_GETSOCKNAME:
			if (rcvd_msg_len != sizeof(struct ipxw_mux_msg)) {
				errno = EINVAL;
				return -1;
			}

			break;
		default:
			errno = ENOTSUP;
			return -1;
	}

	/* handle the message */
	if (!handle_conf_msg_cb(conf_sock, msg, conf_ctx)) {
		errno = EINVAL;
		return -1;
	}

	return rcvd_msg_len;
}

struct ipxhdr *ipxw_mux_xmit_msg_to_ipxh(struct ipxw_mux_msg *xmit_msg, struct
		ipx_addr *saddr)
{
	if (xmit_msg->type != IPXW_MUX_XMIT) {
		return NULL;
	}

	struct ipx_addr daddr = xmit_msg->xmit.daddr;
	__u8 pkt_type = xmit_msg->xmit.pkt_type;

	/* get the correct length for the ipx header */
	if (xmit_msg->xmit.data_len > IPX_MAX_DATA_LEN) {
		return NULL;
	}
	__u16 msg_len = xmit_msg->xmit.data_len + sizeof(struct ipxhdr);

	/* rewrite to ipx msg */
	struct ipxhdr *ipx_msg = (struct ipxhdr *) xmit_msg;
	ipx_msg->csum = IPX_CSUM_NONE;
	ipx_msg->pktlen = htons(msg_len);
	ipx_msg->tc = 0;
	ipx_msg->type = pkt_type;
	ipx_msg->daddr = daddr;
	ipx_msg->saddr = *saddr;

	return ipx_msg;
}

struct ipxw_mux_msg *ipxw_mux_ipxh_to_recv_msg(struct ipxhdr *ipx_msg)
{
	struct ipx_addr saddr = ipx_msg->saddr;
	__u8 pkt_type = ipx_msg->type;

	/* extract the correct data length */
	__u16 data_len = ntohs(ipx_msg->pktlen);
	if (data_len < sizeof(struct ipxw_mux_msg)) {
		return NULL;
	}
	if (data_len > IPXW_MUX_MSG_LEN) {
		return NULL;
	}
	data_len -= sizeof(struct ipxhdr);

	/* determine if the packet is a broadcast */
	bool is_bcast = memcmp(ipx_msg->daddr.node, IPX_BCAST_NODE,
			IPX_ADDR_NODE_BYTES) == 0;

	/* clear the header so we can rewrite into a recv msg */
	memset(ipx_msg, 0, sizeof(struct ipxw_mux_msg));

	/* rewrite to recv msg */
	struct ipxw_mux_msg *recv_msg = (struct ipxw_mux_msg *) ipx_msg;
	recv_msg->type = IPXW_MUX_RECV;
	recv_msg->recv.saddr = saddr;
	recv_msg->recv.pkt_type = pkt_type;
	recv_msg->recv.is_bcast = is_bcast;
	recv_msg->recv.data_len = data_len;

	return recv_msg;
}

ssize_t ipxw_mux_recv_conf(int conf_sock, const struct ipxw_mux_msg *msg)
{
	size_t msg_len = sizeof(struct ipxw_mux_msg);

	/* check for permissible types, check their data_len if they have one
	 * and add it to msg_len  */
	switch (msg->type) {
		case IPXW_MUX_GETSOCKNAME:
			break;
		default:
			errno = ENOTSUP;
			return -1;
	}

	if (msg_len > IPXW_MUX_MSG_LEN) {
		errno = EINVAL;
		return -1;
	}

	ssize_t sent_len = send(conf_sock, msg, msg_len, 0);
	if (sent_len < 0) {
		return -1;
	}

	if (sent_len != msg_len) {
		errno = ECOMM;
		return -1;
	}

	return msg_len;
}
