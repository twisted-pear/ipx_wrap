#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <linux/limits.h>
#include <linux/net_tstamp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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

		/* bind the socket so that it can receive */
		struct sockaddr_in6 dummy_bind = {
			.sin6_family = AF_INET6,
			.sin6_port = 0,
			.sin6_flowinfo = 0,
			.sin6_scope_id = 0
		};
		ipx_to_ipv6_addr(&(dummy_bind.sin6_addr),
				&(bind_msg->bind.addr), res.ack.prefix);

		if (bind(data_sock, (struct sockaddr *) &dummy_bind,
					sizeof(dummy_bind)) < 0) {
			/* if the bind on the data socket failed, inform the
			 * muxer */
			struct ipxw_mux_msg unbind_msg;
			/* no error handling, nothing that can be done */
			unbind_msg.type = IPXW_MUX_UNBIND;
			send(ret.conf_sock, &unbind_msg, sizeof(unbind_msg),
					MSG_DONTWAIT);
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
	if (!ipxw_mux_handle_is_error(h)) {
		struct ipxw_mux_msg unbind_msg;

		/* no error handling, nothing that can be done */
		unbind_msg.type = IPXW_MUX_UNBIND;
		send(h.conf_sock, &unbind_msg, sizeof(unbind_msg),
				MSG_DONTWAIT);
	}

	ipxw_mux_handle_close(h);
}

ssize_t ipxw_mux_send_recv_conf_msg(struct ipxw_mux_handle h, const struct
		ipxw_mux_msg *conf_in, struct ipxw_mux_msg *conf_out)
{
	size_t in_len = sizeof(struct ipxw_mux_msg);

	struct msghdr msgh;
	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;
	msgh.msg_control = NULL;
	msgh.msg_controllen = 0;

	/* prepare a control message in case one is needed */
	union {
		char buf[CMSG_SPACE(sizeof(int))]; /* Space large enough to
						      hold one int */
		struct cmsghdr align;
	} ctrl_msg;
	memset(ctrl_msg.buf, 0, sizeof(ctrl_msg.buf));

	/* check message type and, if necessary, data length, adjust in_len */
	switch (conf_in->type) {
		case IPXW_MUX_GETSOCKNAME:
			break;
		case IPXW_MUX_SPX_CONNECT:
		case IPXW_MUX_SPX_ACCEPT:
			msgh.msg_control = ctrl_msg.buf;
			msgh.msg_controllen = sizeof(ctrl_msg.buf);

			/* prepare ctrl msg header */
			struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
			if (cmsgp == NULL) {
				errno = EINVAL;
				return -1;
			}
			cmsgp->cmsg_level = SOL_SOCKET;
			cmsgp->cmsg_type = SCM_RIGHTS;

			/* store the socket fd we want to send */
			cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
			memcpy(CMSG_DATA(cmsgp),
					&(conf_in->spx_connect.spx_sock),
					sizeof(int));

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

	struct iovec iov;
	iov.iov_base = (struct ipxw_mux_msg *) conf_in;
	iov.iov_len = in_len;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	/* send the message, this blocks */
	ssize_t sent_len = sendmsg(h.conf_sock, &msgh, 0);
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
	switch (conf_out->type) {
		case IPXW_MUX_GETSOCKNAME:
		case IPXW_MUX_SPX_CONNECT:
		case IPXW_MUX_SPX_ACCEPT:
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

ssize_t ipxw_mux_xmit_with_ctrl(struct ipxw_mux_handle h, const struct
		ipxw_mux_msg *msg, bool block, void *ctrl, size_t ctrl_len)
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
	ipx_to_ipv6_addr(&(dummy_dst.sin6_addr), &(msg->xmit.daddr), h.prefix);

	struct iovec iov = {
		.iov_base = (struct ipxw_mux_msg *) msg,
		.iov_len = msg_len
	};
	struct msghdr msgh = {
		.msg_name = &dummy_dst,
		.msg_namelen = sizeof(dummy_dst),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = ctrl,
		.msg_controllen = ctrl_len,
		.msg_flags = 0
	};

	/* send message, may block */
	/* rewriting to IPX happens in the BPF program */
	int flags = (block ? 0 : MSG_DONTWAIT);
	ssize_t sent_len = sendmsg(h.data_sock, &msgh, flags);
	if (sent_len < 0) {
		return -1;
	}

	if (sent_len != msg_len) {
		errno = ECOMM;
		return -1;
	}

	return sent_len;
}

ssize_t ipxw_mux_xmit(struct ipxw_mux_handle h, const struct ipxw_mux_msg *msg,
		bool block)
{
	return ipxw_mux_xmit_with_ctrl(h, msg, block, NULL, 0);
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
	recv(h.data_sock, &msg, rcvd_len, 0);

	return -1;
}

ssize_t ipxw_mux_get_recvd_with_ctrl(struct ipxw_mux_handle h, struct
		ipxw_mux_msg *msg, bool block, void *ctrl, size_t ctrl_len)
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

	memset(ctrl, 0, ctrl_len);
	struct iovec iov = {
		.iov_base = msg,
		.iov_len = max_msg_len
	};
	struct msghdr msgh = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = ctrl,
		.msg_controllen = ctrl_len,
		.msg_flags = 0
	};

	/* receive a msg, may block */
	int flags = (block ? 0 : MSG_DONTWAIT);
	ssize_t rcvd_len = recvmsg(h.data_sock, &msgh, flags);
	if (rcvd_len < 0) {
		return -1;
	}

	/* need at least a full msg */
	if (rcvd_len < sizeof(struct ipxw_mux_msg)) {
		errno = EREMOTEIO;
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

ssize_t ipxw_mux_get_recvd(struct ipxw_mux_handle h, struct ipxw_mux_msg *msg,
		bool block)
{
	return ipxw_mux_get_recvd_with_ctrl(h, msg, block, NULL, 0);
}

/* timestamping helpers */

#define TX_TS_RECV_CTRL_BUF_SIZE 1024

bool ipxw_mux_enable_timestamps(struct ipxw_mux_handle h, bool rx, bool tx)
{
	if (!rx && !tx) {
		errno = EINVAL;
		return false;
	}

	int val = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE;

	if (rx) {
		val |= SOF_TIMESTAMPING_RX_HARDWARE;
		val |= SOF_TIMESTAMPING_RX_SOFTWARE;
		val |= SOF_TIMESTAMPING_OPT_RX_FILTER;
	}

	if (tx) {
		val |= SOF_TIMESTAMPING_TX_HARDWARE;
		val |= SOF_TIMESTAMPING_TX_SOFTWARE;
		val |= SOF_TIMESTAMPING_OPT_ID;
		val |= SOF_TIMESTAMPING_OPT_TSONLY;
	}

	if (setsockopt(h.data_sock, SOL_SOCKET, SO_TIMESTAMPING_NEW, &val,
				sizeof(val)) != 0) {
		return false;
	}

	return true;
}

ssize_t ipxw_mux_set_tx_timestamp_id(void *ctrl, size_t ctrl_len, __u32 ts_id)
{
	if (CMSG_SPACE(sizeof(__u32)) > ctrl_len) {
		errno = EINVAL;
		return -1;
	}

	struct msghdr msgh = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = NULL,
		.msg_iovlen = 0,
		.msg_control = ctrl,
		.msg_controllen = ctrl_len,
		.msg_flags = 0
	};

	memset(ctrl, 0, ctrl_len);

	struct cmsghdr *cmsgh = CMSG_FIRSTHDR(&msgh);
	cmsgh->cmsg_level = SOL_SOCKET;
	cmsgh->cmsg_type = SCM_TS_OPT_ID;
	cmsgh->cmsg_len = CMSG_LEN(sizeof(__u32));
	*((__u32 *) CMSG_DATA(cmsgh)) = ts_id;

	return CMSG_SPACE(sizeof(__u32));
}

bool ipxw_mux_get_tx_timestamp(struct ipxw_mux_handle h, struct
		__kernel_timespec *ts, __u32 *ts_id, bool block)
{
	__u8 ctrl_buf[TX_TS_RECV_CTRL_BUF_SIZE];
	memset(ctrl_buf, 0, TX_TS_RECV_CTRL_BUF_SIZE);

	struct msghdr msgh = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = NULL,
		.msg_iovlen = 0,
		.msg_control = ctrl_buf,
		.msg_controllen = TX_TS_RECV_CTRL_BUF_SIZE,
		.msg_flags = 0
	};

	/* receive a msg, may block */
	int flags = (block ? MSG_ERRQUEUE : (MSG_ERRQUEUE | MSG_DONTWAIT));
	ssize_t rcvd_len = recvmsg(h.data_sock, &msgh, flags);
	if (rcvd_len < 0) {
		return false;
	}

	if (rcvd_len != 0) {
		errno = EREMOTEIO;
		return false;
	}

	bool have_tstamp = false;
	bool have_tstamp_id = false;
	struct scm_timestamping64 tsmsg;
	struct sock_extended_err *ext_err;

	struct cmsghdr *cmsgh;
	for (cmsgh = CMSG_FIRSTHDR(&msgh); cmsgh != NULL; cmsgh =
			CMSG_NXTHDR(&msgh, cmsgh)) {
		/* error msg with timestamp ID */
		if (cmsgh->cmsg_level == SOL_IPV6 && cmsgh->cmsg_type ==
				IPV6_RECVERR) {
			ext_err = (struct sock_extended_err *)
				CMSG_DATA(cmsgh);
			if (ext_err->ee_errno != ENOMSG) {
				continue;
			}
			if (ext_err->ee_info != SCM_TSTAMP_SND) {
				continue;
			}
			*ts_id = ext_err->ee_data;
			have_tstamp_id = true;
			continue;
		}

		/* timestamping message with the actual timestamps */
		if (cmsgh->cmsg_level == SOL_SOCKET && cmsgh->cmsg_type ==
				SO_TIMESTAMPING_NEW) {
			memcpy(&tsmsg, CMSG_DATA(cmsgh), sizeof(tsmsg));
			/* have hardware timestamp */
			if (tsmsg.ts[2].tv_sec != 0 || tsmsg.ts[2].tv_nsec !=
					0) {
				memcpy(ts, &(tsmsg.ts[2]), sizeof(struct
							__kernel_timespec));
				have_tstamp = true;
				continue;
			}
			/* have software timestamp */
			if (tsmsg.ts[0].tv_sec != 0 || tsmsg.ts[0].tv_nsec !=
					0) {
				memcpy(ts, &(tsmsg.ts[0]), sizeof(struct
							__kernel_timespec));
				have_tstamp = true;
				continue;
			}
			continue;
		}
	}

	if (!have_tstamp || !have_tstamp_id) {
		errno = ENOENT;
		return false;
	}

	return true;
}

bool ipxw_mux_get_rx_timestamp(void *ctrl, size_t ctrl_len, struct
		__kernel_timespec *ts)
{
	struct msghdr msgh = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = NULL,
		.msg_iovlen = 0,
		.msg_control = ctrl,
		.msg_controllen = ctrl_len,
		.msg_flags = 0
	};

	struct scm_timestamping64 tsmsg;

	struct cmsghdr *cmsgh;
	for (cmsgh = CMSG_FIRSTHDR(&msgh); cmsgh != NULL; cmsgh =
			CMSG_NXTHDR(&msgh, cmsgh)) {
		if (cmsgh->cmsg_level == SOL_SOCKET && cmsgh->cmsg_type ==
				SO_TIMESTAMPING_NEW) {
			memcpy(&tsmsg, CMSG_DATA(cmsgh), sizeof(tsmsg));
			/* have hardware timestamp */
			if (tsmsg.ts[2].tv_sec != 0 || tsmsg.ts[2].tv_nsec !=
					0) {
				memcpy(ts, &(tsmsg.ts[2]), sizeof(struct
							__kernel_timespec));
				return true;
			}
			/* have software timestamp */
			if (tsmsg.ts[0].tv_sec != 0 || tsmsg.ts[0].tv_nsec !=
					0) {
				memcpy(ts, &(tsmsg.ts[0]), sizeof(struct
							__kernel_timespec));
				return true;
			}
		}
	}

	return false;
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

		/* should not happen, but if it does we report the error */
		if (rcvd_len != sizeof(*bind_msg)) {
			errno = EREMOTEIO;
			break;
		}

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

	/* close the received sockets if an error occurred */
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
		switch (msg.type) {
			case IPXW_MUX_UNBIND:
			case IPXW_MUX_GETSOCKNAME:
			case IPXW_MUX_SPX_CONNECT:
			case IPXW_MUX_SPX_ACCEPT:
			case IPXW_MUX_SPX_CLOSE:
				return sizeof(msg);
			default:
				break;
		}

		/* no other message type permitted */
		errno = EINVAL;
	} while (0);

	/* clear out invalid message */
	recv(conf_sock, &msg, rcvd_len, 0);

	return -1;
}

ssize_t ipxw_mux_do_conf(int conf_sock, struct ipxw_mux_msg *msg, bool
		(*handle_conf_msg_cb)(int conf_sock, struct ipxw_mux_msg *msg,
			int fd, void *ctx), void *conf_ctx)
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

	struct msghdr msgh;
	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;

	struct iovec iov;
	iov.iov_base = msg;
	iov.iov_len = max_msg_len;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	/* prepare the ancillary data buffer */
	union {
		char buf[CMSG_SPACE(sizeof(int))]; /* Space large enough to
						      hold one int */
		struct cmsghdr align;
	} ctrl_msg;

	msgh.msg_control = ctrl_msg.buf;
	msgh.msg_controllen = sizeof(ctrl_msg.buf);

	/* receive msg, this can block if the caller didn't make sure that data
	 * is available */
	ssize_t rcvd_msg_len = recvmsg(conf_sock, &msgh, 0);
	if (rcvd_msg_len < 0) {
		return -1;
	}

	/* must at least receive a full mux msg */
	if (rcvd_msg_len < sizeof(struct ipxw_mux_msg)) {
		errno = EREMOTEIO;
		return -1;
	}

	int rcvd_fd = -1;

	/* should be a more specific message type */
	/* verify message length for all accepted types */
	switch (msg->type) {
		case IPXW_MUX_UNBIND:
		case IPXW_MUX_GETSOCKNAME:
		case IPXW_MUX_SPX_CLOSE:
			if (rcvd_msg_len != sizeof(struct ipxw_mux_msg)) {
				errno = EINVAL;
				return -1;
			}

			break;
		case IPXW_MUX_SPX_CONNECT:
		case IPXW_MUX_SPX_ACCEPT:
			/* get ctrl msg */
			struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);

			/* validate ctrl msg */
			if (cmsgp == NULL) {
				errno = EINVAL;
				return -1;
			}
			if (cmsgp->cmsg_len != CMSG_LEN(sizeof(int))) {
				errno = EINVAL;
				return -1;
			}
			if (cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type
					!= SCM_RIGHTS) {
				errno = EINVAL;
				return -1;
			}

			/* retrive data and config sockets */
			memcpy(&rcvd_fd, CMSG_DATA(cmsgp), sizeof(int));

			if (rcvd_fd < 0) {
				errno = EINVAL;
				return -1;
			}

			if (rcvd_msg_len != sizeof(struct ipxw_mux_msg)) {
				errno = EINVAL;
				close(rcvd_fd);
				return -1;
			}

			break;
		default:
			errno = ENOTSUP;
			return -1;
	}

	/* handle the message */
	if (!handle_conf_msg_cb(conf_sock, msg, rcvd_fd, conf_ctx)) {
		if (rcvd_fd >= 0) {
			close(rcvd_fd);
		}
		errno = EINVAL;
		return -1;
	}

	return rcvd_msg_len;
}

ssize_t ipxw_mux_recv_conf(int conf_sock, const struct ipxw_mux_msg *msg)
{
	size_t msg_len = sizeof(struct ipxw_mux_msg);

	/* check for permissible types, check their data_len if they have one
	 * and add it to msg_len  */
	switch (msg->type) {
		case IPXW_MUX_GETSOCKNAME:
		case IPXW_MUX_SPX_CONNECT:
		case IPXW_MUX_SPX_ACCEPT:
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

/* SPX client API */

enum ipxw_mux_spx_connection_state {
	IPXW_MUX_SPX_INVALID = 0,
	IPXW_MUX_SPX_NEW,
	IPXW_MUX_SPX_CONN_REQ_SENT,
	IPXW_MUX_SPX_CONN_ACCEPTED,
	IPXW_MUX_SPX_CONN_ESTABLISHED,
	IPXW_MUX_SPX_CONN_MUST_SEND_ACK,
	IPXW_MUX_SPX_CONN_WAITING_FOR_ACK,
	IPXW_MUX_SPX_CONN_CLOSED
};

struct ipxw_mux_spx_handle_state {
	enum ipxw_mux_spx_connection_state state;
	__be16 conn_id;
	__u16 remote_alloc_no;
	__u16 local_alloc_no;
	__u16 remote_expected_sequence;
	__u16 local_current_sequence;
	bool spxii;
	__u16 cur_sizng_value;
	__u16 neg_size_to_remote;
	__u16 neg_size_to_local;
	__u16 last_tx_attempts;
	__u16 ticks_since_last_keep_alive;
	__u16 ticks_since_last_verify;
	__u16 ticks_since_last_remote_msg;
	__u16 last_msg_data_len;
	struct {
		struct ipxw_mux_spx_msg last_msg;
		__u8 data[SPXII_MAX_DATA_LEN];
	} __attribute__((packed));
};

bool ipxw_mux_spx_handle_is_error(struct ipxw_mux_spx_handle h)
{
	if (h.last_known_state == NULL) {
		return true;
	}

	return (h.spx_sock < 0) || (h.conf_sock < 0) ||
		(h.last_known_state->state == IPXW_MUX_SPX_INVALID);
}

bool ipxw_mux_spx_handle_is_spxii(struct ipxw_mux_spx_handle h)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		return false;
	}

	return h.last_known_state->spxii;
}

int ipxw_mux_spx_handle_sock(struct ipxw_mux_spx_handle h)
{
	return h.spx_sock;
}

void ipxw_mux_spx_handle_close(struct ipxw_mux_spx_handle *h)
{
	if (h->spx_sock >= 0) {
		close(h->spx_sock);
	}

	h->spx_sock = -1;
	h->conf_sock = -1; /* do not close config socket as it is used
			      elsewhere too */

	if (h->last_known_state != NULL) {
		free(h->last_known_state);
		h->last_known_state = NULL;
	}
}

static struct ipxw_mux_spx_handle ipxw_mux_spx_mk_handle(struct ipxw_mux_handle
		h)
{
	struct ipxw_mux_spx_handle ret;
	ret.spx_sock = -1;
	ret.conf_sock = -1;

	if (ipxw_mux_handle_is_error(h)) {
		errno = EINVAL;
		return ret;
	}

	ret.last_known_state = calloc(1, sizeof(struct
				ipxw_mux_spx_handle_state));
	if (ret.last_known_state == NULL) {
		return ret;
	}

	ret.last_known_state->conn_id = SPX_CONN_ID_UNKNOWN;
	ret.last_known_state->state = IPXW_MUX_SPX_INVALID;

	int spx_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (spx_sock < 0) {
		return ret;
	}

	ret.spx_sock = spx_sock;
	ret.conf_sock = h.conf_sock;

	return ret;
}

static bool ipxw_mux_spx_bind_and_connect(struct ipxw_mux_spx_handle h, __be32
		prefix, struct ipx_addr *saddr, struct ipx_addr *daddr)
{
	/* bind the socket so that it can receive */
	struct sockaddr_in6 dummy_bind = {
		.sin6_family = AF_INET6,
		.sin6_port = 0,
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	ipx_to_ipv6_addr(&(dummy_bind.sin6_addr), saddr, prefix);

	if (bind(h.spx_sock, (struct sockaddr *) &dummy_bind,
				sizeof(dummy_bind)) < 0) {
		return false;
	}

	/* connect the socket so that sending without a specific
	 * destination address works */
	struct sockaddr_in6 dummy_connect = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(IPX_IN_IPV6_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	ipx_to_ipv6_addr(&(dummy_connect.sin6_addr), daddr, prefix);

	if (connect(h.spx_sock, (struct sockaddr *) &dummy_connect,
				sizeof(dummy_connect)) < 0) {
		return false;
	}

	return true;
}

__be16 ipxw_mux_spx_check_for_conn_req(struct ipxw_mux_msg *msg, bool
		*is_spxii)
{
	if (msg->type != IPXW_MUX_RECV) {
		return SPX_CONN_ID_UNKNOWN;
	}
	if (msg->recv.pkt_type != SPX_PKT_TYPE) {
		return SPX_CONN_ID_UNKNOWN;
	}
	if (msg->recv.is_bcast) {
		return SPX_CONN_ID_UNKNOWN;
	}
	if (msg->recv.data_len != sizeof(struct spxhdr)) {
		return SPX_CONN_ID_UNKNOWN;
	}

	struct spxhdr *spxh = (struct spxhdr *) msg->data;
	if ((spxh->connection_control & SPX_CC_MASK_SPX) != (SPX_CC_SYSTEM_PKT
				| SPX_CC_ACK_REQUIRED)) {
		return SPX_CONN_ID_UNKNOWN;
	}
	if (spxh->datastream_type != SPX_DS_NONE) {
		return SPX_CONN_ID_UNKNOWN;
	}
	if (spxh->dst_conn_id != SPX_CONN_ID_UNKNOWN) {
		return SPX_CONN_ID_UNKNOWN;
	}
	if (ntohs(spxh->seq_no) != 0 || ntohs(spxh->ack_no) != 0) {
		return SPX_CONN_ID_UNKNOWN;
	}

	*is_spxii = (spxh->connection_control & SPX_CC_SPXII) != 0;

	return spxh->src_conn_id;
}

static void ipxw_mux_fill_msg_from_state(struct ipxw_mux_spx_handle h, struct
		ipxw_mux_spx_msg *msg)
{
	msg->local_current_sequence =
		h.last_known_state->local_current_sequence;
	msg->remote_expected_sequence =
		h.last_known_state->remote_expected_sequence;
	msg->local_alloc_no = h.last_known_state->local_alloc_no;
	msg->remote_alloc_no = h.last_known_state->remote_alloc_no;
	msg->spxii = h.last_known_state->spxii;
	if (h.last_known_state->spxii) {
		msg->negotiation_size = h.last_known_state->neg_size_to_local;
	}
}

void ipxw_mux_spx_conn_close(struct ipxw_mux_spx_handle *h)
{
	if (!ipxw_mux_spx_handle_is_error(*h)) {
		/* send a close packet if possible */
		switch (h->last_known_state->state) {
			case IPXW_MUX_SPX_CONN_WAITING_FOR_ACK:
				/* try to get our hands on the latest ACK if we
				 * can */
				struct ipxw_mux_spx_msg latest_ack;
				ipxw_mux_spx_get_recvd(*h, &latest_ack, 0,
						false);
				/* continue with regular close logic */
			case IPXW_MUX_SPX_CONN_ESTABLISHED:
			case IPXW_MUX_SPX_CONN_MUST_SEND_ACK:
				struct ipxw_mux_spx_msg close_spx_msg;
				memset(&close_spx_msg, 0, sizeof(struct
							ipxw_mux_spx_msg));
				ipxw_mux_fill_msg_from_state(*h,
						&close_spx_msg);
				close_spx_msg.system = true;
				close_spx_msg.ack_required = true;
				close_spx_msg.datastream_type =
					SPX_DS_END_OF_CONN;
				size_t close_spx_msg_len =
					ipxw_mux_spx_msg_len(0,
							close_spx_msg.spxii);
				send(h->spx_sock, &close_spx_msg,
						close_spx_msg_len,
						MSG_DONTWAIT);
				break;
			default:
				break;
		}

		/* no error handling, nothing that can be done */
		struct ipxw_mux_msg close_msg;
		close_msg.type = IPXW_MUX_SPX_CLOSE;
		close_msg.spx_close.conn_id = h->last_known_state->conn_id;
		send(h->conf_sock, &close_msg, sizeof(close_msg),
				MSG_DONTWAIT);
	}

	ipxw_mux_spx_handle_close(h);
}

static bool ipxw_mux_spx_resend_last_msg(struct ipxw_mux_spx_handle h)
{
	assert(h.last_known_state->state == IPXW_MUX_SPX_CONN_WAITING_FOR_ACK);

	/* retransmit the last message */

	size_t last_msg_len =
		ipxw_mux_spx_msg_len(h.last_known_state->last_msg_data_len,
				h.last_known_state->last_msg.spxii);

	size_t sent_len = send(h.spx_sock, &(h.last_known_state->last_msg),
			last_msg_len, MSG_DONTWAIT);

	if (sent_len < 0) {
		return false;
	}
	if (sent_len != last_msg_len) {
		return false;
	}

	return true;
}

static bool ipxw_mux_spx_send_keep_alive(struct ipxw_mux_spx_handle h)
{
	assert(h.last_known_state->state == IPXW_MUX_SPX_CONN_ESTABLISHED);

	struct ipxw_mux_spx_msg spx_msg;
	memset(&spx_msg, 0, sizeof(struct ipxw_mux_spx_msg));
	ipxw_mux_fill_msg_from_state(h, &spx_msg);
	spx_msg.keep_alive = true;

	if (h.last_known_state->ticks_since_last_verify > SPX_VERIFY_TMO_TICKS)
	{
		/* verify msg*/
		spx_msg.ack_required = true;
	} else if (h.last_known_state->ticks_since_last_keep_alive >
			SPX_KEEP_ALIVE_TMO_TICKS) {
		/* regular keep alive msg*/
	} else {
		/* no need to send anything yet */
		return true;
	}

	/* transmit verify/keep alive message */
	size_t spx_msg_len = ipxw_mux_spx_msg_len(0,
			h.last_known_state->spxii);
	ssize_t sent_len = send(h.spx_sock, &spx_msg, spx_msg_len,
			MSG_DONTWAIT);

	if (sent_len < 0) {
		return false;
	}
	if (sent_len != spx_msg_len) {
		return false;
	}

	/* reset the counters */
	h.last_known_state->ticks_since_last_keep_alive = 0;
	if (spx_msg.ack_required) {
		h.last_known_state->ticks_since_last_verify = 0;
	}

	return true;
}

static bool ipxw_mux_spx_send_sizng_req(struct ipxw_mux_spx_handle h, size_t
		next_size_to_try)
{
	assert(h.last_known_state->state == IPXW_MUX_SPX_CONN_ESTABLISHED ||
			h.last_known_state->state ==
			IPXW_MUX_SPX_CONN_WAITING_FOR_ACK);

	if (!h.last_known_state->spxii) {
		return false;
	}

	if (next_size_to_try < SPXII_WIRE_OVERHEAD) {
		return false;
	}

	struct ipxw_mux_spx_msg *sizng_req = calloc(1, next_size_to_try);
	if (sizng_req == NULL) {
		return false;
	}

	ipxw_mux_fill_msg_from_state(h, sizng_req);
	sizng_req->negotiate_size = true;
	sizng_req->system = true;
	sizng_req->ack_required = true;
	sizng_req->negotiation_size = next_size_to_try;

	bool ret = false;
	ssize_t sent_len = send(h.spx_sock, sizng_req, next_size_to_try,
			MSG_DONTWAIT);
	do {
		if (sent_len < 0) {
			break;
		}
		if (sent_len != next_size_to_try) {
			errno = ECOMM;
			break;
		}

		h.last_known_state->state = IPXW_MUX_SPX_CONN_WAITING_FOR_ACK;

		/* sending a size negotiaion request counts as both keep alive
		 * and verify */
		h.last_known_state->ticks_since_last_keep_alive = 0;
		h.last_known_state->ticks_since_last_verify = 0;

		ret = true;
	} while (0);

	free(sizng_req);
	return ret;
}

static bool ipxw_mux_spx_send_conn_req(struct ipxw_mux_spx_handle h)
{
	struct ipxw_mux_spx_msg spx_connect_req;
	memset(&spx_connect_req, 0, sizeof(struct ipxw_mux_spx_msg));
	spx_connect_req.system = true;
	spx_connect_req.ack_required = true;
	spx_connect_req.spxii = h.last_known_state->spxii;
	spx_connect_req.negotiate_size = h.last_known_state->spxii; /* always
								       negotiate
								       size
								       when
								       using
								       SPXII */
	spx_connect_req.datastream_type = SPX_DS_NONE;

	/* first packet in connection always uses plain SPX header (not SPXII
	 * header) */
	ssize_t sent_len = send(h.spx_sock, &spx_connect_req,
			SPX_WIRE_OVERHEAD, MSG_DONTWAIT);
	if (sent_len < 0) {
		return false;
	}
	if (sent_len != SPX_WIRE_OVERHEAD) {
		errno = ECOMM;
		return false;
	}

	h.last_known_state->state = IPXW_MUX_SPX_CONN_REQ_SENT;

	return true;
}

static bool ipxw_mux_spx_send_ack_wo_state_change(struct ipxw_mux_spx_handle h,
		bool negotiate_size, bool end_of_conn)
{
	struct ipxw_mux_spx_msg ack_msg;
	memset(&ack_msg, 0, sizeof(struct ipxw_mux_spx_msg));
	ipxw_mux_fill_msg_from_state(h, &ack_msg);
	ack_msg.ack = true;
	ack_msg.negotiate_size = negotiate_size;
	if (end_of_conn) {
		ack_msg.datastream_type = SPX_DS_END_OF_CONN_ACK;
	}
	size_t ack_msg_len = ipxw_mux_spx_msg_len(0, h.last_known_state->spxii);

	/* transmit the ack message */
	ssize_t sent_len = send(h.spx_sock, &ack_msg, ack_msg_len,
			MSG_DONTWAIT);

	if (sent_len < 0) {
		return false;
	}
	if (sent_len != ack_msg_len) {
		errno = ECOMM;
		return false;
	}

	return true;
}

static bool ipxw_mux_spx_send_ack(struct ipxw_mux_spx_handle h, bool
		negotiate_size, bool end_of_conn)
{
	assert(h.last_known_state->state == IPXW_MUX_SPX_CONN_MUST_SEND_ACK);

	if (!ipxw_mux_spx_send_ack_wo_state_change(h, negotiate_size,
				end_of_conn)) {
		return false;
	}

	/* reset the counters */
	h.last_known_state->ticks_since_last_keep_alive = 0;

	/* update the state */
	h.last_known_state->state = IPXW_MUX_SPX_CONN_ESTABLISHED;
	if (end_of_conn) {
		h.last_known_state->state = IPXW_MUX_SPX_CONN_CLOSED;
	}

	return true;
}

static bool ipxw_mux_spx_set_init_sizng_size(struct ipxw_mux_spx_handle h, int
		spxii_size_negotiation_hint)
{
	assert(!ipxw_mux_spx_handle_is_error(h));

	/* set the initial size for size negotiation */
	int init_neg_size = ipxw_get_outif_max_spx_data_len_for_peer(h);
	if (init_neg_size <= 0) {
		return false;
	}

	if (init_neg_size > spxii_size_negotiation_hint) {
		init_neg_size = spxii_size_negotiation_hint;
	}

	init_neg_size = ipxw_mux_spx_msg_len(init_neg_size, true);

	h.last_known_state->cur_sizng_value = init_neg_size;

	/* start with zero so that we can pick the largest successful size
	 * negotiation request/ack */
	h.last_known_state->neg_size_to_remote = 0;
	h.last_known_state->neg_size_to_local = 0;

	return true;
}

static bool ipxw_mux_spx_update_sizng_size(struct ipxw_mux_spx_handle h)
{
	assert(!ipxw_mux_spx_handle_is_error(h));

	if (h.last_known_state->cur_sizng_value < 200) {
		/* tries exceeded, give up */
		h.last_known_state->cur_sizng_value = 0;
		return false;
	}

	// TODO: find a better heuristic for this
	h.last_known_state->cur_sizng_value /= 2;

	return true;
}

static bool ipxw_mux_spx_sizng_active(struct ipxw_mux_spx_handle h)
{
	assert(!ipxw_mux_spx_handle_is_error(h));

	return h.last_known_state->cur_sizng_value > 0;
}

static void ipxw_mux_spx_stop_sizeng(struct ipxw_mux_spx_handle h)
{
	assert(!ipxw_mux_spx_handle_is_error(h));

	h.last_known_state->cur_sizng_value = 0;
}

static __u16 ipxw_mux_spx_get_cur_sizng_val(struct ipxw_mux_spx_handle h)
{
	assert(!ipxw_mux_spx_handle_is_error(h));

	return h.last_known_state->cur_sizng_value;
}

struct ipxw_mux_spx_handle ipxw_mux_spx_connect(struct ipxw_mux_handle h,
		struct ipx_addr *daddr, int spxii_size_negotiation_hint)
{
	bool spxii = (spxii_size_negotiation_hint > 0);

	struct ipxw_mux_spx_handle ret = ipxw_mux_spx_mk_handle(h);
	if (ret.last_known_state == NULL || ret.spx_sock < 0) {
		return ret;
	}

	struct ipxw_mux_msg connect_req;
	connect_req.type = IPXW_MUX_SPX_CONNECT;
	connect_req.spx_connect.addr = *daddr;
	connect_req.spx_connect.spx_sock = ret.spx_sock;
	connect_req.spx_connect.conn_id = SPX_CONN_ID_UNKNOWN;

	struct ipxw_mux_msg connect_rsp;
	connect_rsp.type = IPXW_MUX_CONF;
	connect_rsp.conf.data_len = 0;

	ssize_t rcvd_len = ipxw_mux_send_recv_conf_msg(h, &connect_req,
			&connect_rsp);

	do {
		if (rcvd_len < 0) {
			break;
		}

		if (connect_rsp.type != IPXW_MUX_SPX_CONNECT) {
			errno = EINVAL;
			break;
		}

		if (connect_rsp.spx_connect.err != 0) {
			errno = connect_rsp.spx_connect.err;
			break;
		}

		ret.last_known_state->conn_id = connect_rsp.spx_connect.conn_id;
		ret.last_known_state->spxii = spxii;
		ret.last_known_state->state = IPXW_MUX_SPX_NEW;

		if (!ipxw_mux_spx_bind_and_connect(ret, h.prefix,
					&(connect_rsp.spx_connect.addr),
					daddr)) {
			break;
		}

		if (spxii) {
			/* set the initial size for size negotiation */
			if (!ipxw_mux_spx_set_init_sizng_size(ret,
						spxii_size_negotiation_hint)) {
				errno = EMSGSIZE;
				break;
			}
		}

		/* fire off the first packet in the connection */
		if (!ipxw_mux_spx_send_conn_req(ret)) {
			break;
		}

		return ret;
	} while (0);

	ipxw_mux_spx_conn_close(&ret);

	return ret;
}

struct ipxw_mux_spx_handle ipxw_mux_spx_accept(struct ipxw_mux_handle h, struct
		ipx_addr *remote_addr, __be16 remote_conn_id, int
		spxii_size_negotiation_hint)
{
	bool spxii = (spxii_size_negotiation_hint > 0);

	struct ipxw_mux_spx_handle ret = ipxw_mux_spx_mk_handle(h);
	if (ret.last_known_state == NULL || ret.spx_sock < 0) {
		return ret;
	}

	struct ipxw_mux_msg accept_req;
	accept_req.type = IPXW_MUX_SPX_ACCEPT;
	accept_req.spx_accept.addr = *remote_addr;
	accept_req.spx_accept.spx_sock = ret.spx_sock;
	accept_req.spx_accept.conn_id = remote_conn_id;

	struct ipxw_mux_msg accept_rsp;
	accept_rsp.type = IPXW_MUX_CONF;
	accept_rsp.conf.data_len = 0;

	ssize_t rcvd_len = ipxw_mux_send_recv_conf_msg(h, &accept_req,
			&accept_rsp);

	do {
		if (rcvd_len < 0) {
			break;
		}

		if (accept_rsp.type != IPXW_MUX_SPX_ACCEPT) {
			errno = EINVAL;
			break;
		}

		if (accept_rsp.spx_accept.err != 0) {
			errno = accept_rsp.spx_accept.err;
			break;
		}

		ret.last_known_state->conn_id = accept_rsp.spx_accept.conn_id;
		ret.last_known_state->spxii = spxii;
		ret.last_known_state->state = IPXW_MUX_SPX_CONN_ACCEPTED;

		if (!ipxw_mux_spx_bind_and_connect(ret, h.prefix,
					&(accept_rsp.spx_accept.addr),
					remote_addr)) {
			break;
		}

		if (spxii) {
			/* set the initial size for size negotiation */
			if (!ipxw_mux_spx_set_init_sizng_size(ret,
						spxii_size_negotiation_hint)) {
				errno = EMSGSIZE;
				break;
			}
		}

		/* fire off the first packet in the connection */
		struct ipxw_mux_spx_msg spx_accept_rsp;
		memset(&spx_accept_rsp, 0, sizeof(struct ipxw_mux_spx_msg));
		spx_accept_rsp.system = true;
		spx_accept_rsp.spxii = spxii;
		spx_accept_rsp.negotiate_size = spxii; /* always negotiate size
							  when using SPXII */
		spx_accept_rsp.datastream_type = SPX_DS_NONE;
		if (spxii) {
			spx_accept_rsp.negotiation_size =
				ipxw_mux_spx_get_cur_sizng_val(ret);
		}

		size_t msg_len = ipxw_mux_spx_msg_len(0, spxii);
		ssize_t sent_len = send(ret.spx_sock, &spx_accept_rsp, msg_len,
				MSG_DONTWAIT);
		if (sent_len < 0) {
			break;
		}
		if (sent_len != msg_len) {
			errno = ECOMM;
			break;
		}

		ret.last_known_state->state = IPXW_MUX_SPX_CONN_ESTABLISHED;

		if (spxii) {
			ipxw_mux_spx_send_sizng_req(ret, ipxw_mux_spx_get_cur_sizng_val(ret));
		}

		return ret;
	} while (0);

	ipxw_mux_spx_conn_close(&ret);

	return ret;
}

bool ipxw_mux_spx_maintain(struct ipxw_mux_spx_handle h)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		errno = EINVAL;
		return false;
	}

	h.last_known_state->ticks_since_last_remote_msg += 1;
	h.last_known_state->ticks_since_last_verify += 1;
	h.last_known_state->ticks_since_last_keep_alive += 1;

	/* tear down the connection if we haven't heard from the remote station
	 * in too long */
	if (h.last_known_state->ticks_since_last_remote_msg >
			SPX_ABORT_TMO_TICKS) {
		errno = ETIMEDOUT;
		return false;
	}

	bool send_success = false;
	switch (h.last_known_state->state) {
		case IPXW_MUX_SPX_CONN_ESTABLISHED:
			send_success = ipxw_mux_spx_send_keep_alive(h);
			break;

		case IPXW_MUX_SPX_CONN_MUST_SEND_ACK:
			send_success = ipxw_mux_spx_send_ack(h, false, false);
			break;

		case IPXW_MUX_SPX_CONN_REQ_SENT:
			/* proceed with regular retransmit logic */
		case IPXW_MUX_SPX_CONN_WAITING_FOR_ACK:
			/* give up on the connection after too many retransmit
			 * attempts */
			if (h.last_known_state->last_tx_attempts >
					SPX_RETRY_COUNT) {
				errno = ETIMEDOUT;
				return false;
			}

			/* no retransmit necessary yet */
			if (h.last_known_state->ticks_since_last_keep_alive <=
					SPX_KEEP_ALIVE_TMO_TICKS) {
				return true;
			}

			/* need to retransmit the first packet in the
			 * connection */
			if (h.last_known_state->state ==
					IPXW_MUX_SPX_CONN_REQ_SENT) {
				send_success = ipxw_mux_spx_send_conn_req(h);

			/* need to retransmit a size negotiation request with a
			 * lower size than last time */
			} else if (ipxw_mux_spx_sizng_active(h)) {
				if (!ipxw_mux_spx_update_sizng_size(h)) {
					errno = EMSGSIZE;
					return false;
				}

				send_success = ipxw_mux_spx_send_sizng_req(h,
						ipxw_mux_spx_get_cur_sizng_val(h));

			/* need to retransmit the last packet */
			} else {
				/* retransmit the last message */
				send_success = ipxw_mux_spx_resend_last_msg(h);
			}

			/* sending failed, no state update */
			if (!send_success) {
				break;
			}

			/* retransmit counts as both keep alive and verify */
			h.last_known_state->last_tx_attempts += 1;
			h.last_known_state->ticks_since_last_keep_alive = 0;
			h.last_known_state->ticks_since_last_verify = 0;

			return true;

		default:
			errno = EINVAL;
			return false;
	}

	/* even if transmission fails, this call succeeds for some errors and
	 * we retry on the next maintenance call */
	if (!send_success) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK
				|| errno == EMSGSIZE || errno == ENOBUFS) {
			return true;
		}
	}

	return send_success;
}

static bool ipxw_mux_spx_established_pre_sizng(struct ipxw_mux_spx_handle h)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		return false;
	}

	switch (h.last_known_state->state) {
		case IPXW_MUX_SPX_CONN_ESTABLISHED:
		case IPXW_MUX_SPX_CONN_MUST_SEND_ACK:
		case IPXW_MUX_SPX_CONN_WAITING_FOR_ACK:
			return true;
		default:
			return false;
	}

	return false;
}

bool ipxw_mux_spx_established(struct ipxw_mux_spx_handle h)
{
	if (!ipxw_mux_spx_established_pre_sizng(h)) {
		return false;
	}

	if (ipxw_mux_spx_sizng_active(h)) {
		return false;
	}

	return true;
}

int ipxw_mux_spx_max_data_len(struct ipxw_mux_spx_handle h)
{
	if (!ipxw_mux_spx_established(h)) {
		return -1;
	}

	if (!h.last_known_state->spxii) {
		return SPX_MAX_DATA_LEN_WO_SIZNG;
	}

	return ipxw_mux_spx_data_len(h.last_known_state->neg_size_to_remote,
			true);
}

bool ipxw_mux_spx_xmit_ready(struct ipxw_mux_spx_handle h)
{
	if (!ipxw_mux_spx_established(h)) {
		return false;
	}

	/* if an ack is outstanding, try to send it here */
	if (h.last_known_state->state == IPXW_MUX_SPX_CONN_MUST_SEND_ACK) {
		if (!ipxw_mux_spx_send_ack(h, false, false)) {
			return false;
		}
	}

	/* not ready to send or remote not ready to receive */
	if (h.last_known_state->state != IPXW_MUX_SPX_CONN_ESTABLISHED) {
		return false;
	}
	if (spx_seq_less_than(h.last_known_state->remote_alloc_no,
				h.last_known_state->local_current_sequence)) {
		return false;
	}

	return true;
}

void ipxw_mux_spx_prepare_xmit_msg(struct ipxw_mux_spx_handle h, struct
		ipxw_mux_spx_msg *msg)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		return;
	}

	msg->spxii = h.last_known_state->spxii;
}

ssize_t ipxw_mux_spx_xmit(struct ipxw_mux_spx_handle h, struct ipxw_mux_spx_msg
		*msg, size_t data_len, bool block)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		errno = EINVAL;
		return -1;
	}

	/* not ready to send or remote not ready to receive */
	if (h.last_known_state->state != IPXW_MUX_SPX_CONN_ESTABLISHED) {
		errno = ENOBUFS;
		return -1;
	}
	if (spx_seq_less_than(h.last_known_state->remote_alloc_no,
				h.last_known_state->local_current_sequence)) {
		errno = ENOBUFS;
		return -1;
	}

	/* check message length */
	size_t max_data_len =  ipxw_mux_spx_max_data_len(h);
	if (data_len > max_data_len) {
		errno = EINVAL;
		return -1;
	}

	/* don't allow sending end of connection datastream types */
	if (msg->datastream_type == SPX_DS_END_OF_CONN || msg->datastream_type
			== SPX_DS_END_OF_CONN_ACK) {
		errno = EINVAL;
		return -1;
	}

	/* clear output and disallowed message fields */
	msg->keep_alive = false;
	msg->system = false;
	msg->ack = false;
	msg->negotiate_size = false;
	msg->ack_required = true;
	ipxw_mux_fill_msg_from_state(h, msg);

	size_t msg_len = ipxw_mux_spx_msg_len(data_len,
			h.last_known_state->spxii);

	/* actually send the data */
	int flags = block ? 0 : MSG_DONTWAIT;
	ssize_t sent_len = send(h.spx_sock, msg, msg_len, flags);
	if (sent_len < 0) {
		return -1;
	}
	if (sent_len != msg_len) {
		errno = ECOMM;
		return -1;
	}

	/* save the message in case we need to retransmit */
	memcpy(&(h.last_known_state->last_msg), msg, msg_len);
	h.last_known_state->last_msg_data_len = data_len;

	/* sending data counts as both keep alive and verify */
	h.last_known_state->ticks_since_last_keep_alive = 0;
	h.last_known_state->ticks_since_last_verify = 0;

	h.last_known_state->state = IPXW_MUX_SPX_CONN_WAITING_FOR_ACK;

	return sent_len;
}

bool ipxw_mux_spx_recv_ready(struct ipxw_mux_spx_handle h)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		return false;
	}

	/* if an ack is outstanding, try to send it here */
	if (h.last_known_state->state == IPXW_MUX_SPX_CONN_MUST_SEND_ACK) {
		if (!ipxw_mux_spx_send_ack(h, false, false)) {
			return false;
		}
	}

	switch (h.last_known_state->state) {
		case IPXW_MUX_SPX_CONN_REQ_SENT:
		case IPXW_MUX_SPX_CONN_ESTABLISHED:
		case IPXW_MUX_SPX_CONN_WAITING_FOR_ACK:
			return true;
		default:
			return false;
	}

	return false;
}

ssize_t ipxw_mux_spx_peek_recvd_len(struct ipxw_mux_spx_handle h, bool block)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		errno = EINVAL;
		return -1;
	}

	switch (h.last_known_state->state) {
		case IPXW_MUX_SPX_CONN_REQ_SENT:
		case IPXW_MUX_SPX_CONN_ESTABLISHED:
		case IPXW_MUX_SPX_CONN_WAITING_FOR_ACK:
			break;
		default:
			errno = EINVAL;
			return -1;
	}

	struct ipxw_mux_spx_msg msg;

	int flags = (block ? 0 : MSG_DONTWAIT) | MSG_PEEK;
	ssize_t rcvd_len = recv(h.spx_sock, &msg, sizeof(msg), flags);
	if (rcvd_len < 0) {
		return -1;
	}

	do {
		/* need the ipxw_mux_spx_msg */
		if (rcvd_len < SPX_WIRE_OVERHEAD) {
			errno = EREMOTEIO;
			break;
		}

		size_t hdr_len = ipxw_mux_spx_msg_len(0, msg.spxii);
		if (rcvd_len < hdr_len) {
			errno = EREMOTEIO;
			break;
		}

		/* which has to be of the correct type */
		if (msg.mux_msg.type != IPXW_MUX_RECV) {
			errno = EINVAL;
			break;
		}

		/* and the data must fit */
		size_t spx_hdr_len = hdr_len - sizeof(struct ipxhdr);
		size_t data_len = msg.mux_msg.recv.data_len;
		if (data_len < spx_hdr_len) {
			errno = EREMOTEIO;
			break;
		}
		data_len -= spx_hdr_len;
		size_t spx_max_data_len = msg.spxii ? SPXII_MAX_DATA_LEN :
			SPX_MAX_DATA_LEN;
		if (data_len > spx_max_data_len) {
			errno = EREMOTEIO;
			break;
		}

		/* return the size of the message to receive, assuming this
		 * message is an SPXII message, this will allow the caller to
		 * allocate enough space for both cases */
		return data_len + sizeof(struct ipxw_mux_spx_msg);
	} while (0);

	/* clear out invalid message */
	recv(h.spx_sock, &msg, rcvd_len, 0);

	return -1;
}

static bool ipxw_mux_spx_is_current_ack(struct ipxw_mux_spx_handle h, struct
		ipxw_mux_spx_msg *msg)
{
	/* message must be an ACK */
	if (msg->end_of_msg || msg->attention ||
			msg->ack_required || !msg->system) {
		return false;
	}

	/* we want an ACK and it has to ACK the last packet we sent */
	__u16 local_next_sequence = h.last_known_state->local_current_sequence;
	if (h.last_known_state->last_msg_data_len != 0) {
		/* last msg was a non-system packet, therefore we need the ack
		 * number to be one higher than its seq no */
		__builtin_add_overflow(local_next_sequence, 1,
				&local_next_sequence);
	}
	if (msg->remote_expected_sequence !=
			local_next_sequence) {
		return false;
	}

	return true;
}

static bool ipxw_mux_spx_handle_recvd_generic(struct ipxw_mux_spx_handle h,
		struct ipxw_mux_spx_msg *msg, ssize_t msg_len, bool
		waiting_for_ack)
{
	assert(ipxw_mux_spx_established_pre_sizng(h));

	if (h.last_known_state->local_current_sequence !=
			msg->remote_expected_sequence) {
		/* invalid message */
		return false;
	}

	/* update the state */
	if (!msg->system) {
		__builtin_add_overflow(
				h.last_known_state->remote_expected_sequence,
				1,
				&(h.last_known_state->remote_expected_sequence));
		__builtin_add_overflow(h.last_known_state->local_alloc_no, 1,
				&(h.last_known_state->local_alloc_no));

		if (waiting_for_ack) {
			/* update the last message to retransmit */
			ipxw_mux_fill_msg_from_state(h,
					&(h.last_known_state->last_msg));
		}
	} else {
		/* size negotiation request, record this as the largest message
		 * size we have received, unless we have already seen a larger
		 * size negotiation request */
		if (msg->negotiate_size && msg_len >
				h.last_known_state->neg_size_to_local) {
			h.last_known_state->neg_size_to_local = msg_len;
		}
	}

	if (msg->ack_required) {
		bool is_sizng = h.last_known_state->spxii &&
			msg->negotiate_size;
		if (waiting_for_ack) {
			ipxw_mux_spx_send_ack_wo_state_change(h, is_sizng,
					false);
		} else {
			h.last_known_state->state =
				IPXW_MUX_SPX_CONN_MUST_SEND_ACK;
			ipxw_mux_spx_send_ack(h, is_sizng, false);
		}
	}

	return true;
}

ssize_t ipxw_mux_spx_get_recvd(struct ipxw_mux_spx_handle h, struct
		ipxw_mux_spx_msg *msg, size_t data_len, bool block)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		errno = EINVAL;
		return -1;
	}

	switch (h.last_known_state->state) {
		case IPXW_MUX_SPX_CONN_REQ_SENT:
		case IPXW_MUX_SPX_CONN_ESTABLISHED:
		case IPXW_MUX_SPX_CONN_WAITING_FOR_ACK:
			break;
		default:
			errno = EINVAL;
			return -1;
	}

	size_t spx_max_data_len = h.last_known_state->spxii ?
		SPXII_MAX_DATA_LEN : SPX_MAX_DATA_LEN;
	if (data_len > spx_max_data_len) {
		errno = EINVAL;
		return -1;
	}

	/* really get ready to receive the maxium message length, we need the
	 * message header to deterimine if SPX or SPXII */
	size_t max_msg_len = data_len + SPXII_WIRE_OVERHEAD;

	/* receive a msg, may block */
	int flags = (block ? 0 : MSG_DONTWAIT);
	ssize_t rcvd_len = recv(h.spx_sock, msg, max_msg_len, flags);
	if (rcvd_len < 0) {
		return -1;
	}

	/* need at least a full SPX msg */
	if (rcvd_len < SPX_WIRE_OVERHEAD) {
		errno = EREMOTEIO;
		return -1;
	}

	if (msg->datastream_type == SPX_DS_END_OF_CONN) {
		h.last_known_state->state = IPXW_MUX_SPX_CONN_MUST_SEND_ACK;
		ipxw_mux_spx_send_ack(h, false, true);
		errno = ENOTCONN;
		return -1;
	}

	size_t hdr_len = ipxw_mux_spx_msg_len(0, h.last_known_state->spxii);
	size_t msg_buf_len = ipxw_mux_spx_msg_len(data_len,
			h.last_known_state->spxii);

	if (spx_seq_less_than(h.last_known_state->local_alloc_no, msg->seq_no))
	{
		/* invalid message, no output */
		memset(msg, 0, msg_buf_len);
		return 0;
	}

	switch (h.last_known_state->state) {
		case IPXW_MUX_SPX_CONN_ESTABLISHED:
			/* need the correct header length for SPX or SPXII */
			if (rcvd_len < hdr_len) {
				/* invalid message, no output */
				memset(msg, 0, msg_buf_len);
				return 0;
			}

			/* only accept messages of the same SPX version,
			 * downgrade should have happened earlier */
			if (msg->spxii != h.last_known_state->spxii) {
				/* invalid message, no output */
				memset(msg, 0, msg_buf_len);
				return 0;
			}

			if (!ipxw_mux_spx_handle_recvd_generic(h, msg,
						rcvd_len, false))
			{
				/* invalid message, no output */
				memset(msg, 0, msg_buf_len);
				return 0;
			}

			break;

		case IPXW_MUX_SPX_CONN_REQ_SENT:
			/* message must have the correct flags */
			if (msg->end_of_msg || msg->attention ||
					msg->ack_required || !msg->system) {
				/* invalid message, no output */
				memset(msg, 0, msg_buf_len);
				return 0;
			}

			/* this should be the very first packet the remote
			 * station sends */
			if (msg->remote_expected_sequence != 0) {
				/* invalid message, no output */
				memset(msg, 0, msg_buf_len);
				return 0;
			}

			/* this acks the last sent msg */

			/* the connection ACK was SPX and not SPXII, we have to
			 * downgrade the connection here if we started out with
			 * SPXII */
			if (!msg->spxii) {
				h.last_known_state->spxii = false;
				ipxw_mux_spx_stop_sizeng(h);
			}

			h.last_known_state->state =
				IPXW_MUX_SPX_CONN_ESTABLISHED;
			h.last_known_state->last_tx_attempts = 0;

			if (h.last_known_state->spxii) {
				ipxw_mux_spx_send_sizng_req(h,
						ipxw_mux_spx_get_cur_sizng_val(h));
			}

			break;

		case IPXW_MUX_SPX_CONN_WAITING_FOR_ACK:
			/* need the correct header length for SPX or SPXII */
			if (rcvd_len < hdr_len) {
				/* invalid message, no output */
				memset(msg, 0, msg_buf_len);
				return 0;
			}

			/* only accept messages of the same SPX version,
			 * downgrade should have happened earlier */
			if (msg->spxii != h.last_known_state->spxii) {
				/* invalid message, no output */
				memset(msg, 0, msg_buf_len);
				return 0;
			}

			/* message is an ACK */
			if (ipxw_mux_spx_is_current_ack(h, msg)) {
				/* increment sequence number after receiving an
				 * ACK for a non-system message */
				if (h.last_known_state->last_msg_data_len != 0) {
					__builtin_add_overflow(
							h.last_known_state->local_current_sequence,
							1,
							&(h.last_known_state->local_current_sequence));
				}

				if (h.last_known_state->spxii &&
						msg->negotiate_size &&
						msg->negotiation_size >
						h.last_known_state->neg_size_to_remote)
				{
					/* handle size negotiation ACK */
					h.last_known_state->neg_size_to_remote
						= msg->negotiation_size;

					/* size negotiation was successful,
					 * terminate */
					ipxw_mux_spx_stop_sizeng(h);
				}

				/* this acks the last sent msg */
				h.last_known_state->state =
					IPXW_MUX_SPX_CONN_ESTABLISHED;
				h.last_known_state->last_tx_attempts = 0;
				h.last_known_state->last_msg_data_len = 0;

				break;

			}

			/* message is not an ack */

			if (!ipxw_mux_spx_handle_recvd_generic(h, msg,
						rcvd_len, true)) {
				/* invalid message, no output */
				memset(msg, 0, msg_buf_len);
				return 0;
			}

			break;

		default:
			assert(0);
	}

	/* update the state */
	h.last_known_state->ticks_since_last_remote_msg = 0;
	h.last_known_state->remote_alloc_no = msg->remote_alloc_no;

	if (msg->system) {
		/* no output in case of system msg */
		memset(msg, 0, msg_buf_len);
		return 0;
	}

	/* clear system fields before output */
	msg->system = false;
	msg->keep_alive = false;
	msg->ack = false;
	msg->ack_required = false;
	msg->negotiate_size = false;
	msg->remote_alloc_no = 0;
	msg->local_alloc_no = 0;
	msg->remote_expected_sequence = 0;
	msg->seq_no = 0;

	return rcvd_len;
}

/* helpers */

#define NLMSG_BUF_SIZE 1024

static int get_src_to_dst_outif(struct in6_addr *src, struct in6_addr *dst)
{
	struct {
		union {
			struct {
				struct nlmsghdr nh;
				struct rtmsg rtm;
			};
		char buf[NLMSG_BUF_SIZE];
		};
	} nlmsg;
	memset(&nlmsg, 0, sizeof(nlmsg));

	int nlsock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (nlsock < 0) {
		return -1;
	}

	nlmsg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(nlmsg.rtm));
	nlmsg.nh.nlmsg_flags = NLM_F_REQUEST;
	nlmsg.nh.nlmsg_type = RTM_GETROUTE;

	nlmsg.rtm.rtm_family = AF_INET6;
	nlmsg.rtm.rtm_table = RT_TABLE_MAIN;
	nlmsg.rtm.rtm_type = RTN_UNICAST;
	nlmsg.rtm.rtm_protocol = RTPROT_KERNEL;
	nlmsg.rtm.rtm_scope = RT_SCOPE_UNIVERSE;

	struct rtattr *rta = (struct rtattr *)(((char *) &nlmsg) +
			NLMSG_ALIGN(nlmsg.nh.nlmsg_len));
	rta->rta_type = RTA_SRC;
	rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
	memcpy(RTA_DATA(rta), src, sizeof(struct in6_addr));
	nlmsg.nh.nlmsg_len = NLMSG_ALIGN(nlmsg.nh.nlmsg_len) +
		RTA_LENGTH(sizeof(struct in6_addr));

	rta = (struct rtattr *)(((char *) &nlmsg) +
			NLMSG_ALIGN(nlmsg.nh.nlmsg_len));
	rta->rta_type = RTA_DST;
	rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
	memcpy(RTA_DATA(rta), dst, sizeof(struct in6_addr));
	nlmsg.nh.nlmsg_len = NLMSG_ALIGN(nlmsg.nh.nlmsg_len) +
		RTA_LENGTH(sizeof(struct in6_addr));

	do {
		if (send(nlsock, &nlmsg, nlmsg.nh.nlmsg_len, MSG_DONTWAIT) < 0)
		{
			break;
		}

		ssize_t rcv_len = recv(nlsock, nlmsg.buf, sizeof(nlmsg),
				MSG_DONTWAIT);
		if (rcv_len < 0) {
			break;
		}

		struct nlmsghdr *hdr = (struct nlmsghdr *) nlmsg.buf;
		for (; NLMSG_OK(hdr, rcv_len); hdr = NLMSG_NEXT(hdr, rcv_len))
		{
			struct rtmsg *route_msg = (struct rtmsg *)
				NLMSG_DATA(hdr);
			rta = (struct rtattr *) (route_msg + 1);

			if (route_msg->rtm_family == AF_INET6) {
				for (; RTA_OK(rta, rcv_len); rta =
						RTA_NEXT(rta, rcv_len)) {
					if (rta->rta_type == RTA_OIF) {
						int ifidx = *((int *)
								RTA_DATA(rta));
						close(nlsock);
						return ifidx;
					}
				}
			}
		}

		errno = ENOENT;
	} while (0);

	close(nlsock);
	return -1;
}

static int get_if_mtu_for_sock(int ifidx, int sockfd) {
	struct ifreq ifr;
	if (if_indextoname(ifidx, ifr.ifr_name) == NULL) {
		return -1;
	}

	if (ioctl(sockfd, SIOCGIFMTU, &ifr) == -1) {
		return -1;
	}

	return ifr.ifr_mtu;
}

int ipxw_get_outif_max_ipx_data_len_for_dst(struct ipxw_mux_handle h, struct
		ipx_addr *dst)
{
	if (ipxw_mux_handle_is_error(h)) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_in6 sa_src;
	socklen_t sa_src_len = sizeof(struct sockaddr_in6);
	if (getsockname(ipxw_mux_handle_data(h), (struct sockaddr *) &sa_src,
				&sa_src_len) != 0) {
		return -1;
	}
	if (sa_src_len != sizeof(struct sockaddr_in6)) {
		errno = EINVAL;
		return -1;
	}

	struct in6_addr ip6_dst;
	ipx_to_ipv6_addr(&ip6_dst, dst, h.prefix);

	int oifidx = get_src_to_dst_outif(&(sa_src.sin6_addr), &ip6_dst);
	if (oifidx < 0) {
		return -1;
	}

	int mtu = get_if_mtu_for_sock(oifidx, ipxw_mux_handle_data(h));
	if (mtu < 0) {
		return -1;
	}

	if (mtu < IPX_WRAP_OVERHEAD) {
		return 0;
	}

	return (mtu - IPX_WRAP_OVERHEAD);
}

int ipxw_get_outif_max_spx_data_len_for_peer(struct ipxw_mux_spx_handle h)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_in6 sa_src;
	socklen_t sa_src_len = sizeof(struct sockaddr_in6);
	if (getsockname(ipxw_mux_spx_handle_sock(h), (struct sockaddr *)
				&sa_src, &sa_src_len) != 0) {
		return -1;
	}
	if (sa_src_len != sizeof(struct sockaddr_in6)) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_in6 sa_dst;
	socklen_t sa_dst_len = sizeof(struct sockaddr_in6);
	if (getpeername(ipxw_mux_spx_handle_sock(h), (struct sockaddr *)
				&sa_dst, &sa_dst_len) != 0) {
		return -1;
	}
	if (sa_dst_len != sizeof(struct sockaddr_in6)) {
		errno = EINVAL;
		return -1;
	}

	int oifidx = get_src_to_dst_outif(&(sa_src.sin6_addr), &(sa_dst.sin6_addr));
	if (oifidx < 0) {
		return -1;
	}

	int mtu = get_if_mtu_for_sock(oifidx, ipxw_mux_spx_handle_sock(h));
	if (mtu < 0) {
		return -1;
	}

	size_t overhead = h.last_known_state->spxii ? SPXII_WRAP_OVERHEAD :
		SPX_WRAP_OVERHEAD;
	if (mtu < overhead) {
		return 0;
	}

	size_t max_mtu = (h.last_known_state->spxii ? SPXII_MAX_PKT_LEN :
			SPX_MAX_PKT_LEN_WO_SIZNG) + overhead;
	if (mtu > max_mtu) {
		return max_mtu;
	}

	return (mtu - overhead);
}
