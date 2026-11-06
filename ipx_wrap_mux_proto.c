#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <linux/limits.h>
#include <linux/net_tstamp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sctp.h>
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
	msgh.msg_flags = 0;

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

	iov.iov_base = conf_out;
	iov.iov_len = expected_out_len;

	memset(ctrl_msg.buf, 0, sizeof(ctrl_msg.buf));

	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;
	msgh.msg_control = ctrl_msg.buf;
	msgh.msg_controllen = sizeof(ctrl_msg.buf);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_flags = 0;

	/* receive the response, this blocks */
	ssize_t rcvd_len = -1;
	do {
		rcvd_len = recvmsg(h.conf_sock, &msgh, 0);
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

static void ipx_to_ipv6_sockaddr(struct sockaddr_in6 *dst, const struct
		sockaddr_ipx *src, __be32 prefix)
{
	memset(dst, 0, sizeof(struct sockaddr_in6));

	dst->sin6_family = AF_INET6;
	dst->sin6_port = src->sipx_port;
	dst->sin6_scope_id = 0;
	dst->sin6_flowinfo = 0;

	struct ipv6_eui64_addr *res = (struct ipv6_eui64_addr *)
		&(dst->sin6_addr);
	res->prefix = prefix;
	res->ipx_net = src->sipx_network;
	memcpy(&(res->ipx_node_fst), src->sipx_node, IPX_ADDR_NODE_BYTES / 2);
	res->fffe = htons((IPX_DIRECT_MARK << 8) | src->sipx_type);
	memcpy(&(res->ipx_node_snd), &(src->sipx_node[3]), IPX_ADDR_NODE_BYTES
			/ 2);
}

ssize_t ipxw_mux_sendmsg(struct ipxw_mux_handle h, const struct msghdr *msg,
		int flags)
{
	struct msghdr actual_hdr;
	memcpy(&actual_hdr, msg, sizeof(struct msghdr));

	if (actual_hdr.msg_namelen == 0 && actual_hdr.msg_name == NULL) {
		return sendmsg(h.data_sock, &actual_hdr, flags);
	}

	if (actual_hdr.msg_namelen != sizeof(struct sockaddr_ipx) ||
			actual_hdr.msg_name == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (((struct sockaddr *) actual_hdr.msg_name)->sa_family != AF_IPX) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_in6 dummy_dst;
	ipx_to_ipv6_sockaddr(&dummy_dst, (struct sockaddr_ipx *)
			actual_hdr.msg_name, h.prefix);

	actual_hdr.msg_name = &dummy_dst;
	actual_hdr.msg_namelen = sizeof(struct sockaddr_in6);

	return sendmsg(h.data_sock, &actual_hdr, flags);
}

ssize_t ipxw_mux_sendto(struct ipxw_mux_handle h, const void *buf, size_t len,
		int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	if (len > IPX_MAX_DATA_LEN) {
		errno = EMSGSIZE;
		return -1;
	}

	if (addrlen == 0 && dest_addr == NULL) {
		return sendto(h.data_sock, buf, len, flags, NULL, 0);
	}

	if (addrlen != sizeof(struct sockaddr_ipx) || dest_addr == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (dest_addr->sa_family != AF_IPX) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_in6 dummy_dst;
	ipx_to_ipv6_sockaddr(&dummy_dst, (struct sockaddr_ipx *) dest_addr,
			h.prefix);
	return sendto(h.data_sock, buf, len, flags, (struct sockaddr *)
			&dummy_dst, sizeof(struct sockaddr_in6));
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

static void ipv6_to_ipx_sockaddr(struct sockaddr_ipx *dst, const struct
		sockaddr_in6 *src)
{
	memset(dst, 0, sizeof(struct sockaddr_ipx));

	struct ipv6_eui64_addr *saddr = (struct ipv6_eui64_addr *)
		&src->sin6_addr;

	dst->sipx_family = AF_IPX;
	dst->sipx_network = saddr->ipx_net;
	memcpy(dst->sipx_node, saddr->ipx_node_fst, IPX_ADDR_NODE_BYTES / 2);
	memcpy(&(dst->sipx_node[3]), saddr->ipx_node_snd, IPX_ADDR_NODE_BYTES /
			2);
	dst->sipx_port = src->sin6_port;
	dst->sipx_type = ntohs(saddr->fffe) & 0xFF;
}

static void *ipxw_mux_get_rx_cmsg(void *ctrl, size_t ctrl_len, int level, int
		type)
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

	struct cmsghdr *cmsgh;
	for (cmsgh = CMSG_FIRSTHDR(&msgh); cmsgh != NULL; cmsgh =
			CMSG_NXTHDR(&msgh, cmsgh)) {
		if (cmsgh->cmsg_level == level && cmsgh->cmsg_type == type) {
			return CMSG_DATA(cmsgh);
		}
	}

	return NULL;
}

bool ipxw_mux_enable_rx_tc(struct ipxw_mux_handle h)
{
	int val = 1;
	if (setsockopt(h.data_sock, IPXPROTO_IPX, IPX_RECV_TRANSPORT_CONTROL,
				&val, sizeof(val)) != 0) {
		return false;
	}

	return true;
}

__u8 ipxw_mux_get_rx_tc(void *ctrl, size_t ctrl_len)
{
	int tc;

	void *rcvd_tc = ipxw_mux_get_rx_cmsg(ctrl, ctrl_len, IPXPROTO_IPX,
			IPX_TRANSPORT_CONTROL);
	if (rcvd_tc == NULL) {
		return IPXW_TC_INVALID;
	}

	memcpy(&tc, rcvd_tc, sizeof(int));
	return tc;
}

ssize_t ipxw_mux_recvmsg(struct ipxw_mux_handle h, struct msghdr *msg, int
		flags)
{
	/* need both src_addr and addrlen if one is specified */
	if ((msg->msg_namelen == 0) != (msg->msg_name == NULL)) {
		errno = EINVAL;
		return -1;
	}

	struct msghdr actual_hdr;
	memcpy(&actual_hdr, msg, sizeof(struct msghdr));

	struct sockaddr_in6 dummy_src;
	actual_hdr.msg_name = &dummy_src;
	actual_hdr.msg_namelen = sizeof(struct sockaddr_in6);

	ssize_t ret = recvmsg(h.data_sock, &actual_hdr, flags);
	if (ret < 0) {
		return -1;
	}

	if (actual_hdr.msg_namelen != sizeof(struct sockaddr_in6)) {
		errno = EINVAL;
		return -1;
	}
	if (((struct sockaddr *) actual_hdr.msg_name)->sa_family != AF_INET6) {
		errno = EINVAL;
		return -1;
	}

	/* restore info from actual header */
	msg->msg_iovlen = actual_hdr.msg_iovlen;
	msg->msg_controllen = actual_hdr.msg_controllen;
	msg->msg_flags = actual_hdr.msg_flags;

	if (msg->msg_name == NULL) {
		return ret;
	}

	/* restore source address from actual header */
	struct sockaddr_ipx real_src;
	ipv6_to_ipx_sockaddr(&real_src, &dummy_src);

	socklen_t addr_to_write = (msg->msg_namelen < sizeof(struct
				sockaddr_ipx)) ? msg->msg_namelen :
		sizeof(struct sockaddr_ipx);

	memcpy(msg->msg_name, &real_src, addr_to_write);
	msg->msg_namelen = sizeof(struct sockaddr_ipx);

	return ret;
}

ssize_t ipxw_mux_recvfrom(struct ipxw_mux_handle h, void *buf, size_t len, int
		flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	/* need both src_addr and addrlen if one is specified */
	if ((addrlen == NULL) != (src_addr == NULL)) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_in6 dummy_src;
	socklen_t dummy_src_len = sizeof(dummy_src);

	ssize_t ret = recvfrom(h.data_sock, buf, len, flags, (struct sockaddr
				*) &dummy_src, &dummy_src_len);
	if (ret < 0) {
		return -1;
	}

	if (dummy_src_len != sizeof(struct sockaddr_in6)) {
		errno = EINVAL;
		return -1;
	}
	if (dummy_src.sin6_family != AF_INET6) {
		errno = EINVAL;
		return -1;
	}

	if (addrlen == NULL) {
		return ret;
	}

	struct sockaddr_ipx real_src;
	ipv6_to_ipx_sockaddr(&real_src, &dummy_src);

	socklen_t addr_to_write = (*addrlen < sizeof(struct sockaddr_ipx)) ?
		*addrlen : sizeof(struct sockaddr_ipx);

	memcpy(src_addr, &real_src, addr_to_write);
	*addrlen = sizeof(struct sockaddr_ipx);

	return ret;
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

/* define this ourselves in case the 6.13 kernel headers are not available */
#ifndef SCM_TS_OPT_ID
#define SCM_TS_OPT_ID 81
#endif /* SCM_TS_OPT_ID */

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
	struct scm_timestamping64 tsmsg;
	void *rcvd_tsmsg = ipxw_mux_get_rx_cmsg(ctrl, ctrl_len, SOL_SOCKET,
			SO_TIMESTAMPING_NEW);
	if (rcvd_tsmsg == NULL) {
		return false;
	}

	memcpy(&tsmsg, rcvd_tsmsg, sizeof(tsmsg));
	/* have hardware timestamp */
	if (tsmsg.ts[2].tv_sec != 0 || tsmsg.ts[2].tv_nsec != 0) {
		memcpy(ts, &(tsmsg.ts[2]), sizeof(struct __kernel_timespec));
		return true;
	}
	/* have software timestamp */
	if (tsmsg.ts[0].tv_sec != 0 || tsmsg.ts[0].tv_nsec != 0) {
		memcpy(ts, &(tsmsg.ts[0]), sizeof(struct __kernel_timespec));
		return true;
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
	msgh.msg_flags = 0;

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

ssize_t ipxw_mux_recv_conf(int conf_sock, struct ipxw_mux_msg *msg, int
		*transmitted_fd)
{
	if (transmitted_fd == NULL) {
		errno = EINVAL;
		return -1;
	}

	size_t msg_len = sizeof(struct ipxw_mux_msg);
	*transmitted_fd = -1;

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

	struct iovec iov = {
		.iov_base = msg,
		.iov_len = msg_len
	};

	struct msghdr msgh;
	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;
	msgh.msg_control = NULL;
	msgh.msg_controllen = 0;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_flags = 0;

	/* do we need to transmit an FD? */
	union {
		char buf[CMSG_SPACE(sizeof(int))]; /* Space large enough to
						      hold one int */
		struct cmsghdr align;
	} ctrl_msg;
	memset(ctrl_msg.buf, 0, sizeof(ctrl_msg.buf));
	if (*transmitted_fd >= 0) {
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

		/* store the fd we want to send */
		cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsgp), transmitted_fd, sizeof(int));
	}

	ssize_t sent_len = sendmsg(conf_sock, &msgh, 0);
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

bool ipxw_mux_spx_handle_is_error(struct ipxw_mux_spx_handle h)
{
	return (h.spx_sock < 0) || (h.conf_sock < 0) || (h.conn_id ==
			SPX_CONN_ID_UNKNOWN);
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

	if (h->conf_sock >= 0) {
		close(h->conf_sock);
	}

	h->spx_sock = -1;
	h->conf_sock = -1;
	h->conf_sock = SPX_CONN_ID_UNKNOWN;
}

static struct ipxw_mux_spx_handle ipxw_mux_spx_mk_handle(struct ipxw_mux_handle
		h)
{
	struct ipxw_mux_spx_handle ret;
	ret.spx_sock = -1;
	ret.conf_sock = -1;
	ret.conn_id = SPX_CONN_ID_UNKNOWN;

	if (ipxw_mux_handle_is_error(h)) {
		errno = EINVAL;
		return ret;
	}

	int spx_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);
	if (spx_sock < 0) {
		return ret;
	}

	int conf_sock = dup(h.conf_sock);
	if (conf_sock == -1) {
		close(spx_sock);
		return ret;
	}

	ret.spx_sock = spx_sock;
	ret.conf_sock = conf_sock;

	return ret;
}

static bool ipxw_mux_spx_connect(int spx_sock, __be32 prefix, struct ipx_addr
		*saddr, struct ipx_addr *daddr)
{
	/* connect the socket so that sending without a specific
	 * destination address works */
	struct sockaddr_in6 dummy_connect = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(IPX_IN_IPV6_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	ipx_to_ipv6_addr(&(dummy_connect.sin6_addr), daddr, prefix);

	if (connect(spx_sock, (struct sockaddr *) &dummy_connect,
				sizeof(dummy_connect)) < 0) {
		return false;
	}

	return true;
}

__be16 ipxw_mux_kspx_check_for_conn_req(const void *buf, size_t len, const
		struct sockaddr_ipx *src)
{
	if (len != sizeof(struct spxhdr)) {
		return SPX_CONN_ID_UNKNOWN;
	}

	if (src->sipx_type != SPX_PKT_TYPE) {
		return SPX_CONN_ID_UNKNOWN;
	}

	const struct spxhdr *spxh = buf;
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

	return spxh->src_conn_id;
}

void ipxw_mux_spx_conn_close(struct ipxw_mux_spx_handle *h)
{
	if (!ipxw_mux_spx_handle_is_error(*h)) {
		/* no error handling, nothing that can be done */
		struct ipxw_mux_msg close_msg;
		close_msg.type = IPXW_MUX_SPX_CLOSE;
		close_msg.spx_close.conn_id = h->conn_id;
		send(h->conf_sock, &close_msg, sizeof(close_msg),
				MSG_DONTWAIT);
	}

	ipxw_mux_spx_handle_close(h);
}

struct ipxw_mux_spx_handle ipxw_mux_kspx_connect(struct ipxw_mux_handle h,
		struct ipx_addr *daddr)
{
	struct ipxw_mux_spx_handle ret = ipxw_mux_spx_mk_handle(h);
	if (ret.spx_sock < 0) {
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

		ret.conn_id = connect_rsp.spx_connect.conn_id;

		if (!ipxw_mux_spx_connect(ret.spx_sock, h.prefix,
					&(connect_rsp.spx_connect.addr),
					daddr)) {
			break;
		}

		return ret;
	} while (0);

	ipxw_mux_spx_conn_close(&ret);

	return ret;
}

struct ipxw_mux_spx_handle ipxw_mux_kspx_accept(struct ipxw_mux_handle h, const
		struct sockaddr_ipx *remote_sockaddr, __be16 remote_conn_id)
{
	struct ipx_addr remote_addr;
	sockaddr_ipx_to_ipx_addr(&remote_addr, remote_sockaddr);

	struct ipxw_mux_spx_handle ret = ipxw_mux_spx_mk_handle(h);
	if (ret.spx_sock < 0) {
		return ret;
	}

	struct ipxw_mux_msg accept_req;
	accept_req.type = IPXW_MUX_SPX_ACCEPT;
	accept_req.spx_accept.addr = remote_addr;
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

		ret.conn_id = accept_rsp.spx_accept.conn_id;

		if (!ipxw_mux_spx_connect(ret.spx_sock, h.prefix,
					&(accept_rsp.spx_accept.addr),
					&remote_addr)) {
			break;
		}

		return ret;
	} while (0);

	ipxw_mux_spx_conn_close(&ret);

	return ret;
}

ssize_t ipxw_mux_kspx_send(struct ipxw_mux_spx_handle h, const void *buf,
		size_t len, int flags, __u8 datastream_type, __u8 spx_flags)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		errno = EINVAL;
		return -1;
	}

	/* illegal datastream type */
	if (datastream_type == SPX_DS_END_OF_CONN || datastream_type ==
			SPX_DS_END_OF_CONN_ACK) {
		errno = EINVAL;
		return -1;
	}

	/* unsupported flags */
	if ((spx_flags & ~(SPX_F_END_OF_MSG | SPX_F_ATTENTION)) != 0) {
		errno = EINVAL;
		return -1;
	}

	if (len > SPX_MAX_DATA_LEN_WO_SIZNG) {
		errno = EMSGSIZE;
		return -1;
	}

	union kspx_sctp_ppid_info ppid_info;
	ppid_info.ppid = 0;
	ppid_info.datastream_type = datastream_type;
	ppid_info.end_of_msg = (spx_flags & SPX_F_END_OF_MSG) != 0;
	ppid_info.attention = (spx_flags & SPX_F_ATTENTION) != 0;

	struct sctp_sndinfo sndinfo = {
		.snd_sid = 0,
		.snd_flags = 0,
		.snd_ppid = ppid_info.ppid,
		.snd_context = 0,
		.snd_assoc_id = SCTP_CURRENT_ASSOC
	};

	struct iovec iov;
	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	union {
		char buf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
		struct cmsghdr align;
	} ctrl_msg;
	memset(ctrl_msg.buf, 0, sizeof(ctrl_msg.buf));

	struct msghdr msgh;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;
	msgh.msg_control = &ctrl_msg;
	msgh.msg_controllen = sizeof(ctrl_msg.buf);
	msgh.msg_flags = 0;

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
	memcpy(CMSG_DATA(cmsg), &sndinfo, sizeof(struct sctp_sndinfo));

	return sendmsg(h.spx_sock, &msgh, flags);
}

#define SCTP_CTRL_DATA_LEN (CMSG_SPACE(sizeof(struct sctp_rcvinfo)) + \
		CMSG_SPACE(sizeof(struct sctp_nxtinfo)))

ssize_t ipxw_mux_kspx_recv(struct ipxw_mux_spx_handle h, void *buf, size_t len,
		int flags, __u8 *datastream_type, __u8 *spx_flags)
{
	if (ipxw_mux_spx_handle_is_error(h)) {
		errno = EINVAL;
		return -1;
	}

	char ctrl_buf[SCTP_CTRL_DATA_LEN];

	struct iovec iov;
	iov.iov_base = buf;
	iov.iov_len = len;

	struct msghdr msgh;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;
	msgh.msg_control = &ctrl_buf;
	msgh.msg_controllen = SCTP_CTRL_DATA_LEN;
	msgh.msg_flags = 0;

	ssize_t nrcvd = recvmsg(h.spx_sock, &msgh, flags);
	if (nrcvd < 0) {
		return nrcvd;
	}

	*datastream_type = SPX_DS_NONE;
	*spx_flags = 0;

	void *rcvinfo_ptr = ipxw_mux_get_rx_cmsg(ctrl_buf, SCTP_CTRL_DATA_LEN,
			IPPROTO_SCTP, SCTP_RCVINFO);
	if (rcvinfo_ptr == NULL) {
		return nrcvd;
	}

	struct sctp_rcvinfo rcvinfo;
	memcpy(&rcvinfo, rcvinfo_ptr, sizeof(struct sctp_rcvinfo));

	union kspx_sctp_ppid_info ppid_info;
	ppid_info.ppid = rcvinfo.rcv_ppid;
	*datastream_type = ppid_info.datastream_type;
	if (ppid_info.end_of_msg) {
		*spx_flags |= SPX_F_END_OF_MSG;
	}
	if (ppid_info.attention) {
		*spx_flags |= SPX_F_ATTENTION;
	}

	/* caller attempted to determine the message length, try to accomodate
	 * them */
	if ((flags & MSG_PEEK) != 0 && (flags & MSG_TRUNC) != 0) {
		void *nxtinfo_ptr = ipxw_mux_get_rx_cmsg(ctrl_buf,
				SCTP_CTRL_DATA_LEN, IPPROTO_SCTP,
				SCTP_NXTINFO);

		if (nxtinfo_ptr == NULL) {
			return nrcvd;
		}

		struct sctp_nxtinfo nxtinfo;
		memcpy(&nxtinfo, nxtinfo_ptr, sizeof(struct sctp_nxtinfo));
		return nxtinfo.nxt_length;
	}


	return nrcvd;
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

void sockaddr_ipx_to_ipx_addr(struct ipx_addr *addr, const struct sockaddr_ipx
		*sockaddr)
{
	addr->net = sockaddr->sipx_network;
	memcpy(addr->node, sockaddr->sipx_node, IPX_ADDR_NODE_BYTES);
	addr->sock = sockaddr->sipx_port;
}

void ipx_addr_to_sockaddr_ipx(struct sockaddr_ipx *sockaddr, const struct
		ipx_addr *addr, __u8 pkt_type)
{
	sockaddr->sipx_family = AF_IPX;
	sockaddr->sipx_type = pkt_type;
	sockaddr->sipx_network = addr->net;
	memcpy(sockaddr->sipx_node, addr->node, IPX_ADDR_NODE_BYTES);
	sockaddr->sipx_port = addr->sock;
}
