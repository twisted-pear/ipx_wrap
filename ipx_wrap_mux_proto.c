#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "ipx_wrap_mux_proto.h"

/* client functions */

/* much of this code was taken from
 * https://man7.org/tlpi/code/online/dist/sockets/scm_rights_send.c.html */
int ipxw_mux_bind(struct ipxw_mux_msg *bind_msg)
{
	int sv[2] = { -1, -1 };
	int ctrl_sock = -1;

	do {
		if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
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

		if (connect(ctrl_sock, (struct sockaddr *) &ctrl_addr,
					ctrl_addr_len) < 0) {
			break;
		}

		/* force msg type */
		bind_msg->type = IPXW_MUX_BIND;

		struct msghdr msgh;
		msgh.msg_name = NULL;
		msgh.msg_namelen = 0;

		/* send the full message */
		struct iovec iov;
		iov.iov_base = bind_msg;
		iov.iov_len = sizeof(*bind_msg);

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
		memcpy(CMSG_DATA(cmsgp), &sv[1], sizeof(int));

		/* send the ctrl msg */
		/* should always transmit the entire msg or nothing */
		if (sendmsg(ctrl_sock, &msgh, 0) < 0) {
			break;
		}

		int data_sock = sv[0];

		/* receive a reply, this blocks */
		struct ipxw_mux_msg res;
		ssize_t res_len = -1;
		do {
			res_len = recv(data_sock, &res, sizeof(res), 0);
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
				close(sv[1]);
				close(ctrl_sock);
				return data_sock;
			case IPXW_MUX_BIND_ERR:
				errno = res.err.err;
				break;
			default:
				errno = ENOTSUP;
				break;
		}
	} while (0);

	if (sv[0] >= 0) {
		close(sv[0]);
	}
	if (sv[1] >= 0) {
		close(sv[1]);
	}
	if (ctrl_sock >= 0) {
		close(ctrl_sock);
	}

	return -1;
}

void ipxw_mux_unbind(int data_sock)
{
	struct ipxw_mux_msg unbind_msg;

	/* no error handling, nothing that can be done */
	unbind_msg.type = IPXW_MUX_UNBIND;
	send(data_sock, &unbind_msg, sizeof(unbind_msg), MSG_DONTWAIT);

	close(data_sock);
}

ssize_t ipxw_mux_xmit(int data_sock, struct ipxw_mux_msg *msg)
{
	/* check message type */
	if (msg->type != IPXW_MUX_XMIT) {
		errno = EINVAL;
		return -1;
	}

	size_t msg_len = sizeof(struct ipxw_mux_msg) + msg->xmit.data_len;

	/* send message, may block */
	ssize_t sent_len = send(data_sock, msg, msg_len, 0);
	if (sent_len < 0) {
		return -1;
	}

	if (sent_len != msg_len) {
		errno = ECOMM;
		return -1;
	}

	return sent_len;
}

ssize_t ipxw_mux_peek_recvd_len(int data_sock)
{
	struct ipxw_mux_msg msg;

	ssize_t rcvd_len = recv(data_sock, &msg, sizeof(msg), MSG_PEEK);
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
	recv(data_sock, &msg, 0, 0);

	return -1;
}

ssize_t ipxw_mux_get_recvd(int data_sock, struct ipxw_mux_msg *msg)
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

	/* receive a msg */
	ssize_t rcvd_len = recv(data_sock, msg, max_msg_len, 0);
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
		close (ctrl_sock);
		return -1;
	}

	return ctrl_sock;
}

void ipxw_mux_send_bind_resp(int data_sock, struct ipxw_mux_msg *resp_msg)
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
		err = send(data_sock, resp_msg, sizeof(struct ipxw_mux_msg),
				MSG_DONTWAIT);
	} while (err < 0 && errno == EINTR);
}

/* much of this code was taken from
 * https://man7.org/tlpi/code/online/dist/sockets/scm_rights_recv.c.html */
int ipxw_mux_recv_bind_msg(int ctrl_sock, struct ipxw_mux_msg *bind_msg)
{
	int data_sock = -1;

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
		union {
			char buf[CMSG_SPACE(sizeof(int))]; /* Space large
							      enough to hold an
							      'int' */
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
		if (cmsgp->cmsg_len != CMSG_LEN(sizeof(int))) {
			errno = EINVAL;
			break;
		}
		if (cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type !=
				SCM_RIGHTS) {
			errno = EINVAL;
			break;
		}

		/* retrive data socket */
		memcpy(&data_sock, CMSG_DATA(cmsgp), sizeof(int));
		if (data_sock < 0) {
			errno = EINVAL;
			break;
		}

		/* validate bind msg */
		if (bind_msg->type != IPXW_MUX_BIND) {
			errno = ENOTSUP;
			break;
		}

		return data_sock;
	} while (0);

	/* close a received socket if an error occurred */
	if (data_sock >= 0) {
		close(data_sock);
	}

	return -1;
}

ssize_t ipxw_mux_peek_xmit_len(int data_sock)
{
	struct ipxw_mux_msg msg;

	ssize_t rcvd_len = recv(data_sock, &msg, sizeof(msg), MSG_PEEK);
	if (rcvd_len < 0) {
		return -1;
	}

	do {
		/* need the ipxw_mux_msg */
		if (rcvd_len != sizeof(msg)) {
			errno = EREMOTEIO;
			break;
		}

		if (msg.type == IPXW_MUX_UNBIND)  {
			/* return the size of the unbind message */
			return sizeof(msg);
		}

		/* which has to be of the correct type */
		if (msg.type != IPXW_MUX_XMIT) {
			errno = EINVAL;
			break;
		}

		/* and the data must fit */
		if (msg.xmit.data_len > IPX_MAX_DATA_LEN) {
			errno = EREMOTEIO;
			break;
		}

		/* return the size of the message to xmit */
		return msg.xmit.data_len + sizeof(msg);
	} while (0);

	/* clear out invalid message */
	recv(data_sock, &msg, 0, 0);

	return -1;
}

ssize_t ipxw_mux_do_xmit(int data_sock, struct ipxw_mux_msg *msg, int
		(*tx_msg_cb)(int data_sock, struct ipxw_mux_msg *msg, void
			*ctx), void (*handle_unbind_cb)(int data_sock, void
				*ctx), void *tx_ctx, void *unbind_ctx)
{
	/* check if the message buffer is ok */
	if (msg->type != IPXW_MUX_XMIT) {
		errno = EINVAL;
		return -1;
	}

	if (msg->xmit.data_len > IPX_MAX_DATA_LEN) {
		errno = EINVAL;
		return -1;
	}

	size_t max_msg_len = msg->xmit.data_len + sizeof(struct ipxw_mux_msg);

	/* receive msg, this can block if the caller didn't make sure that data
	 * is available */
	ssize_t rcvd_msg_len = recv(data_sock, msg, max_msg_len, 0);
	if (rcvd_msg_len < 0) {
		return -1;
	}

	/* must at least receive a full mux msg */
	if (rcvd_msg_len < sizeof(struct ipxw_mux_msg)) {
		errno = EREMOTEIO;
		return -1;
	}

	switch(msg->type) {
		case IPXW_MUX_UNBIND:
			/* handle unbind */
			handle_unbind_cb(data_sock, unbind_ctx);
			return 0;
		case IPXW_MUX_XMIT:
			/* regular case */
			break;
		default:
			/* invalid message type */
			errno = EINVAL;
			return -1;
	}

	/* check if the data length is correct */
	if (msg->xmit.data_len != rcvd_msg_len - sizeof(struct
				ipxw_mux_msg)) {
		errno = EREMOTEIO;
		return -1;
	}

	/* handle the message */
	if (tx_msg_cb(data_sock, msg, tx_ctx) < 0) {
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

ssize_t ipxw_mux_recv(int data_sock, struct ipxw_mux_msg *msg)
{
	if (msg->type != IPXW_MUX_RECV) {
		errno = EINVAL;
		return -1;
	}

	if (msg->recv.data_len > IPX_MAX_DATA_LEN) {
		errno = EINVAL;
		return -1;
	}

	size_t msg_len = sizeof(struct ipxw_mux_msg) + msg->recv.data_len;
	if (msg_len > IPXW_MUX_MSG_LEN) {
		errno = EINVAL;
		return -1;
	}

	ssize_t sent_len = send(data_sock, msg, msg_len, 0);
	if (sent_len < 0) {
		return -1;
	}

	if (sent_len != msg_len) {
		errno = ECOMM;
		return -1;
	}

	return msg_len;
}
