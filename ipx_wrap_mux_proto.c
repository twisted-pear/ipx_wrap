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
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
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
		while (res_len < 0) {
			res_len = recv(data_sock, &res, sizeof(res), 0);
			if (res_len < 0) {
				/* interrupted, retry */
				if (errno == EINTR) {
					continue;
				}
				break;
			}
		}
		if (res_len < 0) {
			break;
		}

		/* should not happen, but if it does we report the error */
		if (res_len != sizeof(res)) {
			errno = EMSGSIZE;
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

	return -errno;
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
		return -EINVAL;
	}

	size_t msg_len = sizeof(struct ipxw_mux_msg) + msg->xmit.data_len;

	/* send message, may block */
	ssize_t sent_len = send(data_sock, msg, msg_len, 0);
	if (sent_len < 0) {
		return -errno;
	}

	if (sent_len != msg_len) {
		return -EMSGSIZE;
	}

	return sent_len;
}

ssize_t ipxw_mux_get_recvd(int data_sock, struct ipxw_mux_msg *msg)
{
	/* receive a msg */
	ssize_t rcvd_len = recv(data_sock, msg, IPXW_MUX_MSG_LEN, 0);
	if (rcvd_len < 0) {
		return -errno;
	}

	/* need at least a full msg */
	if (rcvd_len < sizeof(struct ipxw_mux_msg)) {
		return -EMSGSIZE;
	}

	/* which has to be of the correct type */
	if (msg->type != IPXW_MUX_RECV) {
		return -EINVAL;
	}

	/* and the data needs to be the correct length */
	size_t data_len = rcvd_len - sizeof(struct ipxw_mux_msg);
	if (msg->recv.data_len != data_len) {
		return -EMSGSIZE;
	}

	return data_len;
}

/* muxer functions */

int ipxw_mux_mk_ctrl_sock()
{
	int ctrl_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (ctrl_sock < 0) {
		return -errno;
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
		return -errno;
	}

	return ctrl_sock;
}

/* much of this code was taken from
 * https://man7.org/tlpi/code/online/dist/sockets/scm_rights_recv.c.html */
int ipxw_mux_do_ctrl(int ctrl_sock, int (*record_bind_cb)(int data_sock, struct
			ipxw_mux_msg_bind *, void *ctx), void *ctx)
{
	struct ipxw_mux_msg resp_msg;
	memset(&resp_msg, 0, sizeof(resp_msg));

	int data_sock = -1;

	do {
		/* prepare buffer to receive the bind message */
		struct ipxw_mux_msg bind_msg;

		struct msghdr msgh;
		msgh.msg_name = NULL;
		msgh.msg_namelen = 0;

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

		msgh.msg_control = ctrl_msg.buf;
		msgh.msg_controllen = sizeof(ctrl_msg.buf);

		/* receive a bind message */
		/* this can block if the caller didn't check if data is
		 * available first */
		int rcvd_len = recvmsg(ctrl_sock, &msgh, 0);
		if (rcvd_len < 0) {
			break;
		}

		/* should not happen, but if it does we report the error */
		if (rcvd_len != sizeof(bind_msg)) {
			errno = EMSGSIZE;
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

		/* from here on out we are ready to send a response */
		resp_msg.type = IPXW_MUX_BIND_ERR;

		/* validate bind msg */
		if (bind_msg.type != IPXW_MUX_BIND) {
			errno = ENOTSUP;
			break;
		}

		if (record_bind_cb(data_sock, &bind_msg.bind, ctx) < 0) {
			errno = EACCES;
			break;
		}

		/* send success msg */
		resp_msg.type = IPXW_MUX_BIND_ACK;
		/* no error handling, there is nothing we can do */
		send(data_sock, &resp_msg, sizeof(resp_msg), MSG_DONTWAIT);

		return data_sock;
	} while (0);

	/* send an error response if the response msg has been prepared */
	if (resp_msg.type == IPXW_MUX_BIND_ERR) {
		resp_msg.err.err = errno;

		/* no error handling, we can't do anything about this */
		send(data_sock, &resp_msg, sizeof(resp_msg), MSG_DONTWAIT);
	}

	/* close a received socket if an error occurred */
	if (data_sock >= 0) {
		close(data_sock);
	}

	return -errno;
}

ssize_t ipxw_mux_do_data(int data_sock, int (*tx_msg_cb)(struct ipxw_mux_msg
			*msg, void *ctx), void (*handle_unbind_cb)(int
				data_sock, void *ctx), void *tx_ctx, void
		*unbind_ctx)
{
	struct ipxw_mux_msg *rcvd_msg = calloc(1, IPXW_MUX_MSG_LEN);
	if (rcvd_msg == NULL) {
		return -errno;
	}

	/* receive msg, this can block if the caller didn't make sure that data
	 * is available */
	ssize_t rcvd_msg_len = recv(data_sock, rcvd_msg, IPXW_MUX_MSG_LEN, 0);
	if (rcvd_msg_len < 0) {
		free(rcvd_msg);
		return -errno;
	}

	/* must at least receive a full mux msg */
	if (rcvd_msg_len < sizeof(struct ipxw_mux_msg)) {
		free(rcvd_msg);
		return -EMSGSIZE;
	}

	switch(rcvd_msg->type) {
		case IPXW_MUX_UNBIND:
			/* handle unbind */
			free(rcvd_msg);
			handle_unbind_cb(data_sock, unbind_ctx);
			return 0;
		case IPXW_MUX_XMIT:
			/* regular case */
			break;
		default:
			/* invalid message type */
			free(rcvd_msg);
			return -EINVAL;
	}

	/* check if the data length is correct */
	if (rcvd_msg->xmit.data_len != rcvd_msg_len - sizeof(struct
				ipxw_mux_msg)) {
		free(rcvd_msg);
		return -EMSGSIZE;
	}

	/* tx_msg_cb has to free the buffer if it is not needed anymore, even
	 * if it returns an error */
	if (tx_msg_cb(rcvd_msg, tx_ctx) < 0) {
		return -EINVAL;
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
	ipx_msg->csum = 0xFFFF;
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
	bool is_bcast = true;
	int i;
	for (i = 0; i < sizeof(ipx_msg->daddr.node); i++) {
		if (ipx_msg->daddr.node[i] != 0xFF) {
			is_bcast = false;
			break;
		}
	}

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

int ipxw_mux_recv(int data_sock, struct ipxw_mux_msg *msg)
{
	if (msg->type != IPXW_MUX_RECV) {
		return -EINVAL;
	}

	if (msg->recv.data_len > IPX_MAX_DATA_LEN) {
		return -EINVAL;
	}

	size_t msg_len = sizeof(struct ipxw_mux_msg) + msg->recv.data_len;
	if (msg_len > IPXW_MUX_MSG_LEN) {
		return -EINVAL;
	}

	ssize_t sent_len = send(data_sock, msg, msg_len, MSG_DONTWAIT);
	if (sent_len < 0) {
		return -errno;
	}

	if (sent_len != msg_len) {
		return -EMSGSIZE;
	}

	return msg_len;
}
