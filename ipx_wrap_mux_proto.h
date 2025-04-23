#ifndef __IPX_WRAP_MUX_PROTO_H__
#define __IPX_WRAP_MUX_PROTO_H__

#include <sys/queue.h>
#include <bpf/bpf.h>

#include "common.h"

#define IPXW_MUX_CTRL_SOCK_NAME "ipxw_mux_ctrl"
#define IPXW_MUX_MSG_LEN (65535 - 8) /* more will not fit into a UDP packet,
					without extension header trickery */

enum ipxw_mux_msg_type {
	IPXW_MUX_BIND_ACK = 0,
	IPXW_MUX_BIND_ERR,
	IPXW_MUX_BIND,
	IPXW_MUX_UNBIND,
	IPXW_MUX_CONF,
	IPXW_MUX_GETSOCKNAME,
	IPXW_MUX_XMIT,
	IPXW_MUX_RECV,
	IPXW_MUX_MAX
};

struct ipxw_mux_msg_bind_ack {
	// empty
} __attribute__((packed));

struct ipxw_mux_msg_bind_err {
	__u32 err;
} __attribute__((packed));

struct ipxw_mux_msg_bind {
	struct ipx_addr addr;
	__u8 pkt_type;
	__u8 recv_bcast:1,
	     pkt_type_any:1,
	     reserved:6;
	__u32 reserved2;
} __attribute__((packed));

struct ipxw_mux_msg_unbind {
	// empty
} __attribute__((packed));

struct ipxw_mux_msg_conf {
	__u8 reserved[sizeof(struct ipx_addr)];
	__u8 reserved2;
	__u8 reserved3;
	__u16 data_len;
	__u16 reserved4;
} __attribute__((packed));

struct ipxw_mux_msg_getsockname {
	struct ipx_addr addr;
	__u8 pkt_type;
	__u8 recv_bcast:1,
	     pkt_type_any:1,
	     reserved:6;
	__u16 reserved2;
	__u16 reserved3;
} __attribute__((packed));

struct ipxw_mux_msg_xmit {
	struct ipx_addr daddr;
	__u8 pkt_type;
	__u8 reserved;
	__u16 data_len;
	__be16 ssock;
} __attribute__((packed));

struct ipxw_mux_msg_recv {
	struct ipx_addr saddr;
	__u8 pkt_type;
	__u8 is_bcast:1,
	     reserved:7;
	__u16 data_len;
	__u16 reserved2;
} __attribute__((packed));

struct ipxw_mux_msg {
	union {
		struct {
			enum ipxw_mux_msg_type type;
			union {
				struct ipxw_mux_msg_bind_ack ack;
				struct ipxw_mux_msg_bind_err err;
				struct ipxw_mux_msg_bind bind;
				struct ipxw_mux_msg_unbind unbind;
				struct ipxw_mux_msg_conf conf;
				struct ipxw_mux_msg_getsockname getsockname;
				struct ipxw_mux_msg_xmit xmit;
				struct ipxw_mux_msg_recv recv;
			};
			STAILQ_ENTRY(ipxw_mux_msg) q_entry;
		} __attribute__((packed));
		struct ipxhdr ipxh;
	};
	__u8 data[0];
} __attribute__((packed));

_Static_assert(sizeof(struct ipxw_mux_msg) == sizeof(struct ipxhdr),
		"ipxw_mux_msg too large");

#define IPX_MAX_DATA_LEN (IPXW_MUX_MSG_LEN - sizeof(struct ipxw_mux_msg))

struct ipxw_mux_handle {
	int data_sock;
	int conf_sock;
};

void ipxw_mux_handle_close(struct ipxw_mux_handle h);
bool ipxw_mux_handle_is_error(struct ipxw_mux_handle h);
int ipxw_mux_handle_data(struct ipxw_mux_handle h);
int ipxw_mux_handle_conf(struct ipxw_mux_handle h);

/* socket-like api */
/* absolutely not multithreading-safe */

#define IPXW_MUX_SK_PKT_TYPE_ANY 0xFF

struct sockaddr_ipx {
	sa_family_t sipx_family;
	__be16 sipx_port;
	__be32 sipx_network;
	__u8 sipx_node[IPX_ADDR_NODE_BYTES];
	__u8 sipx_type;
	__u8 sipx_zero; /* 16 byte fill */
};

int ipxw_mux_sk_socket(int domain, int type, int protocol);
int ipxw_mux_sk_bind(int sockfd, const struct sockaddr *addr, socklen_t
		addrlen);
ssize_t ipxw_mux_sk_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t ipxw_mux_sk_recvfrom(int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen);
int ipxw_mux_sk_close(int fd);

/* client functions */

/* makes the initial socket pair, the first is to be kept, the second will be
 * sent to the muxer */
int ipxw_mux_mk_socketpair(int *sv);

/* send sv[1] to the muxer, returns sv[0] as data socket or negative error, may
 * block until an answer is received from the muxer, if successful sv[1] will
 * be closed, if an error occurrs both sv[0] and sv[1] will be closed, this
 * blocks */
struct ipxw_mux_handle ipxw_mux_bind_socketpair(const struct ipxw_mux_msg
		*bind_msg, int *sv);

/* like ipxw_mux_bind_socketpair but creates and manages the socketpair
 * internally */
struct ipxw_mux_handle ipxw_mux_bind(const struct ipxw_mux_msg *bind_msg);

/* send unbind msg and close socket */
void ipxw_mux_unbind(struct ipxw_mux_handle h);

ssize_t ipxw_mux_send_recv_conf_msg(struct ipxw_mux_handle h, const struct
		ipxw_mux_msg *conf_in, struct ipxw_mux_msg *conf_out);

/* write message to data socket, may block if the caller did not check if the
 * data socket is writeable and block is true */
ssize_t ipxw_mux_xmit(struct ipxw_mux_handle h, const struct ipxw_mux_msg *msg,
		bool block);

/* get the length of the received message from the header, may block */
ssize_t ipxw_mux_peek_recvd_len(struct ipxw_mux_handle h, bool block);

/* get a message from the data socket, assumes msg points to a buffer of at
 * least sizeof(ipxw_mux_msg) bytes and that it is of type IPXW_MUX_RECV and
 * that the maximum IPX payload length that can be received is stored in
 * msg->recv.data_len, may block if the caller did not check if data is
 * available and block is true */
ssize_t ipxw_mux_get_recvd(struct ipxw_mux_handle h, struct ipxw_mux_msg *msg,
		bool block);

/* muxer functions */

/* create the control socket and bind it to the well-known abstract address */
int ipxw_mux_mk_ctrl_sock();

/* send a response to a bind message */
void ipxw_mux_send_bind_resp(struct ipxw_mux_handle h, const struct
		ipxw_mux_msg *resp_msg);

/* receive bind message, this blocks on if the caller didn't check if data is
 * available */
struct ipxw_mux_handle ipxw_mux_recv_bind_msg(int ctrl_sock, struct
		ipxw_mux_msg *bind_msg);

ssize_t ipxw_mux_peek_conf_len(struct ipxw_mux_handle h);

/* get the length of the message to xmit from the header, blocks if the caller
 * did not check that data is available to read */
ssize_t ipxw_mux_peek_xmit_len(struct ipxw_mux_handle h);

ssize_t ipxw_mux_do_conf(struct ipxw_mux_handle h, struct ipxw_mux_msg *msg,
		int (*handle_conf_msg_cb)(struct ipxw_mux_handle h, struct
			ipxw_mux_msg *msg, void *ctx), void *conf_ctx);

/* receive xmit msgs, turn them into IPX messages and attempt to send them
 * (using transmit_msg_cb), this blocks if the caller did not check that data
 * is avaiable to read */
ssize_t ipxw_mux_do_xmit(struct ipxw_mux_handle h, struct ipxw_mux_msg *msg,
		int (*tx_msg_cb)(struct ipxw_mux_handle h, struct ipxw_mux_msg
			*msg, void *ctx), void *tx_ctx);

/* turn an xmit message into an ipx message, conversion happens in place */
struct ipxhdr *ipxw_mux_xmit_msg_to_ipxh(struct ipxw_mux_msg *xmit_msg, struct
		ipx_addr *saddr);

/* turn an ipx message into a recv message, conversion happens in place */
struct ipxw_mux_msg *ipxw_mux_ipxh_to_recv_msg(struct ipxhdr *ipx_msg);

ssize_t ipxw_mux_recv_conf(struct ipxw_mux_handle h, const struct ipxw_mux_msg
		*msg);

/* send the recv msg to the client, will block if the data socket is not
 * writeable */
ssize_t ipxw_mux_recv(struct ipxw_mux_handle h, const struct ipxw_mux_msg
		*msg);

#endif /* __IPX_WRAP_MUX_PROTO_H__ */
