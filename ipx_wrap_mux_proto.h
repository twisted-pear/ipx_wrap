#ifndef __IPX_WRAP_MUX_PROTO_H__
#define __IPX_WRAP_MUX_PROTO_H__

#include <bpf/bpf.h>

#include "common.h"

#define IPXW_MUX_CTRL_SOCK_NAME "ipxw_mux_ctrl"
#define IPXW_MUX_MSG_LEN 4096

enum ipxw_mux_msg_type {
	IPXW_MUX_BIND_ACK = 0,
	IPXW_MUX_BIND_ERR,
	IPXW_MUX_BIND,
	IPXW_MUX_UNBIND,
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
	__u16 reserved2;
} __attribute__((packed));

struct ipxw_mux_msg_unbind {
	// empty
} __attribute__((packed));

struct ipxw_mux_msg_xmit {
	struct ipx_addr daddr;
	__u8 pkt_type;
	__u8 reserved;
	__u16 data_len;
} __attribute__((packed));

struct ipxw_mux_msg_recv {
	struct ipx_addr saddr;
	__u8 pkt_type;
	__u8 is_bcast:1,
	     reserved:7;
	__u16 data_len;
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
				struct ipxw_mux_msg_xmit xmit;
				struct ipxw_mux_msg_recv recv;
			};
		} __attribute__((packed));
		struct ipxhdr ipxh;
	};
	__u8 data[0];
} __attribute__((packed));

#define IPX_MAX_DATA_LEN (IPXW_MUX_MSG_LEN - sizeof(struct ipxw_mux_msg))

/* client functions */

/* return new data socket or negative error, may block until an answer is
 * received from the muxer */
int ipxw_mux_bind(struct ipxw_mux_msg *bind_msg);

/* send unbind msg and close socket */
void ipxw_mux_unbind(int data_sock);

/* write message to data socket, may block if the caller did not check if the
 * data socket is writeable */
ssize_t ipxw_mux_xmit(int data_sock, struct ipxw_mux_msg *msg);

/* get a message from the data socket, assumes msg points to a buffer of at
 * least IPXW_MUX_MSG_LEN bytes, may block if the caller did not check if data
 * is available */
ssize_t ipxw_mux_get_recvd(int data_sock, struct ipxw_mux_msg *msg);

/* muxer functions */

/* create the control socket and bind it to the well-known abstract address */
int ipxw_mux_mk_ctrl_sock();

/* receive bind message and try to enter binding into whatever data structure
 * we use (using the callback), then send ACK or ERR, this blocks on receive if
 * the caller didn't check if data is available */
int ipxw_mux_do_ctrl(int ctrl_sock, int (*record_bind_cb)(int data_sock, struct
			ipxw_mux_msg_bind *, void *ctx), void *ctx);

/* receive xmit msgs, turn them into IPX messages and attempt to send them
 * (using transmit_msg_cb), on receiving and unbind msg, unbind the socket
 * (using handle_unbind_cb), this blocks if the caller did not check that data
 * is avaiable to read */
ssize_t ipxw_mux_do_data(int data_sock, int (*tx_msg_cb)(struct ipxw_mux_msg
			*msg, void *ctx), void (*handle_unbind_cb)(int
				data_sock, void *ctx), void *tx_ctx, void
		*unbind_ctx);

/* turn an xmit message into an ipx message, conversion happens in place */
struct ipxhdr *ipxw_mux_xmit_msg_to_ipxh(struct ipxw_mux_msg *xmit_msg, struct
		ipx_addr *saddr);

/* turn an ipx message into a recv message, conversion happens in place */
struct ipxw_mux_msg *ipxw_mux_ipxh_to_recv_msg(struct ipxhdr *ipx_msg);

/* send the recv msg to the client, will not block if the data socket is not
 * writeable, caller can retry or discard */
int ipxw_mux_recv(int data_sock, struct ipxw_mux_msg *msg);

#endif /* __IPX_WRAP_MUX_PROTO_H__ */
