#ifndef __IPX_WRAP_MUX_PROTO_H__
#define __IPX_WRAP_MUX_PROTO_H__

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <ifaddrs.h>
#include <sys/queue.h>

#include "common.h"
#include "ipx_wrap_common_proto.h"

#define IPXW_MUX_CTRL_SOCK_NAME "ipxw_mux_ctrl"

struct ipxw_mux_msg_bind_ack {
	__be32 prefix;
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

_Static_assert(IPX_MAX_DATA_LEN == (IPXW_MUX_MSG_LEN - sizeof(struct
				ipxw_mux_msg)), "ipxw_mux_msg size mismatch");

struct ipxw_mux_handle {
	int data_sock;
	int conf_sock;
	__be32 prefix;
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
int ipxw_mux_sk_getsockname(int sockfd, struct sockaddr *restrict addr,
		socklen_t *restrict addrlen);
int ipxw_mux_sk_close(int fd);

/* client functions */

/* makes the initial data sockete */
int ipxw_mux_mk_data_sock(void);

/* send data_sock to the muxer, returns it in the handle as data socket or
 * negative error, may block until an answer is received from the muxer, if an
 * error occurrs both data_sock will be closed, this blocks */
struct ipxw_mux_handle ipxw_mux_bind_data_sock(const struct ipxw_mux_msg
		*bind_msg, int datao_sock);

/* like ipxw_mux_bind_data_sock but creates and manages the data socket
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
void ipxw_mux_send_bind_resp(int conf_sock, const struct ipxw_mux_msg
		*resp_msg);

/* receive bind message, this blocks on if the caller didn't check if data is
 * available */
struct ipxw_mux_handle ipxw_mux_recv_bind_msg(int ctrl_sock, struct
		ipxw_mux_msg *bind_msg);

ssize_t ipxw_mux_peek_conf_len(int conf_sock);

ssize_t ipxw_mux_do_conf(int conf_sock, struct ipxw_mux_msg *msg, bool
		(*handle_conf_msg_cb)(int conf_sock, struct ipxw_mux_msg *msg,
			void *ctx), void *conf_ctx);

ssize_t ipxw_mux_recv_conf(int conf_sock, const struct ipxw_mux_msg *msg);

#endif /* __IPX_WRAP_MUX_PROTO_H__ */
