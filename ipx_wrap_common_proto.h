#ifndef __IPX_WRAP_COMMON_PROTO_H__
#define __IPX_WRAP_COMMON_PROTO_H__

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

struct ipxw_mux_msg_xmit {
	struct ipx_addr daddr;
	__u8 pkt_type;
	__u8 reserved;
	__u16 data_len;
	__be16 ssock; // TODO: remove this
} __attribute__((packed));

struct ipxw_mux_msg_min {
	union {
		struct {
			enum ipxw_mux_msg_type type;
			struct ipxw_mux_msg_xmit xmit;
		} __attribute__((packed));
		struct ipxhdr ipxh;
	};
	__u8 data[0];
} __attribute__((packed));

_Static_assert(sizeof(struct ipxw_mux_msg_min) == sizeof(struct ipxhdr),
		"ipxw_mux_msg_min too large");

#define IPX_MAX_DATA_LEN (IPXW_MUX_MSG_LEN - sizeof(struct ipxw_mux_msg_min))

#endif /* __IPX_WRAP_COMMON_PROTO_H__ */
