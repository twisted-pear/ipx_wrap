#ifndef __IPX_WRAP_COMMON_PROTO_H__
#define __IPX_WRAP_COMMON_PROTO_H__

#include <sys/queue.h>

#define MAX_DGRAM_LEN 65535 /* max length of a UDP packet */

#define IPXW_MUX_MSG_LEN (MAX_DGRAM_LEN - sizeof(struct udphdr)) /* more will
								    not fit
								    into a UDP
								    packet,
								    without
								    extension
								    header
								    trickery */


enum ipxw_mux_msg_type {
	IPXW_MUX_BIND_ACK = 0,
	IPXW_MUX_BIND_ERR,
	IPXW_MUX_BIND,
	IPXW_MUX_UNBIND,
	IPXW_MUX_CONF,
	IPXW_MUX_GETSOCKNAME,
	IPXW_MUX_SPX_CONNECT,
	IPXW_MUX_SPX_ACCEPT,
	IPXW_MUX_SPX_CLOSE,
	IPXW_MUX_XMIT,
	IPXW_MUX_RECV,
	IPXW_MUX_MAX
};

struct ipxw_mux_msg_xmit {
	struct ipx_addr daddr;
	__u8 pkt_type;
	__u8 reserved;
	__u16 data_len;
	__be16 reserved2;
} __attribute__((packed));

struct ipxw_mux_msg_recv {
	struct ipx_addr saddr;
	__u8 pkt_type;
	__u8 is_bcast:1,
	     is_spx:1,
	     reserved:6;
	__u16 data_len;
	__u16 reserved2;
} __attribute__((packed));

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

struct ipxw_mux_msg_spx_connect {
	struct ipx_addr addr;
	union {
		int spx_sock;
		__u32 err;
	};
	__be16 conn_id;
} __attribute__((packed));

struct ipxw_mux_msg_spx_accept {
	struct ipx_addr addr;
	union {
		int spx_sock;
		__u32 err;
	};
	__be16 conn_id;
} __attribute__((packed));

struct ipxw_mux_msg_spx_close {
	__be16 conn_id;
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
				struct ipxw_mux_msg_spx_connect spx_connect;
				struct ipxw_mux_msg_spx_accept spx_accept;
				struct ipxw_mux_msg_spx_close spx_close;
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

_Static_assert(IPX_MAX_DATA_LEN == (IPXW_MUX_MSG_LEN - sizeof(struct
				ipxw_mux_msg)), "ipxw_mux_msg size mismatch");

struct mc_bind_entry_key {
	__u32 ifidx;
	__be16 dst_sock;
} __attribute__((packed));

struct bpf_bind_entry {
	struct ipx_addr addr;
	__be32 prefix;
	__u8 pkt_type;
	__u8 recv_bcast:1,
	     pkt_type_any:1,
	     reserved:6;
};

#define SPX_PKT_TYPE 0x05

#define SPX_CC_NEGOTIATE_SIZE 0x04
#define SPX_CC_SPXII 0x08
#define SPX_CC_END_OF_MSG 0x10
#define SPX_CC_ATTENTION 0x20
#define SPX_CC_ACK_REQUIRED 0x40
#define SPX_CC_SYSTEM_PKT 0x80

#define SPX_CC_MASK_SPX 0xF0
#define SPX_CC_MASK_SPXII 0x0D

#define SPX_DS_NONE 0x00
#define SPX_DS_END_OF_CONN 0xFE
#define SPX_DS_END_OF_CONN_ACK 0xFF

#define SPX_CONN_ID_UNKNOWN bpf_htons(0xFFFF)

struct spxhdr {
	__u8 connection_control;
	__u8 datastream_type;
	__be16 src_conn_id;
	__be16 dst_conn_id;
	__be16 seq_no;
	__be16 ack_no;
	__be16 alloc_no;
} __attribute__((packed));

struct ipxw_mux_spx_msg {
	union {
		struct ipxhdr ipxh;
		struct ipxw_mux_msg mux_msg;
	};
	union {
		struct spxhdr spxh;
		struct {
			__u8 end_of_msg:1,
			     attention:1,
			     system:1,
			     keep_alive:1,
			     ack:1,
			     ack_required:1,
			     reserved:2;
			__u8 datastream_type;
			__u16 remote_alloc_no;
			__u16 local_alloc_no;
			__u16 remote_expected_sequence;
			union {
				__u16 local_current_sequence;
				__u16 seq_no;
			};
		} __attribute__((packed));
	};
	__u8 data[0];
} __attribute__((packed));

_Static_assert(sizeof(struct ipxw_mux_spx_msg) == sizeof(struct ipxhdr) +
		sizeof(struct spxhdr), "ipxw_mux_spx_msg_min too large");

#define SPX_MAX_PKT_LEN_WO_SIZNG 576 /* limit without size negotiation */
#define SPX_MAX_DATA_LEN_WO_SIZNG (SPX_MAX_PKT_LEN_WO_SIZNG - (sizeof(struct \
				ipxhdr) + sizeof(struct spxhdr)))

#define SPX_MAX_DATA_LEN (IPX_MAX_DATA_LEN - sizeof(struct spxhdr))

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

struct spx_conn_key {
	struct ipx_addr bind_addr;
	__be16 conn_id;
} __attribute__((packed));

struct bpf_spx_state {
	struct ipx_addr remote_addr;
	struct ipx_addr local_addr;
	__be16 remote_id;
	__be16 local_id;
	__u16 remote_alloc_no;
	__u16 local_alloc_no;
	__u16 remote_expected_sequence;
	__u16 local_current_sequence;
	__be32 prefix;
};

static __always_inline bool spx_seq_less_than(__u16 a, __u16 b)
{
	__s16 res;
	__builtin_sub_overflow(a, b, &res);
	return res < 0;
}

#define IPX_WIRE_OVERHEAD (sizeof(struct ipxhdr))
#define SPX_WIRE_OVERHEAD (sizeof(struct ipxhdr) + sizeof(struct spxhdr))

#define IPX_IN_IPV6UDP_OVERHEAD (sizeof(struct ipv6hdr) + sizeof(struct \
			udphdr))

#define IPX_WRAP_OVERHEAD (IPX_WIRE_OVERHEAD + IPX_IN_IPV6UDP_OVERHEAD)
#define SPX_WRAP_OVERHEAD (SPX_WIRE_OVERHEAD + IPX_IN_IPV6UDP_OVERHEAD)

#endif /* __IPX_WRAP_COMMON_PROTO_H__ */
