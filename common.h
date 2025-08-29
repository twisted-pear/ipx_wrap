#ifndef __COMMON_H__
#define __COMMON_H__

#define IPX_ADDR_NODE_BYTES 6

#define IFINDEX_MAX 64

#ifndef bpf_htons
#	define bpf_htons htons
#endif
#ifndef bpf_htonl
#	define bpf_htonl htonl
#endif

#define IPX_CSUM_NONE bpf_htons(0xFFFF)
#define IPX_NET_LOCAL bpf_htonl(0x0)
#define IPX_NET_ALL_ROUTES bpf_htonl(0xFFFFFFFF)
#define IPX_NET_DEFAULT_ROUTE bpf_htonl(0xFFFFFFFE)
static const __u8 IPX_BCAST_NODE[IPX_ADDR_NODE_BYTES] = { 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF };
static const __u8 IPX_NO_NODE[IPX_ADDR_NODE_BYTES] = { 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00 };
#define IPX_ANY_DYNAMIC_SOCKET bpf_htons(0x0000)
#define IPX_MIN_DYNAMIC_SOCKET bpf_htons(0x4000)
#define IPX_MIN_WELL_KNOWN_SOCKET bpf_htons(0x8000)

#define IPX_IN_IPV6_PORT 213
static const __u8 IPV6_MCAST_ALL_NODES[16] = { 0xFF, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

struct ipx_addr {
	__be32 net;
	__u8 node[IPX_ADDR_NODE_BYTES];
	__be16 sock;
} __attribute__((packed));

struct ipxhdr {
	__be16 csum;
	__be16 pktlen;
	__u8 tc;
	__u8 type;
	struct ipx_addr daddr;
	struct ipx_addr saddr;
} __attribute__((packed));

struct ipv6_eui64_addr {
	__be32 prefix;
	__be32 ipx_net;
	__u8 ipx_node_fst[3];
	__be16 fffe;
	__u8 ipx_node_snd[3];
} __attribute__((packed));

static __always_inline void ipx_to_ipv6_addr(struct in6_addr *dst, const struct
		ipx_addr *src, __be32 prefix)
{
	struct ipv6_eui64_addr *res = (struct ipv6_eui64_addr *) dst;
	res->prefix = prefix;
	res->ipx_net = src->net;
	__builtin_memcpy(&(res->ipx_node_fst), src->node, IPX_ADDR_NODE_BYTES /
			2);
	res->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(&(res->ipx_node_snd), &(src->node[3]),
			IPX_ADDR_NODE_BYTES / 2);
}

struct if_config {
	__be32 prefix;
	__be32 network;
} __attribute__((packed));

struct bpf_cb_info {
	union {
		__u32 cb[5];
		struct {
			__u16 mark;
			__u16 is_bcast:1,
			      is_for_local:1,
			      is_spx_end_of_conn_ack:1,
			      reserved:13;
			struct ipx_addr spx_src;
			__be16 spx_conn_id;
		} __attribute__((packed));
	};
} __attribute__((packed));

_Static_assert(sizeof(struct bpf_cb_info) == (sizeof(__u32) * 5),
		"bpf_cb_info has invalid size");

#define IPX_TO_IPV6_REINJECT_MARK 0x4774
#define IPX_TO_IPV6UDP_REINJECT_MARK 0x7447
#define IPX_SPX_REFLECTED_ACK 0xdead

#endif /* __COMMON_H__ */
