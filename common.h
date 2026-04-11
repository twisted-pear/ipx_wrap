#ifndef __COMMON_H__
#define __COMMON_H__

#define IPX_ADDR_NODE_BYTES 6

#define IFINDEX_MAX 512

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

#define IPX_DIRECT_MARK 0xaa

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

#endif /* __COMMON_H__ */
