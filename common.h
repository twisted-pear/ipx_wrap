#ifndef __COMMON_H__
#define __COMMON_H__

#define IPX_IN_IPV6_PORT 213
static __u8 IPV6_MCAST_ALL_NODES[16] = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

struct ipx_addr {
	__be32 net;
	__u8 node[6];
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

struct if_config {
	__be32 prefix;
	__be32 network;
} __attribute__((packed));

#endif /* __COMMON_H__ */
